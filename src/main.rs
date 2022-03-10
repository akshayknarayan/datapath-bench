use color_eyre::eyre::Report;
use datapath_bench::{dpdk_client, dpdk_server, Client, DoneResp, Server};
use std::path::PathBuf;
use std::time::Duration;
use structopt::StructOpt;
use tracing::info;
use tracing_error::ErrorLayer;
use tracing_subscriber::prelude::*;

#[derive(Debug, Clone, StructOpt)]
struct Opt {
    #[structopt(long)]
    cfg: PathBuf,

    #[structopt(short, long)]
    out_file: Option<std::path::PathBuf>,

    #[structopt(subcommand)]
    mode: Mode,
}

#[derive(Debug, Clone, StructOpt)]
enum Mode {
    Client(Client),
    Server(Server),
}

fn main() -> Result<(), Report> {
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(ErrorLayer::default());
    let d = tracing::Dispatch::new(subscriber);
    d.init();
    color_eyre::install()?;
    let Opt {
        cfg,
        out_file,
        mode,
    } = Opt::from_args();

    match mode {
        Mode::Server(s) => dpdk_server(cfg, s),
        Mode::Client(c) => {
            let load = c.load_req_per_s;
            let tot_reqs = c.num_reqs;
            let clk = quanta::Clock::new();
            let then = clk.start();
            let durs = dpdk_client(cfg, c)?;
            let now = clk.end();
            let elapsed = clk.delta(then, now);
            let remaining = tot_reqs - durs.len();
            write_results(durs, remaining, elapsed, load, out_file);
            Ok(())
        }
    }
}

fn write_results(
    reqs: Vec<DoneResp>,
    remaining_inflight: usize,
    time: Duration,
    attempted_load_req_per_sec: usize,
    out_file: Option<PathBuf>,
) {
    let mut durs: Vec<_> = reqs
        .clone()
        .into_iter()
        .map(|DoneResp { duration, .. }| duration)
        .collect();
    durs.sort();
    let len = durs.len() as f64;
    let quantile_idxs = [0.25, 0.5, 0.75, 0.95];
    let quantiles: Vec<_> = quantile_idxs
        .iter()
        .map(|q| (len * q) as usize)
        .map(|i| durs[i])
        .collect();
    let num = durs.len() as f64;
    let achieved_load_req_per_sec = (num as f64) / time.as_secs_f64();
    let offered_load_req_per_sec = (num + remaining_inflight as f64) / time.as_secs_f64();
    info!(
        num = ?&durs.len(), elapsed = ?time, ?remaining_inflight,
        ?achieved_load_req_per_sec, ?offered_load_req_per_sec, ?attempted_load_req_per_sec,
        min = ?durs[0], p25 = ?quantiles[0], p50 = ?quantiles[1],
        p75 = ?quantiles[2], p95 = ?quantiles[3], max = ?durs[durs.len() - 1],
        "Did accesses"
    );

    println!(
        "Did accesses:\
        num = {:?},\
        elapsed_sec = {:?},\
        remaining_inflight = {:?},\
        achieved_load_req_per_sec = {:?},\
        offered_load_req_per_sec = {:?},\
        attempted_load_req_per_sec = {:?},\
        min_us = {:?},\
        p25_us = {:?},\
        p50_us = {:?},\
        p75_us = {:?},\
        p95_us = {:?},\
        max_us = {:?}",
        durs.len(),
        time.as_secs_f64(),
        remaining_inflight,
        achieved_load_req_per_sec,
        offered_load_req_per_sec,
        attempted_load_req_per_sec,
        durs[0].as_micros(),
        quantiles[0].as_micros(),
        quantiles[1].as_micros(),
        quantiles[2].as_micros(),
        quantiles[3].as_micros(),
        durs[durs.len() - 1].as_micros(),
    );

    if let Some(f) = out_file {
        let mut f = std::fs::File::create(f).expect("Open out file");
        use std::io::Write;
        writeln!(
            &mut f,
            "Offered_load_rps NumOps Completion_ms Latency_us Server_us"
        )
        .expect("write");
        let len = reqs.len();
        for DoneResp { srv_time, duration } in reqs {
            writeln!(
                &mut f,
                "{} {} {} {} {}",
                attempted_load_req_per_sec,
                len,
                time.as_millis(),
                duration.as_micros(),
                srv_time.as_micros()
            )
            .expect("write");
        }
    }
}
