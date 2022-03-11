use color_eyre::eyre::{bail, Report};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use structopt::StructOpt;
use tracing::{error, info};

mod dpdk;
pub use dpdk::{dpdk_client, dpdk_server};

mod shenangort;
pub use shenangort::{shenango_client, shenango_server};

#[derive(Debug, Clone, StructOpt)]
pub struct Client {
    #[structopt(short, long)]
    pub addr: SocketAddrV4,

    #[structopt(short, long)]
    pub num_reqs: usize,

    #[structopt(short, long)]
    pub conn_count: usize,

    #[structopt(short, long)]
    pub load_req_per_s: usize,

    #[structopt(long, default_value = "imm")]
    pub req_work_type: Work,

    #[structopt(long, default_value = "0")]
    pub req_work_disparity: usize,

    #[structopt(long, default_value = "0")]
    pub req_padding_size: usize,
}

#[derive(Debug, Clone, StructOpt)]
pub struct Server {
    #[structopt(short, long)]
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Work {
    Immediate,
    BusyWork(u64),
    Memory(u64),
}

impl FromStr for Work {
    type Err = Report;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sp: Vec<_> = s.split(':').collect();
        match &sp[..] {
            [_, mean] if *mean == "0" => Ok(Work::Immediate),
            [variant] if *variant == "immediate" || *variant == "imm" => Ok(Work::Immediate),
            [variant, mean] if *variant == "sqrts" || *variant == "cpu" => {
                Ok(Work::BusyWork(mean.parse()?))
            }
            [variant, mean] if *variant == "memory" || *variant == "mem" => {
                Ok(Work::Memory(mean.parse()?))
            }
            x => {
                bail!("Could not parse work: {:?}", x)
            }
        }
    }
}

impl Work {
    fn work(self, access_buf: &[usize]) {
        match self {
            Work::Immediate => (),
            Work::BusyWork(amt) => {
                // copy from shenango:
                // https://github.com/shenango/shenango/blob/master/apps/synthetic/src/fakework.rs#L54
                let k = 2350845.545;
                for i in 0..amt {
                    criterion::black_box(f64::sqrt(k * i as f64));
                }
            }
            Work::Memory(amt) => {
                for i in 0..(amt as usize) {
                    criterion::black_box(
                        access_buf[access_buf[i % access_buf.len()] % access_buf.len()],
                    );
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Req {
    pub wrk: Work,
    pub client_time: u64, // 12 bytes
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Resp {
    pub srv_time: Duration,
    pub client_time: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DoneResp {
    pub srv_time: Duration,
    pub duration: Duration,
}

#[derive(Debug, Clone)]
pub enum WorkGenerator {
    Immediate,
    BusyWork { range_start: u64, range_end: u64 },
    BusyWorkConst { mean: u64 },
    Memory { range_start: u64, range_end: u64 },
    MemoryConst { mean: u64 },
}

impl WorkGenerator {
    pub fn new(w: Work, disparity: usize) -> Self {
        match (w, disparity) {
            (Work::Immediate, _) => Self::Immediate,
            (Work::BusyWork(mean), 0) => Self::BusyWorkConst { mean },
            (Work::BusyWork(mean), disparity) => {
                let range_start = mean - ((disparity / 2) as u64);
                Self::BusyWork {
                    range_start,
                    range_end: range_start + disparity as u64,
                }
            }
            (Work::Memory(mean), 0) => Self::MemoryConst { mean },
            (Work::Memory(mean), disparity) => {
                let range_start = mean - ((disparity / 2) as u64);
                Self::Memory {
                    range_start,
                    range_end: range_start + disparity as u64,
                }
            }
        }
    }
}

impl Iterator for WorkGenerator {
    type Item = Work;
    fn next(&mut self) -> Option<Self::Item> {
        Some(match self {
            WorkGenerator::Immediate => Work::Immediate,
            WorkGenerator::BusyWork {
                range_start,
                range_end,
            } => Work::BusyWork(rand::thread_rng().gen_range(*range_start..*range_end)),
            WorkGenerator::Memory {
                range_start,
                range_end,
            } => Work::Memory(rand::thread_rng().gen_range(*range_start..*range_end)),
            WorkGenerator::BusyWorkConst { mean } => Work::BusyWork(*mean),
            WorkGenerator::MemoryConst { mean } => Work::Memory(*mean),
        })
    }
}

pub struct AsyncSpinTimer {
    interarrival: Duration,
    deficit: Duration,
}

impl AsyncSpinTimer {
    pub fn new(interarrival: Duration) -> Self {
        AsyncSpinTimer {
            interarrival,
            deficit: Duration::from_micros(0),
        }
    }

    pub async fn wait(&mut self) {
        let start = tokio::time::Instant::now();
        if self.deficit > self.interarrival {
            self.deficit -= self.interarrival;
            return;
        }

        let target = start + self.interarrival;
        loop {
            let now = tokio::time::Instant::now();
            if now >= target {
                break;
            }

            if target - now > Duration::from_micros(10) {
                tokio::time::sleep(Duration::from_micros(5)).await;
            } else {
                tokio::task::yield_now().await
            }
        }

        let elapsed = tokio::time::Instant::now() - start;
        if elapsed > self.interarrival {
            self.deficit += elapsed - self.interarrival;
        }
    }

    pub fn into_stream(self) -> impl futures_util::stream::Stream<Item = ()> {
        futures_util::stream::unfold(self, |mut this| async move {
            Some({
                this.wait().await;
                ((), this)
            })
        })
    }
}

fn write_results(
    reqs: Vec<DoneResp>,
    remaining_inflight: usize,
    time: Duration,
    attempted_load_req_per_sec: usize,
    out_file: Option<PathBuf>,
) {
    if reqs.is_empty() {
        error!("no requests finished");
        return;
    }

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
