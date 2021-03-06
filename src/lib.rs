use color_eyre::eyre::{bail, eyre, Report, WrapErr};
use quanta::Instant;
use rand::{rngs::ThreadRng, Rng};
use serde::{Deserialize, Serialize};
use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use structopt::StructOpt;
use tracing::{error, info};

mod dpdk;
pub use dpdk::{dpdk_client, dpdk_server};

mod dpdk_inline;
pub use dpdk_inline::{dpdk_inline_client, dpdk_inline_server};

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
    pub work_gen: WorkGenerator,

    #[structopt(long, default_value = "0")]
    pub req_padding_size: usize,
}

#[derive(Debug, Clone, StructOpt)]
pub struct Server {
    /// The port to listen on.
    #[structopt(short, long)]
    pub port: u16,

    /// Maximum number of server threads to spawn.
    ///
    /// For connetion-oriented datapaths, this is the maximum number of concurrent threads to
    /// spawn, while fixed-concurrency datapaths will just spawn this number of threads at the
    /// beginning.
    #[structopt(short, long)]
    pub threads: Option<usize>,
}

fn black_box<T>(dummy: T) -> T {
    unsafe {
        let ret = std::ptr::read_volatile(&dummy);
        std::mem::forget(dummy);
        ret
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
                    black_box(f64::sqrt(k * i as f64));
                }
            }
            Work::Memory(amt) => {
                for i in 0..(amt as usize) {
                    black_box(access_buf[access_buf[i % access_buf.len()] % access_buf.len()]);
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

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Work {
    Immediate,
    BusyWork(u64),
    Memory(u64),
}

/// Work specification that can be constructed from a string.
///
/// The work string specifies the type and amount of work. If nonzero, the amount of work can be
/// distributed uniformly over one (unimodal) or two (bimodal) ranges.
///
/// ```rust,no_run
/// use datapath_bench::WorkGenerator;
/// // no work.
/// let _: WorkGenerator = "imm".parse().unwrap();
/// // exactly 39 random memory accesses in a large array per request
/// let _: WorkGenerator = "mem:39".parse().unwrap();
/// // between [500, 1500] square root computations per request
/// let _: WorkGenerator = "cpu:1000~1000".parse().unwrap();
/// // either [0, 100] or [1000, 2000] memory accesses per request
/// let _: WorkGenerator = "mem:50~100:50%1500~1000".parse().unwrap();
/// ```
#[derive(Debug, Clone, Copy)]
pub struct WorkGenerator {
    kind: WorkType,
    distr: WorkDistribution,
}

#[derive(Debug, Clone, Copy)]
enum WorkType {
    Immediate,
    Cpu,
    Memory,
}

#[derive(Debug, Clone, Copy)]
enum WorkDistribution {
    Unimodal(Distr),
    Bimodal {
        first: Distr,
        first_prob: u8,
        second: Distr,
    },
}

#[derive(Debug, Clone, Copy)]
enum Distr {
    Const { mean: u64 },
    Uniform { range_start: u64, range_end: u64 },
}

impl FromStr for Distr {
    type Err = Report;
    fn from_str(amount: &str) -> Result<Self, Self::Err> {
        Ok(if amount.contains('~') {
            let (m, r) = amount.split_once('~').unwrap(); // we know ~ is present
            let mean: u64 = m
                .parse()
                .wrap_err(eyre!("Parsing uniform distribution mean: {:?}", m))?;
            let range: u64 = r
                .parse()
                .wrap_err(eyre!("Parsing uniform distribution range: {:?}", r))?;
            if range > 1 {
                Distr::Uniform {
                    range_start: mean.saturating_sub(range / 2),
                    range_end: mean + (range / 2),
                }
            } else {
                Distr::Const { mean }
            }
        } else {
            Distr::Const {
                mean: amount
                    .parse()
                    .wrap_err("Parsing constant distribution work amount")?,
            }
        })
    }
}

impl Distr {
    fn get(&self, rng: &mut ThreadRng) -> u64 {
        match self {
            Distr::Const { mean } => *mean,
            Distr::Uniform {
                range_start,
                range_end,
            } => rng.gen_range(*range_start..*range_end),
        }
    }
}

impl FromStr for WorkGenerator {
    type Err = Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sp: Vec<_> = s.split(':').collect();
        let kind = match sp[0] {
            "immediate" | "imm" => WorkType::Immediate,
            "sqrts" | "cpu" => WorkType::Cpu,
            "memory" | "mem" => WorkType::Memory,
            x => {
                bail!("Could not parse work type: {:?}", x)
            }
        };

        if let WorkType::Immediate = kind {
            return Ok(Self {
                kind,
                distr: WorkDistribution::Unimodal(Distr::Const { mean: 0 }),
            });
        }

        let distr = match &sp[1..] {
            [amount] => WorkDistribution::Unimodal(amount.parse()?),
            [amount1, amount2] => {
                let (pct1, first) = match amount1.split_once('%') {
                    None => (None, amount1.parse()?),
                    Some((pct, amt)) => (Some(pct.parse()?), amt.parse()?),
                };

                let (pct2, second): (Option<u8>, _) = match amount2.split_once('%') {
                    None => (None, amount2.parse()?),
                    Some((pct, amt)) => (Some(pct.parse()?), amt.parse()?),
                };

                let first_prob = match (pct1, pct2) {
                    (Some(n1), Some(n2)) if n1 + n2 == 100 => n1,
                    (Some(n), None) if n < 100 => n,
                    (None, Some(n)) if n < 100 => (100 - n),
                    (None, None) => 50,
                    x => bail!("Bimodal percentages must sum to 100%: {:?}", x),
                };

                WorkDistribution::Bimodal {
                    first,
                    first_prob,
                    second,
                }
            }
            x => {
                bail!("Could not parse work distribution: {:?}", x)
            }
        };

        info!(?kind, ?distr, "parsed request work");
        Ok(Self { kind, distr })
    }
}

impl Iterator for WorkGenerator {
    type Item = Work;
    fn next(&mut self) -> Option<Self::Item> {
        if let WorkType::Immediate = self.kind {
            return Some(Work::Immediate);
        }

        let mut rng = rand::thread_rng();
        let amt = match self.distr {
            WorkDistribution::Unimodal(d) => d.get(&mut rng),
            WorkDistribution::Bimodal {
                first,
                first_prob,
                second,
            } => {
                let flip: u8 = rng.gen_range(0..100);
                if flip < first_prob {
                    first.get(&mut rng)
                } else {
                    second.get(&mut rng)
                }
            }
        };

        Some(match self.kind {
            WorkType::Cpu => Work::BusyWork(amt),
            WorkType::Memory => Work::Memory(amt),
            _ => unreachable!(),
        })
    }
}

pub struct AsyncSpinTimer {
    clk: quanta::Clock,
    interarrival: Duration,
    deficit: Duration,
    last_return: Option<Instant>,
}

impl AsyncSpinTimer {
    pub fn new(interarrival: Duration) -> Self {
        AsyncSpinTimer {
            clk: quanta::Clock::new(),
            interarrival,
            deficit: Duration::from_micros(0),
            last_return: None,
        }
    }

    pub async fn wait(&mut self) {
        if self.deficit > self.interarrival {
            self.deficit -= self.interarrival;
            self.last_return = Some(self.clk.now());
            return;
        }

        if self.last_return.is_none() {
            self.last_return = Some(self.clk.now());
        }

        let target = self.last_return.unwrap() + self.interarrival;
        loop {
            let now = self.clk.now();
            if now >= target {
                break;
            }

            if target - now > Duration::from_micros(10) {
                tokio::time::sleep(Duration::from_micros(5)).await;
            } else {
                tokio::task::yield_now().await
            }
        }

        let elapsed = self.clk.now() - self.last_return.unwrap();
        if elapsed > self.interarrival {
            self.deficit += elapsed - self.interarrival;
        }

        self.last_return = Some(self.clk.now());
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
