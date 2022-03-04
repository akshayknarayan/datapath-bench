use color_eyre::eyre::{bail, Report};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::time::Duration;

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
pub enum WorkGenerator<R> {
    Immediate,
    BusyWork {
        rng: R,
        range_start: u64,
        range_end: u64,
    },
    BusyWorkConst {
        mean: u64,
    },
    Memory {
        rng: R,
        range_start: u64,
        range_end: u64,
    },
    MemoryConst {
        mean: u64,
    },
}

impl WorkGenerator<rand::rngs::ThreadRng> {
    pub fn new(w: Work, disparity: usize) -> Self {
        match (w, disparity) {
            (Work::Immediate, _) => Self::Immediate,
            (Work::BusyWork(mean), 0) => Self::BusyWorkConst { mean },
            (Work::BusyWork(mean), disparity) => {
                let range_start = mean - ((disparity / 2) as u64);
                Self::BusyWork {
                    rng: rand::thread_rng(),
                    range_start,
                    range_end: range_start + disparity as u64,
                }
            }
            (Work::Memory(mean), 0) => Self::MemoryConst { mean },
            (Work::Memory(mean), disparity) => {
                let range_start = mean - ((disparity / 2) as u64);
                Self::Memory {
                    rng: rand::thread_rng(),
                    range_start,
                    range_end: range_start + disparity as u64,
                }
            }
        }
    }
}

impl<R: rand::Rng> Iterator for WorkGenerator<R> {
    type Item = Work;
    fn next(&mut self) -> Option<Self::Item> {
        Some(match self {
            WorkGenerator::Immediate => Work::Immediate,
            WorkGenerator::BusyWork {
                rng,
                range_start,
                range_end,
            } => Work::BusyWork(rng.gen_range(*range_start..*range_end)),
            WorkGenerator::Memory {
                rng,
                range_start,
                range_end,
            } => Work::Memory(rng.gen_range(*range_start..*range_end)),
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
