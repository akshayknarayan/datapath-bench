use super::{Client, DoneResp, Req, Resp, Server, Work, WorkGenerator};
use color_eyre::eyre::{ensure, eyre, Report, WrapErr};
use futures_util::stream::StreamExt;
use shenango::sync::Mutex;
use shenango::udp::{self, UdpConnection};
use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tracing::{debug, info, info_span, trace, warn};

pub fn shenango_server(cfg: PathBuf, Server { port }: Server) -> Result<(), Report> {
    info!("KV Server, no chunnels");
    shenango::runtime_init(cfg.to_str().unwrap().to_owned(), move || {
        server(port).unwrap();
    })
    .unwrap();
    Ok(())
}

fn server(port: u16) -> Result<(), Report> {
    let bind_addr = SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, port);

    let idx = Arc::new(AtomicUsize::new(0));
    udp::udp_accept(bind_addr, move |cn| {
        let idx = idx.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        server_conn(cn, idx).unwrap()
    })
    .unwrap()
}

fn server_conn(cn: UdpConnection, idx: usize) -> Result<(), Report> {
    let from = cn.remote_addr();
    info!(?idx, ?from, "new");
    let access_buf = {
        let mut rng = rand::thread_rng();
        let mut mem: Vec<usize> = (0..(8 * 1024)).collect();
        use rand::seq::SliceRandom;
        mem.shuffle(&mut rng);
        mem
    };
    let clk = quanta::Clock::new();
    let mut buf = [0u8; 2048];
    loop {
        let len = cn.recv(&mut buf)?;
        let buf = buf[..len];

        let then = clk.start();
        ensure!(len > 8, "msg too short: {} < 8", buf.len());
        let sz = u64::from_be_bytes(buf[0..8].try_into().unwrap()) as usize;
        ensure!(
            len >= 8 + sz,
            "msg too short for declared size: {} < {}",
            len,
            8 + sz
        );

        let Req { wrk, client_time } = bincode::deserialize(&buf[8..(8 + sz)])?;
        wrk.work(&access_buf[..]);
        let now = clk.end();
        let resp = Resp {
            srv_time: clk.delta(then, now),
            client_time,
        };

        let sz = bincode::serialized_size(&rsp)? as usize;
        buf[0..8].copy_from_slice(&sz.to_be_bytes());
        bincode::serialize_into(&mut buf[8..(8 + sz)], &resp)?;
        if let Err(e) = cn.send(&buf[..(8 + sz)]) {
            warn!(?e, "send failed");
            break Err(e.into());
        }
    }
}

pub fn shenango_client(
    cfg: PathBuf,
    Client {
        addr,
        num_reqs,
        conn_count,
        load_req_per_s,
        req_work_type,
        req_work_disparity,
        req_padding_size,
    }: Client,
) -> Result<Vec<DoneResp>, Report> {
    let work_gen = WorkGenerator::new(req_work_type, req_work_disparity);
    let req_interarrival = Duration::from_secs_f64(conn_count as f64 / (load_req_per_s as f64));

    let (done_s, done_r) = flume::bounded(conn_count);

    for _ in 0..conn_count {
        let cn = UdpConnection::dial(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0), addr)?;
        let wg = work_gen.clone();
        let timer = Timer::new(req_interarrival);
        let ops = wg.take(num_reqs / conn_count);
        let done = done_s.clone();

        shenango::thread::spawn_detached(move || {
            shenango_client_thread(cn, ops, timer, req_padding_size, done_s)
        });
    }

    let mut durs = Vec::with_capacity(conn_count);
    for _ in 0..conn_count {
        let thread_durs = done_r
            .recv()
            .wrap_err("done channel recv")?
            .wrap_err("client thread")?;
        durs.extend(thread_durs);
    }

    Ok(durs)
}

fn shenango_client_thread(
    cn: UdpConnection,
    ops: impl Iterator<Item = Work>,
    ticker: Timer,
    req_padding_size: usize,
    done: flume::Sender<Result<Vec<DoneResp>, Report>>,
) {
    let res = shenango_client_thread_inner(cn, ops, ticker, req_padding_size);
    done.send(res).unwrap();
}

fn shenango_client_thread_inner(
    cn: UdpConnection,
    ops: impl Iterator<Item = Work>,
    ticker: Timer,
    req_padding_size: usize,
) -> Result<Vec<DoneResp>, Report> {
    fn send_req(
        cn: &UdpConnection,
        clk: &quanta::Clock,
        buf: &mut [u8],
        op: Work,
        req_padding_size: usize,
    ) -> Result<(), Report> {
        let req = Req {
            wrk: op,
            client_time: clk.start(),
        };

        let sz = bincode::serialized_size(&req)?;
        buf[0..8].copy_from_slice(&sz.to_be_bytes());
        bincode::serialize_into(&mut buf[8..(8 + sz) as usize], &req)?;

        cn.send(buf)?;
        Ok(())
    }

    fn recv_resp(cn: &UdpConnection, clk: &quanta::Clock) -> Result<DoneResp, Report> {
        let mut buf = [0u8; 2048];
        let len = cn.recv(&mut buf)?;
        let resp_buf = &buf[..len];

        ensure!(resp_buf.len() > 8, "msg too short: {} < 8", resp_buf.len());
        let sz = u64::from_be_bytes(resp_buf[0..8].try_into().unwrap()) as usize;
        ensure!(
            resp_buf.len() >= 8 + sz,
            "msg too short for declared size: {} < {}",
            resp_buf.len(),
            8 + sz
        );
        let resp: Resp = bincode::deserialize(&resp_buf[8..8 + sz]).wrap_err("deserialize")?;
        let duration = clk.delta(resp.client_time, clk.end());

        Ok(DoneResp {
            srv_time: resp.srv_time,
            duration,
        })
    }

    let clk = quanta::Clock::new();
    let done = Arc::new(AtomicBool::new(false));
    let done_reqs = Arc::new(Mutex::new(Vec::with_capacity(1024 * 1024)));
    let send_clk = clk.clone();
    let send_cn = cn.clone();
    let r_done_reqs = Arc::clone(&done_reqs);
    shenango::thread::spawn(move || {
        let done_reqs = r_done_reqs;
        loop {
            if done.load(Ordering::SeqCst) {
                debug!(?client_id, "exiting");
                break;
            }

            let resp = recv_resp(&cn, &clk)?;
            done_reqs.lock().push(resp);
        }
    });

    let mut buf = [0u8; 2048];
    for w in ops {
        ticker.wait();
        send_req(&send_cn, &clk, &mut buf, w, req_padding_size);
    }

    done.store(true, Ordering::SeqCst);
    Ok(done_reqs.lock().clone())
}

struct Timer {
    interarrival: Duration,
    deficit: Duration,
}

impl Timer {
    fn new(interarrival: Duration) -> Self {
        Timer {
            interarrival,
            deficit: Duration::from_micros(0),
        }
    }

    fn wait(&mut self) {
        let start = shenango::microtime();
        if self.deficit > self.interarrival {
            self.deficit -= self.interarrival;
            return;
        }

        let interarrival_us = self.interarrival.as_micros() as u64;
        let target = start + interarrival_us;

        loop {
            let now = shenango::microtime();
            if now >= target {
                break;
            }

            if target - now > 10 {
                shenango::sleep(Duration::from_micros(5));
            } else {
                shenango::thread::thread_yield();
            }
        }

        let elapsed = shenango::microtime() - start;
        if elapsed > interarrival_us {
            self.deficit += Duration::from_micros(elapsed - interarrival_us);
        }
    }
}
