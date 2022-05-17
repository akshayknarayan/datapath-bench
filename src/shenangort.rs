use super::{write_results, Client, DoneResp, Req, Resp, Server, Work};
use color_eyre::eyre::{ensure, Report, WrapErr};
use shenango::sync::Mutex;
use shenango::udp::{self, UdpConnection};
use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tracing::{debug, error, info, warn};

pub fn shenango_server(cfg: PathBuf, Server { port, .. }: Server) -> Result<(), Report> {
    info!(?cfg, ?port, "starting server");
    shenango::runtime_init(cfg.to_str().unwrap().to_owned(), move || {
        if let Err(err) = server(port) {
            error!(?err, "server errored");
            std::process::exit(1);
        } else {
            unreachable!()
        }
    })
    .unwrap();
    Ok(())
}

fn server(port: u16) -> Result<(), Report> {
    let bind_addr = SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, port);
    let idx = Arc::new(AtomicUsize::new(0));
    info!(?bind_addr, "listening");
    udp::udp_accept(bind_addr, move |cn| {
        let idx = idx.fetch_add(1, Ordering::SeqCst);
        if let Err(err) = server_conn(cn, idx) {
            warn!(?err, "server conn failed");
        }
    })
    .wrap_err("udp_accept failed")?;
    Ok(())
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
        let rbuf = &buf[..len];

        let then = clk.start();
        ensure!(len > 8, "msg too short: {} < 8", buf.len());
        let sz = u64::from_be_bytes(rbuf[0..8].try_into().unwrap()) as usize;
        ensure!(
            len >= 8 + sz,
            "msg too short for declared size: {} < {}",
            len,
            8 + sz
        );

        let Req { wrk, client_time } = bincode::deserialize(&rbuf[8..(8 + sz)])?;
        wrk.work(&access_buf[..]);
        let now = clk.end();
        let resp = Resp {
            srv_time: clk.delta(then, now),
            client_time,
        };

        let sz = bincode::serialized_size(&resp)? as usize;
        buf[0..8].copy_from_slice(&sz.to_be_bytes());
        bincode::serialize_into(&mut buf[8..(8 + sz)], &resp)?;
        if let Err(e) = cn.send(&buf[..(8 + sz)]) {
            warn!(?e, "send failed");
            break Err(e.into());
        }
    }
}

pub fn shenango_client(cfg: PathBuf, out_file: Option<PathBuf>, c: Client) -> Result<(), Report> {
    info!(?cfg, ?c, "starting client");
    let load = c.load_req_per_s;
    let tot_reqs = c.num_reqs;
    let clk = quanta::Clock::new();
    let then = clk.start();
    shenango::runtime_init(cfg.to_str().unwrap().to_owned(), move || {
        match shenango_client_inner(c) {
            Ok(durs) => {
                let now = clk.end();
                let elapsed = clk.delta(then, now);
                let remaining = tot_reqs - durs.len();
                write_results(durs, remaining, elapsed, load, out_file);
            }
            Err(err) => {
                error!(?err, "client failed");
            }
        }

        info!("exiting");
        std::process::exit(0);
    })
    .unwrap();
    Ok(())
}

fn shenango_client_inner(
    Client {
        addr,
        num_reqs,
        conn_count,
        load_req_per_s,
        work_gen,
        req_padding_size,
    }: Client,
) -> Result<Vec<DoneResp>, Report> {
    let req_interarrival = Duration::from_secs_f64(conn_count as f64 / (load_req_per_s as f64));

    let (done_s, done_r) = flume::bounded(conn_count);

    for i in 0..conn_count {
        let cn = UdpConnection::dial(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0), addr)
            .unwrap();
        let wg = work_gen.clone();
        let timer = Timer::new(req_interarrival);
        let ops = wg.take(num_reqs / conn_count);
        let done = done_s.clone();

        info!(?i, "starting client thread");
        shenango::thread::spawn_detached(move || {
            shenango_client_thread(cn, ops, timer, req_padding_size, done, i)
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

    info!(num_reqs = ?durs.len(), "done");
    Ok(durs)
}

fn shenango_client_thread(
    cn: UdpConnection,
    ops: impl Iterator<Item = Work>,
    ticker: Timer,
    req_padding_size: usize,
    done: flume::Sender<Result<Vec<DoneResp>, Report>>,
    i: usize,
) {
    let res = shenango_client_thread_inner(cn, ops, ticker, req_padding_size, i);
    if let Err(ref e) = &res {
        warn!(?i, ?e, "client thread failed");
    }
    done.send(res).unwrap();
}

fn shenango_client_thread_inner(
    cn: UdpConnection,
    ops: impl Iterator<Item = Work>,
    mut ticker: Timer,
    req_padding_size: usize,
    i: usize,
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

        cn.send(&buf[..(8 + sz + req_padding_size as u64) as usize])?;
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

    let cn = Arc::new(cn);
    let clk = quanta::Clock::new();
    let done = Arc::new(AtomicBool::new(false));
    let done_reqs = Arc::new(Mutex::new(Vec::with_capacity(1024 * 1024)));

    let r_done = Arc::clone(&done);
    let recv_clk = clk.clone();
    let recv_cn = Arc::clone(&cn);
    let r_done_reqs = Arc::clone(&done_reqs);
    shenango::thread::spawn(move || {
        let done_reqs = r_done_reqs;
        loop {
            if r_done.load(Ordering::SeqCst) {
                info!(?i, "exiting recvs");
                break;
            }

            if let Ok(resp) = recv_resp(&recv_cn, &recv_clk) {
                done_reqs.lock().push(resp);
            }
        }
    });

    info!(?i, "starting sending ops");
    let mut buf = [0u8; 2048];
    for w in ops {
        ticker.wait();
        send_req(&cn, &clk, &mut buf, w, req_padding_size).wrap_err("send req")?;
    }

    done.store(true, Ordering::SeqCst);
    debug!(?i, "finished sending ops");
    let dr = done_reqs.lock();
    Ok(dr.clone())
}

struct Timer {
    interarrival: Duration,
    deficit: Duration,
    last_return: Option<u64>,
}

impl Timer {
    fn new(interarrival: Duration) -> Self {
        Timer {
            interarrival,
            deficit: Duration::from_micros(0),
            last_return: None,
        }
    }

    fn wait(&mut self) {
        if self.deficit > self.interarrival {
            self.deficit -= self.interarrival;
            self.last_return = Some(shenango::microtime());
            return;
        }

        if self.last_return.is_none() {
            self.last_return = Some(shenango::microtime());
        }

        let interarrival_us = self.interarrival.as_micros() as u64;
        let target = self.last_return.unwrap() + interarrival_us;

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

        let elapsed = shenango::microtime() - self.last_return.unwrap();
        if elapsed > interarrival_us {
            self.deficit += Duration::from_micros(elapsed - interarrival_us);
        }

        self.last_return = Some(shenango::microtime());
    }
}
