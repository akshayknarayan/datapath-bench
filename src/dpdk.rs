use super::{AsyncSpinTimer, Client, DoneResp, Req, Resp, Server, Work, WorkGenerator};
use color_eyre::eyre::{ensure, eyre, Report, WrapErr};
use dpdk_wrapper::DpdkConn;
use futures_util::stream::StreamExt;
use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, info, info_span, trace, warn};
use tracing_futures::Instrument;

async fn dpdk_raw_start_iokernel(cfg: PathBuf) -> Result<dpdk_wrapper::DpdkIoKernelHandle, Report> {
    use dpdk_wrapper::DpdkIoKernel;
    let (handle_s, handle_r) = flume::bounded(1);

    std::thread::spawn(move || {
        let (iokernel, handle) = match DpdkIoKernel::new(cfg) {
            Ok(x) => x,
            Err(err) => {
                tracing::error!(err = %format!("{:#?}", err), "Dpdk init failed");
                return;
            }
        };
        handle_s.send(handle).unwrap();
        iokernel.run();
    });

    let handle = handle_r.recv_async().await?;
    Ok(handle)
}

pub fn dpdk_server(cfg: PathBuf, Server { port }: Server) -> Result<(), Report> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let handle = dpdk_raw_start_iokernel(cfg).await?;
        dpdk_server_inner(handle, port).await?;
        Ok(())
    })
}

async fn dpdk_server_inner(
    handle: dpdk_wrapper::DpdkIoKernelHandle,
    port: u16,
) -> Result<(), Report> {
    let incoming = handle.accept(port)?;
    info!(?port, "listening");

    fn do_req(clk: &quanta::Clock, buf: &[u8], access_buf: &[usize]) -> Result<Resp, Report> {
        let then = clk.start();
        ensure!(buf.len() > 8, "msg too short: {} < 8", buf.len());
        let sz = u64::from_be_bytes(buf[0..8].try_into().unwrap()) as usize;
        ensure!(
            buf.len() >= 8 + sz,
            "msg too short for declared size: {} < {}",
            buf.len(),
            8 + sz
        );

        let Req { wrk, client_time } = bincode::deserialize(&buf[8..(8 + sz)])?;
        match wrk {
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

        let now = clk.end();
        Ok(Resp {
            srv_time: clk.delta(then, now),
            client_time,
        })
    }

    async fn echo_conn(conn: dpdk_wrapper::BoundDpdkConn) -> Result<(), Report> {
        let remote = conn.remote_addr();
        let access_buf = {
            let mut rng = rand::thread_rng();
            let mut mem: Vec<usize> = (0..(8 * 1024)).collect();
            use rand::seq::SliceRandom;
            mem.shuffle(&mut rng);
            mem
        };
        let clk = quanta::Clock::new();

        loop {
            let (from, mut buf) = conn.recv_async().await.wrap_err("recv")?;
            trace!(?remote, ?from, "got msg");

            let resp = match do_req(&clk, &buf, &access_buf[..]) {
                Err(err) => {
                    warn!(?err, "request errored");
                    continue;
                }
                Ok(dur) => dur,
            };

            buf.clear();
            let sz = bincode::serialized_size(&resp)?;
            buf.resize((8 + sz as u64) as usize, 0);
            buf[0..8].copy_from_slice(&sz.to_be_bytes());
            bincode::serialize_into(&mut buf[8..], &resp)?;
            conn.send_async(remote, buf).await.wrap_err("send echo")?;
            trace!(?remote, ?from, "sent echo");
        }
    }

    for conn in incoming {
        let remote = conn.remote_addr();
        info!(?remote, "New bound connection");
        tokio::spawn(async move {
            if let Err(e) = echo_conn(conn).await {
                debug!(?e, "conn errored")
            } else {
                unreachable!()
            }
        });
    }

    Err(eyre!("sender for incoming messages dropped"))
}

pub fn dpdk_client(
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

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let handle = dpdk_raw_start_iokernel(cfg).await?;
        let cns = (0..conn_count)
            .map(|_| {
                let cn = handle.socket(None)?;
                let wg = work_gen.clone();
                let timer = AsyncSpinTimer::new(req_interarrival);
                let ops = futures_util::stream::iter(wg)
                    .zip(timer.into_stream())
                    .take(num_reqs / conn_count)
                    .map(|(x, _)| x);
                Ok((cn, ops))
            })
            .collect::<Result<_, Report>>();
        let cns: Vec<_> = cns?;
        let r = futures_util::future::try_join_all(cns.into_iter().enumerate().map(
            |(i, (cn, ops))| {
                dpdk_client_thread(cn, Box::pin(ops), req_padding_size, addr)
                    .instrument(info_span!("dpdk_client_thread", client_id=?i))
            },
        ))
        .await;
        let durs = r?.into_iter().flat_map(|x| x.into_iter()).collect();
        Ok(durs)
    })
}

async fn dpdk_client_thread(
    cn: DpdkConn,
    mut ops: impl futures_util::stream::Stream<Item = Work> + std::marker::Unpin,
    req_padding_size: usize,
    addr: SocketAddrV4,
) -> Result<Vec<DoneResp>, Report> {
    async fn send_req(
        cn: &DpdkConn,
        clk: &quanta::Clock,
        mut buf: Vec<u8>,
        addr: SocketAddrV4,
        op: Work,
        req_padding_size: usize,
    ) -> Result<(), Report> {
        buf.clear();
        let req = Req {
            wrk: op,
            client_time: clk.start(),
        };
        let sz = bincode::serialized_size(&req)?;
        buf.resize((8 + sz + req_padding_size as u64) as usize, 0);
        buf[0..8].copy_from_slice(&sz.to_be_bytes());
        bincode::serialize_into(&mut buf[8..(8 + sz) as usize], &req)?;
        cn.send_async(addr, buf).await?;
        Ok(())
    }

    async fn recv_resp(cn: &DpdkConn, clk: &quanta::Clock) -> Result<(Vec<u8>, DoneResp), Report> {
        let (_, mut resp_buf) = cn.recv_async().await?;
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
        resp_buf.clear();
        Ok((
            resp_buf,
            DoneResp {
                srv_time: resp.srv_time,
                duration,
            },
        ))
    }

    let clk = quanta::Clock::new();
    let mut bufs = vec![vec![0u8; 1500]; 32];
    let mut sends = futures_util::stream::FuturesUnordered::new();
    let mut done_reqs = Vec::with_capacity(1024 * 1024);
    loop {
        tokio::select!(
            w = ops.next() => {
                if let Some(wrk) = w {
                    let send_fut = send_req(&cn, &clk, bufs.pop().unwrap_or_else(|| vec![0u8; 1500]), addr, wrk, req_padding_size);
                    sends.push(send_fut);
                } else {
                    info!("done sending requests");
                    break;
                }
            }
            Some(send_result) = sends.next() => {
                send_result.wrap_err("Error sending request on connection")?;
            },
            recv_result = recv_resp(&cn, &clk) => {
                let (buf, done_resp) = recv_result.wrap_err("response recv failed")?;
                bufs.push(buf);
                done_reqs.push(done_resp);
            }
        );
    }

    Ok(done_reqs)
}
