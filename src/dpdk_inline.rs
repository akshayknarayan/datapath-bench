use crate::{Client, Req, Resp, Server};
use ahash::AHashMap as HashMap;
use color_eyre::eyre::{bail, ensure, Report, WrapErr};
use dpdk_wrapper::{
    bindings::*,
    mbuf_slice,
    utils::{parse_cfg, AddressInfo, HeaderInfo, TOTAL_HEADER_SIZE},
    wrapper::*,
};
use eui48::MacAddress;
use std::collections::VecDeque;
use std::mem::zeroed;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use tracing::{debug, trace, warn};

/// A message from DPDK.
#[derive(Debug)]
pub struct Msg {
    /// The local port.
    pub port: u16,
    /// The remote address.
    pub addr: SocketAddrV4,
    mbuf: *mut rte_mbuf,
    payload_length: usize,
}

impl Msg {
    pub fn get_buf(&self) -> &[u8] {
        unsafe { mbuf_slice!(self.mbuf, TOTAL_HEADER_SIZE, self.payload_length) }
    }
}

impl Drop for Msg {
    fn drop(&mut self) {
        unsafe {
            rte_pktmbuf_free(self.mbuf);
        }
    }
}

/// Spin-polling DPDK datapath event loop.
///
/// There should only be one of these. It is responsible for actually sending and receiving
/// packets, and doing bookkeeping (mux/demux) associated with tracking sockets.
pub struct DpdkState {
    eth_addr: MacAddress,
    eth_addr_raw: rte_ether_addr,
    ip_addr: Ipv4Addr,
    ip_addr_raw: u32,
    port: u16,
    mbuf_pool: *mut rte_mempool,
    arp_table: HashMap<Ipv4Addr, MacAddress>,

    pending_recvs: VecDeque<Msg>,
    rx_bufs: [*mut rte_mbuf; RECEIVE_BURST_SIZE as usize],
    listen_ports: Option<Vec<u16>>,

    tx_bufs: [*mut rte_mbuf; RECEIVE_BURST_SIZE as usize],
    ip_id: u16,
}

impl DpdkState {
    /// Do global initialization.
    ///
    /// `config_path` should be a TOML files with:
    /// - "dpdk" table with "eal_init" key. "eal_init" should be a string array of DPDK init args.
    /// - "net" table with "ip" key and "arp" list-of-tables.
    ///   - "arp" entries should have "ip" and "mac" keys.
    ///
    /// # Example Config
    /// ```toml
    /// [dpdk]
    /// eal_init = ["-n", "4", "--allow", "0000:99:00.0", "--vdev", "net_pcap0,tx_pcap=out.pcap"]
    ///
    /// [net]
    /// ip = "1.2.3.4"
    ///
    ///   [[net.arp]]
    ///   ip = "1.2.3.4"
    ///   mac = "00:01:02:03:04:05"
    ///
    ///   [[net.arp]]
    ///   ip = "4.3.2.1"
    ///   mac = "05:04:03:02:01:00"
    /// ```
    fn new(config_path: std::path::PathBuf) -> Result<Self, Report> {
        let (dpdk_config, ip_addr, arp_table) = parse_cfg(config_path.as_path())?;
        let (mbuf_pools, nb_ports) = dpdk_init(dpdk_config, 1)?;

        let mbuf_pool = mbuf_pools[0];
        let port = nb_ports - 1;

        // what is my ethernet address (rte_ether_addr struct)
        let my_eth = get_my_macaddr(port)?;
        let eth_addr = MacAddress::from_bytes(&my_eth.addr_bytes).wrap_err("Parse mac address")?;
        let eth_addr_raw = rte_ether_addr {
            addr_bytes: eth_addr.to_array(),
        };

        let octets = ip_addr.octets();
        let ip_addr_raw: u32 = unsafe { make_ip(octets[0], octets[1], octets[2], octets[3]) };

        Ok(Self {
            eth_addr,
            eth_addr_raw,
            ip_addr,
            ip_addr_raw,
            port,
            mbuf_pool,
            arp_table,
            rx_bufs: unsafe { zeroed() },
            pending_recvs: VecDeque::with_capacity(RECEIVE_BURST_SIZE as _),
            tx_bufs: unsafe { zeroed() },
            ip_id: 0,
            listen_ports: None,
        })
    }

    fn listen(&mut self, port: u16) {
        if let Some(ref mut lp) = self.listen_ports {
            lp.push(port);
        } else {
            self.listen_ports = Some(vec![port]);
        }
    }

    fn try_recv(&mut self) -> Result<Option<Msg>, Report> {
        // 1. check if already received packets are available to return
        if let Some(m) = self.pending_recvs.pop_front() {
            return Ok(Some(m));
        }

        // 2. try to receive.
        let num_received = unsafe {
            rte_eth_rx_burst(
                self.port,
                0,
                self.rx_bufs.as_mut_ptr(),
                RECEIVE_BURST_SIZE as u16,
            )
        } as usize;
        for i in 0..num_received {
            // first: parse if valid packet, and what the payload size is
            let (is_valid, src_ether, src_ip, src_port, dst_port, payload_length) =
                unsafe { parse_packet(self.rx_bufs[i], &self.eth_addr_raw as _, self.ip_addr_raw) };
            if !is_valid {
                unsafe { rte_pktmbuf_free(self.rx_bufs[i]) };
                continue;
            }

            // if there are defined ports to listen on, enforce that only packets with those
            // dst_ports are received.
            if let Some(ref mut lp) = self.listen_ports {
                if !lp.iter().any(|p| *p == dst_port) {
                    unsafe { rte_pktmbuf_free(self.rx_bufs[i]) };
                    continue;
                }
            }

            let [oct1, oct2, oct3, oct4] = src_ip.to_be_bytes();
            let pkt_src_ip = Ipv4Addr::new(oct1, oct2, oct3, oct4);

            // opportunistically update arp
            self.arp_table
                .entry(pkt_src_ip)
                .or_insert_with(|| MacAddress::from_bytes(&src_ether.addr_bytes).unwrap());
            let pkt_src_addr = SocketAddrV4::new(pkt_src_ip, src_port);
            let msg = Msg {
                port: dst_port,
                addr: pkt_src_addr,
                mbuf: self.rx_bufs[i],
                payload_length,
            };
            self.pending_recvs.push_back(msg);
        }

        // 3. if we received anything, return it.
        if !self.pending_recvs.is_empty() {
            trace!(num_valid=?self.pending_recvs.len(), "Received valid packets");
        }

        Ok(self.pending_recvs.pop_front())
    }

    fn send<'a>(
        &mut self,
        to_addr: SocketAddrV4,
        src_port: u16,
        buf: &'a [u8],
    ) -> Result<(), Report> {
        let to_ip = to_addr.ip();
        let to_port = to_addr.port();
        unsafe {
            let dst_ether_addr = match self.arp_table.get(to_ip) {
                Some(eth) => eth,
                None => {
                    bail!("Could not find IP {:?} in ARP table", to_ip);
                }
            };

            self.tx_bufs[0] = alloc_mbuf(self.mbuf_pool).unwrap();

            let src_info = AddressInfo {
                udp_port: src_port,
                ipv4_addr: self.ip_addr,
                ether_addr: self.eth_addr,
            };

            let dst_info = AddressInfo {
                udp_port: to_port,
                ipv4_addr: *to_ip,
                ether_addr: *dst_ether_addr,
            };

            trace!(?src_info, ?dst_info, "writing header");

            // fill header
            let hdr_size = match fill_in_header(
                self.tx_bufs[0],
                &HeaderInfo { src_info, dst_info },
                buf.len(),
                self.ip_id,
            ) {
                Ok(s) => {
                    self.ip_id += 1;
                    self.ip_id %= 0xffff;
                    s
                }
                Err(err) => {
                    debug!(?err, "Error writing header");
                    rte_pktmbuf_free(self.tx_bufs[0]);
                    bail!("Error writing header: {:?}", err);
                }
            };

            // write payload
            let payload_slice = mbuf_slice!(self.tx_bufs[0], hdr_size, buf.len());
            rte_memcpy_wrapper(
                payload_slice.as_mut_ptr() as _,
                buf.as_ptr() as _,
                buf.len(),
            );

            (*self.tx_bufs[0]).pkt_len = (hdr_size + buf.len()) as u32;
            (*self.tx_bufs[0]).data_len = (hdr_size + buf.len()) as u16;
        }

        if let Err(err) = unsafe { tx_burst(self.port, 0, self.tx_bufs.as_mut_ptr(), 1 as u16) } {
            warn!(?err, "tx_burst error");
        }

        Ok(())
    }

    fn send_burst<'a>(
        &mut self,
        msgs: impl Iterator<Item = (SocketAddrV4, u16, &'a [u8])>,
    ) -> Result<(), Report> {
        let mut i = 0;
        for (to_addr, src_port, buf) in msgs {
            let to_ip = to_addr.ip();
            let to_port = to_addr.port();
            unsafe {
                let dst_ether_addr = match self.arp_table.get(to_ip) {
                    Some(eth) => eth,
                    None => {
                        warn!(?to_ip, "Could not find IP in ARP table");
                        continue;
                    }
                };

                self.tx_bufs[i] = alloc_mbuf(self.mbuf_pool).unwrap();

                let src_info = AddressInfo {
                    udp_port: src_port,
                    ipv4_addr: self.ip_addr,
                    ether_addr: self.eth_addr,
                };

                let dst_info = AddressInfo {
                    udp_port: to_port,
                    ipv4_addr: *to_ip,
                    ether_addr: *dst_ether_addr,
                };

                trace!(?src_info, ?dst_info, "writing header");

                // fill header
                let hdr_size = match fill_in_header(
                    self.tx_bufs[i],
                    &HeaderInfo { src_info, dst_info },
                    buf.len(),
                    self.ip_id,
                ) {
                    Ok(s) => {
                        self.ip_id += 1;
                        self.ip_id %= 0xffff;
                        s
                    }
                    Err(err) => {
                        debug!(?err, "Error writing header");
                        rte_pktmbuf_free(self.tx_bufs[i]);
                        continue;
                    }
                };

                // write payload
                let payload_slice = mbuf_slice!(self.tx_bufs[i], hdr_size, buf.len());
                rte_memcpy_wrapper(
                    payload_slice.as_mut_ptr() as _,
                    buf.as_ptr() as _,
                    buf.len(),
                );

                (*self.tx_bufs[i]).pkt_len = (hdr_size + buf.len()) as u32;
                (*self.tx_bufs[i]).data_len = (hdr_size + buf.len()) as u16;

                i += 1;
                if i >= (RECEIVE_BURST_SIZE as _) {
                    break;
                }
            }
        }

        if i > 0 {
            if let Err(err) = unsafe { tx_burst(self.port, 0, self.tx_bufs.as_mut_ptr(), i as u16) }
            {
                warn!(?err, "tx_burst error");
            }
        }

        Ok(())
    }
}

pub fn dpdk_inline_server(cfg: PathBuf, Server { port }: Server) -> Result<(), Report> {
    let mut dpdk = DpdkState::new(cfg)?;
    let access_buf = {
        let mut rng = rand::thread_rng();
        let mut mem: Vec<usize> = (0..(8 * 1024)).collect();
        use rand::seq::SliceRandom;
        mem.shuffle(&mut rng);
        mem
    };
    let mut tx_buf = [0u8; std::mem::size_of::<Resp>() + 16];
    let clk = quanta::Clock::new();

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
        wrk.work(access_buf);

        let now = clk.end();
        Ok(Resp {
            srv_time: clk.delta(then, now),
            client_time,
        })
    }

    dpdk.listen(port);
    loop {
        // 1. try to receive requests.
        let msg = match dpdk.try_recv()? {
            Some(m) => m,
            None => continue,
        };

        let from = msg.addr;
        trace!(?from, "got msg");

        // 2. if there are requests, deserialize and process them.
        let resp = match do_req(&clk, msg.get_buf(), &access_buf[..]) {
            Err(err) => {
                warn!(?err, "request errored");
                continue;
            }
            Ok(dur) => dur,
        };

        tx_buf.fill(0);
        let sz = bincode::serialized_size(&resp)?;
        ensure!(
            tx_buf.len() >= sz as usize + 8,
            "Stack-allocated message array not big enough"
        );
        tx_buf[0..8].copy_from_slice(&sz.to_be_bytes());
        bincode::serialize_into(&mut tx_buf[8..], &resp)?;

        dpdk.send(from, port, &tx_buf[0..(8 + sz as usize)])?;
        trace!(?from, "sent echo");
    }
}

pub fn dpdk_inline_client(
    cfg: PathBuf,
    out_file: Option<PathBuf>,
    Client {
        addr,
        num_reqs,
        conn_count,
        load_req_per_s,
        req_work_type,
        req_work_disparity,
        req_padding_size,
    }: Client,
) -> Result<(), Report> {
    todo!()
}
