use color_eyre::eyre::Report;
use datapath_bench::{
    dpdk_client, dpdk_inline_client, dpdk_inline_server, dpdk_server, shenango_client,
    shenango_server, Client, Server,
};
use std::path::PathBuf;
use structopt::StructOpt;
use tracing_error::ErrorLayer;
use tracing_subscriber::prelude::*;

#[derive(Debug, Clone, StructOpt)]
struct Opt {
    #[structopt(long)]
    cfg: PathBuf,

    #[structopt(long)]
    datapath: String,

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
        datapath,
        out_file,
        mode,
    } = Opt::from_args();

    match datapath.as_str() {
        "shenango" | "shenangort" => match mode {
            Mode::Server(s) => shenango_server(cfg, s),
            Mode::Client(c) => {
                shenango_client(cfg, out_file, c)?;
                Ok(())
            }
        },
        "dpdk" => match mode {
            Mode::Server(s) => dpdk_server(cfg, s),
            Mode::Client(c) => {
                dpdk_client(cfg, out_file, c)?;
                Ok(())
            }
        },
        "dpdkinline" => match mode {
            Mode::Server(s) => dpdk_inline_server(cfg, s),
            Mode::Client(c) => {
                dpdk_inline_client(cfg, out_file, c)?;
                Ok(())
            }
        },
        _ => panic!("unknown datapath"),
    }
}
