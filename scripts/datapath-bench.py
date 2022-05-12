#!/usr/bin/python3

from kv import ConnectionWrapper, check_machine, get_local, check, get_timeout, write_dpdk_config, write_cfg
import agenda
import argparse
import os
import shutil
import subprocess
import sys
import threading
import time
import toml

def write_shenango_config(conn):
    shenango_config = f"""
host_addr {conn.addr}
host_netmask 255.255.255.0
host_gateway 10.1.1.1
runtime_kthreads 4
runtime_spininng_kthreads 4
runtime_guaranteed_kthreads 4"""
    write_cfg(conn, shenango_config)

def setup_machine(conn, outdir):
    ok = conn.run(f"mkdir -p ~/burrito/{outdir}")
    check(ok, "mk outdir", conn.addr)
    #agenda.subtask(f"building burrito on {conn.addr}")
    #ok = conn.run("../../.cargo/bin/cargo b --release", wd = "~/burrito/datapath-bench")
    #check(ok, "build", conn.addr)
    return conn

dpdk_ld_var = "LD_LIBRARY_PATH=/usr/local/lib64:/usr/local/lib:dpdk-direct/dpdk-wrapper/dpdk/install/lib/x86_64-linux-gnu"

def start_server(conn, outf, num_threads, variant='dpdk'):
    conn.run("sudo pkill -9 datapath-bench")
    if 'shenango' in variant:
        conn.run("sudo pkill -INT iokerneld")
        write_shenango_config(conn)
        conn.run("./iokerneld", wd="~/burrito/shenango-chunnel/caladan", sudo=True, background=True)
    elif 'dpdk' in variant:
        write_dpdk_config(conn)
    else:
        raise Exception("unknown datapath")

    time.sleep(2)
    ok = conn.run(f"RUST_LOG=debug {dpdk_ld_var} ./target/release/datapath-bench --cfg host.config --datapath {variant} server -p 4242 -t {num_threads}",
        wd="~/burrito",
        sudo=True,
        background=True,
        stdout=f"{outf}.out",
        stderr=f"{outf}.err",
        )
    check(ok, "spawn server", conn.addr)
    agenda.subtask("wait for server check")
    time.sleep(8)
    conn.check_proc(f"datapath", f"{outf}.err")

def run_client(conn, server, load, num_clients, num_reqs, work_type, work_disparity, req_padding, variant, outf):
    conn.run("sudo pkill -9 datapath-bench")
    if 'shenango' in variant:
        conn.run("sudo pkill -INT iokerneld")
        write_shenango_config(conn)
        conn.run("./iokerneld", wd="~/burrito/shenango-chunnel/caladan", sudo=True, background=True)
    elif 'dpdk' in variant:
        write_dpdk_config(conn)
    else:
        raise Exception("unknown datapath")

    time.sleep(2)
    agenda.subtask(f"client starting -> {outf}.out")
    ok = conn.run(
        f"RUST_LOG=debug {dpdk_ld_var} ./target/release/datapath-bench \
        --cfg host.config \
        --datapath {variant} \
        --out-file={outf}.data \
        client \
        -a {server}:4242 \
        --load-req-per-s {load} \
        --conn-count {num_clients} \
        --num-reqs {num_reqs} \
        --req-work-type {work_type} \
        --req-work-disparity {work_disparity} \
        --req-padding-size {req_padding} \
        ",
        sudo=True,
        wd="~/burrito",
        stdout=f"{outf}.out",
        stderr=f"{outf}.err",
        )
    check(ok, "start client", conn.addr)
    if 'shenango' in variant:
        conn.run("sudo pkill -INT iokerneld")
    agenda.subtask("client done")

def do_exp(iter_num,
    outdir=None,
    machines=None,
    load=None,
    num_clients=None,
    num_reqs=None,
    work_type=None,
    work_disparity=None,
    req_padding=None,
    datapath=None,
    overwrite=None
):
    assert(
        outdir is not None and
        machines is not None and
        load is not None and
        num_clients is not None and
        num_reqs is not None and
        work_type is not None and
        work_disparity is not None and
        req_padding is not None and
        num_clients is not None and
        datapath is not None and
        overwrite is not None
    )

    server_prefix = f"{outdir}/{datapath}-load={load}-work={work_type}-disparity={work_disparity}-num_clients={num_clients}-padding={req_padding}-{iter_num}-dbench_server"
    outf = f"{outdir}/{datapath}-load={load}-work={work_type}-disparity={work_disparity}-num_clients={num_clients}-padding={req_padding}-{iter_num}-dbench_client"

    for m in machines:
        if m.local:
            m.run(f"mkdir -p {outdir}", wd="~/burrito")
            continue
        m.run(f"rm -rf {outdir}", wd="~/burrito")
        m.run(f"mkdir -p {outdir}", wd="~/burrito")

    if not overwrite and os.path.exists(f"{outf}-{machines[1].addr}.data"):
        agenda.task(f"skipping: {outf}.data")
        return True
    else:
        agenda.task(f"running: {outf}.data")

    time.sleep(2)
    server_addr = machines[0].addr
    agenda.task(f"starting: server = {machines[0].addr}, outf={outf}")

    # first one is the server, start the server
    agenda.subtask("starting server")
    start_server(machines[0], server_prefix, num_clients, variant=datapath)
    time.sleep(7)

    # others are clients
    agenda.task("starting clients")
    clients = [threading.Thread(target=run_client, args=(
            m,
            server_addr,
            load,
            num_clients,
            num_reqs,
            work_type,
            work_disparity,
            req_padding,
            datapath,
            outf,
        ),
    ) for m in machines[1:]]

    [t.start() for t in clients]
    [t.join() for t in clients]
    agenda.task("all clients returned")

    # kill the server
    machines[0].run("sudo pkill -9 datapath")
    if 'shenango' in datapath:
        machines[0].run("sudo pkill -INT iokerneld")

    for m in machines:
        m.run("rm ~/burrito/*.config")

    #agenda.task("get server files")
    #if not machines[0].local:
    #    machines[0].get(f"~/burrito/{server_prefix}.out", local=f"{server_prefix}.out", preserve_mode=False)
    #    machines[0].get(f"~/burrito/{server_prefix}.err", local=f"{server_prefix}.err", preserve_mode=False)

    def get_files(num):
        fn = c.get
        if c.local:
            agenda.subtask(f"Use get_local: {c.host}")
            fn = get_local

        agenda.subtask(f"getting {outf}-{c.addr}.err")
        fn(
            f"burrito/{outf}.err",
            local=f"{outf}-{c.addr}.err",
            preserve_mode=False,
        )
        agenda.subtask(f"getting {outf}-{c.addr}.out")
        fn(
            f"burrito/{outf}.out",
            local=f"{outf}-{c.addr}.out",
            preserve_mode=False,
        )
        agenda.subtask(f"getting {outf}-{c.addr}.data")
        fn(
            f"burrito/{outf}.data",
            local=f"{outf}-{c.addr}.data",
            preserve_mode=False,
        )

    agenda.task("get client files")
    for c in machines[1:]:
        try:
            get_files(0)
        except Exception as e:
            agenda.subfailure(f"At least one file missing for {c}: {e}")

    agenda.task("done")
    return True

### Sample config
### [machines]
### server = { access = "127.0.0.1", alt = "192.168.1.2", exp = "10.1.1.2" }
### clients = [
###     { access = "192.168.1.6", exp = "10.1.1.6" },
### ]
###
### [exp]
### load = [10000, 20000, 40000, 80000, 100000, 160000, 180000, 200000]
### work_type = ['imm', 'cpu:10000', 'mem:10000']
### work_disparity = [0, 1000, 2500, 5000]
### num_clients = [4]
### req_padding = [0, 512, 1024]
### datapath = ['dpdk']
### time_target_s = 30
### iters = 3
###
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, required=True)
    parser.add_argument('--outdir', type=str, required=True)
    parser.add_argument('--overwrite', action='store_true')
    args = parser.parse_args()
    agenda.task(f"reading cfg {args.config}")
    cfg = toml.load(args.config)
    print(cfg)

    outdir = args.outdir

    if len(cfg['machines']['clients']) < 1:
        agenda.failure("Need more machines")
        sys.exit(1)

    required = ['load', 'work_type', 'work_disparity', 'iters']
    for r in required:
        assert(r in cfg['exp'])

    if 'num_clients' not in cfg['exp']:
        cfg['exp']['num_clients'] = [1]
    if 'req_padding' not in cfg['exp']:
        cfg['exp']['req_padding'] = [0]
    if 'datapath' not in cfg['exp']:
        cfg['exp']['datapath'] = ['dpdk']
    for t in cfg['exp']['datapath']:
        if t not in ['dpdk', 'dpdkinline', 'shenango']:
            agenda.failure('unknown datapath: ' + t)
            sys.exit(1)

    agenda.task(f"Checking for connection vs experiment ip")
    ips = [cfg['machines']['server']] + cfg['machines']['clients']
    agenda.task(f"connecting to {ips}")
    machines, commits = zip(*[check_machine(ip) for ip in ips])
    # check all the commits are equal
    if not all(c == commits[0] for c in commits):
        agenda.subfailure(f"not all commits equal: {commits}")
        sys.exit(1)

    for m in machines:
        if m.host in ['127.0.0.1', '::1', 'localhost']:
            agenda.subtask(f"Local conn: {m.host}/{m.addr}")
            m.local = True
        else:
            m.local = False

    # build
    agenda.task("building burrito...")
    thread_ok = True
    setups = [threading.Thread(target=setup_machine, args=(m,outdir)) for m in machines]
    [t.start() for t in setups]
    [t.join() for t in setups]
    if not thread_ok:
        agenda.failure("Something went wrong")
        sys.exit(1)
    agenda.task("...done building burrito")

    # copy config file to outdir
    shutil.copy2(args.config, args.outdir)

    for dp in cfg['exp']['datapath']:
        for nc in cfg['exp']['num_clients']:
            for w in cfg['exp']['work_type']:
                for d in cfg['exp']['work_disparity']:
                    if w == 'imm' and int(d) != 0:
                        agenda.subtask('skipping nonzero disparity for imm work')
                        continue
                    for p in cfg['exp']['req_padding']:
                        for l in cfg['exp']['load']:
                            nr = int(cfg['exp']['time_target_s']) * int(l)
                            for i in range(int(cfg['exp']['iters'])):
                                do_exp(i,
                                        outdir=outdir,
                                        machines=machines,
                                        load=l,
                                        num_clients=nc,
                                        num_reqs=nr,
                                        work_type=w,
                                        work_disparity=d,
                                        req_padding=p,
                                        datapath=dp,
                                        overwrite=args.overwrite
                                        )

    agenda.task("done")
