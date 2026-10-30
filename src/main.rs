mod bench;
mod chain;
mod events;
mod flow_extra;
mod manifest;
mod merkle;
mod netcap;
mod policy;
mod tracer;

use std::path::PathBuf;
use std::process::Command;

use manifest::{Manifest, ManifestBody, Policy};

fn arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(|s| s.as_str())
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn list(args: &[String], name: &str) -> Vec<String> {
    let mut v = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            if let Some(x) = it.next() { v.push(x.clone()); }
        }
    }
    v
}

fn cmd_tail(args: &[String]) -> Vec<String> {
    args.iter().position(|a| a == "--").map(|i| args[i + 1..].to_vec()).unwrap_or_default()
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("keygen") => manifest::keygen(&PathBuf::from(arg(&args, "--out").unwrap_or("trace.key"))),
        Some("manifest") => mk_manifest(&args),
        Some("run") => run(&args),
        Some("verify") => {
            let r = PathBuf::from(arg(&args, "--receipts").unwrap_or("receipts.jsonl"));
            let pk = arg(&args, "--pubkey").unwrap_or("").to_string();
            let problems = chain::verify(&r, &pk);
            if problems.is_empty() { println!("OK: chain intact"); Ok(()) }
            else { for p in &problems { println!("FAIL {p}"); } std::process::exit(1) }
        }
        Some("bench") => bench(&args),
        Some("sink") => flow_extra::run_sink(arg(&args, "--addr").unwrap_or("10.9.9.2:9999"), 64),
        Some("sink-helper") => sink_helper(),
        _ => {
            eprintln!("usage: astrace <keygen|manifest|run|verify|bench|sink>");
            std::process::exit(2)
        }
    }
}

fn default_policy() -> Policy {
    Policy {
        allow_paths: vec!["/usr".into(), "/lib".into(), "/etc".into(), "/tmp".into(), "/proc".into(), "/dev".into()],
        flag_paths: vec!["/home".into()],
        allow_connects: vec!["10.9.9.2:9999".into()],
        allow_flows: vec!["10.9.9.2:9999/tcp".into()],
        flag_iouring: true,
        enforce_block: true,
    }
}

fn mk_manifest(args: &[String]) -> std::io::Result<()> {
    let key = manifest::load_key(&PathBuf::from(arg(args, "--key").unwrap_or("trace.key")))?;
    let policy = if has(args, "--default-policy") {
        default_policy()
    } else {
        Policy {
            allow_paths: list(args, "--allow-path"),
            flag_paths: list(args, "--flag-path"),
            allow_connects: list(args, "--allow-connect"),
            allow_flows: list(args, "--allow-flow"),
            flag_iouring: !has(args, "--no-iouring-flag"),
            enforce_block: has(args, "--enforce"),
        }
    };
    let body = ManifestBody {
        job_id: arg(args, "--job-id").unwrap_or("job").to_string(),
        cmd: cmd_tail(args), policy,
    };
    let m = Manifest::sign(body, &key);
    let out = arg(args, "--out").unwrap_or("manifest.json");
    std::fs::write(out, serde_json::to_string_pretty(&m)?)?;
    println!("manifest -> {out} (sig ok: {})", m.verify());
    Ok(())
}

fn run(args: &[String]) -> std::io::Result<()> {
    let mpath = arg(args, "--manifest").unwrap_or("manifest.json");
    let m: Manifest = serde_json::from_str(&std::fs::read_to_string(mpath)?)?;
    if !m.verify() { eprintln!("manifest signature INVALID"); std::process::exit(2); }
    let rpath = PathBuf::from(arg(args, "--receipts").unwrap_or("receipts.jsonl"));
    let cp = arg(args, "--checkpoint-every").and_then(|s| s.parse().ok()).unwrap_or(8);
    let key = manifest::load_key(&PathBuf::from(arg(args, "--key").unwrap_or("trace.key")))?;
    std::fs::write(&rpath, "")?;
    let mut chain = chain::Chain::create(&rpath, key, cp)?;

    let netns = has(args, "--netns");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut cap_thread = None;
    let mut sink_child = None;
    if netns {
        netcap::enter_userns()?;
        // netns B child: self-enters NEWNET, waits for vethB, serves sink
        let self_exe = std::env::current_exe()?;
        let sink = Command::new(self_exe).args(["sink-helper"]).spawn()?;
        sink_child = Some(sink);
        std::thread::sleep(std::time::Duration::from_millis(300));
        netcap::enter_netns()?;
        netcap::ip(&["link", "add", "vethA", "type", "veth", "peer", "name", "vethB"])?;
        let sink_pid = sink_child.as_ref().unwrap().id();
        netcap::ip(&["link", "set", "vethB", "netns", &sink_pid.to_string()])?;
        netcap::ip(&["addr", "add", "10.9.9.1/24", "dev", "vethA"])?;
        netcap::ip(&["link", "set", "vethA", "up"])?;
        netcap::ip(&["link", "set", "lo", "up"])?;
        let fd = netcap::open_packet("vethA")?;
        let stop2 = stop.clone();
        cap_thread = Some(std::thread::spawn(move ||
            netcap::capture(fd, std::time::Duration::from_secs(120),
                            1_000_000, &stop2)));
    }

    let cmd = if m.body.cmd.is_empty() {
        vec!["/bin/true".to_string()]
    } else { m.body.cmd.clone() };
    let child = tracer::spawn(&cmd)?;
    let mut events = Vec::new();
    let mut o = tracer::TraceOpts {
        policy: m.body.policy.clone(), root_pid: child,
        on_event: Box::new(|ev| events.push(ev.clone())),
    };
    let status = tracer::run(&mut o)?;
    drop(o);
    for ev in events.drain(..) { chain.record(ev)?; }

    if netns {
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(t) = cap_thread {
            let table = t.join().unwrap_or_else(|_| Err(
                std::io::Error::new(std::io::ErrorKind::Other, "cap join")))?;
            let records = table.records();
            let leaves: Vec<_> = records.iter().map(merkle::leaf).collect();
            let root = merkle::root(&leaves);
            for rec in &records {
                chain.record(events::Event {
                    seq: 0, ts_ns: events::now_ns(), pid: 0, ppid: 0,
                    kind: events::EventKind::Flow,
                    detail: rec.clone(),
                    decision: policy::evaluate(
                        &m.body.policy, events::EventKind::Flow, rec),
                })?;
            }
            chain.record(events::Event {
                seq: 0, ts_ns: events::now_ns(), pid: 0, ppid: 0,
                kind: events::EventKind::NetCap,
                detail: serde_json::json!({"merkle_root": root,
                    "flows": records.len(),
                    "packets": table.packets_seen}),
                decision: events::Decision::Allow,
            })?;
        }
    }
    chain.close()?;
    if let Some(mut s) = sink_child { let _ = s.kill(); let _ = s.wait(); }
    println!("receipts -> {} (sig {})", rpath.display(), &chain.pubkey_hex[..12]);
    std::process::exit(status);
}

fn sink_helper() -> std::io::Result<()> {
    netcap::enter_netns()?;
    // wait for the moved vethB, then configure and serve
    for _ in 0..50 {
        let idx = unsafe { libc::if_nametoindex(b"vethB\0".as_ptr().cast()) };
        if idx != 0 { break; }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    netcap::ip(&["addr", "add", "10.9.9.2/24", "dev", "vethB"])?;
    netcap::ip(&["link", "set", "vethB", "up"])?;
    netcap::ip(&["link", "set", "lo", "up"])?;
    flow_extra::run_sink("10.9.9.2:9999", 256)
}

fn bench(args: &[String]) -> std::io::Result<()> {
    let n: usize = arg(args, "--frames")
        .and_then(|s| s.parse().ok()).unwrap_or(200_000);
    let (pkts, d) = bench::flow_hash_rate(n);
    println!("flow hashing: {} frames in {:?} ({:.0} frames/s)",
             pkts, d, pkts as f64 / d.as_secs_f64());

    // syscall-stop overhead: same workload, timed untraced vs traced.
    // faccessat is a syscall we do not decode, so every stop is pure
    // ptrace bookkeeping cost.
    let rounds: usize = arg(args, "--rounds")
        .and_then(|s| s.parse().ok()).unwrap_or(10);
    let w = vec!["/bin/bash".to_string(), "-c".to_string(),
        "for i in $(seq 1 200); do test -f /etc/hostname; done".to_string()];
    let mut t_un = std::time::Duration::ZERO;
    let mut t_tr = std::time::Duration::ZERO;
    for _ in 0..rounds {
        t_un += bench::untraced(&w)?;
        let t0 = std::time::Instant::now();
        let pid = tracer::spawn(&w)?;
        let mut o = tracer::TraceOpts {
            policy: default_policy(), root_pid: pid,
            on_event: Box::new(|_| {}),
        };
        tracer::run(&mut o)?;
        t_tr += t0.elapsed();
    }
    println!("syscall stops: {:?} untraced vs {:?} traced over {} rounds",
             t_un / rounds as u32, t_tr / rounds as u32, rounds);
    println!("per-syscall-stop overhead ~{:.1} us",
             (t_tr - t_un).as_secs_f64() / (rounds as f64 * 200.0) * 1e6);
    Ok(())
}
