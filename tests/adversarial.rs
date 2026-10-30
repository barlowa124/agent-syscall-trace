//! Adversarial integration suite. Each test drives the real `astrace`
//! binary and reads the receipt log it produces.

use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static N: AtomicU64 = AtomicU64::new(0);

fn bin() -> &'static str { env!("CARGO_BIN_EXE_astrace") }
fn probe() -> &'static str { env!("CARGO_BIN_EXE_iouring_probe") }

fn dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "astrace-test-{}-{}", tag, N.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn astrace(d: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(bin()).args(args).current_dir(d)
        .output().expect("spawn astrace")
}

fn receipts(path: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path).unwrap().lines()
        .map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn events(path: &std::path::Path) -> Vec<serde_json::Value> {
    receipts(path).into_iter()
        .filter(|r| r["kind"] == "event")
        .map(|r| r["event"].clone()).collect()
}

fn keygen(d: &std::path::Path) -> String {
    astrace(d, &["keygen", "--out", "k.hex"]);
    let m = astrace(d, &["manifest", "--key", "k.hex",
                         "--job-id", "t", "--default-policy",
                         "--out", "m.json", "--", "/bin/true"]);
    let s = String::from_utf8_lossy(&m.stdout);
    assert!(s.contains("sig ok: true"), "manifest: {s}");
    "k.hex".into()
}

fn run_traced(d: &std::path::Path, cmd: &[&str], receipts_name: &str)
              -> std::process::Output {
    let mut margs = vec!["manifest", "--key", "k.hex", "--job-id", "t",
                         "--default-policy", "--out", "m.json", "--"];
    margs.extend_from_slice(cmd);
    astrace(d, &margs);
    astrace(d, &["run", "--manifest", "m.json",
                 "--receipts", receipts_name, "--key", "k.hex"])
}

fn verify(d: &std::path::Path, receipts_name: &str) -> String {
    let m: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(d.join("m.json")).unwrap()).unwrap();
    let pk = m["pubkey_hex"].as_str().unwrap().to_string();
    let o = astrace(d, &["verify", "--receipts", receipts_name,
                         "--pubkey", &pk]);
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn clean_chain_verifies() {
    let d = dir("clean");
    keygen(&d);
    run_traced(&d, &["/bin/true"], "r.jsonl");
    assert!(verify(&d, "r.jsonl").contains("OK: chain intact"));
}

#[test]
fn mid_chain_edit_detected() {
    let d = dir("tamper");
    keygen(&d);
    run_traced(&d, &["/bin/cat", "/etc/hostname"], "r.jsonl");
    let raw = std::fs::read_to_string(d.join("r.jsonl")).unwrap();
    let tampered = raw.replacen("/etc/hostname", "/etc/XXXXXname", 1);
    assert_ne!(raw, tampered);
    std::fs::write(d.join("r_bad.jsonl"), tampered).unwrap();
    let v = verify(&d, "r_bad.jsonl");
    assert!(v.contains("hash mismatch"), "{v}");
}

#[test]
fn truncation_detected() {
    let d = dir("trunc");
    keygen(&d);
    run_traced(&d, &["/bin/true"], "r.jsonl");
    let raw = std::fs::read_to_string(d.join("r.jsonl")).unwrap();
    let keep: Vec<&str> = raw.lines().collect();
    std::fs::write(d.join("r_t.jsonl"),
                   keep[..keep.len() - 2].join("\n") + "\n").unwrap();
    let v = verify(&d, "r_t.jsonl");
    assert!(v.contains("no closing checkpoint"), "{v}");
}

#[test]
fn mid_delete_detected() {
    let d = dir("midel");
    keygen(&d);
    run_traced(&d, &["/bin/cat", "/etc/hostname"], "r.jsonl");
    let raw = std::fs::read_to_string(d.join("r.jsonl")).unwrap();
    let mut lines: Vec<&str> = raw.lines().collect();
    lines.remove(2);
    std::fs::write(d.join("r_d.jsonl"), lines.join("\n") + "\n").unwrap();
    let v = verify(&d, "r_d.jsonl");
    assert!(v.contains("mismatch"), "{v}");
}

#[test]
fn forked_children_traced() {
    let d = dir("fork");
    keygen(&d);
    run_traced(&d, &["/bin/sh", "-c",
                     "sleep 0.05 & cat /etc/hostname >/dev/null; wait"],
               "r.jsonl");
    let ev = events(&d.join("r.jsonl"));
    let pids: std::collections::HashSet<u64> =
        ev.iter().map(|e| e["pid"].as_u64().unwrap()).collect();
    assert!(ev.iter().any(|e| e["kind"] == "fork"), "no fork event");
    assert!(pids.len() >= 3, "expected parent+2 children: {pids:?}");
}

#[test]
fn shell_wrapper_execs_recorded() {
    let d = dir("wrap");
    keygen(&d);
    run_traced(&d, &["/bin/sh", "-c", "cat /etc/hostname >/dev/null"],
               "r.jsonl");
    let ev = events(&d.join("r.jsonl"));
    let execs: Vec<String> = ev.iter()
        .filter(|e| e["kind"] == "exec")
        .map(|e| e["detail"]["exe"].as_str().unwrap_or("").into())
        .collect();
    assert!(execs.iter().any(|x| x.ends_with("sh"))
            && execs.iter().any(|x| x.ends_with("/cat")),
            "wrapper chain not observed: {execs:?}");
}

#[test]
fn iouring_channel_flagged() {
    let d = dir("uring");
    keygen(&d);
    run_traced(&d, &[probe()], "r.jsonl");
    let ev = events(&d.join("r.jsonl"));
    let iou: Vec<_> = ev.iter().filter(|e| e["kind"] == "iouring").collect();
    assert!(!iou.is_empty(), "io_uring not observed at all");
    assert!(iou.iter().any(|e| e["decision"] == "flag"));
    // residual: the ops submitted inside the ring are NOT traced
}

#[test]
fn disallowed_path_blocked() {
    let d = dir("block");
    keygen(&d);
    run_traced(&d, &["/bin/cat", "/sys/kernel/hostname"], "r.jsonl");
    let ev = events(&d.join("r.jsonl"));
    assert!(ev.iter().any(|e| e["kind"] == "openat"
        && e["decision"] == "block"
        && e["detail"]["path"] == "/sys/kernel/hostname"));
    assert!(ev.iter().any(|e| e["kind"] == "openat"
        && e["detail"]["ret"] == -38), "expected -ENOSYS exit event");
}

#[test]
fn netns_flow_capture_and_flag() {
    // skip cleanly where user namespaces are unavailable
    if !Command::new("unshare").args(["-Urn", "true"]).status()
        .map(|s| s.success()).unwrap_or(false) {
        eprintln!("SKIP: unshare -Urn unavailable");
        return;
    }
    let d = dir("netns");
    keygen(&d);
    // syscall layer allows all connects; the flow layer only lists the
    // sink, so the refused :8888 connect leaves flagged flow evidence.
    astrace(&d, &["manifest", "--key", "k.hex", "--job-id", "t",
                  "--allow-path", "*", "--allow-connect", "*",
                  "--allow-flow", "10.9.9.2:9999/tcp",
                  "--out", "m.json", "--",
                  "/bin/sh", "-c",
                  "exec 3<>/dev/tcp/10.9.9.2/9999 && echo x >&3; \
                   (exec 4<>/dev/tcp/10.9.9.2/8888) 2>/dev/null; true"]);
    let o = astrace(&d, &["run", "--netns", "--manifest", "m.json",
                          "--receipts", "r.jsonl", "--key", "k.hex"]);
    assert!(o.status.success(),
            "run failed: {}", String::from_utf8_lossy(&o.stderr));
    let ev = events(&d.join("r.jsonl"));
    let flows: Vec<&serde_json::Value> = ev.iter()
        .filter(|e| e["kind"] == "flow").collect();
    assert!(flows.iter().any(|f| f["detail"]["flow"]
            .as_str().unwrap_or("").starts_with("10.9.9.2:9999")),
            "sink flow missing: {flows:?}");
    // the refused 8888 attempt leaves a flagged flow record
    assert!(flows.iter().any(|f| f["decision"] == "flag"),
            "unlisted flow not flagged: {flows:?}");
    let merkle: Vec<_> = ev.iter()
        .filter(|e| e["kind"] == "netcap"
               && e["detail"]["merkle_root"].is_string()).collect();
    assert_eq!(merkle.len(), 1, "expected one Merkle commitment");
}
