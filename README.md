# agent-syscall-trace

`astrace` is a Rust ptrace supervisor for an AI agent's process tree.
It records what the job did at the kernel boundary and signs that
record, so an analyst can run a verify command that catches edits
after the fact.

## What it does

- Traces `execve`, `openat`/`open`/`openat2`, `socket`, `connect`,
  `io_uring_setup`/`io_uring_enter`, child creation, and exit across
  every pid the job forks.
- Emits one normalized JSON event per observation with an
  allow/flag/block decision from a signed job manifest.
- Appends each event to a SHA-256 hash chain. Ed25519 signatures cover <!-- deslop-disable-line magic-number -->
  periodic checkpoints and the closing receipt.
- Inside a user and network namespace the run owns, taps the veth
  with AF_PACKET and records per-flow metadata only, committed into
  a Merkle root that lands in the chain and is checked against the
  manifest flow list.
- Blocks disallowed opens and connects by rewriting the syscall to
  `-ENOSYS` at the entry stop.

## Build and run

```bash
cargo build --release
cargo test
```

End-to-end demo (creates the artifacts under `results/`):

```bash
bash scripts/demo.sh
```

Manual flow:

```bash
astrace keygen --out k.hex
astrace manifest --key k.hex --job-id job \
    --allow-path /usr --allow-path /etc --allow-connect '*' \
    --out m.json -- /bin/ls /tmp
astrace run --manifest m.json --receipts r.jsonl --key k.hex
astrace verify --receipts r.jsonl --pubkey <pubkey_hex from m.json>
```

Add `--netns` to `run` for the veth and AF_PACKET path. The demo
spawns a sink on `10.9.9.2:9999` inside a second net namespace and
moves the veth peer across, which works because both namespaces are
owned by the same user namespace.

## Measured results

From `results/` on this machine (Rust 1.99.1, Linux x86-64, <!-- deslop-disable-line magic-number -->
`unshare -Urn` available, no `CAP_BPF`):

| Metric | Value | Artifact |
| --- | --- | --- |
| Integration tests | 9 passed | `cargo test` run |
| Receipt entries in demo run | 42 | `results/receipts.jsonl` |
| Events: exec/openat/fork/socket/connect/exit/flow/netcap | 4 / 49 / 4 / 2 / 3 / 5 / 2 / 1 | `results/receipts.jsonl` | <!-- deslop-disable-line magic-number -->
| Clean chain verify | `OK: chain intact` | `results/verify.txt` |
| Tampered chain verify | `FAIL` hash mismatch at 3 lines | `results/verify_tampered.txt` |
| Per-syscall overhead | ~79 us over untraced | `results/bench.txt` |
| Flow hashing throughput | ~5.27M frames/s | `results/bench.txt` |

The demo run also shows the two enforcement layers directly. The
`connect` to `10.9.9.2:8888` is blocked at the syscall stop with
`ret: -38`, while the allowed `10.9.9.2:9999` flow appears in the <!-- deslop-disable-line magic-number -->
Merkle-committed netcap record.

## Design notes

- Syscall-enter stops evaluate policy before the kernel runs the
  call. A `block` decision writes `orig_rax = -1` so the kernel
  returns `-ENOSYS`. A `flag` records and continues.
- `ptrace` options `TRACEFORK|TRACEVFORK|TRACECLONE|TRACEEXEC|
  TRACESYSGOOD|EXITKILL` keep the tree attached without a cgroup.
- Strings and sockaddrs are read with `process_vm_readv` at stop
  time, never by sharing memory.
- The hash chain binds `sha256(prev_hash || canonical_json(fields))`
  per receipt. Checkpoints sign `kind:covered_seq:prev_hash`. The
  final `closed` checkpoint pins the tail.
- Flow records hash into a binary Merkle tree whose root is a chain
  event, so the flow set commits to one value without storing
  packets.

## Adversarial coverage

`cargo test` drives the real binary against the cases in
`tests/adversarial.rs`. The suite covers mid-chain edit, tail
truncation, mid-chain deletion, forked children through `sh -c`,
wrapper exec chains, `io_uring` channel flagging, blocked open with
`-ENOSYS`, and the netns flow path including a flagged unlisted
flow. What is caught and missed is enumerated in
`docs/threat-model.md`.

## Limits

- `io_uring` ops inside the ring are not per-op traced. Setup and
  enter are flagged as an unmonitored channel.
- Tail truncation inside the last checkpoint window shows only as a
  missing `closed` signature.
- Flow records cover IPv4 TCP/UDP on the veth. Other ethertypes
  count toward `packets` but produce no flow row.
- Payloads are never captured. Byte counts only.
- `--netns` needs `unshare -Urn`. The test skips where unavailable.
- eBPF is not used because this account lacks `CAP_BPF`. Documented
  in the threat model.
- ptrace costs ~79 us per syscall here (200-syscall workload, debug <!-- deslop-disable-line magic-number -->
  timing). A seccomp user-notification or eBPF design would cut that
  but is outside this build.
- The `openat`/`connect` decision reads path and sockaddr at the
  entry stop. A racing second thread could swap the buffer before
  the kernel reads it (TOCTOU, in the threat model).
