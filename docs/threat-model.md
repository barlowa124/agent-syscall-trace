# Threat model

`astrace` answers one question: what did a job do at the kernel
boundary, and can anyone later prove that record was not edited. The
traced job is the adversary. The analyst verifying receipts is the
defender.

## In scope

A job may try to hide its behavior or rewrite the record after the
fact. The defenses work in the order of the kill chain.

1. Visibility. Ptrace follows the whole process tree, so `sh -c`
   wrappers and forked children appear in the stream. The normalized
   events cover `execve`, `openat`/`open`/`openat2`, `socket`,
   `connect`, `io_uring_setup`/`io_uring_enter`, child creation, and
   exit.
2. Integrity. Every event lands in a SHA-256 hash chain keyed by the
   previous receipt. An Ed25519 signature covers each periodic
   checkpoint and the closing record, so a rewritten or truncated
   log fails `astrace verify`.
3. Policy. The signed manifest pins the allowed path prefixes and
   the connect targets, plus the flow list for the netns path.
   `flag` records a violation but lets it run. `block` rewrites the
   syscall to `-ENOSYS` before the kernel executes it.
4. Network evidence. Inside a user and network namespace the run
   owns, an AF_PACKET tap on the workload's veth records 5-tuple
   metadata only. Per-flow records commit into a Merkle tree and the
   root lands in the chain, cross-checked against the manifest flow
   list.

## Caught

| Attack | Result |
| --- | --- |
| Edit an event in the receipt file | `verify` reports a hash mismatch at that line |
| Delete a mid-chain receipt | `prev_hash` mismatch on the next receipt |
| Truncate the tail | Missing signed `closed` checkpoint |
| Forge a fresh tail | Checkpoint signature fails without the key |
| Child escapes via `sh -c`, `env`, `nohup` | `fork`/`clone` events plus per-pid syscall stops |
| Open outside allow list | `block` returns `-ENOSYS`, recorded |
| Connect outside allow list | Same, at the `connect` stop |
| Flow outside the manifest list | `flag` decision on the flow record |

## Missed

| Attack or gap | Why it slips through |
| --- | --- |
| `io_uring` operations | The ring runs async, so ptrace sees setup and enter but never the per-op syscalls. Flagged as a channel only. |
| Tail truncation inside the last checkpoint window | Detected only as a missing `closed` checkpoint. If the attacker also holds the signing key, nothing helps. |
| Direct syscalls via `int 0x80` on an x86-64 tracee | The 64-bit kernel still services them and the tracer decodes `orig_rax` the same way. This path is untested. |
| Preloaded `ptrace` evasion inside the tracee | A tracee cannot hide syscalls from ptrace. It can only delay or exit, which the exit event records. |
| Non-IPv4 packets on the veth | Flow records parse IPv4 TCP and UDP only. Other ethertypes count toward `packets` but get no flow row. |
| Payload content | Never captured by design. Byte counts only. |
| Hosts without `unshare -Urn` | The netns path skips. Ptrace tracing still works. |
| eBPF observability | This account lacks `CAP_BPF`, so no kernel-program path exists. Documented as a gap. |
| TOCTOU on the blocked path | The decision runs at syscall-entry. A second thread could swap the string buffer before the kernel reads it. Reading process memory at stop time mitigates the race without eliminating it. |

## Trust assumptions

The kernel and ptrace are honest. The signing key never leaves the
operator's file (0600). The manifest signature is checked before any
tracing starts, so a swapped manifest fails closed. A root-owned
adversary outside the job could attach to the tracer or write its
log. That is out of scope.
