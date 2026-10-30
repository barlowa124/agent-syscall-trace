//! Policy evaluation: manifest rules -> allow/flag/block per event.

use crate::events::{Decision, EventKind};
use crate::manifest::Policy;

pub fn evaluate(policy: &Policy, kind: EventKind, detail: &serde_json::Value)
                -> Decision {
    match kind {
        EventKind::OpenAt => {
            let path = detail["path"].as_str().unwrap_or("");
            if policy.flag_paths.iter().any(|p| path.starts_with(p.as_str())) {
                Decision::Flag
            } else if policy.allow_paths.iter()
                        .any(|p| path.starts_with(p.as_str()))
                      || policy.allow_paths.iter().any(|p| p == "*") {
                Decision::Allow
            } else if policy.enforce_block {
                Decision::Block
            } else {
                Decision::Flag
            }
        }
        EventKind::Connect => {
            let target = detail["target"].as_str().unwrap_or("");
            if policy.allow_connects.iter().any(|p| p == "*")
               || policy.allow_connects.iter().any(|p| target.starts_with(p.as_str())) {
                Decision::Allow
            } else if policy.enforce_block {
                Decision::Block
            } else {
                Decision::Flag
            }
        }
        EventKind::Flow => {
            // A flow matches an allow entry on either endpoint:
            // "dst:dport/proto" for the request direction,
            // "src:sport/proto" for replies.
            let fwd = detail["flow"].as_str().unwrap_or("");
            let proto_name = match detail["proto"].as_u64() {
                Some(6) => "tcp", Some(17) => "udp", _ => "ip" };
            let rev = format!("{}:{}/{}",
                detail["src"].as_str().unwrap_or(""),
                detail["sport"].as_u64().unwrap_or(0), proto_name);
            let m = |k: &str| policy.allow_flows.iter()
                .any(|p| p == "*" || k.starts_with(p.as_str()));
            if m(fwd) || m(&rev) { Decision::Allow } else { Decision::Flag }
        }
        EventKind::IoUring => {
            if policy.flag_iouring { Decision::Flag } else { Decision::Allow }
        }
        _ => Decision::Allow,
    }
}
