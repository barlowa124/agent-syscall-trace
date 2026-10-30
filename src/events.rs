//! Normalized event stream shared by the ptrace tracer and the netns
//! flow capture. Every observation lands as one JSON record.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub ts_ns: u128,
    pub pid: u32,
    pub ppid: u32,
    pub kind: EventKind,
    pub detail: serde_json::Value,
    pub decision: Decision,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    Exec,
    Fork,
    OpenAt,
    Connect,
    Socket,
    IoUring,
    Exit,
    Flow,
    NetCap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Flag,
    Block,
}

pub fn now_ns() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
