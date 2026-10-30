//! Binary Merkle tree over flow-record leaves. Root commits the whole
//! flow set into one receipt without retaining any payload.

use crate::chain::sha256;

pub fn leaf(flow_json: &serde_json::Value) -> [u8; 32] {
    sha256(serde_json::to_string(flow_json).unwrap().as_bytes())
}

pub fn root(leaves: &[[u8; 32]]) -> String {
    if leaves.is_empty() {
        return hex::encode(sha256(b"empty"));
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let mut buf = pair[0].to_vec();
            buf.extend_from_slice(pair.get(1).unwrap_or(&pair[0]));
            next.push(sha256(&buf));
        }
        level = next;
    }
    hex::encode(level[0])
}
