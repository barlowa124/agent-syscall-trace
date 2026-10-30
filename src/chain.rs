//! Hash-chained receipt log with Ed25519-signed checkpoints.
//!
//! Each receipt binds one event:
//!   hash = sha256(prev_hash || canonical_json(entry minus hash))
//!
//! A `checkpoint` receipt every N events carries
//!   sig = ed25519_sign(session_sk, "checkpoint" || covered_seq || last_hash)
//! and the run ends with a `closed` checkpoint whose covered_seq must
//! equal the final receipt seq. Without the signing key a truncation that
//! keeps the file internally consistent cannot fabricate the closing
//! checkpoint; mid-edits break the hash links. Tail truncation inside the
//! last checkpoint window is the residual: caught at the next verify
//! because the closing checkpoint is missing.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use crate::events::Event;

pub fn canonical(v: &serde_json::Value) -> Vec<u8> {
    serde_json::to_string(v).unwrap().into_bytes()
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub seq: u64,
    pub kind: String, // "event" | "checkpoint" | "closed"
    pub event: Option<Event>,
    pub covered_seq: Option<u64>,
    pub signature: Option<String>,
    pub prev_hash: String,
    pub hash: String,
}

pub struct Chain {
    path: std::path::PathBuf,
    seq: u64,
    prev: String,
    checkpoint_every: u64,
    signer: Option<ed25519_dalek::SigningKey>,
    pub pubkey_hex: String,
}

impl Chain {
    pub fn create(
        path: &Path,
        signer: ed25519_dalek::SigningKey,
        checkpoint_every: u64,
    ) -> std::io::Result<Self> {
        let pk = ed25519_dalek::VerifyingKey::from(&signer);
        Ok(Self {
            path: path.to_path_buf(),
            seq: 0,
            prev: "0".repeat(64),
            checkpoint_every,
            pubkey_hex: hex::encode(pk.to_bytes()),
            signer: Some(signer),
        })
    }

    fn entry_hash(prev: &str, fields: &serde_json::Value) -> String {
        let mut buf = prev.as_bytes().to_vec();
        buf.extend_from_slice(&canonical(fields));
        hex::encode(sha256(&buf))
    }

    fn append(&mut self, r: &Receipt) -> std::io::Result<()> {
        let mut f = OpenOptions::new().append(true).open(&self.path)?;
        f.write_all(serde_json::to_string(r).unwrap().as_bytes())?;
        f.write_all(b"\n")?;
        self.seq = r.seq;
        self.prev = r.hash.clone();
        Ok(())
    }

    fn fields_for(&self, seq: u64, kind: &str, event: &Option<Event>,
                  covered_seq: Option<u64>, signature: &Option<String>)
                  -> serde_json::Value {
        serde_json::json!({
            "seq": seq, "kind": kind, "event": event,
            "covered_seq": covered_seq, "signature": signature,
            "prev_hash": self.prev,
        })
    }

    pub fn record(&mut self, ev: Event) -> std::io::Result<()> {
        let seq = self.seq + 1;
        let fields = self.fields_for(seq, "event", &Some(ev.clone()), None, &None);
        let hash = Self::entry_hash(&self.prev, &fields);
        let r = Receipt {
            seq, kind: "event".into(), event: Some(ev),
            covered_seq: None, signature: None,
            prev_hash: self.prev.clone(), hash,
        };
        self.append(&r)?;
        if self.checkpoint_every > 0 && seq % self.checkpoint_every == 0 {
            self.checkpoint("checkpoint")?;
        }
        Ok(())
    }

    pub fn checkpoint(&mut self, kind: &str) -> std::io::Result<()> {
        let seq = self.seq + 1;
        let covered = self.seq;
        let payload = format!("{}:{}:{}", kind, covered, self.prev);
        let sig = self.signer.as_ref().map(|sk| {
            use ed25519_dalek::Signer;
            hex::encode(sk.sign(payload.as_bytes()).to_bytes())
        });
        let fields = self.fields_for(seq, kind, &None, Some(covered), &sig);
        let hash = Self::entry_hash(&self.prev, &fields);
        let r = Receipt {
            seq, kind: kind.into(), event: None,
            covered_seq: Some(covered), signature: sig,
            prev_hash: self.prev.clone(), hash,
        };
        self.append(&r)
    }

    pub fn close(&mut self) -> std::io::Result<()> {
        self.checkpoint("closed")
    }
}

/// Verify a receipt file. Returns a list of problems; empty is clean.
pub fn verify(path: &Path, pubkey_hex: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => return vec![format!("open: {e}")],
    };
    let pk_bytes = match hex::decode(pubkey_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return vec!["bad pubkey".into()],
    };
    let pk = ed25519_dalek::VerifyingKey::from_bytes(
        pk_bytes.as_slice().try_into().unwrap(),
    );
    let (mut prev, mut seq, mut closed) = ("0".repeat(64), 0u64, false);
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = match line {
            Ok(l) if !l.trim().is_empty() => l,
            Ok(_) => continue,
            Err(e) => {
                problems.push(format!("line {}: {e}", i + 1));
                break;
            }
        };
        let r: Receipt = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                problems.push(format!("line {}: parse {e}", i + 1));
                break;
            }
        };
        seq += 1;
        if r.seq != seq {
            problems.push(format!("line {}: seq {} != {}", i + 1, r.seq, seq));
        }
        if r.prev_hash != prev {
            problems.push(format!("line {}: prev_hash mismatch", i + 1));
        }
        let fields = serde_json::json!({
            "seq": r.seq, "kind": r.kind, "event": r.event,
            "covered_seq": r.covered_seq, "signature": r.signature,
            "prev_hash": r.prev_hash,
        });
        if Chain::entry_hash(&prev, &fields) != r.hash {
            problems.push(format!("line {}: hash mismatch", i + 1));
        }
        if matches!(r.kind.as_str(), "checkpoint" | "closed") {
            let want = format!("{}:{}:{}", r.kind, r.covered_seq.unwrap_or(0), r.prev_hash);
            let ok = r.signature.as_deref().map_or(false, |s| {
                pk.as_ref().ok().and_then(|pk| {
                    let sigb = hex::decode(s).ok()?;
                    let sig = ed25519_dalek::Signature::from_bytes(
                        sigb.as_slice().try_into().ok()?);
                    pk.verify_strict(want.as_bytes(), &sig).ok()
                }).is_some()
            });
            if !ok {
                problems.push(format!("line {}: bad checkpoint sig", i + 1));
            }
        }
        if r.kind == "closed" {
            closed = true;
            if r.covered_seq != Some(seq - 1) {
                problems.push(format!(
                    "line {}: closed covers {:?} not {}",
                    i + 1, r.covered_seq, seq - 1));
            }
        }
        prev = r.hash;
    }
    if !closed {
        problems.push("no closing checkpoint".into());
    }
    problems
}
