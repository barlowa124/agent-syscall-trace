//! Ed25519-signed job manifest. The manifest is the contract the
//! receipts are checked against: the command, the policy, and the
//! allowed outbound flows.

use serde::{Deserialize, Serialize};

use crate::chain::canonical;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    /// Path prefixes allowed for openat (read or write).
    pub allow_paths: Vec<String>,
    /// Path prefixes that are allowed but flagged.
    pub flag_paths: Vec<String>,
    /// socket+connect targets allowed as "host:port" strings or "*".
    pub allow_connects: Vec<String>,
    /// Flow keys allowed in the netns capture, "dst:port/proto" or "*".
    pub allow_flows: Vec<String>,
    /// If true, any io_uring channel is flagged.
    pub flag_iouring: bool,
    /// If true, block rather than flag on violation.
    pub enforce_block: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestBody {
    pub job_id: String,
    pub cmd: Vec<String>,
    pub policy: Policy,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub body: ManifestBody,
    pub pubkey_hex: String,
    pub signature_hex: String,
}

impl Manifest {
    pub fn sign(body: ManifestBody, sk: &ed25519_dalek::SigningKey) -> Self {
        use ed25519_dalek::Signer;
        let payload = canonical(&serde_json::to_value(&body).unwrap());
        let sig = sk.sign(&payload);
        Self {
            body,
            pubkey_hex: hex::encode(
                ed25519_dalek::VerifyingKey::from(sk).to_bytes()),
            signature_hex: hex::encode(sig.to_bytes()),
        }
    }

    pub fn verify(&self) -> bool {
        use ed25519_dalek::Verifier;
        let Ok(pkb) = hex::decode(&self.pubkey_hex) else { return false };
        let Ok(sb) = hex::decode(&self.signature_hex) else { return false };
        let (Ok(pk), Ok(sig)) = (
            ed25519_dalek::VerifyingKey::from_bytes(
                pkb.as_slice().try_into().unwrap_or(&[0; 32])),
            TryInto::<[u8; 64]>::try_into(sb.as_slice())
                .map(|b| ed25519_dalek::Signature::from_bytes(&b)),
        ) else { return false };
        let payload = canonical(&serde_json::to_value(&self.body).unwrap());
        pk.verify(&payload, &sig).is_ok()
    }
}

/// Generate a fresh keypair and persist the secret to a file with 0600.
pub fn keygen(path: &std::path::Path) -> std::io::Result<()> {
    use rand_core::OsRng;
    let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
    std::fs::write(path, hex::encode(sk.to_bytes()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn load_key(path: &std::path::Path) -> std::io::Result<ed25519_dalek::SigningKey> {
    let hexkey = std::fs::read_to_string(path)?;
    let bytes = hex::decode(hexkey.trim())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let arr: [u8; 32] = bytes.as_slice().try_into()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData,
                                       "key must be 32 bytes"))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&arr))
}
