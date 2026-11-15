//! Public keys, signature checks and the signer trait.

use crate::{Digest, Error};
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED, ED25519};
use serde::{Deserialize, Serialize};

/// Signature schemes a principal's key may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum KeyAlg {
    /// Ed25519. Used for keys held in software, such as agent and app keys.
    #[serde(rename = "ed25519")]
    Ed25519,
    /// ECDSA over P-256 with SHA-256, signature as fixed-length `r || s`.
    /// This is the scheme a Mac's secure chip signs with.
    #[serde(rename = "p256")]
    P256,
}

/// A public key and its scheme.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PublicKey {
    /// The signature scheme.
    #[serde(rename = "a")]
    pub alg: KeyAlg,
    /// Ed25519: 32 bytes. P-256: 65 bytes, uncompressed.
    #[serde(rename = "k", with = "serde_bytes")]
    pub bytes: Vec<u8>,
}

impl PublicKey {
    /// Builds a key, checking only its length. A key that is not on its
    /// curve fails at the first verification.
    pub fn new(alg: KeyAlg, bytes: Vec<u8>) -> Result<Self, Error> {
        let expected = match alg {
            KeyAlg::Ed25519 => 32,
            KeyAlg::P256 => 65,
        };
        if bytes.len() != expected {
            return Err(Error::BadKey);
        }
        Ok(PublicKey { alg, bytes })
    }

    /// Checks `sig` over `msg` under `domain`.
    pub fn verify(&self, domain: &str, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        let framed = frame(domain, msg);
        let result = match self.alg {
            KeyAlg::Ed25519 => UnparsedPublicKey::new(&ED25519, &self.bytes).verify(&framed, sig),
            KeyAlg::P256 => {
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &self.bytes).verify(&framed, sig)
            }
        };
        result.map_err(|_| Error::BadSignature)
    }

    /// A digest that commits to this key without revealing it.
    pub fn fingerprint(&self) -> Digest {
        let mut data = Vec::with_capacity(1 + self.bytes.len());
        data.push(match self.alg {
            KeyAlg::Ed25519 => 1,
            KeyAlg::P256 => 2,
        });
        data.extend_from_slice(&self.bytes);
        Digest::of("key", &data)
    }
}

/// Something that can sign without handing out its private key.
///
/// Key stores implement this, so a key in a secure chip and a key in memory
/// look the same to everything above them.
pub trait Signer: Send + Sync {
    /// The public half.
    fn public_key(&self) -> PublicKey;
    /// Signs `framed` exactly as given. Callers pass the output of [`frame`].
    fn sign(&self, framed: &[u8]) -> Result<Vec<u8>, Error>;
}

/// The bytes that are actually signed or hashed: a fixed prefix, the domain,
/// a zero byte, then the message. No domain may contain a zero byte.
pub fn frame(domain: &str, msg: &[u8]) -> Vec<u8> {
    const PREFIX: &[u8] = b"isonomic-id/v1/";
    debug_assert!(!domain.as_bytes().contains(&0));
    let mut out = Vec::with_capacity(PREFIX.len() + domain.len() + 1 + msg.len());
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(domain.as_bytes());
    out.push(0);
    out.extend_from_slice(msg);
    out
}
