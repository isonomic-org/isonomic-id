// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: Apache-2.0

//! Core types shared by every identity crate.
//!
//! Principal IDs, public keys and signature checks, digests, the byte
//! encoding, the signed envelope every grant and log entry travels in, and
//! the key log that an identity is rooted in.

mod codec;
mod envelope;
mod key;
pub mod log;
mod principal;

pub use codec::{from_cbor, to_cbor, MAX_ENCODED_BYTES};
pub use envelope::Signed;
pub use key::{frame, KeyAlg, PublicKey, Signer};
pub use principal::PrincipalId;

use serde::{Deserialize, Serialize};
use std::fmt;

/// Seconds since the Unix epoch.
pub type Timestamp = u64;

/// Everything that can go wrong in this crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The signature does not match the key and message.
    BadSignature,
    /// The public key has the wrong length or is not on its curve.
    BadKey,
    /// The bytes are not a valid encoding of the expected value.
    Malformed(&'static str),
    /// The encoded value is larger than [`MAX_ENCODED_BYTES`].
    TooLarge,
    /// The key store refused or failed to sign.
    Signer(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadSignature => write!(f, "signature does not verify"),
            Error::BadKey => write!(f, "public key is not valid"),
            Error::Malformed(what) => write!(f, "malformed {what}"),
            Error::TooLarge => write!(f, "encoded value is too large"),
            Error::Signer(why) => write!(f, "signing failed: {why}"),
        }
    }
}

impl std::error::Error for Error {}

/// A SHA-256 digest, always computed with a domain so that a digest made
/// for one purpose can never be mistaken for another.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Digest(#[serde(with = "serde_bytes")] [u8; 32]);

impl Digest {
    /// Digest of `data` under `domain`, for example `"grant"`.
    pub fn of(domain: &str, data: &[u8]) -> Self {
        let framed = frame(domain, data);
        let hash = ring::digest::digest(&ring::digest::SHA256, &framed);
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_ref());
        Digest(out)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wraps raw bytes, for values read from storage.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Digest(bytes)
    }

    /// Lowercase hexadecimal text.
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", &self.to_hex()[..12])
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Lowercase hexadecimal text for any bytes.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}

/// Answers whether a key speaks for a principal right now.
///
/// This is the seam to the key log: grants and checks ask this question and
/// never look at how an identity keeps its keys. [`log::Directory`] answers
/// it from the logs it has verified.
pub trait KeyResolver {
    /// True when `key` is a valid signing key of `principal` at time `at`.
    fn is_current_key(&self, principal: &PrincipalId, key: &PublicKey, at: Timestamp) -> bool;
}
