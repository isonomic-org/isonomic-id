// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The signed envelope.

use crate::{frame, from_cbor, to_cbor, Digest, Error, PublicKey, Signer};
use serde::{Deserialize, Serialize};

/// Payload bytes, the key that signed them, and the signature.
///
/// The payload is carried as bytes and the signature covers those bytes, so
/// a verifier never has to re-encode anything. The envelope proves only that
/// the holder of `signer` signed the payload; whether that key speaks for a
/// principal is a separate question for a [`crate::KeyResolver`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    #[serde(rename = "p", with = "serde_bytes")]
    payload: Vec<u8>,
    #[serde(rename = "k")]
    signer: PublicKey,
    #[serde(rename = "s", with = "serde_bytes")]
    sig: Vec<u8>,
}

impl Signed {
    /// Signs `payload` under `domain`.
    pub fn seal(domain: &str, payload: Vec<u8>, signer: &dyn Signer) -> Result<Self, Error> {
        let sig = signer.sign(&frame(domain, &payload))?;
        Ok(Signed {
            payload,
            signer: signer.public_key(),
            sig,
        })
    }

    /// Checks the signature under `domain`.
    pub fn verify(&self, domain: &str) -> Result<(), Error> {
        self.signer.verify(domain, &self.payload, &self.sig)
    }

    /// The payload bytes. Call [`Signed::verify`] before trusting them.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The key that signed.
    pub fn signer(&self) -> &PublicKey {
        &self.signer
    }

    /// The ID of this object: the digest of its payload under `domain`.
    /// Two envelopes with the same payload have the same ID.
    pub fn id(&self, domain: &str) -> Digest {
        Digest::of(domain, &self.payload)
    }

    /// Encodes the envelope for storage or transport.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        to_cbor(self)
    }

    /// Decodes an envelope. This does not check the signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        from_cbor(bytes)
    }
}
