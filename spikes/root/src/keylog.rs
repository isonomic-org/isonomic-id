// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: Apache-2.0

//! Option C: the identity is a signed key log, with an Ethereum account
//! bound into it.
//!
//! The ID is the digest of the first entry. Every later entry names the
//! entry before it and must be signed by a key the previous entry committed
//! to in advance (by digest, so the key itself stays unseen until used).
//! Those "rotation keys" are used once and then destroyed. Everyday device
//! signing keys are listed in the log but have no power to change it.

use crate::eth::{self, Address};
use id_core::{from_cbor, hex, to_cbor, Digest, PublicKey, Signed, Signer};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const DOMAIN: &str = "spike-log";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Op {
    AddDevice(PublicKey),
    RemoveDevice(PublicKey),
    /// Binds an Ethereum key and its account address. `proof` is the
    /// Ethereum key's own signature over this identity, so the binding is
    /// signed in both directions.
    BindEth {
        #[serde(with = "serde_bytes")]
        key: Address,
        #[serde(with = "serde_bytes")]
        account: Address,
        #[serde(with = "serde_bytes")]
        proof: Vec<u8>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub prev: Option<Digest>,
    pub ops: Vec<Op>,
    /// Digests of the keys allowed to sign the next entry.
    pub next: Vec<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub id: Digest,
    pub head: Digest,
    pub seq: u64,
    pub devices: BTreeSet<PublicKey>,
    pub next: BTreeSet<Digest>,
    pub eth: Option<(Address, Address)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogError {
    Empty,
    Malformed(u64),
    BadSignature(u64),
    /// The signer was not committed to by the previous entry.
    NotCommitted(u64),
    BrokenChain(u64),
    BadBinding(u64),
    /// The log shown is not a continuation of the one seen before.
    Fork,
}

/// What the Ethereum key signs to bind itself to an identity.
pub fn binding_message(id: &Digest, account: &Address) -> Vec<u8> {
    format!(
        "Isonomic ID binding v1\n{}\n0x{}",
        id.to_hex(),
        hex(account)
    )
    .into_bytes()
}

/// The account address bound to an identity: salted with the ID, owned by
/// the Ethereum key.
pub fn bound_account(id: &Digest, eth_key: &Address) -> Address {
    eth::account_address(eth_key, id.as_bytes())
}

/// Verifies a whole log from the first entry, with nothing but the log.
pub fn replay(log: &[Signed]) -> Result<State, LogError> {
    let first = log.first().ok_or(LogError::Empty)?;
    let mut state = State {
        id: first.id(DOMAIN),
        head: first.id(DOMAIN),
        seq: 0,
        devices: BTreeSet::new(),
        next: BTreeSet::new(),
        eth: None,
    };
    for (n, signed) in log.iter().enumerate() {
        let n = n as u64;
        signed
            .verify(DOMAIN)
            .map_err(|_| LogError::BadSignature(n))?;
        let entry: Entry = from_cbor(signed.payload()).map_err(|_| LogError::Malformed(n))?;
        if n == 0 {
            if entry.prev.is_some() || entry.seq != 0 {
                return Err(LogError::BrokenChain(0));
            }
        } else {
            if entry.prev != Some(state.head) || entry.seq != n {
                return Err(LogError::BrokenChain(n));
            }
            if !state.next.contains(&signed.signer().fingerprint()) {
                return Err(LogError::NotCommitted(n));
            }
        }
        for op in entry.ops {
            match op {
                Op::AddDevice(key) => {
                    state.devices.insert(key);
                }
                Op::RemoveDevice(key) => {
                    state.devices.remove(&key);
                }
                Op::BindEth {
                    key,
                    account,
                    proof,
                } => {
                    let signed_by = eth::recover(&binding_message(&state.id, &account), &proof);
                    if signed_by != Some(key) || account != bound_account(&state.id, &key) {
                        return Err(LogError::BadBinding(n));
                    }
                    state.eth = Some((key, account));
                }
            }
        }
        state.next = entry.next.into_iter().collect();
        state.head = signed.id(DOMAIN);
        state.seq = n;
    }
    Ok(state)
}

/// Adds an entry at the head, signed by `rotation_key`, and re-verifies.
pub fn append(
    log: &mut Vec<Signed>,
    ops: Vec<Op>,
    next: Vec<Digest>,
    rotation_key: &dyn Signer,
) -> Result<State, LogError> {
    let (seq, prev) = match log.last() {
        Some(last) => (log.len() as u64, Some(last.id(DOMAIN))),
        None => (0, None),
    };
    let entry = Entry {
        seq,
        prev,
        ops,
        next,
    };
    let payload = to_cbor(&entry).map_err(|_| LogError::Malformed(seq))?;
    let signed =
        Signed::seal(DOMAIN, payload, rotation_key).map_err(|_| LogError::BadSignature(seq))?;
    let mut candidate = log.clone();
    candidate.push(signed);
    let state = replay(&candidate)?;
    *log = candidate;
    Ok(state)
}

/// A verifier that remembers what it has already accepted for one identity
/// and refuses any log that is not a continuation of it.
#[derive(Default)]
pub struct Pinned {
    seen: Vec<Digest>,
}

impl Pinned {
    pub fn accept(&mut self, log: &[Signed]) -> Result<State, LogError> {
        let state = replay(log)?;
        let shown: Vec<Digest> = log.iter().map(|e| e.id(DOMAIN)).collect();
        if shown.len() < self.seen.len() || shown[..self.seen.len()] != self.seen[..] {
            return Err(LogError::Fork);
        }
        self.seen = shown;
        Ok(state)
    }
}
