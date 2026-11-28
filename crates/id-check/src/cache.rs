// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Remembering chains that have already been verified.

use crate::{check_with, Decision, Request, World};
use id_core::{Digest, Timestamp};
use id_grants::{verify_chain, Authority, SignedGrant};
use std::collections::HashMap;
use std::sync::Mutex;

/// The most chains a cache holds before it starts again from empty.
pub const MAX_CACHED: usize = 4096;

/// A [`World`] that can say when anything a chain depends on has changed.
pub trait VersionedWorld: World {
    /// A number that goes up whenever a key log or the revocation list
    /// changes. Every cached chain is dropped when it moves.
    fn version(&self) -> u64;
}

/// Verified chains, so a repeated check skips the signatures.
///
/// A chain is cached only once it has verified. It is used again only while
/// the world's version is unchanged and the time is inside every link's
/// dates. Everything that is not about the chain itself (ownership, scope,
/// budgets, membership, approval, derived data) is decided afresh every time.
#[derive(Default)]
pub struct ChainCache {
    entries: Mutex<HashMap<Digest, Entry>>,
}

struct Entry {
    version: u64,
    authority: Authority,
}

impl ChainCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decides one request, like [`crate::check`], reusing a verified chain.
    pub fn check(&self, request: &Request<'_>, world: &dyn VersionedWorld) -> Decision {
        check_with(request, world, &|proof, now| {
            let version = world.version();
            let Some(key) = key(proof) else {
                return verify_chain(proof, world, world, now);
            };
            if let Some(authority) = self.get(&key, version, now) {
                return Ok(authority);
            }
            let authority = verify_chain(proof, world, world, now)?;
            self.put(key, version, authority.clone());
            Ok(authority)
        })
    }

    /// How many chains are held.
    pub fn len(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }

    /// True when no chain is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn get(&self, key: &Digest, version: u64, now: Timestamp) -> Option<Authority> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(key)?;
        let a = &entry.authority;
        let in_dates =
            a.not_before.is_none_or(|nbf| now >= nbf) && a.expires.is_none_or(|exp| now < exp);
        (entry.version == version && in_dates).then(|| a.clone())
    }

    fn put(&self, key: Digest, version: u64, authority: Authority) {
        if let Ok(mut entries) = self.entries.lock() {
            if entries.len() >= MAX_CACHED {
                entries.clear();
            }
            entries.insert(key, Entry { version, authority });
        }
    }
}

/// The cache key: a digest of every link exactly as presented, signatures
/// included, so a chain with any byte changed is verified from scratch.
fn key(chain: &[SignedGrant]) -> Option<Digest> {
    let mut bytes = Vec::new();
    for link in chain {
        let encoded = link.to_bytes().ok()?;
        bytes.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&encoded);
    }
    Some(Digest::of("chain-cache", &bytes))
}
