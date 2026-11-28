// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The in-memory key store.

use crate::{KeyError, KeyHandle, KeyStore, Protection};
use id_core::{KeyAlg, PublicKey};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use std::collections::BTreeMap;
use std::sync::Mutex;

enum Pair {
    Ed25519(Ed25519KeyPair),
    P256(EcdsaKeyPair),
}

/// Keys held in process memory. For tests, and for keys that need not
/// outlive the process.
pub struct MemoryKeyStore {
    rng: SystemRandom,
    keys: Mutex<BTreeMap<String, Pair>>,
}

impl Default for MemoryKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryKeyStore {
    /// An empty store.
    pub fn new() -> Self {
        MemoryKeyStore {
            rng: SystemRandom::new(),
            keys: Mutex::new(BTreeMap::new()),
        }
    }

    /// Adds an Ed25519 key made from a fixed seed, so tests get the same key
    /// and the same signatures on every run. Never use it for a real key.
    pub fn insert_ed25519_seed(&self, label: &str, seed: &[u8; 32]) -> Result<KeyHandle, KeyError> {
        let pair = Ed25519KeyPair::from_seed_unchecked(seed)
            .map_err(|_| KeyError::Store("seed refused".into()))?;
        self.insert(label, Pair::Ed25519(pair))
    }

    fn insert(&self, label: &str, pair: Pair) -> Result<KeyHandle, KeyError> {
        let mut keys = self.lock()?;
        if keys.contains_key(label) {
            return Err(KeyError::Exists);
        }
        keys.insert(label.to_string(), pair);
        Ok(KeyHandle(label.to_string()))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, Pair>>, KeyError> {
        self.keys
            .lock()
            .map_err(|_| KeyError::Store("lock poisoned".into()))
    }
}

impl KeyStore for MemoryKeyStore {
    fn generate(&self, alg: KeyAlg, label: &str) -> Result<KeyHandle, KeyError> {
        let failed = |_| KeyError::Store("key generation failed".into());
        let pair = match alg {
            KeyAlg::Ed25519 => {
                let pkcs8 = Ed25519KeyPair::generate_pkcs8(&self.rng).map_err(failed)?;
                Pair::Ed25519(
                    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
                        .map_err(|_| KeyError::Store("key generation failed".into()))?,
                )
            }
            KeyAlg::P256 => {
                let alg = &ECDSA_P256_SHA256_FIXED_SIGNING;
                let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &self.rng).map_err(failed)?;
                Pair::P256(
                    EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &self.rng)
                        .map_err(|_| KeyError::Store("key generation failed".into()))?,
                )
            }
        };
        self.insert(label, pair)
    }

    fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, KeyError> {
        let keys = self.lock()?;
        let (alg, bytes) = match keys.get(&key.0).ok_or(KeyError::NotFound)? {
            Pair::Ed25519(pair) => (KeyAlg::Ed25519, pair.public_key().as_ref().to_vec()),
            Pair::P256(pair) => (KeyAlg::P256, pair.public_key().as_ref().to_vec()),
        };
        PublicKey::new(alg, bytes).map_err(|e| KeyError::Store(e.to_string()))
    }

    fn sign(&self, key: &KeyHandle, framed: &[u8]) -> Result<Vec<u8>, KeyError> {
        let keys = self.lock()?;
        match keys.get(&key.0).ok_or(KeyError::NotFound)? {
            Pair::Ed25519(pair) => Ok(pair.sign(framed).as_ref().to_vec()),
            Pair::P256(pair) => pair
                .sign(&self.rng, framed)
                .map(|sig| sig.as_ref().to_vec())
                .map_err(|_| KeyError::Store("signing failed".into())),
        }
    }

    fn delete(&self, key: &KeyHandle) -> Result<(), KeyError> {
        self.lock()?
            .remove(&key.0)
            .map(|_| ())
            .ok_or(KeyError::NotFound)
    }

    fn handles(&self) -> Vec<KeyHandle> {
        self.lock()
            .map(|keys| keys.keys().cloned().map(KeyHandle).collect())
            .unwrap_or_default()
    }

    fn protection(&self) -> Protection {
        Protection::Memory
    }
}
