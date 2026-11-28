// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Key stores.
//!
//! A key store creates keys, signs with them and deletes them. It has no way
//! to hand out a private key: there is no export call in the trait, so code
//! above a store cannot leak what it never sees.
//!
//! This crate ships the in-memory store used by tests and by keys that only
//! need to live as long as a process, and, on a Mac, the store backed by the
//! secure chip and the keychain.

#[cfg(target_os = "macos")]
mod macos;
mod memory;

#[cfg(target_os = "macos")]
pub use macos::MacKeyStore;
pub use memory::MemoryKeyStore;

use id_core::{Error, KeyAlg, PublicKey, Signer};
use std::fmt;
use std::sync::Arc;

/// Names one key inside one store. It is a label, not key material.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyHandle(pub String);

/// How well a store protects its private keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protection {
    /// Keys live in process memory and die with it.
    Memory,
    /// Keys are held by the operating system's keychain.
    OsKeychain,
    /// Keys are generated in, and never leave, a hardware secure chip.
    Hardware,
}

/// Why a key-store call failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// No key with that handle.
    NotFound,
    /// A key with that label already exists.
    Exists,
    /// This store cannot make keys of that scheme.
    Unsupported(KeyAlg),
    /// The store itself failed.
    Store(String),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::NotFound => write!(f, "no such key"),
            KeyError::Exists => write!(f, "a key with that label already exists"),
            KeyError::Unsupported(alg) => write!(f, "this store cannot hold {alg:?} keys"),
            KeyError::Store(why) => write!(f, "key store failed: {why}"),
        }
    }
}

impl std::error::Error for KeyError {}

/// A place that holds private keys and signs with them.
pub trait KeyStore: Send + Sync {
    /// Creates a new key under `label`.
    fn generate(&self, alg: KeyAlg, label: &str) -> Result<KeyHandle, KeyError>;
    /// The public half of a key.
    fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, KeyError>;
    /// Signs `framed` (the output of `id_core::frame`) with a key.
    fn sign(&self, key: &KeyHandle, framed: &[u8]) -> Result<Vec<u8>, KeyError>;
    /// Destroys a key. Afterwards nothing can sign with it again.
    fn delete(&self, key: &KeyHandle) -> Result<(), KeyError>;
    /// Every key in the store.
    fn handles(&self) -> Vec<KeyHandle>;
    /// How this store protects its keys.
    fn protection(&self) -> Protection;
}

/// One key in a store, usable wherever a [`Signer`] is expected.
#[derive(Clone)]
pub struct StoredKey {
    store: Arc<dyn KeyStore>,
    handle: KeyHandle,
    public: PublicKey,
}

impl StoredKey {
    /// Creates a key in `store` and returns a signer for it.
    pub fn generate(store: Arc<dyn KeyStore>, alg: KeyAlg, label: &str) -> Result<Self, KeyError> {
        let handle = store.generate(alg, label)?;
        Self::open(store, handle)
    }

    /// A signer for an existing key.
    pub fn open(store: Arc<dyn KeyStore>, handle: KeyHandle) -> Result<Self, KeyError> {
        let public = store.public_key(&handle)?;
        Ok(StoredKey {
            store,
            handle,
            public,
        })
    }

    /// The key's handle.
    pub fn handle(&self) -> &KeyHandle {
        &self.handle
    }

    /// Destroys the key in its store.
    pub fn destroy(self) -> Result<(), KeyError> {
        self.store.delete(&self.handle)
    }
}

impl Signer for StoredKey {
    fn public_key(&self) -> PublicKey {
        self.public.clone()
    }

    fn sign(&self, framed: &[u8]) -> Result<Vec<u8>, Error> {
        self.store
            .sign(&self.handle, framed)
            .map_err(|e| Error::Signer(e.to_string()))
    }
}
