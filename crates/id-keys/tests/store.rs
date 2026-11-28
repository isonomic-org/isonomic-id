// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

//! What every key store must do, run against the in-memory store.

use id_core::{frame, KeyAlg, Signed, Signer};
use id_keys::{KeyError, KeyHandle, KeyStore, MemoryKeyStore, Protection, StoredKey};
use std::sync::Arc;

fn store() -> Arc<dyn KeyStore> {
    Arc::new(MemoryKeyStore::new())
}

#[test]
fn both_schemes_sign_and_verify() {
    let store = store();
    for (alg, label) in [(KeyAlg::Ed25519, "ed"), (KeyAlg::P256, "p256")] {
        let key = StoredKey::generate(store.clone(), alg, label).expect("generate");
        let sealed = Signed::seal("test", b"payload".to_vec(), &key).expect("seal");
        sealed.verify("test").expect("verifies");
        assert_eq!(sealed.signer().alg, alg);
    }
    assert_eq!(store.handles().len(), 2);
    assert_eq!(store.protection(), Protection::Memory);
}

#[test]
fn labels_are_unique_and_missing_keys_are_reported() {
    let store = store();
    store.generate(KeyAlg::Ed25519, "a").expect("generate");
    assert_eq!(store.generate(KeyAlg::P256, "a"), Err(KeyError::Exists));
    let ghost = KeyHandle("ghost".into());
    assert_eq!(store.public_key(&ghost), Err(KeyError::NotFound));
    assert_eq!(store.sign(&ghost, b"x"), Err(KeyError::NotFound));
    assert_eq!(store.delete(&ghost), Err(KeyError::NotFound));
}

#[test]
fn a_deleted_key_can_never_sign_again() {
    let store = store();
    let key = StoredKey::generate(store.clone(), KeyAlg::P256, "device").expect("generate");
    let handle = key.handle().clone();
    let signer = key.clone();
    key.destroy().expect("destroy");
    assert!(signer.sign(&frame("test", b"x")).is_err());
    assert_eq!(store.sign(&handle, b"x"), Err(KeyError::NotFound));
    assert!(store.handles().is_empty());
}

#[test]
fn seeded_keys_are_the_same_on_every_run() {
    let a = MemoryKeyStore::new();
    let b = MemoryKeyStore::new();
    let ha = a.insert_ed25519_seed("k", &[9; 32]).expect("insert");
    let hb = b.insert_ed25519_seed("k", &[9; 32]).expect("insert");
    assert_eq!(a.public_key(&ha), b.public_key(&hb));
    assert_eq!(a.sign(&ha, b"m"), b.sign(&hb, b"m"));
}
