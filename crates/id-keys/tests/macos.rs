// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: Apache-2.0

//! The Mac key store against the real keychain. Runs only on a Mac, and only
//! when asked, because it writes to the login keychain and may prompt:
//!
//! ```sh
//! cargo test -p id-keys --test macos -- --ignored --nocapture
//! ```
#![cfg(target_os = "macos")]

use id_core::{frame, KeyAlg};
use id_keys::{KeyError, KeyHandle, KeyStore, MacKeyStore};
use std::time::{SystemTime, UNIX_EPOCH};

fn label(alg: &str) -> String {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos());
    format!("test-{alg}-{}", t.unwrap_or(0))
}

#[test]
#[ignore = "writes to the login keychain; run by hand on a Mac"]
fn keys_live_in_the_keychain_sign_and_are_destroyed() {
    let store = MacKeyStore::new();
    println!("P-256 keys are held by: {:?}", store.p256_protection());

    for (alg, name) in [(KeyAlg::P256, "p256"), (KeyAlg::Ed25519, "ed25519")] {
        let label = label(name);
        let handle = store.generate(alg, &label).expect("generate");
        assert_eq!(store.generate(alg, &label), Err(KeyError::Exists));
        let public = store.public_key(&handle).expect("public key");
        assert_eq!(public.alg, alg);

        // A fresh store finds the same key, and its signatures verify.
        let again = MacKeyStore::new();
        assert!(again.handles().contains(&handle), "{name} not listed");
        let sig = again.sign(&handle, &frame("test", b"hello")).expect("sign");
        public.verify("test", b"hello", &sig).expect("verifies");

        store.delete(&handle).expect("delete");
        assert_eq!(store.public_key(&handle), Err(KeyError::NotFound));
        assert_eq!(store.sign(&KeyHandle(label), b"x"), Err(KeyError::NotFound));
    }
}
