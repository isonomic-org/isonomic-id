// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The key store on a Mac.
//!
//! P-256 keys are made inside the secure chip when the running program is
//! allowed to keep keys there; such keys can sign but can never be read out.
//! Otherwise, and for Ed25519 (which the chip does not offer), keys live in
//! the login keychain. [`MacKeyStore::p256_protection`] says which one this
//! store got.

use crate::{KeyError, KeyHandle, KeyStore, Protection};
use id_core::{KeyAlg, PublicKey};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use security_framework::item::{
    ItemClass, ItemSearchOptions, KeyClass, Limit, Location, Reference, SearchResult,
};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework::passwords;

/// Every key this crate stores carries this prefix, so it never touches
/// anything else in the keychain.
const PREFIX: &str = "isonomic-id:";
/// The keychain service under which Ed25519 keys are kept.
const SERVICE: &str = "isonomic-id";
/// The label of the key made once to learn whether the secure chip works.
const PROBE: &str = "isonomic-id:probe";

fn failed(what: &str, e: impl std::fmt::Display) -> KeyError {
    KeyError::Store(format!("{what}: {e}"))
}

/// Keys in the Mac's secure chip and keychain.
pub struct MacKeyStore {
    chip: bool,
    rng: SystemRandom,
}

impl MacKeyStore {
    /// Opens the store. It tries the secure chip once, and falls back to the
    /// login keychain for P-256 keys if the chip refuses.
    pub fn new() -> Self {
        let chip = p256_options(PROBE, true).and_then(|o| SecKey::new(&o).ok());
        if let Some(key) = &chip {
            let _ = key.delete();
        }
        MacKeyStore {
            chip: chip.is_some(),
            rng: SystemRandom::new(),
        }
    }

    /// Where this store makes P-256 keys.
    pub fn p256_protection(&self) -> Protection {
        if self.chip {
            Protection::Hardware
        } else {
            Protection::OsKeychain
        }
    }

    fn search(&self, class: KeyClass, label: Option<&str>) -> ItemSearchOptions {
        let mut options = ItemSearchOptions::new();
        options.class(ItemClass::key()).key_class(class);
        if let Some(label) = label {
            options.label(label);
        }
        if self.chip {
            options.ignore_legacy_keychains();
        }
        options
    }

    fn p256(&self, label: &str) -> Option<SecKey> {
        let mut options = self.search(KeyClass::private(), Some(label));
        options.load_refs(true).limit(1i64);
        let found = options.search().ok()?;
        found.into_iter().find_map(|item| match item {
            SearchResult::Ref(Reference::Key(key)) => Some(key),
            _ => None,
        })
    }

    fn ed25519(&self, label: &str) -> Option<Ed25519KeyPair> {
        let pkcs8 = passwords::get_generic_password(SERVICE, label).ok()?;
        Ed25519KeyPair::from_pkcs8(&pkcs8).ok()
    }

    fn exists(&self, label: &str) -> bool {
        self.p256(label).is_some() || self.ed25519(label).is_some()
    }
}

impl Default for MacKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Options for a P-256 key kept under `label`, in the chip or in software.
fn p256_options(label: &str, chip: bool) -> Option<GenerateKeyOptions> {
    let mut options = GenerateKeyOptions::default();
    options
        .set_key_type(KeyType::ec_sec_prime_random())
        .set_size_in_bits(256)
        .set_label(label);
    if chip {
        options
            .set_token(Token::SecureEnclave)
            .set_location(Location::DataProtectionKeychain);
    } else {
        options
            .set_token(Token::Software)
            .set_location(Location::DefaultFileKeychain);
    }
    Some(options)
}

fn full(label: &str) -> String {
    format!("{PREFIX}{label}")
}

impl KeyStore for MacKeyStore {
    fn generate(&self, alg: KeyAlg, label: &str) -> Result<KeyHandle, KeyError> {
        let name = full(label);
        if self.exists(&name) {
            return Err(KeyError::Exists);
        }
        match alg {
            KeyAlg::P256 => {
                let options = p256_options(&name, self.chip)
                    .ok_or_else(|| KeyError::Store("no key options".into()))?;
                SecKey::new(&options).map_err(|e| failed("key generation failed", e))?;
            }
            KeyAlg::Ed25519 => {
                let pkcs8 = Ed25519KeyPair::generate_pkcs8(&self.rng)
                    .map_err(|_| KeyError::Store("key generation failed".into()))?;
                passwords::set_generic_password(SERVICE, &name, pkcs8.as_ref())
                    .map_err(|e| failed("keychain refused the key", e))?;
            }
        }
        Ok(KeyHandle(label.to_string()))
    }

    fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, KeyError> {
        let name = full(&key.0);
        let (alg, bytes) = if let Some(private) = self.p256(&name) {
            let public = private
                .public_key()
                .and_then(|p| p.external_representation())
                .ok_or_else(|| KeyError::Store("no public key".into()))?;
            (KeyAlg::P256, public.bytes().to_vec())
        } else if let Some(pair) = self.ed25519(&name) {
            (KeyAlg::Ed25519, pair.public_key().as_ref().to_vec())
        } else {
            return Err(KeyError::NotFound);
        };
        PublicKey::new(alg, bytes).map_err(|e| KeyError::Store(e.to_string()))
    }

    fn sign(&self, key: &KeyHandle, framed: &[u8]) -> Result<Vec<u8>, KeyError> {
        let name = full(&key.0);
        if let Some(private) = self.p256(&name) {
            let der = private
                .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, framed)
                .map_err(|e| failed("signing failed", e))?;
            // The keychain returns DER; Isonomic signatures are r || s.
            let sig = p256::ecdsa::Signature::from_der(&der)
                .map_err(|e| failed("unexpected signature", e))?;
            return Ok(sig.to_bytes().to_vec());
        }
        let pair = self.ed25519(&name).ok_or(KeyError::NotFound)?;
        Ok(pair.sign(framed).as_ref().to_vec())
    }

    fn delete(&self, key: &KeyHandle) -> Result<(), KeyError> {
        let name = full(&key.0);
        if self.p256(&name).is_some() {
            for class in [KeyClass::private(), KeyClass::public()] {
                let _ = self.search(class, Some(&name)).delete();
            }
            return match self.p256(&name) {
                None => Ok(()),
                Some(_) => Err(KeyError::Store("keychain kept the key".into())),
            };
        }
        if self.ed25519(&name).is_some() {
            return passwords::delete_generic_password(SERVICE, &name)
                .map_err(|e| failed("keychain refused to delete", e));
        }
        Err(KeyError::NotFound)
    }

    fn handles(&self) -> Vec<KeyHandle> {
        let mut labels = Vec::new();
        let mut keys = self.search(KeyClass::private(), None);
        keys.load_attributes(true).limit(Limit::All);
        let mut passwords = ItemSearchOptions::new();
        passwords
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .load_attributes(true)
            .limit(Limit::All);
        for (options, field) in [(keys, "labl"), (passwords, "acct")] {
            for item in options.search().unwrap_or_default() {
                let name = item.simplify_dict().and_then(|d| d.get(field).cloned());
                if let Some(label) = name.as_deref().and_then(|n| n.strip_prefix(PREFIX)) {
                    if label != "probe" {
                        labels.push(KeyHandle(label.to_string()));
                    }
                }
            }
        }
        labels.sort();
        labels.dedup();
        labels
    }

    fn protection(&self) -> Protection {
        // Ed25519 keys are always in the keychain, so that is the floor.
        Protection::OsKeychain
    }
}
