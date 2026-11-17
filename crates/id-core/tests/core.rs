// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: Apache-2.0

//! Envelope, codec and ID behaviour, plus the dependency allow-list.

use id_core::{frame, from_cbor, Digest, Error, KeyAlg, PrincipalId, PublicKey, Signed, Signer};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use std::collections::BTreeSet;
use std::path::Path;

struct Ed(Ed25519KeyPair);

impl Ed {
    fn from_seed(seed: u8) -> Self {
        Ed(Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).expect("seed"))
    }
}

impl Signer for Ed {
    fn public_key(&self) -> PublicKey {
        PublicKey::new(KeyAlg::Ed25519, self.0.public_key().as_ref().to_vec()).expect("key")
    }
    fn sign(&self, framed: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.sign(framed).as_ref().to_vec())
    }
}

#[test]
fn envelope_round_trips_and_verifies() {
    let signer = Ed::from_seed(1);
    let sealed = Signed::seal("test", b"hello".to_vec(), &signer).expect("seal");
    sealed.verify("test").expect("verifies");
    let bytes = sealed.to_bytes().expect("encode");
    let back = Signed::from_bytes(&bytes).expect("decode");
    assert_eq!(back, sealed);
    assert_eq!(back.id("test"), Digest::of("test", b"hello"));
}

#[test]
fn a_signature_is_bound_to_its_domain_payload_and_key() {
    let signer = Ed::from_seed(1);
    let sealed = Signed::seal("grant", b"hello".to_vec(), &signer).expect("seal");
    assert_eq!(sealed.verify("log"), Err(Error::BadSignature));

    let other = Signed::seal("grant", b"hullo".to_vec(), &signer).expect("seal");
    let mut bytes = sealed.to_bytes().expect("encode");
    let other_bytes = other.to_bytes().expect("encode");
    // Swap in the other payload: same length, different content.
    let at = bytes
        .windows(5)
        .position(|w| w == b"hello")
        .expect("payload");
    bytes[at..at + 5].copy_from_slice(b"hullo");
    let forged = Signed::from_bytes(&bytes).expect("decode");
    assert_eq!(forged.verify("grant"), Err(Error::BadSignature));
    assert_ne!(bytes, other_bytes);
}

#[test]
fn p256_signatures_verify() {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).expect("gen");
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
        .expect("pair");
    let key = PublicKey::new(KeyAlg::P256, pair.public_key().as_ref().to_vec()).expect("key");
    let sig = pair.sign(&rng, &frame("test", b"msg")).expect("sign");
    key.verify("test", b"msg", sig.as_ref()).expect("verifies");
    assert_eq!(
        key.verify("test", b"other", sig.as_ref()),
        Err(Error::BadSignature)
    );
}

#[test]
fn decoding_refuses_trailing_bytes_oversize_and_bad_keys() {
    let sealed = Signed::seal("test", vec![7; 8], &Ed::from_seed(2)).expect("seal");
    let mut bytes = sealed.to_bytes().expect("encode");
    bytes.push(0);
    assert!(Signed::from_bytes(&bytes).is_err());
    assert_eq!(from_cbor::<u8>(&vec![0u8; 70_000]), Err(Error::TooLarge));
    assert_eq!(
        PublicKey::new(KeyAlg::Ed25519, vec![0; 31]),
        Err(Error::BadKey)
    );
    assert!(from_cbor::<Signed>(&[0xff, 0x00, 0x13]).is_err());
}

#[test]
fn digests_differ_by_domain_and_fingerprints_by_scheme() {
    assert_ne!(Digest::of("a", b"x"), Digest::of("b", b"x"));
    assert_eq!(Digest::of("a", b"x").to_hex().len(), 64);
    let key = Ed::from_seed(3).public_key();
    assert_ne!(key.fingerprint(), Digest::of("key", &key.bytes));
}

#[test]
fn principal_ids_are_checked() {
    assert!(PrincipalId::new("iso:person:abc-123").is_ok());
    for bad in ["", "Has Upper", "space here", &"x".repeat(129)] {
        assert!(PrincipalId::new(bad).is_err(), "{bad:?} should be refused");
    }
    assert!(from_cbor::<PrincipalId>(&id_core::to_cbor(&"NOT OK").expect("encode")).is_err());
}

/// The library must stay pure: no network and no chain client can enter the
/// dependency tree without a reviewed change to `docs/deps-allow.txt`.
#[test]
fn every_dependency_is_on_the_allow_list() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let allow = std::fs::read_to_string(root.join("docs/deps-allow.txt")).expect("allow-list");
    let allow: BTreeSet<&str> = allow
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let lock = std::fs::read_to_string(root.join("Cargo.lock")).expect("Cargo.lock");
    let extra: Vec<&str> = lock
        .lines()
        .filter_map(|l| l.strip_prefix("name = \"")?.strip_suffix('"'))
        .filter(|name| !allow.contains(name))
        .collect();
    assert!(extra.is_empty(), "not on docs/deps-allow.txt: {extra:?}");
}
