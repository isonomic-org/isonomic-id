// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: Apache-2.0

//! Known answers for the arithmetic, and the binding inside a key log.

use id_core::log::{Commitment, Directory, Kind, Log, LogError, Op};
use id_core::{hex, KeyAlg, Signer};
use id_eth::{
    account_salt, binding_message, bound_address, create2, keccak256, recover, EthBinding, EthKey,
};
use id_keys::{KeyStore, MemoryKeyStore, StoredKey};
use std::sync::Arc;

#[test]
fn arithmetic_matches_published_answers() {
    // Keccak-256 of nothing.
    assert_eq!(
        hex(&keccak256(&[])),
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
    // The address of the secret key 1.
    let mut one = [0u8; 32];
    one[31] = 1;
    let key = EthKey::from_bytes(&one).expect("valid key");
    assert_eq!(
        hex(&key.address()),
        "7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    );
    assert!(EthKey::from_bytes(&[0u8; 32]).is_none());
    // The first example of the standard that defines salted deployment:
    // deployer zero, salt zero, init code 0x00.
    let address = create2(&[0u8; 20], &[0u8; 32], &keccak256(&[&[0u8]]));
    assert_eq!(hex(&address), "4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38");
}

#[test]
fn keys_derive_from_a_seed_and_signatures_recover_their_address() {
    let a = EthKey::from_seed(&[7; 32]);
    assert_eq!(a.address(), EthKey::from_seed(&[7; 32]).address());
    assert_ne!(a.address(), EthKey::from_seed(&[8; 32]).address());
    assert_ne!(a.address(), EthKey::generate().address());

    let sig = a.sign_message(b"hello");
    assert_eq!(sig.len(), 65);
    assert!(sig[64] == 27 || sig[64] == 28);
    assert_eq!(recover(b"hello", &sig), Some(a.address()));
    assert_ne!(recover(b"hullo", &sig), Some(a.address()));
    // Wallets that end the signature in 0 or 1 are accepted too.
    let mut low = sig.clone();
    low[64] -= 27;
    assert_eq!(recover(b"hello", &low), Some(a.address()));
    assert_eq!(recover(b"hello", &sig[..64]), None);
}

#[test]
fn an_identity_binds_its_ethereum_key_from_both_sides() {
    let store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let make = |label| StoredKey::generate(store.clone(), KeyAlg::P256, label).expect("key");
    let dev = |key: &StoredKey| Commitment::device(&key.public_key());
    let (d1, r1, r2, r3, r4) = (make("d1"), make("r1"), make("r2"), make("r3"), make("r4"));
    let ops = vec![Op::add(d1.public_key())];
    let mut log = Log::create(Kind::Person, None, ops, vec![dev(&r1)], 100, &d1).expect("create");
    let id = log.id().clone();
    let eth = EthKey::from_seed(&[1; 32]);
    let checks: [&dyn id_core::log::BindingCheck; 1] = [&EthBinding];

    // The message a wallet would show names the identity in plain text.
    let message = String::from_utf8(binding_message(&id)).expect("text");
    assert_eq!(message, format!("Isonomic ID binding v1\n{id}"));

    // A proof made for another identity is refused.
    let other = Log::create(
        Kind::Person,
        None,
        vec![Op::add(d1.public_key())],
        vec![],
        100,
        &d1,
    )
    .expect("other");
    let stolen = Op::Bind(eth.bind(other.id()));
    let tried = log.append(vec![stolen], vec![dev(&r2)], 110, &r1, &checks);
    assert_eq!(tried.err(), Some(LogError::Binding(1)));
    // So is a binding nobody is there to check.
    let bind = Op::Bind(eth.bind(&id));
    let tried = log.append(vec![bind.clone()], vec![dev(&r2)], 110, &r1, &[]);
    assert_eq!(tried.err(), Some(LogError::Binding(1)));

    // The real one is accepted, and a second verifier sees it from the log.
    let state = log.append(vec![bind], vec![dev(&r2)], 110, &r1, &checks);
    assert_eq!(bound_address(state.expect("bound")), Some(eth.address()));
    let mut directory = Directory::default();
    let seen = directory.accept(log.entries(), &checks).expect("verifies");
    assert_eq!(bound_address(seen), Some(eth.address()));
    assert_eq!(
        directory.accept(log.entries(), &[]).err(),
        Some(LogError::Binding(1))
    );

    // The Ethereum key can be replaced or dropped; the ID stays.
    let eth2 = EthKey::generate();
    let rebind = vec![Op::Bind(eth2.bind(&id))];
    let state = log.append(rebind, vec![dev(&r3)], 120, &r2, &checks);
    assert_eq!(bound_address(state.expect("rebound")), Some(eth2.address()));
    let unbind = vec![Op::Unbind("eth".into())];
    let state = log
        .append(unbind, vec![dev(&r4)], 130, &r3, &checks)
        .expect("unbound");
    assert_eq!(bound_address(state), None);
    assert_eq!(state.id, id);

    // The account salt follows from the ID alone.
    assert_eq!(account_salt(&id), account_salt(log.id()));
    assert_ne!(account_salt(&id), account_salt(other.id()));
}
