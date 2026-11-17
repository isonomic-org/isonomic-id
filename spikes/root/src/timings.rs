// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: Apache-2.0

//! How long each step takes on this machine.

use crate::eth::{self, EthKey};
use crate::keylog::{self, append, replay, Op};
use id_check::{check, ChainCache, Context, Request};
use id_core::{frame, KeyAlg, PrincipalId, Signed, Signer};
use id_grants::{Action, Grant};
use id_keys::{KeyStore, MemoryKeyStore, StoredKey};
use id_resource::Selector;
use id_testkit::TestWorld;
use std::sync::Arc;
use std::time::Instant;

fn time(label: &str, rounds: u32, mut step: impl FnMut()) {
    step();
    let start = Instant::now();
    for _ in 0..rounds {
        step();
    }
    let micros = start.elapsed().as_secs_f64() * 1e6 / f64::from(rounds);
    println!("   {micros:>9.1} µs  {label}");
}

pub fn print() {
    println!("Timings (software keys; a secure chip adds its own signing time)");
    let store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let mut n = 0u32;
    let mut make = |alg| {
        n += 1;
        StoredKey::generate(store.clone(), alg, &format!("k{n}")).expect("key")
    };

    // Creating an identity: three keys and one signed entry.
    let mut created = Vec::new();
    time(
        "create an identity (3 P-256 keys, first log entry)",
        200,
        || {
            let (device, rotation, kit) =
                (make(KeyAlg::P256), make(KeyAlg::P256), make(KeyAlg::P256));
            let mut log = Vec::new();
            let next = vec![
                rotation.public_key().fingerprint(),
                kit.public_key().fingerprint(),
            ];
            append(
                &mut log,
                vec![Op::AddDevice(device.public_key())],
                next,
                &device,
            )
            .expect("create");
            created = log;
        },
    );

    let device = make(KeyAlg::P256);
    let agent = make(KeyAlg::Ed25519);
    let message = frame("timing", &[7u8; 256]);
    time("sign, P-256 (device key)", 2000, || {
        device.sign(&message).expect("sign");
    });
    time("sign, Ed25519 (agent key)", 2000, || {
        agent.sign(&message).expect("sign");
    });
    let sealed = Signed::seal("timing", vec![7u8; 256], &device).expect("seal");
    time("verify, P-256", 2000, || {
        sealed.verify("timing").expect("verify")
    });
    let sealed = Signed::seal("timing", vec![7u8; 256], &agent).expect("seal");
    time("verify, Ed25519", 2000, || {
        sealed.verify("timing").expect("verify")
    });

    // A log with ten entries, replayed from the bytes.
    let mut log = Vec::new();
    let mut signer = make(KeyAlg::P256);
    for _ in 0..10 {
        let next_key = make(KeyAlg::P256);
        let ops = vec![Op::AddDevice(next_key.public_key())];
        append(
            &mut log,
            ops,
            vec![next_key.public_key().fingerprint()],
            &signer,
        )
        .expect("append");
        signer = next_key;
    }
    time("verify a 10-entry key log from scratch", 200, || {
        replay(&log).expect("replay");
    });

    // The Ethereum binding.
    let id = replay(&created).expect("replay").id;
    let eth_key = EthKey::generate();
    let account = keylog::bound_account(&id, &eth_key.address());
    let msg = keylog::binding_message(&id, &account);
    time("sign the Ethereum binding", 500, || {
        eth_key.sign_message(&msg);
    });
    let proof = eth_key.sign_message(&msg);
    time("verify the Ethereum binding", 500, || {
        assert_eq!(eth::recover(&msg, &proof), Some(eth_key.address()));
    });

    // A three-link grant chain: user (P-256) → agent → subagent → worker.
    let mut world = TestWorld::new();
    let user_id = PrincipalId::new("iso:timing:user").expect("id");
    world.register(&user_id, device.public_key());
    let (a, b, c) = (
        world.principal("a"),
        world.principal("b"),
        world.principal("c"),
    );
    let owner = id_testkit::TestPrincipal {
        id: user_id,
        key: device,
    };
    let doc = world.resource(&owner, None, &[]);
    let read = Action::new("read").expect("action");
    let g1 = Grant::from_owner(
        owner.id.clone(),
        a.id.clone(),
        Selector::Any,
        [read.clone()],
    )
    .delegable(2)
    .sign(&owner.key)
    .expect("sign");
    let g2 = Grant::passing_on(&g1, b.id.clone())
        .sign(&a.key)
        .expect("sign");
    let g3 = Grant::passing_on(&g2, c.id.clone())
        .sign(&b.key)
        .expect("sign");
    let chain = [g1, g2, g3];
    let size: usize = chain
        .iter()
        .map(|g| g.to_bytes().expect("encode").len())
        .sum();
    let request = Request {
        principal: &c.id,
        action: &read,
        resource: &doc.id,
        proof: &chain,
        context: Context::at(1_800_000_000),
    };
    time(
        "check a three-link grant chain (target: under 1000 µs)",
        2000,
        || {
            assert!(check(&request, &world).is_allowed());
        },
    );
    let cache = ChainCache::new();
    time(
        "check the same chain again, from the cache (target: under 100 µs)",
        20000,
        || {
            assert!(cache.check(&request, &world).is_allowed());
        },
    );
    println!("   {size:>9} bytes, the three grants together");
}
