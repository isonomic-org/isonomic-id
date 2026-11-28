// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Mutated grants, each signed again by its issuer's test key, so the
//! fuzzer reaches the chain rules behind the signature check. For every
//! chain: verifying never panics, and the cached check always gives the same
//! answer as the plain one.
#![no_main]

use id_check::{check, ChainCache, Context, Request};
use id_core::from_cbor;
use id_grants::{Action, Grant, SignedGrant};
use id_resource::ResourceMeta;
use id_testkit::{TestPrincipal, TestWorld};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

struct Scene {
    world: TestWorld,
    people: Vec<TestPrincipal>,
    docs: Vec<ResourceMeta>,
}

fn scene() -> &'static Scene {
    static SCENE: OnceLock<Scene> = OnceLock::new();
    SCENE.get_or_init(|| {
        let mut world = TestWorld::new();
        let people: Vec<TestPrincipal> = ["user", "agent", "sub", "team"]
            .iter()
            .map(|n| world.principal(n))
            .collect();
        let doc = world.resource(&people[0], None, &[]);
        let child = world.resource(&people[0], Some(doc.id), &[]);
        let derived = world.resource(&people[0], None, &[doc.id]);
        world.add_member(&people[2].id, &people[3].id);
        Scene {
            world,
            people,
            docs: vec![doc, child, derived],
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let s = scene();
    let chain: Vec<SignedGrant> = parts(data, 9)
        .into_iter()
        .filter_map(|part| from_cbor::<Grant>(part).ok())
        .filter_map(|grant| {
            let signer = s.people.iter().find(|p| p.id == grant.issuer)?;
            grant.sign(&signer.key).ok()
        })
        .collect();
    let Some(last) = chain.last() else { return };
    let caller = last.grant().recipient.clone();
    let cache = ChainCache::new();
    for name in ["read", "write"] {
        let Ok(action) = Action::new(name) else {
            return;
        };
        for doc in &s.docs {
            for now in [1_800_000_000, 1_900_000_000] {
                let request = Request {
                    principal: &caller,
                    action: &action,
                    resource: &doc.id,
                    proof: &chain,
                    context: Context::at(now),
                };
                let plain = check(&request, &s.world);
                assert_eq!(cache.check(&request, &s.world), plain);
                assert_eq!(cache.check(&request, &s.world), plain);
            }
        }
    }
});

/// Splits input into parts, each preceded by a two-byte big-endian length.
fn parts(mut data: &[u8], max: usize) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while out.len() < max && data.len() >= 2 {
        let n = usize::from(u16::from_be_bytes([data[0], data[1]]));
        let end = (2 + n).min(data.len());
        out.push(&data[2..end]);
        data = &data[end..];
    }
    out
}
