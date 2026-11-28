// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The check function over real key logs: a person, an agent and a subagent.

use id_check::{check, ChainCache, Context, Decision, Reason, Request, VersionedWorld, World};
use id_core::log::{Commitment, Directory, Kind, Log, Op};
use id_core::{KeyAlg, KeyResolver, PrincipalId, PublicKey, Signer, Timestamp};
use id_grants::{Action, Grant, GrantError, GrantId, Revocations, SignedGrant};
use id_keys::{KeyStore, MemoryKeyStore, StoredKey};
use id_resource::{ResourceId, ResourceLookup, ResourceMeta, Selector};
use std::sync::Arc;

const NOW: Timestamp = 1_800_000_000;

/// A Capsule that knows identities only through their logs.
struct Capsule {
    directory: Directory,
    doc: ResourceMeta,
}

impl KeyResolver for Capsule {
    fn is_current_key(&self, who: &PrincipalId, key: &PublicKey, at: Timestamp) -> bool {
        self.directory.is_current_key(who, key, at)
    }
}

impl Revocations for Capsule {
    fn is_revoked(&self, _id: &GrantId) -> bool {
        false
    }
}

impl ResourceLookup for Capsule {
    fn resource(&self, id: &ResourceId) -> Option<ResourceMeta> {
        (*id == self.doc.id).then(|| self.doc.clone())
    }
}

impl World for Capsule {}

impl VersionedWorld for Capsule {
    fn version(&self) -> u64 {
        self.directory.version()
    }
}

fn read() -> Action {
    Action::new("read").expect("action")
}

fn ask(capsule: &Capsule, who: &PrincipalId, proof: &[SignedGrant]) -> Decision {
    let request = Request {
        principal: who,
        action: &read(),
        resource: &capsule.doc.id,
        proof,
        context: Context::at(NOW),
    };
    check(&request, capsule)
}

#[test]
fn a_person_issues_an_agent_and_grants_follow_the_logs() {
    let store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let make = |label, alg| StoredKey::generate(store.clone(), alg, label).expect("key");
    let add = |key: &StoredKey| Op::add(key.public_key());

    // A person with one device and a recovery kit.
    let (d1, r1, k1) = (
        make("d1", KeyAlg::P256),
        make("r1", KeyAlg::P256),
        make("k1", KeyAlg::P256),
    );
    let next = vec![
        Commitment::device(&r1.public_key()),
        Commitment::recovery(&k1.public_key()),
    ];
    let mut person = Log::create(Kind::Person, None, vec![add(&d1)], next, 100, &d1).expect("id");
    let user = person.id().clone();

    // The person's engine issues an agent and a subagent: each its own log
    // naming its owner, each with its own key.
    let issue = |label, owner: &PrincipalId| {
        let key = make(label, KeyAlg::Ed25519);
        let log = Log::create(
            Kind::Agent,
            Some(owner.clone()),
            vec![add(&key)],
            vec![],
            100,
            &key,
        );
        (log.expect("agent"), key)
    };
    let (agent_log, agent_key) = issue("agent", &user);
    let (sub_log, _sub_key) = issue("subagent", agent_log.id());
    let (agent, sub) = (agent_log.id().clone(), sub_log.id().clone());

    let doc = ResourceMeta {
        id: ResourceId::from_parts(1, [1; 10]),
        kind: "doc".into(),
        owner: user.clone(),
        parent: None,
        collection: ResourceId::from_parts(0, [0; 10]),
        derived_from: vec![],
    };
    let mut capsule = Capsule {
        directory: Directory::default(),
        doc,
    };
    for log in [&person, &agent_log, &sub_log] {
        capsule.directory.accept(log.entries(), &[]).expect("log");
    }

    // user → agent → subagent, each link signed by a key from a log.
    let grant = |signer: &StoredKey| {
        Grant::from_owner(user.clone(), agent.clone(), Selector::Any, [read()])
            .delegable(1)
            .sign(signer)
            .expect("sign")
    };
    let g1 = grant(&d1);
    let g2 = Grant::passing_on(&g1, sub.clone())
        .sign(&agent_key)
        .expect("sign");
    let chain = [g1, g2.clone()];
    assert_eq!(ask(&capsule, &user, &[]), Decision::Allow(Reason::Owner));
    assert!(ask(&capsule, &sub, &chain).is_allowed());
    let cache = ChainCache::new();
    let warm = Request {
        principal: &sub,
        action: &read(),
        resource: &capsule.doc.id,
        proof: &chain,
        context: Context::at(NOW),
    };
    assert!(cache.check(&warm, &capsule).is_allowed());
    assert_eq!(ask(&capsule, &sub, &[]), Decision::Deny(Reason::NoProof));

    // The laptop is lost. The kit removes its key and admits a new device.
    let (d2, r2, k2) = (
        make("d2", KeyAlg::P256),
        make("r2", KeyAlg::P256),
        make("k2", KeyAlg::P256),
    );
    let next = vec![
        Commitment::device(&r2.public_key()),
        Commitment::recovery(&k2.public_key()),
    ];
    let ops = vec![Op::RemoveKey(d1.public_key()), add(&d2)];
    person.append(ops, next, 200, &k1, &[]).expect("recover");
    capsule
        .directory
        .accept(person.entries(), &[])
        .expect("update");

    // Everything the lost laptop signed stops working at once, and the same
    // identity issues it again from the new device.
    let lost = Reason::Proof(GrantError::UnknownKey { link: 0 });
    assert_eq!(ask(&capsule, &sub, &chain), Decision::Deny(lost.clone()));
    let warm = Request {
        principal: &sub,
        action: &read(),
        resource: &capsule.doc.id,
        proof: &chain,
        context: Context::at(NOW),
    };
    assert_eq!(cache.check(&warm, &capsule), Decision::Deny(lost));
    assert_eq!(person.id(), &user);
    let g1 = grant(&d2);
    let g2 = Grant::passing_on(&g1, sub.clone())
        .sign(&agent_key)
        .expect("sign");
    assert!(ask(&capsule, &sub, &[g1, g2]).is_allowed());
}
