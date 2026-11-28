// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Frozen version 1 formats.
//!
//! `vectors/v1/vectors.txt` holds real key logs and grants as bytes, with the
//! IDs and results they must produce. Every later version must decode and
//! verify these bytes to the same answers. Never edit the file by hand; to
//! write a new one (only for a new format version), run the tests with
//! `ISONOMIC_WRITE_VECTORS=1`.

use id_check::{check, Context, Decision, Reason, Request, World};
use id_core::log::{Commitment, Directory, Kind, Log, Op};
use id_core::{KeyAlg, KeyResolver, PrincipalId, PublicKey, Signed, Signer, Timestamp};
use id_eth::{bound_address, EthBinding, EthKey};
use id_grants::{verify_chain, Action, Grant, GrantId, Revocations, SignedGrant};
use id_keys::{KeyStore, MemoryKeyStore, StoredKey};
use id_resource::{ResourceId, ResourceLookup, ResourceMeta, Selector};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;

/// The time every check in the file is made at.
const NOW: Timestamp = 1_800_000_000;

fn path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/v1/vectors.txt")
}

fn action(name: &str) -> Action {
    Action::new(name).expect("action")
}

fn doc(owner: &PrincipalId) -> ResourceMeta {
    ResourceMeta {
        id: ResourceId::from_parts(1_700_000_000_000, [7; 10]),
        kind: "doc".into(),
        owner: owner.clone(),
        parent: None,
        collection: ResourceId::from_parts(1_700_000_000_000, [1; 10]),
        derived_from: vec![],
    }
}

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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Makes the logs and grants, and returns the file's lines.
fn write() -> String {
    let store = Arc::new(MemoryKeyStore::new());
    let seeded = |label: &str, n: u8| {
        let handle = store.insert_ed25519_seed(label, &[n; 32]).expect("seed");
        StoredKey::open(store.clone(), handle).expect("key")
    };
    let store_dyn: Arc<dyn KeyStore> = store.clone();
    let d1 = StoredKey::generate(store_dyn, KeyAlg::P256, "d1").expect("key");
    let (r1, r2, r3) = (seeded("r1", 1), seeded("r2", 2), seeded("r3", 3));
    let (k1, k2, d2) = (seeded("k1", 4), seeded("k2", 5), seeded("d2", 6));
    let checks: [&dyn id_core::log::BindingCheck; 1] = [&EthBinding];

    // A person: first device, then the Ethereum binding, then a recovery
    // that replaces the device and the recovery kit.
    let next = vec![
        Commitment::device(&r1.public_key()),
        Commitment::recovery(&k1.public_key()),
    ];
    let first = vec![Op::add(d1.public_key())];
    let mut person = Log::create(Kind::Person, None, first, next, 100, &d1).expect("create");
    let eth = EthKey::from_seed(&[9; 32]);
    let next = vec![
        Commitment::device(&r2.public_key()),
        Commitment::recovery(&k1.public_key()),
    ];
    let bind = vec![Op::Bind(eth.bind(person.id()))];
    person.append(bind, next, 200, &r1, &checks).expect("bind");
    let ops = vec![Op::RemoveKey(d1.public_key()), Op::add(d2.public_key())];
    let next = vec![
        Commitment::device(&r3.public_key()),
        Commitment::recovery(&k2.public_key()),
    ];
    person
        .append(ops, next, 300, &k1, &checks)
        .expect("recover");

    // An agent the person owns.
    let a1 = seeded("a1", 10);
    let first = vec![Op::add(a1.public_key())];
    let owner = Some(person.id().clone());
    let agent = Log::create(Kind::Agent, owner, first, vec![], 400, &a1).expect("agent");
    let s1 = seeded("s1", 11);
    let first = vec![Op::add(s1.public_key())];
    let owner = Some(agent.id().clone());
    let sub = Log::create(Kind::Agent, owner, first, vec![], 400, &s1).expect("subagent");

    let res = Selector::One(doc(person.id()).id);
    let g1 = Grant::from_owner(
        person.id().clone(),
        agent.id().clone(),
        res,
        [action("read"), action("write")],
    )
    .until(NOW + 86_400)
    .with_budget("tokens", 50_000)
    .delegable(1)
    .sign(&d2)
    .expect("grant");
    let g2 = Grant::passing_on(&g1, sub.id().clone())
        .allowing([action("read")])
        .sign(&a1)
        .expect("grant");

    let mut out = String::new();
    let mut line = |name: &str, value: String| {
        let _ = writeln!(out, "{name} {value}");
    };
    for (name, log) in [("person", &person), ("agent", &agent), ("subagent", &sub)] {
        for (n, entry) in log.entries().iter().enumerate() {
            line(
                &format!("{name}.{n}"),
                hex(&entry.to_bytes().expect("bytes")),
            );
        }
        line(&format!("{name}.id"), log.id().to_string());
    }
    line("person.eth", hex(eth.address().as_slice()));
    for (name, g) in [("grant.1", &g1), ("grant.2", &g2)] {
        line(name, hex(&g.to_bytes().expect("bytes")));
        line(&format!("{name}.id"), g.id().to_hex());
    }
    out
}

fn read(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn log(v: &BTreeMap<String, String>, name: &str) -> Vec<Signed> {
    (0..)
        .map_while(|n| v.get(&format!("{name}.{n}")))
        .map(|h| Signed::from_bytes(&unhex(h)).expect("entry decodes"))
        .collect()
}

#[test]
fn version_1_bytes_still_verify_to_the_same_answers() {
    if std::env::var_os("ISONOMIC_WRITE_VECTORS").is_some() {
        std::fs::write(path(), write()).expect("write vectors");
    }
    let text = std::fs::read_to_string(path()).expect("vectors/v1/vectors.txt");
    let v = read(&text);
    let checks: [&dyn id_core::log::BindingCheck; 1] = [&EthBinding];

    let mut directory = Directory::default();
    let mut ids = BTreeMap::new();
    for name in ["person", "agent", "subagent"] {
        let entries = log(&v, name);
        let opened = Log::open(entries.clone(), &checks).expect("log verifies");
        assert_eq!(opened.id().to_string(), v[&format!("{name}.id")], "{name}");
        directory.accept(&entries, &checks).expect("accepted");
        ids.insert(name, opened.id().clone());
        if name == "person" {
            assert_eq!(opened.state().seq, 2);
            let eth = bound_address(opened.state()).expect("bound");
            assert_eq!(hex(eth.as_slice()), v["person.eth"]);
        }
    }

    let chain: Vec<SignedGrant> = ["grant.1", "grant.2"]
        .iter()
        .map(|name| {
            let g = SignedGrant::from_bytes(&unhex(&v[*name])).expect("grant decodes");
            assert_eq!(g.id().to_hex(), v[&format!("{name}.id")], "{name}");
            g
        })
        .collect();
    let capsule = Capsule {
        directory,
        doc: doc(&ids["person"]),
    };
    let authority = verify_chain(&chain, &capsule, &capsule, NOW).expect("chain verifies");
    assert_eq!(authority.owner, ids["person"]);
    assert_eq!(authority.holder, ids["subagent"]);
    assert_eq!(authority.expires, Some(NOW + 86_400));
    // The passed-on link carries the budget forward; both apply.
    assert_eq!(authority.budgets.len(), 2);

    let ask = |name: &str| {
        let action = action(name);
        let request = Request {
            principal: &ids["subagent"],
            action: &action,
            resource: &capsule.doc.id,
            proof: &chain,
            context: Context::at(NOW),
        };
        check(&request, &capsule)
    };
    let leaf = chain[1].id();
    assert_eq!(ask("read"), Decision::Allow(Reason::Granted { leaf }));
    assert_eq!(ask("write"), Decision::Deny(Reason::ActionNotGranted));
}
