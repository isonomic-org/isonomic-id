// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

//! IDs, graph walks and selectors.

use id_core::PrincipalId;
use id_resource::{
    ancestors, sources, ResourceError, ResourceId, ResourceLookup, ResourceMeta, Selector,
};
use std::collections::BTreeMap;

#[derive(Default)]
struct Store(BTreeMap<ResourceId, ResourceMeta>);

impl ResourceLookup for Store {
    fn resource(&self, id: &ResourceId) -> Option<ResourceMeta> {
        self.0.get(id).cloned()
    }
}

fn rid(n: u8) -> ResourceId {
    ResourceId::from_parts(1_000 + n as u64, [n; 10])
}

impl Store {
    fn add(&mut self, n: u8, parent: Option<u8>, derived: &[u8]) -> ResourceMeta {
        let meta = ResourceMeta {
            id: rid(n),
            kind: "doc".into(),
            owner: PrincipalId::new("iso:owner").expect("id"),
            parent: parent.map(rid),
            collection: rid(200),
            derived_from: derived.iter().map(|d| rid(*d)).collect(),
        };
        self.0.insert(meta.id, meta.clone());
        meta
    }
}

#[test]
fn ids_are_unique_sortable_and_carry_their_time() {
    let a = ResourceId::new(1_700_000_000_000);
    let b = ResourceId::new(1_700_000_000_001);
    assert_ne!(a, ResourceId::new(1_700_000_000_000));
    assert!(a < b);
    assert_eq!(a.created_ms(), 1_700_000_000_000);
    assert_eq!(a.to_string().len(), 4 + 32);
}

#[test]
fn ancestors_walk_up_and_refuse_loops_and_gaps() {
    let mut store = Store::default();
    store.add(1, None, &[]);
    store.add(2, Some(1), &[]);
    let leaf = store.add(3, Some(2), &[]);
    assert_eq!(ancestors(&store, &leaf), Ok(vec![rid(2), rid(1)]));

    let orphan = store.add(4, Some(99), &[]);
    assert_eq!(
        ancestors(&store, &orphan),
        Err(ResourceError::Missing(rid(99)))
    );

    store.add(5, Some(6), &[]);
    let looped = store.add(6, Some(5), &[]);
    assert_eq!(ancestors(&store, &looped), Err(ResourceError::TooDeep));
}

#[test]
fn sources_are_followed_through_derived_data_once_each() {
    let mut store = Store::default();
    store.add(1, None, &[]);
    store.add(2, None, &[]);
    store.add(3, None, &[1, 2]); // a summary of 1 and 2
    let index = store.add(4, None, &[3, 1]); // an index over the summary and 1
    let mut found: Vec<ResourceId> = sources(&store, &index)
        .expect("sources")
        .iter()
        .map(|m| m.id)
        .collect();
    found.sort();
    assert_eq!(found, vec![rid(1), rid(2), rid(3)]);

    let dangling = store.add(5, None, &[77]);
    assert_eq!(
        sources(&store, &dangling),
        Err(ResourceError::Missing(rid(77)))
    );
}

#[test]
fn selectors_match_and_narrow() {
    let mut store = Store::default();
    store.add(1, None, &[]);
    let child = store.add(2, Some(1), &[]);
    let up = ancestors(&store, &child).expect("ancestors");

    assert!(Selector::Any.matches(&child, &up));
    assert!(Selector::Collection(rid(200)).matches(&child, &up));
    assert!(!Selector::Collection(rid(201)).matches(&child, &up));
    assert!(Selector::Tree(rid(1)).matches(&child, &up));
    assert!(Selector::Tree(rid(2)).matches(&child, &up));
    assert!(!Selector::Tree(rid(3)).matches(&child, &up));
    assert!(Selector::One(rid(2)).matches(&child, &up));
    assert!(!Selector::One(rid(1)).matches(&child, &up));

    assert!(Selector::Any.may_narrow_to(&Selector::Tree(rid(1))));
    assert!(Selector::Tree(rid(1)).may_narrow_to(&Selector::One(rid(2))));
    assert!(!Selector::Tree(rid(1)).may_narrow_to(&Selector::Any));
    assert!(!Selector::One(rid(1)).may_narrow_to(&Selector::One(rid(2))));
    assert!(!Selector::One(rid(1)).may_narrow_to(&Selector::Tree(rid(1))));
    assert!(!Selector::Collection(rid(200)).may_narrow_to(&Selector::Collection(rid(201))));
}
