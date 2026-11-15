//! Chains of grants: what verifies and what is refused.

use id_core::{KeyAlg, KeyResolver, PrincipalId, PublicKey, Signer, Timestamp};
use id_grants::{
    verify_chain, Action, Grant, GrantError, GrantId, Revocations, SignedGrant, Widening,
};
use id_keys::{KeyStore, MemoryKeyStore, StoredKey};
use id_resource::{ResourceId, Selector};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const NOW: Timestamp = 1_800_000_000;

struct Who {
    id: PrincipalId,
    key: StoredKey,
}

#[derive(Default)]
struct World {
    keys: BTreeMap<PrincipalId, PublicKey>,
    revoked: BTreeSet<GrantId>,
}

impl KeyResolver for World {
    fn is_current_key(&self, who: &PrincipalId, key: &PublicKey, _at: Timestamp) -> bool {
        self.keys.get(who) == Some(key)
    }
}

impl Revocations for World {
    fn is_revoked(&self, id: &GrantId) -> bool {
        self.revoked.contains(id)
    }
}

fn setup() -> (World, Who, Who, Who) {
    let store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let mut world = World::default();
    let mut make = |name: &str, alg| {
        let id = PrincipalId::new(format!("iso:{name}")).expect("id");
        let key = StoredKey::generate(store.clone(), alg, name).expect("key");
        world.keys.insert(id.clone(), key.public_key());
        Who { id, key }
    };
    let user = make("user", KeyAlg::P256);
    let agent = make("agent", KeyAlg::Ed25519);
    let sub = make("subagent", KeyAlg::Ed25519);
    (world, user, agent, sub)
}

fn act(names: &[&str]) -> Vec<Action> {
    names
        .iter()
        .map(|n| Action::new(*n).expect("action"))
        .collect()
}

fn folder() -> ResourceId {
    ResourceId::from_parts(1, [1; 10])
}

/// user → agent: read and write under a folder, for an hour, 1000 tokens,
/// and the agent may pass it on twice.
fn user_grant(user: &Who, agent: &Who) -> SignedGrant {
    Grant::from_owner(
        user.id.clone(),
        agent.id.clone(),
        Selector::Tree(folder()),
        act(&["read", "write"]),
    )
    .until(NOW + 3600)
    .with_budget("tokens", 1000)
    .delegable(2)
    .sign(&user.key)
    .expect("sign")
}

#[test]
fn user_to_agent_to_subagent_verifies_and_only_narrows() {
    let (world, user, agent, sub) = setup();
    let g1 = user_grant(&user, &agent);
    let g2 = Grant::passing_on(&g1, sub.id.clone())
        .allowing(act(&["read"]))
        .until(NOW + 600)
        .with_budget("tokens", 200)
        .sign(&agent.key)
        .expect("sign");

    let authority = verify_chain(&[g1.clone(), g2.clone()], &world, &world, NOW).expect("chain");
    assert_eq!(authority.owner, user.id);
    assert_eq!(authority.holder, sub.id);
    assert_eq!(authority.actions, act(&["read"]).into_iter().collect());
    assert_eq!(authority.expires, Some(NOW + 600));
    assert_eq!(authority.budgets.len(), 2);
    assert_eq!(authority.selectors.len(), 2);
    assert_eq!(authority.leaf, g2.id());

    // Stored and read back, the chain is the same chain.
    let back = SignedGrant::from_bytes(&g2.to_bytes().expect("encode")).expect("decode");
    assert_eq!(back, g2);
    assert_eq!(back.id(), g2.id());
}

#[test]
fn every_kind_of_widening_is_refused() {
    let (world, user, agent, sub) = setup();
    let g1 = user_grant(&user, &agent);
    let base = || Grant::passing_on(&g1, sub.id.clone());
    let other = ResourceId::from_parts(2, [2; 10]);
    let cases: Vec<(Grant, Widening)> = vec![
        (base().allowing(act(&["read", "delete"])), Widening::Actions),
        (base().on(Selector::Any), Widening::Resource),
        (base().until(NOW + 7200), Widening::Expiry),
        (base().with_budget("tokens", 5000), Widening::Budget),
        (base().with_budget("cents", 10), Widening::Budget),
        (base().delegable(2), Widening::Delegations),
    ];
    for (grant, what) in cases {
        let g2 = grant.sign(&agent.key).expect("sign");
        assert_eq!(
            verify_chain(&[g1.clone(), g2], &world, &world, NOW),
            Err(GrantError::Widens { link: 1, what }),
        );
    }
    let mut no_expiry = base();
    no_expiry.expires = None;
    let mut no_budget = base();
    no_budget.budget = None;
    for (grant, what) in [(no_expiry, Widening::Expiry), (no_budget, Widening::Budget)] {
        let g2 = grant.sign(&agent.key).expect("sign");
        assert_eq!(
            verify_chain(&[g1.clone(), g2], &world, &world, NOW),
            Err(GrantError::Widens { link: 1, what }),
        );
    }
    // A subtree that may or may not lie inside the folder passes here; the
    // chain still covers only what both links cover.
    let g2 = base()
        .on(Selector::Tree(other))
        .sign(&agent.key)
        .expect("sign");
    assert!(verify_chain(&[g1.clone(), g2], &world, &world, NOW).is_ok());

    // "Ask first" cannot be dropped.
    let asking = Grant::from_owner(
        user.id.clone(),
        agent.id.clone(),
        Selector::Any,
        act(&["read"]),
    )
    .asking_first()
    .delegable(1)
    .sign(&user.key)
    .expect("sign");
    let mut silent = Grant::passing_on(&asking, sub.id.clone());
    silent.ask_first = false;
    let silent = silent.sign(&agent.key).expect("sign");
    assert_eq!(
        verify_chain(&[asking, silent], &world, &world, NOW),
        Err(GrantError::Widens {
            link: 1,
            what: Widening::AskFirst
        }),
    );
}

#[test]
fn expired_revoked_and_not_yet_valid_grants_are_refused() {
    let (mut world, user, agent, sub) = setup();
    let g1 = user_grant(&user, &agent);
    let g2 = Grant::passing_on(&g1, sub.id.clone())
        .sign(&agent.key)
        .expect("sign");
    let chain = [g1.clone(), g2.clone()];

    assert_eq!(
        verify_chain(&chain, &world, &world, NOW + 3600),
        Err(GrantError::Expired { link: 0 })
    );
    let mut later = Grant::from_owner(
        user.id.clone(),
        agent.id.clone(),
        Selector::Any,
        act(&["read"]),
    );
    later.not_before = Some(NOW + 10);
    let later = later.sign(&user.key).expect("sign");
    assert_eq!(
        verify_chain(&[later], &world, &world, NOW),
        Err(GrantError::NotYetValid { link: 0 })
    );

    // Revoking the user's grant kills everything below it.
    world.revoked.insert(g1.id());
    assert_eq!(
        verify_chain(&chain, &world, &world, NOW),
        Err(GrantError::Revoked { link: 0 })
    );
    world.revoked.clear();
    world.revoked.insert(g2.id());
    assert_eq!(
        verify_chain(&chain, &world, &world, NOW),
        Err(GrantError::Revoked { link: 1 })
    );
    assert!(verify_chain(&chain[..1], &world, &world, NOW).is_ok());
}

#[test]
fn forged_and_misattached_links_are_refused() {
    let (mut world, user, agent, sub) = setup();
    let g1 = user_grant(&user, &agent);
    assert_eq!(
        verify_chain(&[], &world, &world, NOW),
        Err(GrantError::Empty)
    );

    // The subagent signs a link in the agent's name.
    let forged = Grant::passing_on(&g1, sub.id.clone())
        .sign(&sub.key)
        .expect("sign");
    assert_eq!(
        verify_chain(&[g1.clone(), forged], &world, &world, NOW),
        Err(GrantError::UnknownKey { link: 1 })
    );

    // A link issued by someone who was never given the grant.
    let mut stranger = Grant::passing_on(&g1, sub.id.clone());
    stranger.issuer = sub.id.clone();
    let stranger = stranger.sign(&sub.key).expect("sign");
    assert_eq!(
        verify_chain(&[g1.clone(), stranger], &world, &world, NOW),
        Err(GrantError::WrongIssuer { link: 1 })
    );

    // A link that hangs off a different grant.
    let g1b = user_grant(&user, &agent);
    let g2 = Grant::passing_on(&g1b, sub.id.clone())
        .sign(&agent.key)
        .expect("sign");
    assert_eq!(
        verify_chain(&[g1.clone(), g2.clone()], &world, &world, NOW),
        Err(GrantError::BrokenLink { link: 1 })
    );
    assert_eq!(
        verify_chain(&[g2], &world, &world, NOW),
        Err(GrantError::RootHasParent)
    );

    // A grant that may not be passed on.
    let fixed = Grant::from_owner(
        user.id.clone(),
        agent.id.clone(),
        Selector::Any,
        act(&["read"]),
    )
    .sign(&user.key)
    .expect("sign");
    let onward = Grant::passing_on(&fixed, sub.id.clone())
        .sign(&agent.key)
        .expect("sign");
    assert_eq!(
        verify_chain(&[fixed, onward], &world, &world, NOW),
        Err(GrantError::NoDelegation { link: 1 })
    );

    // Once the user's key is replaced, grants signed with the old key stop.
    world.keys.insert(user.id.clone(), agent.key.public_key());
    assert_eq!(
        verify_chain(std::slice::from_ref(&g1), &world, &world, NOW),
        Err(GrantError::UnknownKey { link: 0 })
    );

    // A tampered payload no longer matches its signature.
    let mut bytes = g1.to_bytes().expect("encode");
    let at = bytes.windows(4).position(|w| w == b"read").expect("action");
    bytes[at..at + 4].copy_from_slice(b"reap");
    let tampered = SignedGrant::from_bytes(&bytes).expect("decode");
    assert_eq!(
        verify_chain(&[tampered], &world, &world, NOW),
        Err(GrantError::BadSignature { link: 0 })
    );
}
