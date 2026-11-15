//! A cached chain must never allow what a fresh check would deny.

use id_check::{check, ChainCache, Context, Cost, Decision, Reason, Request};
use id_grants::{Action, Grant, GrantError, SignedGrant};
use id_resource::{ResourceId, Selector};
use id_testkit::{TestPrincipal, TestWorld};

const NOW: u64 = 1_800_000_000;

struct Scene {
    world: TestWorld,
    agent: TestPrincipal,
    sub: TestPrincipal,
    doc: ResourceId,
    chain: [SignedGrant; 2],
}

fn read() -> Action {
    Action::new("read").expect("action")
}

fn scene() -> Scene {
    let mut world = TestWorld::new();
    let user = world.principal("user");
    let agent = world.principal("agent");
    let sub = world.principal("subagent");
    let doc = world.resource(&user, None, &[]).id;
    let g1 = Grant::from_owner(user.id.clone(), agent.id.clone(), Selector::Any, [read()])
        .until(NOW + 3600)
        .with_budget("tokens", 100)
        .delegable(1)
        .sign(&user.key)
        .expect("sign");
    let g2 = Grant::passing_on(&g1, sub.id.clone())
        .sign(&agent.key)
        .expect("sign");
    Scene {
        world,
        agent,
        sub,
        doc,
        chain: [g1, g2],
    }
}

fn ask(cache: &ChainCache, s: &Scene, chain: &[SignedGrant], context: Context) -> Decision {
    let action = read();
    let request = Request {
        principal: &s.sub.id,
        action: &action,
        resource: &s.doc,
        proof: chain,
        context,
    };
    let cached = cache.check(&request, &s.world);
    // A cached answer always equals the uncached one.
    assert_eq!(cached, check(&request, &s.world));
    cached
}

#[test]
fn a_verified_chain_is_reused_and_never_goes_stale() {
    let mut s = scene();
    let cache = ChainCache::new();
    let chain = s.chain.clone();
    assert!(ask(&cache, &s, &chain, Context::at(NOW)).is_allowed());
    assert_eq!(cache.len(), 1);
    assert!(ask(&cache, &s, &chain, Context::at(NOW + 1)).is_allowed());
    assert_eq!(cache.len(), 1);

    // Past the earliest expiry.
    let expired = Reason::Proof(GrantError::Expired { link: 0 });
    let at = Context::at(NOW + 3600);
    assert_eq!(ask(&cache, &s, &chain, at), Decision::Deny(expired));

    // Revoked.
    s.world.revoke(chain[1].id());
    let revoked = Reason::Proof(GrantError::Revoked { link: 1 });
    assert_eq!(
        ask(&cache, &s, &chain, Context::at(NOW)),
        Decision::Deny(revoked)
    );
}

#[test]
fn a_removed_key_ends_a_cached_chain() {
    let mut s = scene();
    let cache = ChainCache::new();
    let chain = s.chain.clone();
    assert!(ask(&cache, &s, &chain, Context::at(NOW)).is_allowed());
    s.world.drop_keys(&s.agent.id);
    let lost = Reason::Proof(GrantError::UnknownKey { link: 1 });
    assert_eq!(
        ask(&cache, &s, &chain, Context::at(NOW)),
        Decision::Deny(lost)
    );
}

#[test]
fn budgets_and_changed_bytes_are_never_served_from_the_cache() {
    let mut s = scene();
    let cache = ChainCache::new();
    let chain = s.chain.clone();
    assert!(ask(&cache, &s, &chain, Context::at(NOW)).is_allowed());

    // Spending is checked on every use.
    s.world.spend(chain[0].id(), "tokens", 95);
    let costly = Context {
        cost: Some(Cost {
            unit: "tokens".into(),
            amount: 10,
        }),
        ..Context::at(NOW)
    };
    let over = Reason::OverBudget {
        grant: chain[0].id(),
    };
    assert_eq!(ask(&cache, &s, &chain, costly), Decision::Deny(over));

    // The same grants with one signature byte changed are verified afresh.
    let mut bytes = chain[1].to_bytes().expect("encode");
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let forged = SignedGrant::from_bytes(&bytes).expect("decode");
    let tampered = [chain[0].clone(), forged];
    let bad = Reason::Proof(GrantError::BadSignature { link: 1 });
    assert_eq!(
        ask(&cache, &s, &tampered, Context::at(NOW)),
        Decision::Deny(bad)
    );
}
