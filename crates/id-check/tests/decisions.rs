//! The check function's decisions, case by case.

use id_check::{check, Context, Cost, Decision, Reason, Request};
use id_grants::{Action, Grant, GrantError, SignedGrant};
use id_resource::{ResourceId, ResourceMeta, Selector};
use id_testkit::{ManualClock, TestPrincipal, TestWorld};

const NOW: u64 = 1_800_000_000;

struct Scene {
    world: TestWorld,
    user: TestPrincipal,
    agent: TestPrincipal,
    sub: TestPrincipal,
    folder: ResourceMeta,
    doc: ResourceMeta,
    private: ResourceMeta,
    /// user → agent: read and write under `folder`, 1000 tokens, one hour.
    g1: SignedGrant,
    /// agent → subagent: read only, 200 tokens.
    g2: SignedGrant,
}

fn act(name: &str) -> Action {
    Action::new(name).expect("action")
}

fn scene() -> Scene {
    let mut world = TestWorld::new();
    let user = world.principal("user");
    let agent = world.principal("agent");
    let sub = world.principal("subagent");
    let folder = world.resource(&user, None, &[]);
    let doc = world.resource(&user, Some(folder.id), &[]);
    let private = world.resource(&user, None, &[]);
    let g1 = Grant::from_owner(
        user.id.clone(),
        agent.id.clone(),
        Selector::Tree(folder.id),
        [act("read"), act("write")],
    )
    .until(NOW + 3600)
    .with_budget("tokens", 1000)
    .delegable(1)
    .sign(&user.key)
    .expect("sign");
    let g2 = Grant::passing_on(&g1, sub.id.clone())
        .allowing([act("read")])
        .with_budget("tokens", 200)
        .sign(&agent.key)
        .expect("sign");
    Scene {
        world,
        user,
        agent,
        sub,
        folder,
        doc,
        private,
        g1,
        g2,
    }
}

fn ask(
    world: &TestWorld,
    who: &TestPrincipal,
    action: &str,
    resource: ResourceId,
    proof: &[SignedGrant],
    context: Context,
) -> Decision {
    let action = act(action);
    check(
        &Request {
            principal: &who.id,
            action: &action,
            resource: &resource,
            proof,
            context,
        },
        world,
    )
}

#[test]
fn owner_is_allowed_and_everyone_else_is_denied_by_default() {
    let s = scene();
    let at = || Context::at(NOW);
    assert_eq!(
        ask(&s.world, &s.user, "delete", s.doc.id, &[], at()),
        Decision::Allow(Reason::Owner)
    );
    assert_eq!(
        ask(&s.world, &s.agent, "read", s.doc.id, &[], at()),
        Decision::Deny(Reason::NoProof)
    );
    let nowhere = ResourceId::from_parts(999, [9; 10]);
    assert_eq!(
        ask(&s.world, &s.user, "read", nowhere, &[], at()),
        Decision::Deny(Reason::UnknownResource)
    );
}

#[test]
fn a_chain_allows_exactly_what_every_link_allows() {
    let s = scene();
    let at = || Context::at(NOW);
    let one = [s.g1.clone()];
    let two = [s.g1.clone(), s.g2.clone()];
    let granted = |g: &SignedGrant| Decision::Allow(Reason::Granted { leaf: g.id() });

    assert_eq!(
        ask(&s.world, &s.agent, "write", s.doc.id, &one, at()),
        granted(&s.g1)
    );
    assert_eq!(
        ask(&s.world, &s.agent, "read", s.folder.id, &one, at()),
        granted(&s.g1)
    );
    assert_eq!(
        ask(&s.world, &s.sub, "read", s.doc.id, &two, at()),
        granted(&s.g2)
    );

    // The subagent was given read only.
    assert_eq!(
        ask(&s.world, &s.sub, "write", s.doc.id, &two, at()),
        Decision::Deny(Reason::ActionNotGranted)
    );
    // Nobody was given delete.
    assert_eq!(
        ask(&s.world, &s.agent, "delete", s.doc.id, &one, at()),
        Decision::Deny(Reason::ActionNotGranted)
    );
    // The grant covers the folder, not the private document.
    assert_eq!(
        ask(&s.world, &s.agent, "read", s.private.id, &one, at()),
        Decision::Deny(Reason::OutOfScope)
    );
    // The agent cannot use the subagent's chain, nor the reverse.
    assert_eq!(
        ask(&s.world, &s.agent, "read", s.doc.id, &two, at()),
        Decision::Deny(Reason::NotHolder)
    );
    assert_eq!(
        ask(&s.world, &s.sub, "read", s.doc.id, &one, at()),
        Decision::Deny(Reason::NotHolder)
    );
}

#[test]
fn a_link_naming_something_outside_its_parent_grants_nothing() {
    let mut s = scene();
    // The agent "passes on" the private document, which it was never given.
    let reach = Grant::passing_on(&s.g1, s.sub.id.clone())
        .on(Selector::Tree(s.private.id))
        .sign(&s.agent.key)
        .expect("sign");
    let chain = [s.g1.clone(), reach];
    assert_eq!(
        ask(
            &s.world,
            &s.sub,
            "read",
            s.private.id,
            &chain,
            Context::at(NOW)
        ),
        Decision::Deny(Reason::OutOfScope)
    );

    // A grant from someone who does not own the resource is worthless.
    let other = s.world.principal("other");
    let theirs = Grant::from_owner(
        other.id.clone(),
        s.agent.id.clone(),
        Selector::Any,
        [act("read")],
    )
    .sign(&other.key)
    .expect("sign");
    assert_eq!(
        ask(
            &s.world,
            &s.agent,
            "read",
            s.doc.id,
            &[theirs],
            Context::at(NOW)
        ),
        Decision::Deny(Reason::NotOwnersGrant)
    );
}

#[test]
fn expiry_revocation_and_lost_keys_turn_allow_into_deny() {
    let mut s = scene();
    let clock = ManualClock::at(NOW);
    let two = [s.g1.clone(), s.g2.clone()];
    assert!(ask(
        &s.world,
        &s.sub,
        "read",
        s.doc.id,
        &two,
        Context::at(clock.now())
    )
    .is_allowed());

    clock.advance(3600);
    assert_eq!(
        ask(
            &s.world,
            &s.sub,
            "read",
            s.doc.id,
            &two,
            Context::at(clock.now())
        ),
        Decision::Deny(Reason::Proof(GrantError::Expired { link: 0 }))
    );

    s.world.revoke(s.g1.id());
    assert_eq!(
        ask(&s.world, &s.sub, "read", s.doc.id, &two, Context::at(NOW)),
        Decision::Deny(Reason::Proof(GrantError::Revoked { link: 0 }))
    );

    let mut s = scene();
    s.world.drop_keys(&s.agent.id);
    assert_eq!(
        ask(
            &s.world,
            &s.sub,
            "read",
            s.doc.id,
            &two_of(&s),
            Context::at(NOW)
        ),
        Decision::Deny(Reason::Proof(GrantError::UnknownKey { link: 1 }))
    );
}

fn two_of(s: &Scene) -> [SignedGrant; 2] {
    [s.g1.clone(), s.g2.clone()]
}

#[test]
fn budgets_apply_at_every_link() {
    let mut s = scene();
    let two = two_of(&s);
    let costing = |amount| Context {
        now: NOW,
        cost: Some(Cost {
            unit: "tokens".into(),
            amount,
        }),
        approved: false,
    };
    assert!(ask(&s.world, &s.sub, "read", s.doc.id, &two, costing(200)).is_allowed());
    assert_eq!(
        ask(&s.world, &s.sub, "read", s.doc.id, &two, costing(201)),
        Decision::Deny(Reason::OverBudget { grant: s.g2.id() })
    );
    // The agent's own spending counts against the user's ceiling too.
    s.world.spend(s.g1.id(), "tokens", 900);
    assert_eq!(
        ask(&s.world, &s.sub, "read", s.doc.id, &two, costing(150)),
        Decision::Deny(Reason::OverBudget { grant: s.g1.id() })
    );
    // A cost in another unit is not limited by a token budget.
    let seconds = Context {
        now: NOW,
        cost: Some(Cost {
            unit: "seconds".into(),
            amount: 10_000,
        }),
        approved: false,
    };
    assert!(ask(&s.world, &s.sub, "read", s.doc.id, &two, seconds).is_allowed());
}

#[test]
fn ask_first_asks_until_a_person_approves() {
    let s = scene();
    let careful = Grant::from_owner(
        s.user.id.clone(),
        s.agent.id.clone(),
        Selector::One(s.doc.id),
        [act("network")],
    )
    .asking_first()
    .sign(&s.user.key)
    .expect("sign");
    let chain = [careful.clone()];
    assert_eq!(
        ask(
            &s.world,
            &s.agent,
            "network",
            s.doc.id,
            &chain,
            Context::at(NOW)
        ),
        Decision::Ask(Reason::AskFirst { leaf: careful.id() })
    );
    let approved = Context {
        approved: true,
        ..Context::at(NOW)
    };
    assert!(ask(
        &s.world,
        &s.agent,
        "network",
        s.doc.id,
        &chain,
        approved.clone()
    )
    .is_allowed());
    // Approval never rescues a request that would be denied anyway.
    assert_eq!(
        ask(&s.world, &s.agent, "delete", s.doc.id, &chain, approved),
        Decision::Deny(Reason::ActionNotGranted)
    );
}

#[test]
fn derived_data_is_only_as_open_as_its_sources() {
    let mut s = scene();
    // A summary filed in the shared folder, made from the shared document
    // and from the private one.
    let clean = s.world.resource(&s.user, Some(s.folder.id), &[s.doc.id]);
    let leaky = s
        .world
        .resource(&s.user, Some(s.folder.id), &[s.doc.id, s.private.id]);
    let one = [s.g1.clone()];
    assert!(ask(&s.world, &s.agent, "read", clean.id, &one, Context::at(NOW)).is_allowed());
    assert_eq!(
        ask(&s.world, &s.agent, "read", leaky.id, &one, Context::at(NOW)),
        Decision::Deny(Reason::Source {
            source: s.private.id,
            why: Box::new(Reason::OutOfScope),
        })
    );
    // The owner still sees everything.
    assert!(ask(&s.world, &s.user, "read", leaky.id, &[], Context::at(NOW)).is_allowed());
}

#[test]
fn a_grant_to_a_team_is_usable_by_its_members() {
    let mut s = scene();
    let team = s.world.principal("team");
    let member = s.world.principal("member");
    let grant = Grant::from_owner(
        s.user.id.clone(),
        team.id.clone(),
        Selector::Any,
        [act("read")],
    )
    .sign(&s.user.key)
    .expect("sign");
    let chain = [grant];
    assert_eq!(
        ask(
            &s.world,
            &member,
            "read",
            s.doc.id,
            &chain,
            Context::at(NOW)
        ),
        Decision::Deny(Reason::NotHolder)
    );
    s.world.add_member(&member.id, &team.id);
    assert!(ask(
        &s.world,
        &member,
        "read",
        s.doc.id,
        &chain,
        Context::at(NOW)
    )
    .is_allowed());
}
