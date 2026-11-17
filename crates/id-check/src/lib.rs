// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: Apache-2.0

//! The check function.
//!
//! `check(request, world)` answers one question: may this principal perform
//! this action on this resource right now? The answer is allow, deny or ask,
//! always with a reason. The engine, the agent host, Cells and the SDK all
//! call it, and nothing else decides access. A model is never asked.
//!
//! Version 1 logic, in order:
//!
//! 1. The resource must exist.
//! 2. Its owner is allowed.
//! 3. Anyone else needs a chain of grants that verifies, starts at the
//!    resource's owner, ends at the caller, allows the action, covers the
//!    resource at every link, and has budget left.
//! 4. If the resource was derived from others (a summary, an embedding, an
//!    index), the caller must also be able to read every source.
//! 5. If any link says "ask first" and no person has approved, the answer is
//!    ask. Everything else is deny.
//!
//! Shared workspaces add one thing: [`World::is_member`], so a grant issued
//! to a team is usable by its members. Callers do not change.
//!
//! Verifying a chain's signatures is the expensive part. A caller that checks
//! the same chain many times, such as the broker for one app session, uses a
//! [`ChainCache`] so that only the first check pays for them.

mod cache;

pub use cache::{ChainCache, VersionedWorld};

use id_core::{KeyResolver, PrincipalId, Timestamp};
use id_grants::{verify_chain, Action, Authority, GrantError, GrantId, Revocations, SignedGrant};
use id_resource::{ancestors, sources, ResourceError, ResourceId, ResourceLookup, ResourceMeta};

/// The answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Go ahead.
    Allow(Reason),
    /// Do not.
    Deny(Reason),
    /// Allowed only once a person approves this use.
    Ask(Reason),
}

impl Decision {
    /// True for [`Decision::Allow`].
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow(_))
    }
}

/// Why the answer is what it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The caller owns the resource.
    Owner,
    /// A verified chain of grants allows it. `leaf` is the last link.
    Granted { leaf: GrantId },
    /// A link in the chain requires approval, and none was given.
    AskFirst { leaf: GrantId },
    /// There is no such resource.
    UnknownResource,
    /// The caller is not the owner and presented no grants.
    NoProof,
    /// The chain of grants does not verify.
    Proof(GrantError),
    /// The chain does not start at the resource's owner.
    NotOwnersGrant,
    /// The chain was issued to someone else.
    NotHolder,
    /// The chain does not allow this action.
    ActionNotGranted,
    /// Some link in the chain does not cover this resource.
    OutOfScope,
    /// The grant with this ID has too little budget left.
    OverBudget { grant: GrantId },
    /// The resource's parent or provenance links cannot be followed.
    Graph(ResourceError),
    /// The resource is derived data and the caller may not read this source.
    Source {
        source: ResourceId,
        why: Box<Reason>,
    },
}

/// What a use will cost, checked against every budget in the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cost {
    /// What is being counted. Budgets in other units are not affected.
    pub unit: String,
    /// How much this use will spend.
    pub amount: u64,
}

/// The circumstances of a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    /// The current time.
    pub now: Timestamp,
    /// What this use will cost, if it costs anything.
    pub cost: Option<Cost>,
    /// True when a person has approved exactly this use. The caller must
    /// have verified that approval; a model's say-so does not count.
    pub approved: bool,
}

impl Context {
    /// A context with no cost and no approval.
    pub fn at(now: Timestamp) -> Self {
        Context {
            now,
            cost: None,
            approved: false,
        }
    }
}

/// One access question.
#[derive(Clone, Debug)]
pub struct Request<'a> {
    /// Who is asking.
    pub principal: &'a PrincipalId,
    /// What they want to do.
    pub action: &'a Action,
    /// To what.
    pub resource: &'a ResourceId,
    /// The chain of grants they present, owner's grant first. Empty when
    /// the caller claims to be the owner.
    pub proof: &'a [SignedGrant],
    /// The circumstances.
    pub context: Context,
}

/// Everything the check function needs to know about the Capsule.
pub trait World: KeyResolver + Revocations + ResourceLookup {
    /// How much has already been spent under a grant, in `unit`.
    fn spent(&self, _grant: &GrantId, _unit: &str) -> u64 {
        0
    }

    /// True when `who` belongs to the team or organization `group`.
    /// Version 1 has no groups, so the default is false.
    fn is_member(&self, _who: &PrincipalId, _group: &PrincipalId) -> bool {
        false
    }
}

/// Verifies a presented chain at a given time.
type Verify<'a> = dyn Fn(&[SignedGrant], Timestamp) -> Result<Authority, GrantError> + 'a;

/// Decides one request. Deny is the default.
pub fn check(request: &Request<'_>, world: &dyn World) -> Decision {
    check_with(request, world, &|proof, now| {
        verify_chain(proof, world, world, now)
    })
}

fn check_with(request: &Request<'_>, world: &dyn World, verify: &Verify<'_>) -> Decision {
    let Some(meta) = world.resource(request.resource) else {
        return Decision::Deny(Reason::UnknownResource);
    };
    let mut proof = Proof::Unchecked;
    let mut decision = decide(request, world, &meta, request.action, &mut proof, verify);
    if matches!(decision, Decision::Deny(_)) {
        return decision;
    }

    // Derived data is only as open as everything it was made from.
    let derived_from = match sources(world, &meta) {
        Ok(found) => found,
        Err(e) => return Decision::Deny(Reason::Graph(e)),
    };
    let Ok(read) = Action::new("read") else {
        return Decision::Deny(Reason::ActionNotGranted);
    };
    for source in derived_from {
        match decide(request, world, &source, &read, &mut proof, verify) {
            Decision::Allow(_) => {}
            Decision::Ask(why) => decision = Decision::Ask(why),
            Decision::Deny(why) => {
                return Decision::Deny(Reason::Source {
                    source: source.id,
                    why: Box::new(why),
                })
            }
        }
    }
    decision
}

/// The caller's chain, verified at most once per request.
enum Proof {
    Unchecked,
    Checked(Result<Authority, GrantError>),
}

fn decide(
    request: &Request<'_>,
    world: &dyn World,
    meta: &ResourceMeta,
    action: &Action,
    proof: &mut Proof,
    verify: &Verify<'_>,
) -> Decision {
    if *request.principal == meta.owner {
        return Decision::Allow(Reason::Owner);
    }
    if request.proof.is_empty() {
        return Decision::Deny(Reason::NoProof);
    }
    if matches!(proof, Proof::Unchecked) {
        *proof = Proof::Checked(verify(request.proof, request.context.now));
    }
    let authority = match proof {
        Proof::Checked(Ok(authority)) => authority,
        Proof::Checked(Err(e)) => return Decision::Deny(Reason::Proof(e.clone())),
        Proof::Unchecked => return Decision::Deny(Reason::NoProof),
    };

    if authority.owner != meta.owner {
        return Decision::Deny(Reason::NotOwnersGrant);
    }
    if authority.holder != *request.principal
        && !world.is_member(request.principal, &authority.holder)
    {
        return Decision::Deny(Reason::NotHolder);
    }
    if !authority.actions.contains(action) {
        return Decision::Deny(Reason::ActionNotGranted);
    }
    let parents = match ancestors(world, meta) {
        Ok(parents) => parents,
        Err(e) => return Decision::Deny(Reason::Graph(e)),
    };
    if !authority
        .selectors
        .iter()
        .all(|s| s.matches(meta, &parents))
    {
        return Decision::Deny(Reason::OutOfScope);
    }
    if let Some(cost) = &request.context.cost {
        for (grant, budget) in &authority.budgets {
            let spent = world.spent(grant, &cost.unit);
            if budget.unit == cost.unit && spent.saturating_add(cost.amount) > budget.limit {
                return Decision::Deny(Reason::OverBudget { grant: *grant });
            }
        }
    }
    if authority.ask_first && !request.context.approved {
        return Decision::Ask(Reason::AskFirst {
            leaf: authority.leaf,
        });
    }
    Decision::Allow(Reason::Granted {
        leaf: authority.leaf,
    })
}
