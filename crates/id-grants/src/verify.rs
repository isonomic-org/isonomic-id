// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: Apache-2.0

//! Checking a chain of grants.

use crate::{Action, Budget, Grant, GrantId, SignedGrant, DOMAIN, MAX_CHAIN};
use id_core::{KeyResolver, PrincipalId, Timestamp};
use id_resource::Selector;
use std::collections::BTreeSet;
use std::fmt;

/// Knows which grants have been revoked. In version 1 the Capsule keeps the
/// list; later a commitment to it is anchored publicly.
pub trait Revocations {
    /// True when the grant with this ID has been revoked.
    fn is_revoked(&self, id: &GrantId) -> bool;
}

/// The way in which a link tried to reach beyond its parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Widening {
    /// It allows an action its parent does not.
    Actions,
    /// It names resources its parent visibly does not cover.
    Resource,
    /// It expires later than its parent, or never.
    Expiry,
    /// It becomes valid earlier than its parent.
    NotBefore,
    /// It drops its parent's budget, changes its unit or raises its limit.
    Budget,
    /// It drops its parent's "ask first".
    AskFirst,
    /// It allows as many further links as its parent, or more.
    Delegations,
}

/// Why a chain was refused. `link` counts from zero at the owner's grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrantError {
    /// No grants were presented.
    Empty,
    /// More than [`MAX_CHAIN`] links.
    TooLong,
    /// A signature does not verify.
    BadSignature { link: usize },
    /// The signing key does not currently speak for the link's issuer.
    UnknownKey { link: usize },
    /// The first link names a parent, so it is not an owner's grant.
    RootHasParent,
    /// A link does not name the link before it as its parent.
    BrokenLink { link: usize },
    /// A link's issuer is not the recipient of the link before it.
    WrongIssuer { link: usize },
    /// The link before this one did not allow passing the grant on.
    NoDelegation { link: usize },
    /// A link reaches beyond its parent.
    Widens { link: usize, what: Widening },
    /// A link has expired.
    Expired { link: usize },
    /// A link is not valid yet.
    NotYetValid { link: usize },
    /// A link has been revoked. Everything below it falls with it.
    Revoked { link: usize },
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for GrantError {}

/// What a verified chain lets its holder do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authority {
    /// The issuer of the first link. The caller must still confirm that this
    /// principal owns the resource in question.
    pub owner: PrincipalId,
    /// The recipient of the last link: who may use the chain.
    pub holder: PrincipalId,
    /// The actions allowed: those of the last link.
    pub actions: BTreeSet<Action>,
    /// One selector per link. A resource is covered only if all match.
    pub selectors: Vec<Selector>,
    /// The latest start date in the chain.
    pub not_before: Option<Timestamp>,
    /// The earliest expiry in the chain.
    pub expires: Option<Timestamp>,
    /// Every budget in the chain, each with the grant that carries it. All
    /// of them apply.
    pub budgets: Vec<(GrantId, Budget)>,
    /// True when any link asks for approval first.
    pub ask_first: bool,
    /// The ID of the last link.
    pub leaf: GrantId,
}

/// Verifies a chain of grants, owner's grant first.
///
/// It checks every signature, that each signing key currently speaks for its
/// link's issuer, that each link hangs off the one before it and only
/// narrows it, that every link is within its dates, and that none has been
/// revoked. It needs no network.
pub fn verify_chain(
    chain: &[SignedGrant],
    keys: &dyn KeyResolver,
    revoked: &dyn Revocations,
    now: Timestamp,
) -> Result<Authority, GrantError> {
    let (first, last) = match (chain.first(), chain.last()) {
        (Some(first), Some(last)) => (first, last),
        _ => return Err(GrantError::Empty),
    };
    if chain.len() > MAX_CHAIN {
        return Err(GrantError::TooLong);
    }
    if first.grant().parent.is_some() {
        return Err(GrantError::RootHasParent);
    }

    let mut budgets = Vec::new();
    for (link, signed) in chain.iter().enumerate() {
        let grant = signed.grant();
        signed
            .envelope()
            .verify(DOMAIN)
            .map_err(|_| GrantError::BadSignature { link })?;
        if !keys.is_current_key(&grant.issuer, signed.envelope().signer(), now) {
            return Err(GrantError::UnknownKey { link });
        }
        if link > 0 {
            narrows(&chain[link - 1], grant, link)?;
        }
        if grant.not_before.is_some_and(|nbf| now < nbf) {
            return Err(GrantError::NotYetValid { link });
        }
        if grant.expires.is_some_and(|exp| now >= exp) {
            return Err(GrantError::Expired { link });
        }
        if revoked.is_revoked(&signed.id()) {
            return Err(GrantError::Revoked { link });
        }
        if let Some(budget) = &grant.budget {
            budgets.push((signed.id(), budget.clone()));
        }
    }

    let grants = || chain.iter().map(SignedGrant::grant);
    Ok(Authority {
        owner: first.grant().issuer.clone(),
        holder: last.grant().recipient.clone(),
        actions: last.grant().actions.clone(),
        selectors: grants().map(|g| g.resource.clone()).collect(),
        not_before: grants().filter_map(|g| g.not_before).max(),
        expires: grants().filter_map(|g| g.expires).min(),
        budgets,
        ask_first: grants().any(|g| g.ask_first),
        leaf: last.id(),
    })
}

/// Checks that `child` hangs off `parent` and only narrows it.
fn narrows(parent: &SignedGrant, child: &Grant, link: usize) -> Result<(), GrantError> {
    let from = parent.grant();
    let widens = |what| Err(GrantError::Widens { link, what });
    if child.parent != Some(parent.id()) {
        return Err(GrantError::BrokenLink { link });
    }
    if child.issuer != from.recipient {
        return Err(GrantError::WrongIssuer { link });
    }
    if from.delegations == 0 {
        return Err(GrantError::NoDelegation { link });
    }
    if child.delegations >= from.delegations {
        return widens(Widening::Delegations);
    }
    if !child.actions.is_subset(&from.actions) {
        return widens(Widening::Actions);
    }
    if !from.resource.may_narrow_to(&child.resource) {
        return widens(Widening::Resource);
    }
    if let Some(limit) = from.expires {
        if child.expires.is_none_or(|exp| exp > limit) {
            return widens(Widening::Expiry);
        }
    }
    if let Some(start) = from.not_before {
        if child.not_before.is_none_or(|nbf| nbf < start) {
            return widens(Widening::NotBefore);
        }
    }
    if let Some(budget) = &from.budget {
        let kept = child
            .budget
            .as_ref()
            .is_some_and(|b| b.unit == budget.unit && b.limit <= budget.limit);
        if !kept {
            return widens(Widening::Budget);
        }
    }
    if from.ask_first && !child.ask_first {
        return widens(Widening::AskFirst);
    }
    Ok(())
}
