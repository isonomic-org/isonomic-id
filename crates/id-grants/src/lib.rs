// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The grant: one signed format for every permission.
//!
//! A grant says that an issuer lets a recipient perform some actions on some
//! resources, under conditions. A recipient may pass a narrower grant on, so
//! authority travels as a chain: owner → agent → subagent. [`verify_chain`]
//! checks a whole chain with no network and no database.
//!
//! Two rules make a chain safe:
//!
//! - **A link may only narrow.** Fewer actions, an earlier expiry, a smaller
//!   budget; "ask first" can be added and never removed.
//! - **A chain covers only what every link covers.** Even where narrowing
//!   cannot be judged from two grants alone (one folder inside another), a
//!   link that names something its parent did not cover grants nothing.

mod verify;

pub use verify::{verify_chain, Authority, GrantError, Revocations, Widening};

use id_core::{from_cbor, to_cbor, Digest, Error, PrincipalId, Signed, Signer, Timestamp};
use id_resource::Selector;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The signing and hashing domain of grants.
pub const DOMAIN: &str = "grant";
/// The only grant version this crate reads and writes.
pub const VERSION: u8 = 1;
/// The longest chain [`verify_chain`] accepts.
pub const MAX_CHAIN: usize = 8;

/// A grant's ID: the digest of its signed payload. Revocations name it.
pub type GrantId = Digest;

/// Something a principal may do, for example `read` or `network`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Action(String);

impl Action {
    /// Checks and wraps an action name: lowercase letters, digits, `.`, `_`
    /// and `-`, at most 64 bytes.
    pub fn new(name: impl Into<String>) -> Result<Self, Error> {
        let name = name.into();
        let ok = !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));
        if ok {
            Ok(Action(name))
        } else {
            Err(Error::Malformed("action"))
        }
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Action {
    type Error = Error;
    fn try_from(name: String) -> Result<Self, Error> {
        Action::new(name)
    }
}

impl From<Action> for String {
    fn from(action: Action) -> String {
        action.0
    }
}

/// A spending ceiling, counted in `unit` (tokens, cents, seconds, calls).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    /// What is being counted.
    #[serde(rename = "u")]
    pub unit: String,
    /// The most that may be spent under this grant, in total.
    #[serde(rename = "l")]
    pub limit: u64,
}

/// The body of a grant, before signing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// Format version. Always [`VERSION`].
    #[serde(rename = "v")]
    pub version: u8,
    /// Who gives the permission.
    #[serde(rename = "iss")]
    pub issuer: PrincipalId,
    /// Who receives it.
    #[serde(rename = "aud")]
    pub recipient: PrincipalId,
    /// Which resources it covers.
    #[serde(rename = "res")]
    pub resource: Selector,
    /// Which actions it allows.
    #[serde(rename = "act")]
    pub actions: BTreeSet<Action>,
    /// Not valid before this time.
    #[serde(rename = "nbf", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<Timestamp>,
    /// Not valid from this time on.
    #[serde(rename = "exp", default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<Timestamp>,
    /// A spending ceiling.
    #[serde(rename = "bud", default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<Budget>,
    /// When true, every use must first be approved by a person.
    #[serde(rename = "ask", default)]
    pub ask_first: bool,
    /// How many further links may hang below this grant. Zero means the
    /// recipient cannot pass anything on.
    #[serde(rename = "dep", default)]
    pub delegations: u8,
    /// The grant this one narrows. `None` for a grant from the owner.
    #[serde(rename = "par", default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<GrantId>,
    /// Random bytes that make every grant, and so every grant ID, unique.
    #[serde(rename = "n", with = "serde_bytes")]
    pub nonce: [u8; 16],
}

impl Grant {
    /// A grant straight from an owner: these actions on these resources,
    /// with no expiry, no budget, no approval step and no right to pass it
    /// on. Tighten or loosen it with the builder methods before signing.
    pub fn from_owner(
        issuer: PrincipalId,
        recipient: PrincipalId,
        resource: Selector,
        actions: impl IntoIterator<Item = Action>,
    ) -> Self {
        let mut nonce = [0u8; 16];
        // The system generator failing is not a state this library can run in.
        SystemRandom::new()
            .fill(&mut nonce)
            .expect("system random generator");
        Grant {
            version: VERSION,
            issuer,
            recipient,
            resource,
            actions: actions.into_iter().collect(),
            not_before: None,
            expires: None,
            budget: None,
            ask_first: false,
            delegations: 0,
            parent: None,
            nonce,
        }
    }

    /// A grant that passes `parent` on to `recipient` unchanged, with one
    /// fewer delegation left. Narrow it with the builder methods.
    pub fn passing_on(parent: &SignedGrant, recipient: PrincipalId) -> Self {
        let from = parent.grant();
        let mut grant = Grant::from_owner(
            from.recipient.clone(),
            recipient,
            from.resource.clone(),
            from.actions.iter().cloned(),
        );
        grant.not_before = from.not_before;
        grant.expires = from.expires;
        grant.budget = from.budget.clone();
        grant.ask_first = from.ask_first;
        grant.delegations = from.delegations.saturating_sub(1);
        grant.parent = Some(parent.id());
        grant
    }

    /// Sets the resources covered.
    pub fn on(mut self, resource: Selector) -> Self {
        self.resource = resource;
        self
    }

    /// Sets the actions allowed.
    pub fn allowing(mut self, actions: impl IntoIterator<Item = Action>) -> Self {
        self.actions = actions.into_iter().collect();
        self
    }

    /// Sets the expiry.
    pub fn until(mut self, expires: Timestamp) -> Self {
        self.expires = Some(expires);
        self
    }

    /// Sets a spending ceiling.
    pub fn with_budget(mut self, unit: &str, limit: u64) -> Self {
        self.budget = Some(Budget {
            unit: unit.to_string(),
            limit,
        });
        self
    }

    /// Requires a person's approval before every use.
    pub fn asking_first(mut self) -> Self {
        self.ask_first = true;
        self
    }

    /// Lets the recipient pass the grant on, up to `links` links deep.
    pub fn delegable(mut self, links: u8) -> Self {
        self.delegations = links;
        self
    }

    /// Signs the grant.
    pub fn sign(self, signer: &dyn Signer) -> Result<SignedGrant, Error> {
        let envelope = Signed::seal(DOMAIN, to_cbor(&self)?, signer)?;
        let id = envelope.id(DOMAIN);
        Ok(SignedGrant {
            envelope,
            grant: self,
            id,
        })
    }
}

/// A grant with its signature. This is what is stored and sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedGrant {
    envelope: Signed,
    grant: Grant,
    id: GrantId,
}

impl SignedGrant {
    /// The grant's body. Trust it only after [`verify_chain`].
    pub fn grant(&self) -> &Grant {
        &self.grant
    }

    /// The grant's ID.
    pub fn id(&self) -> GrantId {
        self.id
    }

    /// The signed envelope.
    pub fn envelope(&self) -> &Signed {
        &self.envelope
    }

    /// Encodes the grant for storage or transport.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.envelope.to_bytes()
    }

    /// Decodes a grant. This checks the shape and version, not the
    /// signature: that is [`verify_chain`]'s job.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let envelope = Signed::from_bytes(bytes)?;
        let grant: Grant = from_cbor(envelope.payload())?;
        if grant.version != VERSION {
            return Err(Error::Malformed("grant: unsupported version"));
        }
        let id = envelope.id(DOMAIN);
        Ok(SignedGrant {
            envelope,
            grant,
            id,
        })
    }
}
