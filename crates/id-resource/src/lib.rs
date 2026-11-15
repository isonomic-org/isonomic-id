//! The resource model.
//!
//! Every protected thing (a document, a file, a session, an index, a tool)
//! has the same small record: a stable ID that needs no coordination to
//! create, a type, an owner, an optional parent, a collection (which is also
//! its encryption scope) and what it was derived from.
//!
//! Derived data inherits its sources' restrictions: [`sources`] walks the
//! `derived_from` links so a caller can require access to every source
//! before releasing a summary, an embedding or an index entry.

mod selector;

pub use selector::Selector;

use id_core::PrincipalId;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// How far up a parent chain, and how wide a provenance graph, a walk goes
/// before it gives up.
pub const MAX_DEPTH: usize = 32;
/// The most sources one resource may derive from, counting indirect ones.
pub const MAX_SOURCES: usize = 256;

/// A 128-bit resource ID: 48 bits of creation time in milliseconds, then 80
/// random bits. IDs sort by creation time and two Capsules that have never
/// met cannot produce the same one.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResourceId(#[serde(with = "serde_bytes")] [u8; 16]);

impl ResourceId {
    /// A new ID stamped with `now_ms`.
    pub fn new(now_ms: u64) -> Self {
        let mut random = [0u8; 10];
        // The system generator failing is not a state this library can run in.
        SystemRandom::new()
            .fill(&mut random)
            .expect("system random generator");
        Self::from_parts(now_ms, random)
    }

    /// Builds an ID from its two parts. Tests use this for fixed IDs.
    pub fn from_parts(now_ms: u64, random: [u8; 10]) -> Self {
        let mut bytes = [0u8; 16];
        bytes[..6].copy_from_slice(&now_ms.to_be_bytes()[2..]);
        bytes[6..].copy_from_slice(&random);
        ResourceId(bytes)
    }

    /// The creation time, in milliseconds since the Unix epoch.
    pub fn created_ms(&self) -> u64 {
        let mut ms = [0u8; 8];
        ms[2..].copy_from_slice(&self.0[..6]);
        u64::from_be_bytes(ms)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "res_{}", id_core::hex(&self.0))
    }
}

impl fmt::Debug for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// The record every protected thing carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceMeta {
    /// The resource's own ID.
    pub id: ResourceId,
    /// What kind of thing it is, for example `doc` or `chat.session`.
    pub kind: String,
    /// Who owns it. A field, not part of the ID, so ownership can move.
    pub owner: PrincipalId,
    /// The resource it sits under, if any.
    pub parent: Option<ResourceId>,
    /// The collection it belongs to, which is also its encryption scope.
    pub collection: ResourceId,
    /// What it was computed from. Empty for original data.
    pub derived_from: Vec<ResourceId>,
}

/// Looks resources up. The engine implements this over its store.
pub trait ResourceLookup {
    /// The record for `id`, or `None` when there is no such resource.
    fn resource(&self, id: &ResourceId) -> Option<ResourceMeta>;
}

/// Why a walk over the resource graph stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourceError {
    /// A parent or source link points at a resource that does not exist.
    Missing(ResourceId),
    /// The parent chain loops or is deeper than [`MAX_DEPTH`].
    TooDeep,
    /// More than [`MAX_SOURCES`] sources.
    TooManySources,
}

impl fmt::Display for ResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResourceError::Missing(id) => write!(f, "{id} does not exist"),
            ResourceError::TooDeep => write!(f, "parent chain loops or is too deep"),
            ResourceError::TooManySources => write!(f, "too many sources"),
        }
    }
}

impl std::error::Error for ResourceError {}

/// The parents of `meta`, nearest first, not including `meta` itself.
pub fn ancestors(
    lookup: &dyn ResourceLookup,
    meta: &ResourceMeta,
) -> Result<Vec<ResourceId>, ResourceError> {
    let mut out = Vec::new();
    let mut next = meta.parent;
    while let Some(id) = next {
        if out.len() >= MAX_DEPTH || id == meta.id || out.contains(&id) {
            return Err(ResourceError::TooDeep);
        }
        out.push(id);
        next = lookup
            .resource(&id)
            .ok_or(ResourceError::Missing(id))?
            .parent;
    }
    Ok(out)
}

/// Every resource `meta` was derived from, directly or through other derived
/// data. Loops are harmless: each source is visited once.
pub fn sources(
    lookup: &dyn ResourceLookup,
    meta: &ResourceMeta,
) -> Result<Vec<ResourceMeta>, ResourceError> {
    let mut seen = BTreeSet::from([meta.id]);
    let mut queue: Vec<ResourceId> = meta.derived_from.clone();
    let mut out = Vec::new();
    while let Some(id) = queue.pop() {
        if !seen.insert(id) {
            continue;
        }
        if out.len() >= MAX_SOURCES {
            return Err(ResourceError::TooManySources);
        }
        let source = lookup.resource(&id).ok_or(ResourceError::Missing(id))?;
        queue.extend(source.derived_from.iter().copied());
        out.push(source);
    }
    Ok(out)
}
