// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: Apache-2.0

//! Which resources a grant covers.

use crate::{ResourceId, ResourceMeta};
use serde::{Deserialize, Serialize};

/// The resources a grant covers.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Selector {
    /// Everything the issuer owns.
    #[serde(rename = "any")]
    Any,
    /// Everything in one collection.
    #[serde(rename = "col")]
    Collection(ResourceId),
    /// One resource and everything under it.
    #[serde(rename = "tree")]
    Tree(ResourceId),
    /// Exactly one resource.
    #[serde(rename = "one")]
    One(ResourceId),
}

impl Selector {
    /// True when this selector covers the resource. `ancestors` is the
    /// resource's parent chain, from [`crate::ancestors`].
    pub fn matches(&self, meta: &ResourceMeta, ancestors: &[ResourceId]) -> bool {
        match self {
            Selector::Any => true,
            Selector::Collection(id) => meta.collection == *id,
            Selector::Tree(id) => meta.id == *id || ancestors.contains(id),
            Selector::One(id) => meta.id == *id,
        }
    }

    /// False when `child` can be seen to reach beyond this selector without
    /// looking anything up.
    ///
    /// Some pairs cannot be judged from the selectors alone: whether one
    /// subtree lies inside another depends on the resource graph. Those
    /// pairs pass here and are still safe, because a chain of grants covers
    /// only what every link covers.
    pub fn may_narrow_to(&self, child: &Selector) -> bool {
        match (self, child) {
            (Selector::Any, _) => true,
            (_, Selector::Any) => false,
            (Selector::One(a), Selector::One(b)) => a == b,
            (Selector::One(_), _) => false,
            (Selector::Collection(a), Selector::Collection(b)) => a == b,
            (Selector::Collection(_), _) | (Selector::Tree(_), _) => true,
        }
    }
}
