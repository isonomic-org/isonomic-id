// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: Apache-2.0

//! Principal IDs.

use crate::{Digest, Error};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The ID of anything that can hold authority: a person, a device, an agent,
/// an app, and later an organization or a team.
///
/// A real ID is `did:iso:` followed by the digest of the first entry of the
/// principal's key log, in hexadecimal, so it never changes when keys do.
/// Other text that passes the length and character checks is accepted too,
/// which keeps test names short.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PrincipalId(String);

impl PrincipalId {
    /// Longest accepted ID, in bytes.
    pub const MAX_LEN: usize = 128;

    /// Checks and wraps an ID.
    pub fn new(text: impl Into<String>) -> Result<Self, Error> {
        let text = text.into();
        let ok = !text.is_empty()
            && text.len() <= Self::MAX_LEN
            && text
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b":._-".contains(&b));
        if ok {
            Ok(PrincipalId(text))
        } else {
            Err(Error::Malformed("principal id"))
        }
    }

    /// The ID of the principal whose key log starts with the entry that has
    /// this digest.
    pub fn from_genesis(first_entry: &Digest) -> Self {
        PrincipalId(format!("did:iso:{}", first_entry.to_hex()))
    }

    /// The text form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PrincipalId {
    type Error = Error;
    fn try_from(text: String) -> Result<Self, Error> {
        PrincipalId::new(text)
    }
}

impl From<PrincipalId> for String {
    fn from(id: PrincipalId) -> String {
        id.0
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
