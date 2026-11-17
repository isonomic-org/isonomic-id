// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: Apache-2.0

//! The one byte encoding: CBOR, with a size limit and no trailing bytes.
//!
//! Signatures and IDs are always computed over bytes exactly as they were
//! received, never over a re-encoding, so nothing here depends on two
//! encoders agreeing byte for byte.

use crate::Error;
use serde::{de::DeserializeOwned, Serialize};

/// Largest encoded value this crate will produce or decode.
pub const MAX_ENCODED_BYTES: usize = 64 * 1024;

/// Encodes a value.
pub fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).map_err(|_| Error::Malformed("value to encode"))?;
    if out.len() > MAX_ENCODED_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(out)
}

/// Decodes a value. Refuses oversized input and input with bytes left over.
pub fn from_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    if bytes.len() > MAX_ENCODED_BYTES {
        return Err(Error::TooLarge);
    }
    let mut rest = bytes;
    let value = ciborium::de::from_reader_with_recursion_limit(&mut rest, 32)
        .map_err(|_| Error::Malformed("encoding"))?;
    if !rest.is_empty() {
        return Err(Error::Malformed("encoding: trailing bytes"));
    }
    Ok(value)
}
