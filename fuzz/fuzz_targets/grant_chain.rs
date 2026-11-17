// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: Apache-2.0

//! Any bytes, split into length-prefixed grants: decoding and verifying the
//! chain never panics.
#![no_main]

use id_grants::{verify_chain, SignedGrant};
use id_testkit::TestWorld;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let world = TestWorld::new();
    let chain: Vec<SignedGrant> = parts(data, 9)
        .into_iter()
        .filter_map(|part| SignedGrant::from_bytes(part).ok())
        .collect();
    let _ = verify_chain(&chain, &world, &world, 1_800_000_000);
});

/// Splits input into parts, each preceded by a two-byte big-endian length.
fn parts(mut data: &[u8], max: usize) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while out.len() < max && data.len() >= 2 {
        let n = usize::from(u16::from_be_bytes([data[0], data[1]]));
        let end = (2 + n).min(data.len());
        out.push(&data[2..end]);
        data = &data[end..];
    }
    out
}
