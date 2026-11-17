// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: Apache-2.0

//! Any bytes, split into length-prefixed entries: replaying a key log, with Ethereum
//! bindings checked, and offering it to a directory never panic.
#![no_main]

use id_core::log::{replay, BindingCheck, Directory};
use id_core::Signed;
use id_eth::EthBinding;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let entries: Vec<Signed> = parts(data, 64)
        .into_iter()
        .filter_map(|part| Signed::from_bytes(part).ok())
        .collect();
    let checks: [&dyn BindingCheck; 1] = [&EthBinding];
    let _ = replay(&entries, &checks);
    let mut directory = Directory::default();
    let _ = directory.accept(&entries, &checks);
    let _ = directory.accept(&entries, &checks);
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
