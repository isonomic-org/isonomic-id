//! Any bytes: decoding a signed envelope never panics, and what decodes
//! re-encodes and verifies without panicking.
#![no_main]

use id_core::Signed;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(signed) = Signed::from_bytes(data) {
        let _ = signed.verify("grant");
        let _ = signed.verify("log");
        let _ = signed.to_bytes();
    }
});
