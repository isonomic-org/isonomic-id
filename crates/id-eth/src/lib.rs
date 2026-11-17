// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: Apache-2.0

//! Ethereum, ready from day one and not required.
//!
//! An identity can carry an Ethereum key. The key's address is bound into
//! the identity's log from both sides: the log entry is signed by the
//! identity, and the Ethereum key signs the identity's ID. Anyone can check
//! both offline.
//!
//! Everything here is arithmetic. Nothing in this crate talks to a chain,
//! and nothing is deployed. [`create2`] computes the address a smart account
//! would have; which account factory to use is decided later, with the
//! chain, so no account address is bound yet.

use id_core::log::{Binding, BindingCheck, State};
use id_core::PrincipalId;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use sha3::{Digest as _, Keccak256};

/// A 20-byte Ethereum address.
pub type Address = [u8; 20];

/// The binding scheme name used in key logs.
pub const SCHEME: &str = "eth";

/// Keccak-256 of the parts, one after another.
pub fn keccak256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn last_20(hash: &[u8; 32]) -> Address {
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

fn address_of(key: &VerifyingKey) -> Address {
    let point = key.to_encoded_point(false);
    last_20(&keccak256(&[&point.as_bytes()[1..]]))
}

/// The hash a wallet signs for a personal message.
fn message_hash(msg: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
    keccak256(&[prefix.as_bytes(), msg])
}

/// What the Ethereum key signs to bind itself to an identity. It is plain
/// text, so a wallet shows the person exactly what they are agreeing to.
pub fn binding_message(id: &PrincipalId) -> Vec<u8> {
    format!("Isonomic ID binding v1\n{id}").into_bytes()
}

/// The address that signed `msg` as a personal message, if `sig` is a
/// well-formed 65-byte signature. The last byte may be 0, 1, 27 or 28.
pub fn recover(msg: &[u8], sig: &[u8]) -> Option<Address> {
    let (rs, v) = sig.split_at_checked(64)?;
    let [v] = v else { return None };
    let recovery = RecoveryId::from_byte(if *v >= 27 { v - 27 } else { *v })?;
    let sig = Signature::from_slice(rs).ok()?;
    let key = VerifyingKey::recover_from_prehash(&message_hash(msg), &sig, recovery).ok()?;
    Some(address_of(&key))
}

/// The address a contract gets when a factory deploys it with a salt: the
/// same on every chain, and computable before anything is deployed.
pub fn create2(factory: &Address, salt: &[u8; 32], init_code_hash: &[u8; 32]) -> Address {
    last_20(&keccak256(&[&[0xff], factory, salt, init_code_hash]))
}

/// The salt an identity's smart account is deployed with: a digest of its
/// ID, so the account address follows from the identity and nothing else
/// the owner chooses.
pub fn account_salt(id: &PrincipalId) -> [u8; 32] {
    keccak256(&[b"isonomic-id/v1/account\0", id.as_str().as_bytes()])
}

struct Len32;

impl hkdf::KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

/// An Ethereum key held in software.
pub struct EthKey(SigningKey);

impl EthKey {
    /// A new random key.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        // The system generator failing is not a state this library can run in.
        SystemRandom::new()
            .fill(&mut seed)
            .expect("system random generator");
        Self::from_seed(&seed)
    }

    /// The key derived from a seed, the same every time. Deriving it from
    /// the recovery kit's seed means the kit brings the Ethereum key back.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"isonomic-id/v1").extract(seed);
        for counter in 0..=u8::MAX {
            let info = [b"eth".as_slice(), &[counter]];
            let mut bytes = [0u8; 32];
            let filled = prk
                .expand(&info, Len32)
                .and_then(|okm| okm.fill(&mut bytes));
            if let (Ok(()), Some(key)) = (filled, Self::from_bytes(&bytes)) {
                return key;
            }
        }
        // 256 outputs in a row outside the curve order cannot happen.
        unreachable!("no valid key derived from the seed")
    }

    /// The key with exactly these secret bytes, if they are a valid key.
    pub fn from_bytes(secret: &[u8; 32]) -> Option<Self> {
        SigningKey::from_slice(secret).ok().map(EthKey)
    }

    /// The key's address.
    pub fn address(&self) -> Address {
        address_of(self.0.verifying_key())
    }

    /// Signs a personal message the way wallets do: 65 bytes, ending in 27
    /// or 28.
    pub fn sign_message(&self, msg: &[u8]) -> Vec<u8> {
        let (sig, recovery) = self
            .0
            .sign_prehash_recoverable(&message_hash(msg))
            .expect("signing a 32-byte hash");
        let mut out = sig.to_bytes().to_vec();
        out.push(27 + recovery.to_byte());
        out
    }

    /// The binding of this key to `id`, ready to put in a log entry.
    pub fn bind(&self, id: &PrincipalId) -> Binding {
        Binding {
            scheme: SCHEME.to_string(),
            subject: self.address().to_vec(),
            proof: self.sign_message(&binding_message(id)),
        }
    }
}

/// Checks Ethereum bindings in a key log. Pass it to `replay`.
pub struct EthBinding;

impl BindingCheck for EthBinding {
    fn scheme(&self) -> &str {
        SCHEME
    }

    fn verify(&self, id: &PrincipalId, binding: &Binding) -> bool {
        let signed_by = recover(&binding_message(id), &binding.proof);
        signed_by.is_some_and(|address| address.as_slice() == binding.subject.as_slice())
    }
}

/// The Ethereum address bound to an identity, if it has one.
pub fn bound_address(state: &State) -> Option<Address> {
    let binding = state.bindings.get(SCHEME)?;
    binding.subject.as_slice().try_into().ok()
}
