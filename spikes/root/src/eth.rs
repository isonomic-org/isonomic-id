//! The Ethereum side: a key, its address, a not-yet-deployed account
//! address, and message signatures. Pure computation, no chain calls.

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use ring::rand::{SecureRandom, SystemRandom};
use sha3::{Digest as _, Keccak256};

/// A 20-byte Ethereum address.
pub type Address = [u8; 20];

/// Stand-ins for the account factory and the account code. A real build
/// pins a deployed factory and its code hash; the arithmetic is the same.
const FACTORY: Address = [0xfa; 20];
const ACCOUNT_CODE: &[u8] = b"account implementation, version 1";

pub fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn address_of(key: &VerifyingKey) -> Address {
    let point = key.to_encoded_point(false);
    let hash = keccak(&[&point.as_bytes()[1..]]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

/// The address a smart account will have once deployed, computed the way
/// CREATE2 does: from the factory, a salt and the hash of the code plus its
/// first owners. It can be computed long before anything is deployed, and
/// it is fixed forever by those inputs.
pub fn account_address(first_owners: &[u8], salt: &[u8; 32]) -> Address {
    account_address_with(ACCOUNT_CODE, first_owners, salt)
}

/// The same, for a given version of the account code.
pub fn account_address_with(code: &[u8], first_owners: &[u8], salt: &[u8; 32]) -> Address {
    let init_code_hash = keccak(&[code, first_owners]);
    let hash = keccak(&[&[0xff], &FACTORY, salt, &init_code_hash]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

fn message_hash(msg: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
    keccak(&[prefix.as_bytes(), msg])
}

/// An Ethereum key held in software.
pub struct EthKey(SigningKey);

impl EthKey {
    pub fn generate() -> Self {
        let rng = SystemRandom::new();
        loop {
            let mut bytes = [0u8; 32];
            rng.fill(&mut bytes).expect("system random generator");
            if let Ok(key) = SigningKey::from_slice(&bytes) {
                return EthKey(key);
            }
        }
    }

    pub fn address(&self) -> Address {
        address_of(self.0.verifying_key())
    }

    /// Signs a message the way wallets sign personal messages: 65 bytes.
    pub fn sign_message(&self, msg: &[u8]) -> Vec<u8> {
        let (sig, recovery) = self
            .0
            .sign_prehash_recoverable(&message_hash(msg))
            .expect("signing a 32-byte hash");
        let mut out = sig.to_bytes().to_vec();
        out.push(recovery.to_byte());
        out
    }
}

/// The address that signed `msg`, if the signature is well formed.
pub fn recover(msg: &[u8], sig: &[u8]) -> Option<Address> {
    let (rs, v) = sig.split_at_checked(64)?;
    let sig = Signature::from_slice(rs).ok()?;
    let recovery = RecoveryId::from_byte(*v.first()?)?;
    let key = VerifyingKey::recover_from_prehash(&message_hash(msg), &sig, recovery).ok()?;
    Some(address_of(&key))
}
