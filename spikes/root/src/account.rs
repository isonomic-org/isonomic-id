//! Option A: the identity is a smart-account address.
//!
//! The name is the address the account will have once deployed. It is fixed
//! by the factory, the account code and the first owners. Which keys control
//! the account afterwards is state on a chain, one copy per chain.
//!
//! Two variants are modelled:
//!
//! - **pure**: a key change is a transaction, so it needs the chain.
//! - **queued**: key changes are signed offline, kept locally, and replayed
//!   on a chain later.

use crate::eth::{self, Address};
use id_core::{from_cbor, to_cbor, PublicKey, Signed, Signer};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const DOMAIN: &str = "spike-account";

#[derive(Clone, Debug)]
pub struct Account {
    pub address: Address,
    pub first_owners: BTreeSet<PublicKey>,
}

/// Computes the account's address offline, before anything is deployed.
pub fn create(first_owners: &[PublicKey]) -> Account {
    let first_owners: BTreeSet<PublicKey> = first_owners.iter().cloned().collect();
    let mut material = Vec::new();
    for key in &first_owners {
        material.extend_from_slice(&key.bytes);
    }
    Account {
        address: eth::account_address(&material, &[0u8; 32]),
        first_owners,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Change {
    #[serde(with = "serde_bytes")]
    pub account: Address,
    pub nonce: u64,
    pub add: Vec<PublicKey>,
    pub remove: Vec<PublicKey>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountError {
    /// The chain cannot be reached, so nothing can change.
    Offline,
    NotAnOwner,
    BadNonce,
    Malformed,
}

pub fn sign_change(
    account: &Account,
    nonce: u64,
    add: &[PublicKey],
    remove: &[PublicKey],
    owner: &dyn Signer,
) -> Signed {
    let change = Change {
        account: account.address,
        nonce,
        add: add.to_vec(),
        remove: remove.to_vec(),
    };
    let payload = to_cbor(&change).expect("change encodes");
    Signed::seal(DOMAIN, payload, owner).expect("owner key signs")
}

fn apply(
    owners: &mut BTreeSet<PublicKey>,
    nonce: &mut u64,
    account: &Account,
    signed: &Signed,
) -> Result<(), AccountError> {
    signed
        .verify(DOMAIN)
        .map_err(|_| AccountError::NotAnOwner)?;
    let change: Change = from_cbor(signed.payload()).map_err(|_| AccountError::Malformed)?;
    if change.account != account.address || change.nonce != *nonce {
        return Err(AccountError::BadNonce);
    }
    if !owners.contains(signed.signer()) {
        return Err(AccountError::NotAnOwner);
    }
    for key in change.remove {
        owners.remove(&key);
    }
    owners.extend(change.add);
    *nonce += 1;
    Ok(())
}

/// One chain's copy of the account. Each chain has its own.
#[derive(Default)]
pub struct Chain {
    pub online: bool,
    pub owners: Option<BTreeSet<PublicKey>>,
    pub nonce: u64,
    pub transactions: u32,
}

impl Chain {
    /// Sends a key change as a transaction. The first transaction deploys
    /// the account with its first owners, whatever has happened elsewhere.
    pub fn submit(&mut self, account: &Account, change: &Signed) -> Result<(), AccountError> {
        if !self.online {
            return Err(AccountError::Offline);
        }
        let mut owners = self.owners.clone().unwrap_or(account.first_owners.clone());
        let mut nonce = self.nonce;
        apply(&mut owners, &mut nonce, account, change)?;
        self.owners = Some(owners);
        self.nonce = nonce;
        self.transactions += 1;
        Ok(())
    }
}

/// The queued variant's offline check: start from the first owners and
/// apply every stored key change in order.
pub fn replay_queue(
    account: &Account,
    queue: &[Signed],
) -> Result<BTreeSet<PublicKey>, AccountError> {
    let mut owners = account.first_owners.clone();
    let mut nonce = 0;
    for change in queue {
        apply(&mut owners, &mut nonce, account, change)?;
    }
    Ok(owners)
}
