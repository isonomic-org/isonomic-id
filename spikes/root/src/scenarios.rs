// Copyright 2026 Anud Inc.
// SPDX-License-Identifier: Apache-2.0

//! The same ten tests, run against each way of rooting an identity.

use crate::account::{self, AccountError, Chain};
use crate::eth::{self, EthKey};
use crate::keylog::{self, append, replay, LogError, Op, Pinned};
use id_core::{KeyAlg, Signed, Signer};
use id_keys::{KeyStore, MemoryKeyStore, StoredKey};
use std::collections::BTreeSet;
use std::sync::Arc;

pub const TESTS: [&str; 10] = [
    "create with no network",
    "add a second device, no network",
    "lose a device, recover from the kit, no network",
    "replace a key, no network",
    "a second Capsule verifies everything, no network",
    "a stolen old key cannot extend the real history",
    "a stolen old key cannot fool a newcomer with a forged history",
    "a misused everyday signing key cannot change the keys",
    "bind and verify the Ethereum address, no network",
    "move to a new account version and keep the identity",
];

pub struct Outcome {
    pub pass: bool,
    pub note: &'static str,
}

fn outcome(pass: bool, note: &'static str) -> Outcome {
    Outcome { pass, note }
}

struct Keys(Arc<dyn KeyStore>);

impl Keys {
    fn new() -> Self {
        Keys(Arc::new(MemoryKeyStore::new()))
    }
    /// A P-256 key, the kind a Mac's secure chip holds.
    fn make(&self, label: &str) -> StoredKey {
        StoredKey::generate(self.0.clone(), KeyAlg::P256, label).expect("key")
    }
}

/// Option C: a key log with an Ethereum account bound in.
pub fn key_log() -> Vec<Outcome> {
    let keys = Keys::new();
    let fp = |k: &StoredKey| k.public_key().fingerprint();
    let pk = |k: &StoredKey| k.public_key();
    let [d1, d2, d3, d2b, thief] = ["d1", "d2", "d3", "d2b", "thief"].map(|l| keys.make(l));
    let [first, r1, r1b, r2, r2b, r3, r3b, kit, kit2] = [
        "first", "r1", "r1b", "r2", "r2b", "r3", "r3b", "kit", "kit2",
    ]
    .map(|l| keys.make(l));
    let mut out = Vec::new();
    let mut log: Vec<Signed> = Vec::new();

    // 1. Create: device 1, with its next rotation key and the recovery kit
    // committed in advance.
    let created = append(
        &mut log,
        vec![Op::AddDevice(pk(&d1))],
        vec![fp(&r1), fp(&kit)],
        &first,
    );
    let id = created.as_ref().map(|s| s.id).expect("created");
    out.push(outcome(
        created.is_ok(),
        "the ID is the digest of the first entry",
    ));

    // 2. Device 1 admits device 2, then destroys the rotation key it used.
    let added = append(
        &mut log,
        vec![Op::AddDevice(pk(&d2))],
        vec![fp(&r1b), fp(&r2), fp(&kit)],
        &r1,
    );
    let spent_key = r1.clone();
    r1.destroy().expect("destroy");
    out.push(outcome(added.is_ok(), "one signed entry"));

    // 3. Device 1 is lost with its signing key and its rotation key r1b.
    // The kit removes it and admits device 3.
    let before_recovery = log.clone();
    let recovered = append(
        &mut log,
        vec![Op::RemoveDevice(pk(&d1)), Op::AddDevice(pk(&d3))],
        vec![fp(&r2), fp(&r3), fp(&kit2)],
        &kit,
    );
    out.push(outcome(recovered.is_ok(), "one entry signed by the kit"));

    // 4. Device 2 replaces its signing key.
    let replaced = append(
        &mut log,
        vec![Op::RemoveDevice(pk(&d2)), Op::AddDevice(pk(&d2b))],
        vec![fp(&r2b), fp(&r3), fp(&kit2)],
        &r2,
    );
    out.push(outcome(replaced.is_ok(), "one signed entry"));

    // 5. A second Capsule gets only the log's bytes.
    let bytes: Vec<Vec<u8>> = log.iter().map(|e| e.to_bytes().expect("encode")).collect();
    let shown: Vec<Signed> = bytes
        .iter()
        .map(|b| Signed::from_bytes(b).expect("decode"))
        .collect();
    let seen = replay(&shown);
    let current: BTreeSet<_> = [pk(&d3), pk(&d2b)].into();
    out.push(outcome(
        seen.as_ref()
            .is_ok_and(|s| s.devices == current && s.id == id),
        "replays the log; needs nothing else",
    ));

    // 6. The thief tries to continue the real log with every old key.
    let attempt = |signer: &StoredKey| {
        let mut copy = log.clone();
        append(&mut copy, vec![Op::AddDevice(pk(&thief))], vec![], signer)
    };
    let refused = [&d1, &r1b]
        .iter()
        .all(|k| attempt(k) == Err(LogError::NotCommitted(4)))
        && attempt(&spent_key).is_err();
    out.push(outcome(
        refused,
        "old keys are not committed to; used ones no longer exist",
    ));

    // 7. The thief forks the log at the point where r1b was still good.
    let mut forged = before_recovery.clone();
    let fork = append(
        &mut forged,
        vec![Op::RemoveDevice(pk(&d2)), Op::AddDevice(pk(&thief))],
        vec![fp(&thief)],
        &r1b,
    );
    let newcomer_fooled = fork.is_ok() && replay(&forged).is_ok();
    let mut pinned = Pinned::default();
    let caught = pinned.accept(&log).is_ok() && pinned.accept(&forged) == Err(LogError::Fork);
    out.push(outcome(
        !newcomer_fooled,
        if caught {
            "a newcomer is fooled; anyone who saw the real log refuses the fork"
        } else {
            "fork not caught"
        },
    ));

    // 8. Code that can use device 3's everyday signing key tries to add a key.
    out.push(outcome(
        attempt(&d3) == Err(LogError::NotCommitted(4)),
        "signing keys have no say over the log",
    ));

    // 9. Bind an Ethereum key and its account, signed in both directions.
    let eth_key = EthKey::generate();
    let bind = |key: &EthKey, account: eth::Address| Op::BindEth {
        key: key.address(),
        account,
        proof: key.sign_message(&keylog::binding_message(&id, &account)),
    };
    let account = keylog::bound_account(&id, &eth_key.address());
    let bound = append(
        &mut log,
        vec![bind(&eth_key, account)],
        vec![fp(&r3b), fp(&kit2)],
        &r3,
    );
    let mut wrong = log.clone();
    let mismatch = append(&mut wrong, vec![bind(&eth_key, [7; 20])], vec![], &r3b);
    out.push(outcome(
        bound.is_ok_and(|s| s.eth == Some((eth_key.address(), account)))
            && mismatch == Err(LogError::BadBinding(5)),
        "log binds the address and the address signs the ID",
    ));

    // 10. Bind a different Ethereum key and account: same ID.
    let eth_key2 = EthKey::generate();
    let account2 = keylog::bound_account(&id, &eth_key2.address());
    let rebound = append(
        &mut log,
        vec![bind(&eth_key2, account2)],
        vec![fp(&kit2)],
        &r3b,
    );
    out.push(outcome(
        rebound.is_ok_and(|s| s.id == id && s.eth == Some((eth_key2.address(), account2))),
        "the Ethereum account is an attachment and can be replaced",
    ));
    out
}

/// Option A: a smart-account address as the identity. `queued` keeps signed
/// key changes locally; otherwise every change is a transaction.
pub fn smart_account(queued: bool) -> Vec<Outcome> {
    let keys = Keys::new();
    let pk = |k: &StoredKey| k.public_key();
    let [d1, d2, d3, d2b, kit, thief] =
        ["d1", "d2", "d3", "d2b", "kit", "thief"].map(|l| keys.make(l));
    let acct = account::create(&[pk(&d1), pk(&kit)]);
    let mut out = vec![outcome(true, "the address is computed before deployment")];

    // 2 to 4: the same three key changes as above.
    let changes = [
        account::sign_change(&acct, 0, &[pk(&d2)], &[], &d1),
        account::sign_change(&acct, 1, &[pk(&d3)], &[pk(&d1)], &kit),
        account::sign_change(&acct, 2, &[pk(&d2b)], &[pk(&d2)], &d2),
    ];
    let mut chain_x = Chain::default();
    for (n, change) in changes.iter().enumerate() {
        if queued {
            let held = account::replay_queue(&acct, &changes[..=n]).is_ok();
            out.push(outcome(held, "signed offline and held for a chain later"));
        } else {
            let refused = chain_x.submit(&acct, change) == Err(AccountError::Offline);
            out.push(outcome(
                !refused,
                "needs a transaction and a fee, on every chain",
            ));
        }
    }

    // 5. What can a second Capsule know with no network?
    let current: BTreeSet<_> = [pk(&kit), pk(&d3), pk(&d2b)].into();
    if queued {
        let replayed = account::replay_queue(&acct, &changes);
        out.push(outcome(
            replayed == Ok(current),
            "replays the held changes: a key log by another name",
        ));
    } else {
        let stale = acct.first_owners.contains(&pk(&d1));
        out.push(outcome(
            !stale,
            "sees only the first owners, which still include the lost device",
        ));
    }

    // 6. Once the changes have landed on chain X, the old key is refused there.
    chain_x.online = true;
    let landed = changes.iter().all(|c| chain_x.submit(&acct, c).is_ok());
    let late = account::sign_change(&acct, 3, &[pk(&thief)], &[], &d1);
    let refused = landed && chain_x.submit(&acct, &late) == Err(AccountError::NotAnOwner);
    out.push(outcome(
        refused,
        "refused wherever the changes have landed (3 transactions per chain)",
    ));

    // 7. On a chain the account has never used, the first key still rules;
    // and offline, the old key can forge a different history.
    let mut chain_y = Chain {
        online: true,
        ..Chain::default()
    };
    let takeover = account::sign_change(&acct, 0, &[pk(&thief)], &[pk(&kit)], &d1);
    let taken = chain_y.submit(&acct, &takeover).is_ok();
    let forged = [
        changes[0].clone(),
        account::sign_change(&acct, 1, &[pk(&thief)], &[pk(&kit), pk(&d2)], &d1),
    ];
    let fooled = account::replay_queue(&acct, &forged).is_ok();
    out.push(outcome(
        !(taken || (queued && fooled)),
        "the first key still controls the name on every chain not yet updated",
    ));

    // 8. Owner keys are the everyday signing keys, so misuse of one changes the keys.
    let misuse = account::sign_change(&acct, 3, &[pk(&thief)], &[], &d3);
    let changed = chain_x.submit(&acct, &misuse).is_ok();
    out.push(outcome(
        !changed,
        "an owner key signs both data and key changes",
    ));

    // 9. The name is the address.
    out.push(outcome(true, "the identity is the address"));

    // 10. A new account version has a different address, so a different name.
    let mut material = Vec::new();
    acct.first_owners
        .iter()
        .for_each(|k| material.extend_from_slice(&k.bytes));
    let upgraded =
        eth::account_address_with(b"account implementation, version 2", &material, &[0; 32]);
    out.push(outcome(
        upgraded == acct.address,
        "the name is tied to one factory and one account code",
    ));
    out
}
