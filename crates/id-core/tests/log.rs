//! The key log, through the life of one identity.

use id_core::log::{Commitment, Directory, Kind, Log, LogError, Op};
use id_core::{KeyAlg, KeyResolver, Signed, Signer};
use id_keys::{KeyStore, MemoryKeyStore, StoredKey};
use std::sync::Arc;

struct Keys(Arc<dyn KeyStore>);

impl Keys {
    fn new() -> Self {
        Keys(Arc::new(MemoryKeyStore::new()))
    }
    fn make(&self, label: &str) -> StoredKey {
        StoredKey::generate(self.0.clone(), KeyAlg::P256, label).expect("key")
    }
}

fn dev(key: &StoredKey) -> Commitment {
    Commitment::device(&key.public_key())
}

fn kit(key: &StoredKey) -> Commitment {
    Commitment::recovery(&key.public_key())
}

fn add(key: &StoredKey) -> Op {
    Op::add(key.public_key())
}

fn remove(key: &StoredKey) -> Op {
    Op::RemoveKey(key.public_key())
}

/// A person with one device `d1`, its rotation key `r1` and a kit key `k1`.
fn person(keys: &Keys) -> (Log, StoredKey, StoredKey, StoredKey) {
    let (d1, r1, k1) = (keys.make("d1"), keys.make("r1"), keys.make("k1"));
    let next = vec![dev(&r1), kit(&k1)];
    let log = Log::create(Kind::Person, None, vec![add(&d1)], next, 100, &d1).expect("create");
    (log, d1, r1, k1)
}

#[test]
fn devices_are_added_replaced_and_recovered_offline_under_one_id() {
    let keys = Keys::new();
    let (mut log, d1, r1, k1) = person(&keys);
    let id = log.id().clone();
    assert!(id.as_str().starts_with("did:iso:") && id.as_str().len() == 72);

    // Device 1 admits device 2. Each device now has its own rotation key.
    let (d2, r1b, r2) = (keys.make("d2"), keys.make("r1b"), keys.make("r2"));
    let next = vec![dev(&r1b), dev(&r2), kit(&k1)];
    log.append(vec![add(&d2)], next, 110, &r1, &[])
        .expect("add");
    r1.destroy().expect("used once");

    // Device 2 replaces its signing key.
    let (d2b, r2b) = (keys.make("d2b"), keys.make("r2b"));
    let next = vec![dev(&r1b), dev(&r2b), kit(&k1)];
    let ops = vec![remove(&d2), add(&d2b)];
    log.append(ops, next, 120, &r2, &[]).expect("replace");

    // Device 1 is lost. The kit removes it and admits device 3.
    let (d3, r3, k2) = (keys.make("d3"), keys.make("r3"), keys.make("k2"));
    let next = vec![dev(&r2b), dev(&r3), kit(&k2)];
    let ops = vec![remove(&d1), add(&d3)];
    let state = log.append(ops, next, 130, &k1, &[]).expect("recover");
    assert_eq!(state.id, id);
    assert_eq!(state.seq, 3);

    // A second verifier gets only bytes.
    let bytes: Vec<Vec<u8>> = log
        .entries()
        .iter()
        .map(|e| e.to_bytes().expect("encode"))
        .collect();
    let shown: Vec<Signed> = bytes
        .iter()
        .map(|b| Signed::from_bytes(b).expect("decode"))
        .collect();
    let mut directory = Directory::default();
    let seen = directory.accept(&shown, &[]).expect("verifies").clone();
    assert_eq!(&seen, log.state());
    assert!(directory.is_current_key(&id, &d3.public_key(), 0));
    assert!(directory.is_current_key(&id, &d2b.public_key(), 0));
    assert!(!directory.is_current_key(&id, &d1.public_key(), 0));
    assert!(!directory.is_current_key(&id, &d2.public_key(), 0));
}

#[test]
fn only_a_committed_unused_rotation_key_can_change_the_log() {
    let keys = Keys::new();
    let (mut log, d1, r1, k1) = person(&keys);
    let thief = keys.make("thief");
    let r1b = keys.make("r1b");
    let good = vec![dev(&r1b), kit(&k1)];

    // An everyday signing key, and a key nobody committed to.
    for signer in [&d1, &thief] {
        let tried = log.append(vec![add(&thief)], good.clone(), 110, signer, &[]);
        assert_eq!(tried.err(), Some(LogError::NotCommitted(1)));
    }
    // A rotation key may not commit to itself again.
    let again = vec![dev(&r1), kit(&k1)];
    let tried = log.append(vec![], again, 110, &r1, &[]);
    assert_eq!(tried.err(), Some(LogError::Reused(1)));
    // A device rotation key may not drop or swap the recovery kit.
    for next in [vec![dev(&r1b)], vec![dev(&r1b), kit(&thief)]] {
        let tried = log.append(vec![], next, 110, &r1, &[]);
        assert_eq!(tried.err(), Some(LogError::RecoveryChanged(1)));
    }
    // Time does not go backwards.
    let tried = log.append(vec![], good.clone(), 99, &r1, &[]);
    assert_eq!(tried.err(), Some(LogError::BrokenChain(1)));
    assert_eq!(log.state().seq, 0);

    // Used properly it works once, and then it is spent.
    log.append(vec![], good, 110, &r1, &[]).expect("append");
    let tried = log.append(vec![add(&thief)], vec![kit(&k1)], 120, &r1, &[]);
    assert_eq!(tried.err(), Some(LogError::NotCommitted(2)));
}

#[test]
fn a_fork_is_refused_by_anyone_who_saw_the_real_log() {
    let keys = Keys::new();
    let (mut log, d1, r1, k1) = person(&keys);
    let (d2, r1b, r2) = (keys.make("d2"), keys.make("r1b"), keys.make("r2"));
    let next = vec![dev(&r1b), dev(&r2), kit(&k1)];
    log.append(vec![add(&d2)], next, 110, &r1, &[])
        .expect("add");
    let stolen_at = log.clone();

    // The owner carries on: the kit removes the stolen device.
    let (k2, thief) = (keys.make("k2"), keys.make("thief"));
    let next = vec![dev(&r2), kit(&k2)];
    log.append(vec![remove(&d1)], next, 120, &k1, &[])
        .expect("evict");

    // The thief holds device 1's unused rotation key and forks.
    let mut forged = stolen_at.clone();
    let next = vec![dev(&thief), kit(&k1)];
    let ops = vec![remove(&d2), add(&thief)];
    forged.append(ops, next, 120, &r1b, &[]).expect("forge");

    // A newcomer shown only the forged log has no way to tell.
    assert!(Directory::default().accept(forged.entries(), &[]).is_ok());

    // Anyone who has seen the real log refuses the fork, and is told that
    // the competing entry was not signed by the recovery kit.
    let mut directory = Directory::default();
    directory.accept(log.entries(), &[]).expect("real log");
    let fork = LogError::Fork {
        at: 2,
        by_recovery: false,
    };
    assert_eq!(directory.accept(forged.entries(), &[]).err(), Some(fork));
    assert!(!directory.is_current_key(log.id(), &thief.public_key(), 0));

    // The other way round, the verifier is told the kit signed it.
    let mut fooled = Directory::default();
    fooled.accept(forged.entries(), &[]).expect("forged first");
    let fork = LogError::Fork {
        at: 2,
        by_recovery: true,
    };
    assert_eq!(fooled.accept(log.entries(), &[]).err(), Some(fork));

    // An older copy of the real log is accepted and changes nothing.
    let state = directory.accept(stolen_at.entries(), &[]).expect("older");
    assert_eq!(state.seq, 2);
}

#[test]
fn tampered_reordered_and_misrooted_logs_are_refused() {
    let keys = Keys::new();
    let (mut log, d1, r1, k1) = person(&keys);
    let r1b = keys.make("r1b");
    let next = vec![dev(&r1b), kit(&k1)];
    log.append(vec![], next, 110, &r1, &[]).expect("append");
    let entries = log.entries().to_vec();

    assert_eq!(Log::open(vec![], &[]).err(), Some(LogError::Empty));
    let reversed = vec![entries[1].clone(), entries[0].clone()];
    assert_eq!(Log::open(reversed, &[]).err(), Some(LogError::Malformed(0)));
    let doubled = vec![entries[0].clone(), entries[0].clone()];
    assert_eq!(Log::open(doubled, &[]).err(), Some(LogError::Malformed(1)));

    let mut bytes = entries[0].to_bytes().expect("encode");
    let at = bytes.windows(6).position(|w| w == b"person").expect("kind");
    bytes[at..at + 6].copy_from_slice(b"pErson");
    let tampered = Signed::from_bytes(&bytes).expect("decode");
    assert_eq!(
        Log::open(vec![tampered], &[]).err(),
        Some(LogError::BadSignature(0))
    );

    // The first entry must be signed by a key it adds.
    let other = keys.make("other");
    let made = Log::create(Kind::Person, None, vec![add(&d1)], vec![], 100, &other);
    assert_eq!(made.err(), Some(LogError::GenesisSigner));

    // Two identities made from the same keys still have different IDs.
    let twin = Log::create(Kind::Person, None, vec![add(&d1)], vec![], 100, &d1).expect("twin");
    assert_ne!(twin.id(), log.id());
}

#[test]
fn an_agent_has_its_own_log_that_names_its_owner() {
    let keys = Keys::new();
    let (owner, ..) = person(&keys);
    let (a1, ar1) = (keys.make("a1"), keys.make("ar1"));
    let controller = Some(owner.id().clone());
    let mut agent = Log::create(
        Kind::Agent,
        controller,
        vec![add(&a1)],
        vec![dev(&ar1)],
        100,
        &a1,
    )
    .expect("agent");
    assert_eq!(agent.state().kind, Kind::Agent);
    assert_eq!(agent.state().controller.as_ref(), Some(owner.id()));
    assert_ne!(agent.id(), owner.id());

    // Moving to a new owner is one entry; the ID does not change.
    let id = agent.id().clone();
    let (new_owner, ..) = person(&Keys::new());
    let ops = vec![Op::SetController(new_owner.id().clone())];
    let state = agent.append(ops, vec![], 110, &ar1, &[]).expect("move");
    assert_eq!(state.controller.as_ref(), Some(new_owner.id()));
    assert_eq!(state.id, id);
}
