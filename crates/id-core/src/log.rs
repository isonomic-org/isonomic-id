//! The key log.
//!
//! An identity is a small, append-only, signed log that its owner keeps. The
//! ID is the digest of the first entry, so it never changes. Every later
//! entry names the entry before it and is signed by a rotation key that the
//! previous entry committed to by fingerprint. A rotation key is used once.
//!
//! Two kinds of key never mix:
//!
//! - **Signing keys**, one per device, sign grants and data. They are listed
//!   in the log and have no power to change it.
//! - **Rotation keys** change the log. Each is committed in advance with a
//!   role: `device` for everyday changes, `recovery` for the recovery kit.
//!   Only a recovery key may change which recovery keys are committed, so a
//!   stolen device cannot lock the owner's kit out.
//!
//! Anyone handed the log can verify all of it offline with [`replay`]. A
//! [`Directory`] remembers what it has accepted and refuses a log that is
//! not a continuation of it.

use crate::{
    from_cbor, to_cbor, Digest, KeyResolver, PrincipalId, PublicKey, Signed, Signer, Timestamp,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// The signing and hashing domain of log entries.
pub const DOMAIN: &str = "log";
/// The only entry version this crate reads and writes.
pub const VERSION: u8 = 1;
/// The longest log [`replay`] accepts.
pub const MAX_ENTRIES: usize = 4096;

/// What kind of principal a log belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    #[serde(rename = "person")]
    Person,
    #[serde(rename = "agent")]
    Agent,
    #[serde(rename = "app")]
    App,
}

/// What a rotation key is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Role {
    /// Held by one device, for everyday changes.
    #[serde(rename = "device")]
    Device,
    /// Derived from the recovery kit.
    #[serde(rename = "recovery")]
    Recovery,
}

/// A promise that the key with this fingerprint may sign the next entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Commitment {
    #[serde(rename = "k")]
    pub key: Digest,
    #[serde(rename = "r")]
    pub role: Role,
}

impl Commitment {
    /// Commits to a device's next rotation key.
    pub fn device(key: &PublicKey) -> Self {
        Commitment {
            key: key.fingerprint(),
            role: Role::Device,
        }
    }

    /// Commits to the recovery kit's next rotation key.
    pub fn recovery(key: &PublicKey) -> Self {
        Commitment {
            key: key.fingerprint(),
            role: Role::Recovery,
        }
    }
}

/// What only the first entry carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Genesis {
    #[serde(rename = "kind")]
    pub kind: Kind,
    /// For an agent or an app: the principal that owns it.
    #[serde(rename = "ctl", default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<PrincipalId>,
    /// Random bytes, so two logs never share an ID.
    #[serde(rename = "n", with = "serde_bytes")]
    pub nonce: [u8; 16],
}

/// A link to an account outside Isonomic, proved from both sides: the log
/// entry is signed by the identity, and `proof` is signed by the account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    /// Which kind of account, for example `eth`.
    #[serde(rename = "s")]
    pub scheme: String,
    /// The account, in the scheme's own encoding.
    #[serde(rename = "a", with = "serde_bytes")]
    pub subject: Vec<u8>,
    /// The account's signature over this identity's ID.
    #[serde(rename = "p", with = "serde_bytes")]
    pub proof: Vec<u8>,
}

/// Checks bindings of one scheme. The Ethereum crate provides one; this
/// crate knows no scheme itself.
pub trait BindingCheck {
    /// The scheme this checker understands.
    fn scheme(&self) -> &str;
    /// True when `binding.proof` is the account's signature over `id`.
    fn verify(&self, id: &PrincipalId, binding: &Binding) -> bool;
}

/// One change to an identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    /// Adds a signing key, with the encryption key that goes with it.
    #[serde(rename = "add")]
    AddKey {
        #[serde(rename = "k")]
        key: PublicKey,
        #[serde(rename = "e", default, skip_serializing_if = "Option::is_none")]
        enc: Option<ByteBuf>,
    },
    /// Removes a signing key.
    #[serde(rename = "remove")]
    RemoveKey(PublicKey),
    /// Binds an outside account, replacing any binding of the same scheme.
    /// It cannot appear in the first entry, because its proof signs the ID.
    #[serde(rename = "bind")]
    Bind(Binding),
    /// Drops the binding of a scheme.
    #[serde(rename = "unbind")]
    Unbind(String),
    /// Moves an agent or an app to a new owner.
    #[serde(rename = "ctl")]
    SetController(PrincipalId),
}

impl Op {
    /// Adds a signing key with no encryption key.
    pub fn add(key: PublicKey) -> Self {
        Op::AddKey { key, enc: None }
    }
}

/// The body of a log entry, before signing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    #[serde(rename = "v")]
    pub version: u8,
    #[serde(rename = "seq")]
    pub seq: u64,
    #[serde(rename = "prev", default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<Digest>,
    #[serde(rename = "gen", default, skip_serializing_if = "Option::is_none")]
    pub genesis: Option<Genesis>,
    #[serde(rename = "ops")]
    pub ops: Vec<Op>,
    /// The keys that may sign the next entry.
    #[serde(rename = "next")]
    pub next: Vec<Commitment>,
    /// When the author says the entry was written. Never goes backwards.
    #[serde(rename = "at")]
    pub at: Timestamp,
}

/// Why a log was refused. Numbers are entry positions, from zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogError {
    Empty,
    TooLong,
    /// The entry does not decode, or has the wrong version or position.
    Malformed(u64),
    BadSignature(u64),
    /// The entry does not follow the one before it.
    BrokenChain(u64),
    /// The first entry is not signed by a key it adds.
    GenesisSigner,
    /// The signer was not committed to by the previous entry.
    NotCommitted(u64),
    /// The entry commits again to the rotation key that signed it.
    Reused(u64),
    /// A device rotation key tried to change the recovery commitments.
    RecoveryChanged(u64),
    /// A binding has no checker, or its proof does not verify.
    Binding(u64),
    /// The key store refused to sign.
    Signing,
    /// The log shown is not a continuation of the one accepted before. It
    /// parts ways at entry `at`; `by_recovery` says whether the competing
    /// entry was signed by a recovery key. A person decides what to do.
    Fork {
        at: u64,
        by_recovery: bool,
    },
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for LogError {}

/// What a verified log says about its identity right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub id: PrincipalId,
    pub kind: Kind,
    pub controller: Option<PrincipalId>,
    /// Current signing keys, each with its encryption key if it has one.
    pub keys: BTreeMap<PublicKey, Option<Vec<u8>>>,
    /// The keys that may sign the next entry.
    pub next: Vec<Commitment>,
    /// Bound outside accounts, by scheme.
    pub bindings: BTreeMap<String, Binding>,
    /// The digest of the latest entry. This is what gets anchored later.
    pub head: Digest,
    pub seq: u64,
    pub at: Timestamp,
}

fn open(n: u64, signed: &Signed) -> Result<Entry, LogError> {
    signed
        .verify(DOMAIN)
        .map_err(|_| LogError::BadSignature(n))?;
    let entry: Entry = from_cbor(signed.payload()).map_err(|_| LogError::Malformed(n))?;
    if entry.version != VERSION || entry.seq != n {
        return Err(LogError::Malformed(n));
    }
    Ok(entry)
}

fn recovery_keys(next: &[Commitment]) -> BTreeSet<Digest> {
    let recovery = next.iter().filter(|c| c.role == Role::Recovery);
    recovery.map(|c| c.key).collect()
}

impl State {
    fn start(first: &Signed, checks: &[&dyn BindingCheck]) -> Result<Self, LogError> {
        let entry = open(0, first)?;
        let genesis = entry.genesis.clone().ok_or(LogError::BrokenChain(0))?;
        if entry.prev.is_some() {
            return Err(LogError::BrokenChain(0));
        }
        let head = first.id(DOMAIN);
        let mut state = State {
            id: PrincipalId::from_genesis(&head),
            kind: genesis.kind,
            controller: genesis.controller,
            keys: BTreeMap::new(),
            next: Vec::new(),
            bindings: BTreeMap::new(),
            head,
            seq: 0,
            at: entry.at,
        };
        state.run(entry, checks)?;
        if !state.keys.contains_key(first.signer()) {
            return Err(LogError::GenesisSigner);
        }
        Ok(state)
    }

    fn step(&mut self, signed: &Signed, checks: &[&dyn BindingCheck]) -> Result<(), LogError> {
        let n = self.seq + 1;
        let entry = open(n, signed)?;
        if entry.genesis.is_some() || entry.prev != Some(self.head) || entry.at < self.at {
            return Err(LogError::BrokenChain(n));
        }
        let signer = signed.signer().fingerprint();
        let committed = self.next.iter().find(|c| c.key == signer);
        let role = committed.ok_or(LogError::NotCommitted(n))?.role;
        if entry.next.iter().any(|c| c.key == signer) {
            return Err(LogError::Reused(n));
        }
        if role == Role::Device && recovery_keys(&entry.next) != recovery_keys(&self.next) {
            return Err(LogError::RecoveryChanged(n));
        }
        self.head = signed.id(DOMAIN);
        self.seq = n;
        self.at = entry.at;
        self.run(entry, checks)
    }

    fn run(&mut self, entry: Entry, checks: &[&dyn BindingCheck]) -> Result<(), LogError> {
        for op in entry.ops {
            match op {
                Op::AddKey { key, enc } => {
                    self.keys.insert(key, enc.map(ByteBuf::into_vec));
                }
                Op::RemoveKey(key) => {
                    self.keys.remove(&key);
                }
                Op::Bind(binding) => {
                    let check = checks.iter().find(|c| c.scheme() == binding.scheme);
                    if entry.seq == 0 || !check.is_some_and(|c| c.verify(&self.id, &binding)) {
                        return Err(LogError::Binding(entry.seq));
                    }
                    self.bindings.insert(binding.scheme.clone(), binding);
                }
                Op::Unbind(scheme) => {
                    self.bindings.remove(&scheme);
                }
                Op::SetController(owner) => self.controller = Some(owner),
            }
        }
        self.next = entry.next;
        Ok(())
    }
}

/// Verifies a whole log from its first entry, with nothing but the log.
pub fn replay(log: &[Signed], checks: &[&dyn BindingCheck]) -> Result<State, LogError> {
    let (first, rest) = log.split_first().ok_or(LogError::Empty)?;
    if log.len() > MAX_ENTRIES {
        return Err(LogError::TooLong);
    }
    let mut state = State::start(first, checks)?;
    for signed in rest {
        state.step(signed, checks)?;
    }
    Ok(state)
}

fn seal(entry: &Entry, signer: &dyn Signer) -> Result<Signed, LogError> {
    let payload = to_cbor(entry).map_err(|_| LogError::Malformed(entry.seq))?;
    Signed::seal(DOMAIN, payload, signer).map_err(|_| LogError::Signing)
}

/// A log its owner can add to.
#[derive(Clone, Debug)]
pub struct Log {
    entries: Vec<Signed>,
    state: State,
}

impl Log {
    /// Starts an identity. `signer` must be one of the keys `ops` adds.
    pub fn create(
        kind: Kind,
        controller: Option<PrincipalId>,
        ops: Vec<Op>,
        next: Vec<Commitment>,
        at: Timestamp,
        signer: &dyn Signer,
    ) -> Result<Self, LogError> {
        let mut nonce = [0u8; 16];
        // The system generator failing is not a state this library can run in.
        SystemRandom::new()
            .fill(&mut nonce)
            .expect("system random generator");
        let entry = Entry {
            version: VERSION,
            seq: 0,
            prev: None,
            genesis: Some(Genesis {
                kind,
                controller,
                nonce,
            }),
            ops,
            next,
            at,
        };
        let first = seal(&entry, signer)?;
        let state = State::start(&first, &[])?;
        Ok(Log {
            entries: vec![first],
            state,
        })
    }

    /// Verifies stored entries and takes them up again.
    pub fn open(entries: Vec<Signed>, checks: &[&dyn BindingCheck]) -> Result<Self, LogError> {
        let state = replay(&entries, checks)?;
        Ok(Log { entries, state })
    }

    /// Adds an entry signed by a committed rotation key. The caller destroys
    /// that key afterwards. Nothing changes if the entry is refused.
    pub fn append(
        &mut self,
        ops: Vec<Op>,
        next: Vec<Commitment>,
        at: Timestamp,
        rotation_key: &dyn Signer,
        checks: &[&dyn BindingCheck],
    ) -> Result<&State, LogError> {
        let entry = Entry {
            version: VERSION,
            seq: self.state.seq + 1,
            prev: Some(self.state.head),
            genesis: None,
            ops,
            next,
            at,
        };
        let signed = seal(&entry, rotation_key)?;
        let mut state = self.state.clone();
        state.step(&signed, checks)?;
        self.entries.push(signed);
        self.state = state;
        Ok(&self.state)
    }

    /// The signed entries, oldest first. This is what is stored and shared.
    pub fn entries(&self) -> &[Signed] {
        &self.entries
    }

    /// The identity's current state.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// The identity's ID.
    pub fn id(&self) -> &PrincipalId {
        &self.state.id
    }
}

/// The logs a verifier has accepted, one per identity.
#[derive(Clone, Debug, Default)]
pub struct Directory {
    known: BTreeMap<PrincipalId, (Vec<Digest>, State)>,
}

impl Directory {
    /// Verifies a log and remembers it. A longer continuation of a known log
    /// replaces it; an older copy changes nothing; a log that parts ways
    /// with the known one is refused as a [`LogError::Fork`].
    pub fn accept(
        &mut self,
        log: &[Signed],
        checks: &[&dyn BindingCheck],
    ) -> Result<&State, LogError> {
        let state = replay(log, checks)?;
        let shown: Vec<Digest> = log.iter().map(|e| e.id(DOMAIN)).collect();
        let id = state.id.clone();
        let newer = match self.known.get(&id) {
            None => true,
            Some((seen, _)) => {
                let same = seen.iter().zip(&shown).take_while(|(a, b)| a == b).count();
                if same < seen.len() && same < shown.len() {
                    let by_recovery = signer_role(log, same) == Some(Role::Recovery);
                    return Err(LogError::Fork {
                        at: same as u64,
                        by_recovery,
                    });
                }
                shown.len() > seen.len()
            }
        };
        if newer {
            self.known.insert(id.clone(), (shown, state));
        }
        Ok(&self.known[&id].1)
    }

    /// The last accepted state of an identity.
    pub fn state(&self, id: &PrincipalId) -> Option<&State> {
        self.known.get(id).map(|(_, state)| state)
    }
}

impl KeyResolver for Directory {
    fn is_current_key(&self, principal: &PrincipalId, key: &PublicKey, _at: Timestamp) -> bool {
        self.state(principal)
            .is_some_and(|state| state.keys.contains_key(key))
    }
}

/// The role under which entry `i` of a verified log was signed.
fn signer_role(log: &[Signed], i: usize) -> Option<Role> {
    let before: Entry = from_cbor(log.get(i.checked_sub(1)?)?.payload()).ok()?;
    let signer = log.get(i)?.signer().fingerprint();
    let committed = before.next.iter().find(|c| c.key == signer)?;
    Some(committed.role)
}
