//! Test helpers: fake principals, a fake world and a manual clock.
//!
//! Principals made here have keys derived from their names, so the same name
//! gives the same key and the same signatures on every run. That is what
//! makes frozen test vectors possible. Nothing here is fit for real keys.

use id_check::{VersionedWorld, World};
use id_core::{Digest, KeyResolver, PrincipalId, PublicKey, Signer, Timestamp};
use id_grants::{GrantId, Revocations};
use id_keys::{KeyStore, MemoryKeyStore, StoredKey};
use id_resource::{ResourceId, ResourceLookup, ResourceMeta};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A principal with a key, for tests.
#[derive(Clone)]
pub struct TestPrincipal {
    /// The principal's ID, `iso:test:<name>`.
    pub id: PrincipalId,
    /// A signer for its key.
    pub key: StoredKey,
}

/// A clock that moves only when told to.
#[derive(Debug)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    /// A clock set to `now`.
    pub fn at(now: Timestamp) -> Self {
        ManualClock(AtomicU64::new(now))
    }

    /// The current time.
    pub fn now(&self) -> Timestamp {
        self.0.load(Ordering::SeqCst)
    }

    /// Moves the clock forward.
    pub fn advance(&self, seconds: u64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

/// An in-memory Capsule as the check function sees it.
pub struct TestWorld {
    store: Arc<MemoryKeyStore>,
    keys: BTreeMap<PrincipalId, Vec<PublicKey>>,
    revoked: BTreeSet<GrantId>,
    resources: BTreeMap<ResourceId, ResourceMeta>,
    spent: BTreeMap<(GrantId, String), u64>,
    members: BTreeSet<(PrincipalId, PrincipalId)>,
    next_resource: u64,
    version: u64,
}

impl Default for TestWorld {
    fn default() -> Self {
        Self::new()
    }
}

impl TestWorld {
    /// An empty world.
    pub fn new() -> Self {
        TestWorld {
            store: Arc::new(MemoryKeyStore::new()),
            keys: BTreeMap::new(),
            revoked: BTreeSet::new(),
            resources: BTreeMap::new(),
            spent: BTreeMap::new(),
            members: BTreeSet::new(),
            next_resource: 1,
            version: 0,
        }
    }

    /// Creates a principal whose key is derived from `name` and registers
    /// that key as current.
    pub fn principal(&mut self, name: &str) -> TestPrincipal {
        let id = PrincipalId::new(format!("iso:test:{name}")).expect("test principal name");
        let seed = *Digest::of("testkit-seed", name.as_bytes()).as_bytes();
        let handle = self
            .store
            .insert_ed25519_seed(name, &seed)
            .expect("unique test principal name");
        let store: Arc<dyn KeyStore> = self.store.clone();
        let key = StoredKey::open(store, handle).expect("key just inserted");
        self.keys
            .entry(id.clone())
            .or_default()
            .push(key.public_key());
        self.version += 1;
        TestPrincipal { id, key }
    }

    /// Registers `key` as a current key of `who`, for principals whose key
    /// was made outside this kit.
    pub fn register(&mut self, who: &PrincipalId, key: PublicKey) {
        self.keys.entry(who.clone()).or_default().push(key);
        self.version += 1;
    }

    /// Makes `who`'s keys no longer current, as after a lost device.
    pub fn drop_keys(&mut self, who: &PrincipalId) {
        self.keys.remove(who);
        self.version += 1;
    }

    /// Adds a resource owned by `owner` and returns its record. IDs count
    /// up from one, so tests can predict them.
    pub fn resource(
        &mut self,
        owner: &TestPrincipal,
        parent: Option<ResourceId>,
        derived_from: &[ResourceId],
    ) -> ResourceMeta {
        let n = self.next_resource;
        self.next_resource += 1;
        let meta = ResourceMeta {
            id: ResourceId::from_parts(n, [n as u8; 10]),
            kind: "doc".to_string(),
            owner: owner.id.clone(),
            parent,
            collection: parent
                .and_then(|p| self.resources.get(&p))
                .map(|p| p.collection)
                .unwrap_or(ResourceId::from_parts(0, [0xc0; 10])),
            derived_from: derived_from.to_vec(),
        };
        self.resources.insert(meta.id, meta.clone());
        meta
    }

    /// Revokes a grant.
    pub fn revoke(&mut self, grant: GrantId) {
        self.revoked.insert(grant);
        self.version += 1;
    }

    /// Records spending under a grant.
    pub fn spend(&mut self, grant: GrantId, unit: &str, amount: u64) {
        *self.spent.entry((grant, unit.to_string())).or_default() += amount;
    }

    /// Makes `who` a member of `group`.
    pub fn add_member(&mut self, who: &PrincipalId, group: &PrincipalId) {
        self.members.insert((who.clone(), group.clone()));
    }
}

impl KeyResolver for TestWorld {
    fn is_current_key(&self, who: &PrincipalId, key: &PublicKey, _at: Timestamp) -> bool {
        self.keys.get(who).is_some_and(|keys| keys.contains(key))
    }
}

impl Revocations for TestWorld {
    fn is_revoked(&self, id: &GrantId) -> bool {
        self.revoked.contains(id)
    }
}

impl ResourceLookup for TestWorld {
    fn resource(&self, id: &ResourceId) -> Option<ResourceMeta> {
        self.resources.get(id).cloned()
    }
}

impl World for TestWorld {
    fn spent(&self, grant: &GrantId, unit: &str) -> u64 {
        self.spent
            .get(&(*grant, unit.to_string()))
            .copied()
            .unwrap_or(0)
    }

    fn is_member(&self, who: &PrincipalId, group: &PrincipalId) -> bool {
        self.members.contains(&(who.clone(), group.clone()))
    }
}

impl VersionedWorld for TestWorld {
    fn version(&self) -> u64 {
        self.version
    }
}
