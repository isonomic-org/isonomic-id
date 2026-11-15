# Progress

## 15 Nov 2026, after the decision

- Omar decided the root: a key log with an Ethereum account bound in.
- `id-core`: the key log. IDs are `did:iso:` plus the digest of the first
  entry. Rotation keys with device and recovery roles, used once. The
  directory accepts continuations and refuses forks.
- `id-eth`: key derivation from a seed, address, personal-message signing
  and recovery, the two-way binding, account address arithmetic.
- `id-check`: a test over real logs. A person issues an agent and a
  subagent; a lost device is recovered from the kit; old grants stop and are
  issued again under the same ID.
- Spec, status and README rewritten for the key-log root.
- 37 tests across the workspace.

## 15 Nov 2026

- Repository created. Workspace, shared CI, README, spec.
- `id-core`: principal IDs (opaque), public keys and signature checks for
  Ed25519 and P-256, digests with domains, CBOR codec, signed envelope.
- Dependency allow-list and the test that enforces it.
- `id-keys`: key-store trait, in-memory store, seeded keys for tests.
- `id-resource`: resource IDs, the resource record, parent and provenance
  walks, selectors.
- `id-grants`: the grant format and chain verification.
- `id-check`: the check function. `id-testkit`: principals, world, clock.
- `spikes/root`: a smart-account root (two variants) and a key-log root run
  through the same ten tests, with timings. 28 tests across the workspace.
- Decision memo written and sent to Omar.
