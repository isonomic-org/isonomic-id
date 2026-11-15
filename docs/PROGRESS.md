# Progress

## 15 Nov 2026, closing the gate

- CI builds with `--locked` (issue 7).
- `id-check`: `ChainCache` remembers verified chains; a repeated check takes
  1.7 µs on Linux against 174 µs from cold (issue 17). The directory has a
  version that moves whenever a log changes.
- Four fuzz targets, ten minutes each with no failure (issue 9). One signs
  mutated grants again so the chain rules themselves are reached, and checks
  that the cached and plain answers always agree.
- Version 1 frozen: `vectors/v1/vectors.txt` holds real logs and grants as
  bytes with the IDs and decisions they must keep producing.
- `id-keys`: `MacKeyStore`, the secure chip where allowed, the login
  keychain otherwise (issue 8). Tested on the Intel Mac, where a cached chain
  check takes 7.2 µs and a first check 256 µs.
- Adoption requests filed with the engine, the harness, the SDK and Cells.

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
