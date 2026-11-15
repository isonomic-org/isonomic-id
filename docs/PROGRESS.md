# Progress

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
- Decision memo written and sent to Omar. Waiting on the root decision.
