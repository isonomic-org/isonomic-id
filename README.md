# isonomic-id

Identity and authority for Isonomic.

- Every person, agent and app has a cryptographic identity: a signed key log
  its owner keeps, with an Ethereum key bound in.
- Every permission is a signed grant.
- One function decides access: allow, deny or ask, with a reason.

This is a pure library. It opens no socket and makes no chain call, and a
test keeps it that way (`docs/deps-allow.txt`).

## Crates

| Crate | Holds |
| --- | --- |
| `id-core` | Principal IDs, the key log, public keys, digests, the byte encoding, the signed envelope. |
| `id-keys` | The key-store trait and the in-memory store. Private keys never leave a store. |
| `id-resource` | Resource IDs, owner, collection, provenance, selectors. |
| `id-grants` | The grant format, narrowing, revocation, chain verification. |
| `id-check` | The check function. |
| `id-eth` | The Ethereum key, its address and the two-way binding. No chain calls. |
| `id-testkit` | Fake principals, a fake world and a manual clock. |
| `spikes/root` | The two ways of rooting an identity that were tested before the key log was chosen. Evidence; not shipped. |

## Working here

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

- One task per branch and pull request. Merge when every check is green.
- The ID format, the grant format and the check function are shared
  contracts. Once frozen, a change to any of them gets the label
  `needs-master`.
- Every source and doc file stays under 20 KB.
- Cryptography comes from audited libraries. No primitive is written here.
- Tests are hermetic. Anything that needs a Mac is one command, documented in
  `docs/status.md`.

Read `docs/spec.md` for the contracts, `docs/status.md` for where things
stand, and `docs/PROGRESS.md` for the log.
