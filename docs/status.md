# Status

Updated 15 Nov 2026.

## The root is decided

Omar decided on 15 Nov 2026: an identity is rooted in a key log, with an
Ethereum account bound in. The memo is "Decision: the root of an Isonomic
identity"; the design is "Isonomic Identity and Authority: architecture
v0.1". Both are in the architecture folder.

## Frozen

Version 1 of the ID, the key log, the grant format and the check function is
frozen. `vectors/v1/vectors.txt` holds a person's three-entry log (first
device, Ethereum binding, recovery), an agent and a subagent, and a two-link
grant chain, as bytes, with the IDs, the Ethereum address and the decisions
they must produce. Every later version must reproduce them. A change to any
of these needs `needs-master`.

## Built

| Crate | State |
| --- | --- |
| `id-core` | IDs, the key log, the directory, keys, digests, codec, envelope |
| `id-keys` | Trait, in-memory store, and `MacKeyStore`: the secure chip where allowed, the login keychain otherwise. Tested on the Intel Mac. |
| `id-resource` | IDs, record, graph walks, selectors |
| `id-grants` | Format, narrowing, revocation, chain verification |
| `id-check` | The check function, tested over real key logs; a cache of verified chains |
| `id-eth` | Key derivation, address, two-way binding, account address arithmetic |
| `id-testkit` | Principals, world, clock |
| `spikes/root` | The evidence behind the root decision. Kept, not shipped. |

## Decisions taken here

Newest first.

1. **Verified chains are cached, and nothing else is.** A cached chain is
   found by the digest of its exact bytes and dropped whenever the world's
   version moves (a key log or the revocation list changed) or the time
   leaves any link's dates. Ownership, scope, budgets, membership and
   approval are decided on every check, so a cache can never allow what a
   fresh check would deny; a test asserts the two agree.
2. **A fork is shown to a person, never resolved by rule.** The directory
   refuses a competing branch and reports whether a recovery key signed it.
   A rule that lets the recovery kit win automatically would also let an old,
   stolen kit rewrite history for everyone, so there is none.
3. **Only a recovery key may change the recovery commitments.** A stolen
   device can add itself; it cannot lock the kit out, so the kit can always
   evict it without a fork.
4. **A device is a key, not a principal.** It has no log of its own.
5. **Agents and apps have their own logs**, naming their owner. Moving one to
   a new owner is one entry. Checking that both owners agreed is not built
   yet: it needs both owners' logs and belongs to the engine.
6. **Bindings are checked by a pluggable checker.** `id-core` knows no
   scheme; a log with a binding does not verify unless a checker for its
   scheme is present.
7. **The Ethereum key's address is bound from day one; the smart-account
   address is not.** It depends on an account factory, which is chosen with
   the chain. `account_salt` already fixes its salt to the ID.
8. **The Ethereum key is derived from a seed**, so the recovery kit restores
   it.
9. **Encoding.** CBOR. Signatures and IDs cover bytes as received.
10. **Schemes.** P-256 for keys in a secure chip, Ed25519 for keys in
   software. Every signature and digest carries a domain.
11. **Grant format: our own.** Size and speed are close to existing
    capability tokens. Ours names the recipient of every link, gives every
    link an ID to revoke, and returns allow, deny or ask.
12. **A chain covers only what every link covers.**
13. **A signing key must be current at check time.**
14. **No policy engine in version 1.** Membership is one lookup.
15. **Derived data** needs read access to every source.
16. **Purity.** A test fails when a package outside `docs/deps-allow.txt`
    enters `Cargo.lock`.

## The gate

| Item | State |
| --- | --- |
| ID created, devices added, removed, replaced, recovered, all offline; a second verifier from the log alone | Done, from encoded bytes. |
| A stolen old key cannot extend the log | Done for signing keys, used rotation keys and uncommitted keys. Limit stated in the spec: a newcomer can be shown a forged branch. |
| User issues an agent ID; user → agent → subagent only narrows; widening, expired and revoked grants refused | Done, over real logs. |
| Check denies by default; allow, deny or ask with a reason; vectors frozen | Done. Version 1 frozen: `vectors/v1/vectors.txt`. |
| Ethereum key and address derived; two-way binding verifies offline; no chain call; allow-list | Done. |
| Private keys stay in the key store; macOS store tested on the Intel Mac | Done. On the Intel Mac, P-256 and Ed25519 keys were made in the login keychain, signed, verified and destroyed. A test build may not use the secure chip, so P-256 fell back to the keychain, as designed. Rerun with `cargo test -p id-keys --test macos -- --ignored --nocapture`. |
| Timings on the Intel Mac; three-link grant chain under 1 ms | Done. 256 µs for a first check and 7.2 µs from the cache on the Intel Mac. |
| Decoders fuzzed for ten minutes | Done: four targets, ten minutes each, no failure. See below. |
| Requests filed with the engine, harness, SDK and Cells | Done: isonomic-capsule R7, and entries in the harness, SDK and Cells request lists, all pinned to `c67932d`. |

## Timings

Release build, software keys, measured with `cargo run --release -p
root-spike`. The prototype log does the same work as the library's.

| Step | Linux, x86-64 2.1 GHz | Intel test Mac |
| --- | --- | --- |
| Create an identity (3 P-256 keys, first log entry) | 261 µs | 267 µs |
| Sign, P-256 | 29 µs | 38 µs |
| Sign, Ed25519 | 33 µs | 24 µs |
| Verify, P-256 | 70 µs | 98 µs |
| Verify, Ed25519 | 47 µs | 94 µs |
| Verify a 10-entry key log from scratch | 735 µs | 904 µs |
| Sign the Ethereum binding | 73 µs | 132 µs |
| Verify the Ethereum binding | 199 µs | 336 µs |
| Check a three-link grant chain, first time (target under 1000 µs) | 173 µs | 256 µs |
| Check the same chain again, from the cache (target under 100 µs) | 1.7 µs | 7.2 µs |

The three grants together are 720 bytes.

The Intel figures are from a second run on 15 Nov. The first run, on a busy
machine, took 1499 µs for a first chain check, over the target; that is why
verified chains are cached, as the design expects: the broker verifies a chain
once per session, and `ChainCache` makes every later check a few microseconds.

To measure again on the Intel Mac, from a checkout:

```sh
cargo run --release -p root-spike
```

## Fuzzing

Ten minutes per target on a 2-core Linux machine, stable toolchain, no
sanitizer (this workspace forbids `unsafe`). How to run them is in
`fuzz/README.md`.

| Target | Runs | Failures |
| --- | --- | --- |
| `envelope`: any bytes as a signed envelope | 59.8 million | 0 |
| `key_log`: entries replayed with Ethereum bindings, offered to a directory | 18.3 million | 0 |
| `grant_chain`: grants decoded and the chain verified | 65.0 million | 0 |
| `grant_logic`: mutated grants signed again, checked plain and cached | 9.9 million | 0 |

Random bytes almost never carry a valid signature, so the first three
targets mostly test decoding and stop at the signature check. `grant_logic`
signs each mutated grant again with its issuer's test key, so the narrowing,
scope, budget and delegation rules are reached, and it asserts that the cached
check always gives the plain check's answer. The key-log rules behind the
signature check are covered by the unit tests, not by fuzzing.

## Open

- The recovery kit is issue 14; signed checkpoints for data are issue 15.
- The approval a person gives for an "ask first" grant is a flag on the
  request. It becomes a one-use grant when the agent host adopts this crate.
- Transfer of an agent between owners is recorded but not yet verified
  against both owners.
- No account factory is pinned, so no smart-account address is bound.
- `MacKeyStore` makes P-256 keys in the secure chip only for a program
  signed with a keychain entitlement. A test binary is not, so it falls back
  to the login keychain. The engine gets the chip once its signed app carries
  that entitlement (isonomic-capsule R7).
