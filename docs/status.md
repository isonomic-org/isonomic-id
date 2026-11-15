# Status

Updated 15 Nov 2026.

## The root is decided

Omar decided on 15 Nov 2026: an identity is rooted in a key log, with an
Ethereum account bound in. The memo is "Decision: the root of an Isonomic
identity"; the design is "Isonomic Identity and Authority: architecture
v0.1". Both are in the architecture folder.

## Built

| Crate | State |
| --- | --- |
| `id-core` | IDs, the key log, the directory, keys, digests, codec, envelope |
| `id-keys` | Trait and in-memory store. The secure-chip store is issue 8. |
| `id-resource` | IDs, record, graph walks, selectors |
| `id-grants` | Format, narrowing, revocation, chain verification |
| `id-check` | The check function, tested over real key logs |
| `id-eth` | Key derivation, address, two-way binding, account address arithmetic |
| `id-testkit` | Principals, world, clock |
| `spikes/root` | The evidence behind the root decision. Kept, not shipped. |

## Decisions taken here

Newest first.

1. **A fork is shown to a person, never resolved by rule.** The directory
   refuses a competing branch and reports whether a recovery key signed it.
   A rule that lets the recovery kit win automatically would also let an old,
   stolen kit rewrite history for everyone, so there is none.
2. **Only a recovery key may change the recovery commitments.** A stolen
   device can add itself; it cannot lock the kit out, so the kit can always
   evict it without a fork.
3. **A device is a key, not a principal.** It has no log of its own.
4. **Agents and apps have their own logs**, naming their owner. Moving one to
   a new owner is one entry. Checking that both owners agreed is not built
   yet: it needs both owners' logs and belongs to the engine.
5. **Bindings are checked by a pluggable checker.** `id-core` knows no
   scheme; a log with a binding does not verify unless a checker for its
   scheme is present.
6. **The Ethereum key's address is bound from day one; the smart-account
   address is not.** It depends on an account factory, which is chosen with
   the chain. `account_salt` already fixes its salt to the ID.
7. **The Ethereum key is derived from a seed**, so the recovery kit restores
   it.
8. **Encoding.** CBOR. Signatures and IDs cover bytes as received.
9. **Schemes.** P-256 for keys in a secure chip, Ed25519 for keys in
   software. Every signature and digest carries a domain.
10. **Grant format: our own.** Size and speed are close to existing
    capability tokens. Ours names the recipient of every link, gives every
    link an ID to revoke, and returns allow, deny or ask.
11. **A chain covers only what every link covers.**
12. **A signing key must be current at check time.**
13. **No policy engine in version 1.** Membership is one lookup.
14. **Derived data** needs read access to every source.
15. **Purity.** A test fails when a package outside `docs/deps-allow.txt`
    enters `Cargo.lock`.

## The gate

| Item | State |
| --- | --- |
| ID created, devices added, removed, replaced, recovered, all offline; a second verifier from the log alone | Done, from encoded bytes. |
| A stolen old key cannot extend the log | Done for signing keys, used rotation keys and uncommitted keys. Limit stated in the spec: a newcomer can be shown a forged branch. |
| User issues an agent ID; user → agent → subagent only narrows; widening, expired and revoked grants refused | Done, over real logs. |
| Check denies by default; allow, deny or ask with a reason; vectors frozen | Done, except freezing. |
| Ethereum key and address derived; two-way binding verifies offline; no chain call; allow-list | Done. |
| Private keys stay in the key store; macOS store tested on the Intel Mac | Trait and in-memory store done. macOS store: issue 8. |
| Timings on the Intel Mac | Linux numbers below. Intel Mac: run the command below. |
| Decoders fuzzed for ten minutes | Issue 9. The formats freeze after it. |
| Requests filed with the engine, harness, SDK and Cells | After the freeze. |

## Timings

Linux, x86-64 at 2.1 GHz, software keys, release build, measured with the
prototype log, which does the same work as the library's:

| Step | Time |
| --- | --- |
| Create an identity (3 P-256 keys, first log entry) | 261 µs |
| Sign, P-256 | 29 µs |
| Sign, Ed25519 | 33 µs |
| Verify, P-256 | 70 µs |
| Verify, Ed25519 | 47 µs |
| Verify a 10-entry key log from scratch | 735 µs |
| Sign the Ethereum binding | 73 µs |
| Verify the Ethereum binding | 199 µs |
| Check a three-link grant chain (target under 1000 µs) | 173 µs |

The three grants together are 720 bytes.

On the Intel Mac, from a checkout of this repository:

```sh
cargo run --release -p root-spike
```

Record the block under "Timings" in this file.

## Open

- The formats are not frozen. Fuzzing comes first (issue 9).
- CI does not pass `--locked` yet (issue 7).
- The recovery kit is issue 14; signed checkpoints for data are issue 15.
- Check vectors are table-driven tests, not yet frozen files.
- The approval a person gives for an "ask first" grant is a flag on the
  request. It becomes a one-use grant when the agent host adopts this crate.
- Transfer of an agent between owners is recorded but not yet verified
  against both owners.
- No account factory is pinned, so no smart-account address is bound.
