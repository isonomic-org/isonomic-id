# Status

Updated 15 Nov 2026.

## Waiting on one decision

What an identity is rooted in: a smart-account address, or a key log with an
Ethereum account bound in. Omar decides. The evidence is `spikes/root` and
the memo "Decision: the root of an Isonomic identity" in the architecture
folder.

Until then `PrincipalId` is opaque, `id-core` has no key log and there is no
`id-eth` crate. Everything below was built so that it does not move when the
decision lands: it reaches identities only through
`KeyResolver::is_current_key`.

## Built

| Crate | State |
| --- | --- |
| `id-core` | IDs (opaque), keys, digests, codec, signed envelope |
| `id-keys` | Trait and in-memory store. The secure-chip store is next. |
| `id-resource` | IDs, record, graph walks, selectors |
| `id-grants` | Format, narrowing, revocation, chain verification |
| `id-check` | The check function |
| `id-testkit` | Principals, world, clock |
| `spikes/root` | Both roots through ten tests; a test pins the findings |

## Decisions taken here

1. **Encoding.** CBOR. Signatures and IDs cover bytes as received, so nothing
   depends on canonical re-encoding.
2. **Schemes.** P-256 for keys in a secure chip, Ed25519 for keys in
   software. Every signature and digest carries a domain.
3. **Grant format: our own.** Existing capability-token formats were built
   and measured beside it. Size and speed are close. Ours names the
   recipient of every link, gives every link an ID to revoke, and returns
   allow, deny or ask; those are the reasons.
4. **A chain covers only what every link covers.** Widening that can be seen
   from two grants is refused outright; the rest grants nothing.
5. **A signing key must be current at check time.** When a key is replaced,
   grants it signed stop and the engine issues them again.
6. **No policy engine in version 1.** Membership for shared workspaces is
   one lookup behind the same function.
7. **Derived data** needs read access to every source, direct or indirect.
8. **Resource IDs** carry their creation time. That is visible to anyone who
   sees the ID.
9. **Purity.** A test fails when a package outside `docs/deps-allow.txt`
   enters `Cargo.lock`.

## The gate

| Item | State |
| --- | --- |
| ID created, devices added, removed, replaced, recovered, all offline; a second process verifies from the log alone | Shown in `spikes/root`. Moves into `id-core` after the decision. |
| A stolen old key cannot extend the log | Shown in `spikes/root`, with the limit stated: a newcomer who has never seen the real log can be shown a forged one. |
| User issues an agent ID; user → agent → subagent only narrows; widening, expired and revoked grants refused | Narrowing, expiry and revocation: done. Agent IDs: after the decision. |
| Check denies by default; allow, deny or ask with a reason; vectors frozen | Done, except freezing, which follows the format freeze. |
| Ethereum key and address derived; two-way binding verifies offline; no chain call; allow-list | Binding shown in `spikes/root`. Allow-list: done. `id-eth`: after the decision. |
| Private keys stay in the key store; macOS store tested on the Intel Mac | Trait and in-memory store: done. macOS store: not started. |
| Timings on the Intel Mac | Linux numbers below. Intel Mac: run the command below. |
| Decoders fuzzed for ten minutes | Not started. |
| Requests filed with the engine, harness, SDK and Cells | After the formats freeze. |

## Timings

Linux, x86-64 at 2.1 GHz, software keys, release build:

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

Paste the block under "Timings" back to the session.

## Open

- `Cargo.lock` is not committed yet and CI does not pass `--locked`.
- Check vectors are table-driven tests, not yet frozen files.
- The approval a person gives for an "ask first" grant is a flag on the
  request. It becomes a one-use grant when the agent host adopts this crate.
