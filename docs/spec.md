# Specification

What the crates promise. **Version 1 is frozen** as of 15 Nov 2026.
`vectors/v1/vectors.txt` holds real key logs and grants as bytes, with the
IDs and the decision they must produce; every later version must still
decode and verify them to the same answers (`crates/id-check/tests/vectors.rs`).
A change to a format, the ID rule or the check function needs the label
`needs-master`.

## Principals

A principal is anything that can hold authority. Version 1 has three kinds
with a key log of their own: a person, an agent and an app. Organizations and
teams come later, in the same format.

A device is not a principal. It is a signing key in its owner's log, and a
signature shows which device made it.

A principal's ID is `did:iso:` followed by the digest of the first entry of
its key log, in hexadecimal: 72 characters. It never changes when keys do.

Whether a key speaks for a principal is answered by one trait,
`KeyResolver::is_current_key(principal, key, at)`. Grants and checks ask that
question and nothing else about identities. `log::Directory` answers it.

## Keys and signatures

| Scheme | Used for | Public key | Signature |
| --- | --- | --- | --- |
| P-256 with SHA-256 | Keys in a Mac's secure chip | 65 bytes, uncompressed | 64 bytes, `r` then `s` |
| Ed25519 | Keys held in software: agents, apps | 32 bytes | 64 bytes |

Everything signed or hashed is framed first:

```
"isonomic-id/v1/" + domain + 0x00 + message
```

The domain names the purpose (`log`, `grant`, `key`), so a signature or
digest made for one purpose is never valid for another.

## Encoding

CBOR, at most 64 KiB, at most 32 levels deep, no trailing bytes.

Signatures and IDs are computed over bytes exactly as received. Nothing is
re-encoded before it is verified, so no two encoders ever have to agree byte
for byte.

## The signed envelope

| Field | Meaning |
| --- | --- |
| `p` | The payload bytes |
| `k` | The public key that signed: `a` scheme, `k` bytes |
| `s` | The signature over the framed payload |

An object's ID is the digest of its payload under its domain.

## The key log

An identity is an append-only list of signed entries, in the envelope above
under the domain `log`. Its owner keeps it; anyone handed it can verify all of
it offline.

| Field | Meaning |
| --- | --- |
| `v` | Version, 1 |
| `seq` | Position, from 0 |
| `prev` | The ID of the entry before. Absent in the first entry. |
| `gen` | First entry only: `kind` (person, agent, app), `ctl` the owner of an agent or app, `n` 16 random bytes |
| `ops` | Changes, below |
| `next` | The rotation keys that may sign the next entry: `k` fingerprint, `r` role |
| `at` | When the author says it was written. Never goes backwards. |

| Change | Meaning |
| --- | --- |
| `add` | Adds a signing key `k`, with an optional encryption key `e` |
| `remove` | Removes a signing key |
| `bind` | Binds an outside account: scheme `s`, account `a`, the account's signature over the ID `p` |
| `unbind` | Drops the binding of a scheme |
| `ctl` | Moves an agent or app to a new owner |

Two kinds of key never mix:

- **Signing keys** sign grants and data. They have no power over the log.
- **Rotation keys** change the log. Each is committed in advance by
  fingerprint, with a role: `device` or `recovery`. Each is used once and
  then destroyed.

Rules a log must pass:

1. The first entry is signed by a signing key it adds.
2. Every later entry names the entry before it and is signed by a rotation
   key that entry committed to.
3. An entry may not commit again to the key that signed it.
4. Only a recovery key may change which recovery keys are committed. A
   stolen device cannot lock the recovery kit out.
5. A binding is accepted only when a checker for its scheme verifies the
   account's signature. It cannot be in the first entry.
6. At most 4096 entries.

`Directory` remembers the logs it has accepted. A longer continuation
replaces what it knew; an older copy changes nothing; a log that parts ways
with the known one is refused as a fork, with the position and whether the
competing entry was signed by a recovery key. A person decides what to do
with a fork. Nothing switches branches on its own. `Directory::version`
goes up whenever what it knows changes.

What this does not stop: someone holding an unused rotation key from a lost,
unlocked device can show a forged branch to a verifier that has never seen
the real log. Publishing the latest entry's digest (`State::head`) to a chain
closes that. This library defines the digest; it publishes nothing.

## Ethereum

`id-eth` is arithmetic only.

- A key is derived from a seed with HKDF, so the recovery kit brings it back.
- The binding scheme is `eth`. The account is the key's 20-byte address. The
  proof is the key's personal-message signature over
  `Isonomic ID binding v1` and, on the next line, the ID.
- `create2` computes the address a smart account would have, and
  `account_salt` its salt from the ID. No account address is bound yet: it
  depends on the account factory, which is chosen with the chain.

## Key stores

`KeyStore` creates keys, signs with them and deletes them. It has no export
call. `StoredKey` is one key in a store, usable wherever a `Signer` is
expected. A store reports how it protects keys: memory, operating-system
keychain or hardware.

`MacKeyStore`, on macOS only:

- P-256 keys are made inside the secure chip when the running program may
  keep keys there, which needs a signed app with a keychain entitlement.
  Otherwise they are made in software and kept in the login keychain.
  `p256_protection` says which.
- Ed25519 keys, which the chip does not offer, are kept in the login
  keychain.
- Every item it writes is labelled `isonomic-id:<label>`; it touches
  nothing else.

## Resources

Every protected thing has one record:

| Field | Meaning |
| --- | --- |
| `id` | 128 bits: 48 bits of creation time in milliseconds, 80 random bits. Needs no coordination. |
| `kind` | What it is, for example `doc` |
| `owner` | A principal. A field, so ownership can move. |
| `parent` | The resource it sits under, if any |
| `collection` | Its collection, which is also its encryption scope |
| `derived_from` | What it was computed from |

Derived data (summaries, embeddings, indexes) is only as open as its sources:
to use it, a caller must be able to read every source, direct or indirect.

A selector names the resources a grant covers: `any`, one collection (`col`),
one resource and everything under it (`tree`), or exactly one resource
(`one`).

## Grants

One signed format for every permission, in the envelope above under the
domain `grant`.

| Field | Meaning |
| --- | --- |
| `v` | Version, 1 |
| `iss` | Who gives the permission |
| `aud` | Who receives it |
| `res` | A selector |
| `act` | The actions allowed, for example `read`, `write`, `network`, `spend` |
| `nbf`, `exp` | Valid from, valid until |
| `bud` | A budget: unit `u` and limit `l` |
| `ask` | Ask a person before every use |
| `dep` | How many further links may hang below this grant |
| `par` | The ID of the grant this one narrows |
| `n` | 16 random bytes, so every grant ID is unique |

A chain is verified owner's grant first:

1. Every signature verifies, and each signing key currently speaks for its
   link's issuer. When a key is removed from a log, grants it signed stop
   working and are issued again.
2. Each link names the link before it as its parent, and is issued by that
   link's recipient.
3. Each link only narrows: no new action, no later expiry, no larger or
   dropped budget, "ask first" never removed, fewer delegations left.
4. Every link is within its dates.
5. No link is revoked. Revoking a link ends everything below it.
6. At most 8 links.

A chain covers only what every link covers. Where narrowing cannot be judged
from two grants alone (one folder inside another), a link that names
something its parent did not cover grants nothing.

## The check function

`check(request, world)` returns allow, deny or ask, with a reason. In order:

1. The resource must exist.
2. Its owner is allowed.
3. Anyone else needs a verified chain that starts at the resource's owner,
   ends at the caller, allows the action, covers the resource at every link
   and has budget left at every link.
4. For derived data, the caller must also be able to read every source.
5. If any link says "ask first" and no person has approved, the answer is
   ask. Approval never rescues a request that would be denied.
6. Everything else is denied.

There is no policy engine. Shared workspaces add one lookup,
`World::is_member(who, group)`, so a grant issued to a team is usable by its
members. Callers do not change.

### Checking the same chain again

`ChainCache::check` gives the same answer as `check`, but remembers chains
that verified. A chain is found again by the digest of its bytes exactly as
presented, so a changed byte means a fresh verification. A remembered chain
is used only while:

- the world's version (`VersionedWorld::version`) is unchanged, which a host
  bumps whenever a key log or the revocation list changes, and
- the time is within every link's dates.

Only the signatures and the chain's own rules are remembered. Ownership,
scope, budgets, membership, approval and derived data are decided afresh on
every check. The cache holds at most 4096 chains and starts again from empty
when full.
