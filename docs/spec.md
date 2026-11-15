# Specification

What the crates promise. Nothing here is frozen yet: the formats freeze after
the decision on the root of an identity, and from then on a change needs the
label `needs-master`.

## Principals

A principal is anything that can hold authority: a person, a device, an agent
or an app; later an organization or a team. All share one ID type,
`PrincipalId`.

The ID's text form is opaque for now: 1 to 128 bytes of lowercase letters,
digits, `:`, `.`, `_` and `-`. Its exact syntax is fixed together with the
root decision.

Whether a key speaks for a principal is answered by one trait,
`KeyResolver::is_current_key(principal, key, at)`. Grants and checks ask that
question and never look at how an identity keeps its keys. The key log
implements it.

## Keys and signatures

| Scheme | Used for | Public key | Signature |
| --- | --- | --- | --- |
| P-256 with SHA-256 | Keys in a Mac's secure chip | 65 bytes, uncompressed | 64 bytes, `r` then `s` |
| Ed25519 | Keys held in software: agents, apps | 32 bytes | 64 bytes |

Everything signed or hashed is framed first:

```
"isonomic-id/v1/" + domain + 0x00 + message
```

The domain names the purpose (`grant`, `key`, ...), so a signature or digest
made for one purpose is never valid for another.

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

The envelope proves that the holder of `k` signed `p`. It does not prove that
`k` speaks for anyone; that is the resolver's job.

## Key stores

`KeyStore` creates keys, signs with them and deletes them. It has no export
call. `StoredKey` is one key in a store, usable wherever a `Signer` is
expected. A store reports how it protects keys: memory, operating-system
keychain or hardware.

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
   link's issuer. When a key is replaced, grants signed with the old key
   stop working and are issued again.
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
