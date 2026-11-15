# Fuzzing

Four targets, each built to never panic on any input:

| Target | Input | What it exercises |
| --- | --- | --- |
| `envelope` | Any bytes | Decoding a signed envelope, verifying it, encoding it again |
| `key_log` | Length-prefixed entries | Replaying a key log with Ethereum bindings checked; offering it to a directory twice |
| `grant_chain` | Length-prefixed grants | Decoding grants and verifying the chain |
| `grant_logic` | Length-prefixed grant bodies | Each body is signed again by its issuer's test key, so the chain rules behind the signature check are reached. Also asserts the cached check always equals the plain one. |

Each input is cut into parts by a two-byte big-endian length before each part.

Run one for ten minutes, from this folder:

```sh
cargo fuzz run -O <target> -- -max_total_time=600 -max_len=16384
```

`cargo fuzz` needs a nightly toolchain. On a stable toolchain, set
`RUSTC_BOOTSTRAP=1` and add `-s none` (no sanitizer); the coverage guidance
still works. The crate is kept out of the main workspace, so CI does not
build it. Corpora, crash files and the lockfile stay local (`.gitignore`).

Seed corpora can be made from `vectors/v1/vectors.txt`: each entry or grant
on its own for `envelope`, and each log or chain with length prefixes for the
other targets.
