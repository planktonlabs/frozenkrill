# Upgrade vsss-rs from 4.3.8 to 5.4.0 (bead frozenkrill-gxv)

## Problem

`frozenkrill-core` currently depends on `vsss-rs = "4"` (resolved to 4.3.8).
The latest published version is **5.4.0**, which is a breaking API rewrite.
This bead is the v4 → v5 migration of the Pedersen Verifiable Secret Sharing
core that powers the new `split-secret` / `combine-secret` commands.

The only file that actually imports `vsss_rs::*` is
`frozenkrill-core/src/secret_sharing.rs`. Everything else (`wallet_description.rs`,
the CLI commands, etc.) consumes our own `Share` / `VssJsonWalletDescriptionV0`
abstractions, so the blast radius outside that one file should be small —
but the *internal* rewrite of `secret_sharing.rs` is non-trivial.

### Current v4 imports (the call surface that has to move)

```rust
use vsss_rs::curve25519::{WrappedRistretto, WrappedScalar};
use vsss_rs::pedersen::{StdPedersenResult, split_secret};
use vsss_rs::{PedersenResult, PedersenVerifierSet, combine_shares};
```

### Concrete API changes 4.x → 5.x

| Surface | v4 (current) | v5 (target) |
|---|---|---|
| Share data type | `Vec<u8>` (raw bytes; **first byte = share identifier**) | `DefaultShare<IdentifierPrimeField<WrappedScalar>, IdentifierPrimeField<WrappedScalar>>` (typed scalar + typed identifier) |
| `StdPedersenResult` type params | `<G, Id, Share>` (3 params) | `<S, V>` (2 params) |
| `pedersen::split_secret` secret arg | by value | by reference (`&S::Value`) |
| `combine_shares` | free function `vsss_rs::combine_shares(...)` | typically `result.combine()` method on the result; for raw share collections look at `shamir::combine_shares` or the per-result method on the v5 docs |
| Identifier extraction in our code | `secret_share[0]` (first byte of the raw share blob) | typed `IdentifierPrimeField<WrappedScalar>` field on the v5 `Share` type |
| Verifier set | `vsss_rs::PedersenVerifierSet` trait + `verify_share_and_blinder` method | `pedersen::Pedersen` re-export + restructured trait surface; the verifier-set `verify_share_and_blinder` (or its v5 equivalent) is what we need |

### v5 reference (already verified upstream on `main`)

- Crates.io: `vsss-rs = "5.4.0"` (curve25519 feature still exists)
- Source: <https://github.com/mikelodder7/vsss-rs/tree/main>
- Curve25519 wrapper module: `src/curve25519.rs` — `WrappedRistretto` and
  `WrappedScalar` still exist and still wrap the same curve25519-dalek types
- Pedersen split: see `src/pedersen.rs` — the new free `split_secret`
  signature is documented in the upstream rustdoc; an `Ed25519Share` type
  alias example lives in `src/lib.rs`'s top-level docstring

If the v5 crate exposes traits or functions whose exact names you can't pin
down from this prompt, use `cargo doc -p vsss-rs --open`-style inspection
through the source files and the `cargo expand` output rather than
guessing — getting share-identifier extraction wrong will silently break
recovery.

## Files to change

### Primary

- `frozenkrill-core/Cargo.toml` — bump `vsss-rs = { version = "5", features = ["curve25519"] }`. Confirm the `curve25519` feature still gates `WrappedRistretto`/`WrappedScalar` exports.
- `frozenkrill-core/src/secret_sharing.rs` — the actual rewrite. Specifically:
  - **`split_one_scalar`** (search for the `StdPedersenResult` call): the
    `split_secret(...)` call signature changes (secret is now by reference,
    type params drop one position). The 3 lines that pull
    `result.secret_shares()`, `result.blinder_shares()`, and
    `result.pedersen_verifier_set()` may need to be re-typed against v5's
    trait shapes.
  - **`combine_one_half`** (search for `combine_shares(&good)`): the
    free `combine_shares` likely moves; substitute the v5 equivalent.
  - **`verified_unique_share_pairs`**: the verifier-set parsing
    (`parse_ristretto_points`) and the `verify_share_and_blinder` call
    are the heart of the per-share Pedersen check. Keep the same
    semantics: every `(secret_share, blinder_share)` pair must verify
    against the candidate verifier; first-wins dedupe by share
    identifier.
  - **Identifier extraction**: every place that reads `secret_share[0]`
    or `secret_share.first()` to recover the share identifier must
    switch to v5's typed identifier on the new `Share` type. This
    appears in `verified_unique_share_pairs` (dedupe) and in the
    candidate-cross-product enumeration in `combine_vss_wallets`.
  - **`parse_ristretto_points`**: keep returning a vec the verifier
    consumes; if v5 names the type differently, follow.
  - **`threshold_from_pedersen`**: the verifier-set length math
    (`length = threshold + 2` for `[g, h, C_0..C_{t-1}]`) should still
    hold in v5 if the Pedersen scheme is unchanged — verify and keep.

### Supporting

- All test code in `frozenkrill-core/src/secret_sharing.rs` (see
  `mod tests` near the bottom — ~30 tests). Most should "just work"
  since they go through our `Share` / `combine_vss_wallets` API; the
  ones that construct raw `Share` values, manipulate `share_data` hex
  bytes by hand, or assert on identifier-byte positions may need
  fixups.

### Out of scope

- **Do NOT** bump `rand` / `rand_core`. vsss-rs 5.x main still pins
  `rand_core = "0.6"`, and our `bip39` git fork explicitly caps at
  `crate_rand = ">=0.6.0, <0.9.0"`. Leave those alone.
- **Do NOT** refactor the surrounding wallet_description /
  share-encryption / CLI code beyond what's strictly necessary to fit
  the new vsss-rs types. The codex review loop just signed off on
  this code — minimize blast radius.
- **Do NOT** change behavior outside the vsss-rs migration. The
  Pedersen+blinder verification scheme stays. The candidate-cross-
  product enumeration stays. The fail-closed authentication stays.
  Strict-majority is_duress aggregation stays. Etc.

## On-disk format implications

Our share files (`*.frozenkrill`) persist:
- `share_data` — hex-encoded bytes, currently the raw byte format vsss-rs
  4.x emits for a `Vec<u8>` share (first byte = identifier, remaining
  bytes = scalar)
- `blinder_share_data` — same structure, for the blinder polynomial
- `verification_data` — comma-separated hex of compressed Ristretto
  points (`[g, h, C_0, C_1, …, C_{t-1}]`)

The `share_data` / `blinder_share_data` byte format **will change** under
v5 because v5 serializes typed scalars + typed identifiers differently
than v4's raw byte concatenation. This is acceptable: the secret-sharing
feature has not been released — it's still the open PR #33 against
`master`, no users have committed share files yet.

The `verification_data` (compressed Ristretto points) **probably** stays
byte-compatible because Ristretto compression is a stable, well-defined
encoding. **Verify** rather than assume — write a quick local check that
splits with v5 and round-trips through the existing
`parse_ristretto_points` → `verify_share_and_blinder` flow.

Document the v5 byte layout in a top-of-file comment in
`secret_sharing.rs` so future readers (and the next codex review pass)
understand what the on-disk hex represents under v5.

## Implementation hints

1. **Read the v5 source first.** The vsss-rs 5.4.0 crate is small;
   reading `src/pedersen.rs`, `src/share.rs`, and `src/curve25519.rs`
   from the upstream tree (or via `cargo doc`) is faster than
   trial-and-error against the compiler.
2. **Look at v5 examples.** `src/lib.rs` in the upstream crate has a
   top-level docstring with a working `Ed25519Share` example using
   the v5 API end-to-end (split → combine). Adapt that pattern to
   the Pedersen path.
3. **Preserve every codex-hardened invariant.** Specifically:
   - per-share dedupe by share identifier (now typed, but same
     semantics)
   - fail-closed metadata authentication in `combine_vss_wallets`
   - candidate cross-product enumeration for split lo/hi corruption
   - threshold extraction from verifier-set length
   - per-share verifier corruption tolerance (verify against the
     winning verifier, not the share's own copy)
4. **Run the tests early and often.** The test suite in
   `frozenkrill-core/src/secret_sharing.rs::tests` is the
   authoritative regression suite. Get a handful of them passing
   end-to-end before declaring a structural change "done" — type
   errors during the migration are easy; subtle correctness
   regressions are not.
5. **Keep changes minimal outside `secret_sharing.rs`**. Touching
   `wallet_description.rs` should only happen if the v5 types leak
   through `VssJsonWalletDescriptionV0`'s `share_data` /
   `blinder_share_data` String fields — and they shouldn't, because
   we serialize as hex strings either way.

## IMPORTANT: Exclude orchestration state from review scope

Files under `.ralph-burning/`, `.ralph/`, and `.beads/` are live
orchestration / issue-tracking state and MUST NOT be reviewed or
flagged. Only review source code under `src/`, `frozenkrill-core/src/`,
`tests/`, `docs/`, and config files (`Cargo.toml`, `Cargo.lock`, etc.).

## Acceptance criteria

- `vsss-rs = "5"` (or `"5.4"`) in `frozenkrill-core/Cargo.toml`
- `Cargo.lock` resolves vsss-rs to 5.x
- `nix develop --command cargo build --workspace` clean
- `nix develop --command cargo test --workspace` green —
  every existing `secret_sharing::tests::*` test passes,
  every `frozenkrill-core` integration test passes,
  every CLI integration test passes
- `nix develop --command cargo clippy --workspace --all-targets -- -D warnings` clean
- `nix develop --command cargo fmt --check` clean
- `nix build` passes (the authoritative gate, not just `cargo test`)
- The cryptographic semantics are preserved:
  - Same curve (Curve25519/Ristretto via
    `vsss_rs::curve25519::WrappedRistretto` / `WrappedScalar`)
  - Same Pedersen blind-commitment verification (`g^a · h^b`,
    per-share `verify_share_and_blinder`-equivalent check)
  - Same threshold-secret-sharing behavior
- The v5 on-disk byte layout is documented inline in
  `secret_sharing.rs` (one paragraph at the top of the file or near
  the `Share` struct definition)
- All codex-hardened invariants from the v4 code still hold (per-
  share dedupe by cryptographic identifier, fail-closed metadata
  authentication, candidate cross-product enumeration for split
  lo/hi corruption, etc.)

## How this bead is tracked

- Bead ID: `frozenkrill-gxv`
- Branch: `feat/frozenkrill-gxv-vsss-5x-upgrade`
- Base branch (PR target): `feature/pedersen-secret-sharing` (the
  open PR #33 against `master`)
- After merge: `br close --actor assistant frozenkrill-gxv --reason "..."`
