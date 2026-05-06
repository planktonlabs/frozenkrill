# Collapse internal `Share` schema + drop `SuccessEntry` verifier fields (bead frozenkrill-ugd)

## Problem

Two structural simplifications inside
`frozenkrill-core/src/secret_sharing.rs`. Land together — both touch
the recovery path's internal data shapes.

The previous simplification beads (`frozenkrill-hd8`, `frozenkrill-x2z`)
removed ~440 lines (test-only Share checksum, Share-regroup helper,
threat-model comment bloat, OriginalWalletJson tagged enum, third
copy of the encryption envelope). Codex review #2 found further
opportunities — this bead handles the two P2 structural ones.

### Finding 1: Collapse the duplicate internal `Share` schema (~150–200 lines)

`Share` (defined around `secret_sharing.rs:158-159`) now shadows
almost every field on the public `VssJsonWalletDescriptionV0`:

- `version`, `share_index`, `threshold`, `total_shares`,
  `mnemonic_length`
- `share_data`, `blinder_share_data`, `verification_data`
- `share_data_hi`, `blinder_share_data_hi`, `verification_data_hi`
- `created_at`, `scheme`

The rest of the file pays for that second schema twice:

- `split_singlesig_wallet()` builds `Share` values then immediately
  clones every field into the public `VssJsonWalletDescriptionV0`.
- `combine_shares_to_mnemonic()` and the candidate-cross-product
  enumeration in `combine_vss_wallets` clone inputs back into
  synthetic `Share` values just to call internal helpers.

**Drop the internal `Share` struct.** Every code path that uses it
should consume `VssJsonWalletDescriptionV0` directly, OR a smaller
shared payload type both structs embed (if a clean factoring exists).

The trade-off: raw-mnemonic tests in `secret_sharing.rs::tests`
become slightly more end-to-end because they go through
`VssJsonWalletDescriptionV0` instead of the lower-level `Share`.
But split/combine rules then live in exactly one place.

### Finding 2: Drop redundant verifier fields from `SuccessEntry` (~40–60 lines)

`SuccessEntry` (around `secret_sharing.rs:900-906`) currently looks
roughly like:

```rust
type SuccessEntry<'a> = (
    SecretBox<Mnemonic>,
    Vec<&'a VssJsonWalletDescriptionV0>,  // verified_inputs
    String,                                // lo verifier hex (redundant)
    Option<String>,                        // hi verifier hex (redundant)
);
```

The `verified_inputs` already encode the candidate verifier — every
input in there carries the same `verification_data` /
`verification_data_hi` that we actually verified against.
`derive_metadata()` then re-parses those redundant strings just to
rerun the same per-share filter that already produced
`verified_inputs`.

Change `derive_metadata()` to consume the verified group directly
(reading the verifier off any element, since they all match by
construction). Drop the two trailing tuple fields and the
"why we carry these" comment.

The trade-off: `SuccessEntry` stops being self-sufficient for
re-verifying its own inputs later. Nothing currently uses it that
way, so the loss is only theoretical.

## Implementation hints

### Where to look

- `frozenkrill-core/src/secret_sharing.rs` — the only file that needs
  to change for both findings. `Share` definition + every
  consumer of it.
- `frozenkrill-core/src/wallet_description.rs` — only as a reader of
  `VssJsonWalletDescriptionV0`'s public API; do not modify it for
  this bead.
- `frozenkrill-core/src/lib.rs` — only if it imports `Share` or
  the regrouped helpers (probably no change needed).
- `docs/secret_sharing.md` — skim for stale references to `Share`
  if you're tightening anything that's documented there.

### Refactor ordering

1. **Finding 2 first** (drop verifier tuple fields). Smaller, more
   localized — sets up `derive_metadata` to read verifiers off
   `verified_inputs`, which is also the shape the bigger refactor
   in finding 1 will rely on.
2. **Finding 1 second** (collapse `Share`). Bigger structural
   change — easier to reason about once `SuccessEntry` is simpler.

After each finding, run the test suite. Don't try to land both
without verifying correctness in between.

### Cryptographic semantics — DO NOT change

- Pedersen blind-commitment verification (`g^a · h^b` per share).
- Threshold reconstruction (M-of-N Shamir).
- Fail-closed authentication in `combine_vss_wallets`.
- Candidate cross-product enumeration for split lo/hi corruption
  (the GGG-1 fix from the codex hardening loop).
- Strict-majority `is_duress` aggregation; abstain on tie.
- Per-share verifier-corruption tolerance (verify against the
  winning verifier, not the share's own copy).
- The on-disk JSON layout of `VssJsonWalletDescriptionV0` (no
  format changes — both findings are purely internal).

If a refactor would silently weaken any of these, back it out.

### Test surface

Currently 67 `secret_sharing::tests::*` tests pass. After the
`Share` removal, some tests that constructed raw `Share` values
will need to construct `VssJsonWalletDescriptionV0` instead.
Equivalent assertions, more end-to-end shape. **Do not delete
tests** to make the migration easier — adapt them.

## IMPORTANT: Exclude orchestration state from review scope

Files under `.ralph-burning/`, `.ralph/`, and `.beads/` are live
orchestration / issue-tracking state and MUST NOT be reviewed or
flagged. Only review source code under `src/`,
`frozenkrill-core/src/`, `tests/`, `docs/`, and config files
(`Cargo.toml`, `Cargo.lock`, etc.).

## Acceptance criteria

- All existing `secret_sharing::tests::*` tests still pass (some
  may be rewritten end-to-end through `VssJsonWalletDescriptionV0`
  if `Share` goes away).
- `nix develop --command cargo build --workspace` clean
- `nix develop --command cargo test --workspace` green
- `nix develop --command cargo clippy --workspace --all-targets -- -D warnings` clean
- `nix develop --command cargo fmt --check` clean
- `nix build` passes
- **Net line reduction in `frozenkrill-core/src/secret_sharing.rs`
  of at least 180 lines.** Measure via
  `git diff --stat origin/feature/pedersen-secret-sharing..HEAD --
  frozenkrill-core/src/secret_sharing.rs`.
- All cryptographic semantics preserved (see "DO NOT change" above).

## Out of scope (separate bead — frozenkrill-1si)

- Removing the test-only `to_singlesig` path in `wallet_description.rs`.
- Deduplicating split-secret preflight in `commands/split_secret.rs`.
- Trimming the stale post-combine comment in `commands/combine_secret.rs`.

## How this bead is tracked

- Bead ID: `frozenkrill-ugd`
- Branch: `feat/frozenkrill-ugd-collapse-share-schema`
- Base branch: `feature/pedersen-secret-sharing`
- After merge: `br close --actor assistant frozenkrill-ugd --reason "..."`
