# Drop `OriginalWalletJson` tagged enum + unify VSS encryption envelope (bead frozenkrill-x2z)

## Problem

Two cross-file API simplifications from the codex simplification review.
Both are in `frozenkrill-core/src/wallet_description.rs` and
`frozenkrill-core/src/lib.rs`, with one or two tiny propagations into
`secret_sharing.rs` and the CLI as type signatures change. Land them
together because they're related-shape API cleanups.

The previous bead (`frozenkrill-hd8`) already simplified
`secret_sharing.rs` internals; this bead does the cross-file API
cleanup that didn't fit there.

### Finding 1: Store singlesig metadata directly in VSS shares (~70-100 lines)

`VssJsonWalletDescriptionV0::original_wallet` is currently typed as the
`OriginalWalletJson` tagged enum:

```rust
enum OriginalWalletJson {
    Singlesig(SinglesigPublicMetadataV0),
    Multisig(/* something */),
}
```

But every VSS share in this branch is created by `split_singlesig_wallet`,
and recovery only ever consumes `SinglesigPublicMetadataV0`. The enum
wrapping is speculative generality.

Change the field to `original_wallet: SinglesigPublicMetadataV0` directly.
This removes:
- The `OriginalWalletJson` enum definition.
- Any `is_singlesig` / `is_multisig` helpers.
- Defensive `Multisig` match arms in `to_singlesig` / `derive_metadata`
  (and any other call sites — search the codebase).
- The Multisig-variant unreachable! / bail! noise.

If/when a real multisig share format ever needs to be added later,
re-introduce the enum at that point. **Do not pre-design for it now.**

### Finding 2: Reuse standard wallet encryption envelope for VSS (~50-70 lines)

`generate_encrypted_encoded_vss_wallet` in
`frozenkrill-core/src/lib.rs` is effectively a third copy of the same
envelope: serialize → compress → encrypt → header → pad → serialize.
The singlesig and multisig `generate_encrypted_encoded_*` functions
already do this same dance.

Extract a helper (e.g. `encrypt_with_standard_envelope<T: Serialize>(...)`,
or use traits if cleaner) and have all three call sites use it.

The trade-off is one generic helper signature, which is still simpler
than maintaining three near-identical crypto wrappers and reduces
drift when the encrypted-header / padding rules change later.

## Implementation hints

### Where to look

Required reading:
- `frozenkrill-core/src/wallet_description.rs` — `OriginalWalletJson`
  enum definition + `VssJsonWalletDescriptionV0::original_wallet` field
  + `to_singlesig` / `derive_metadata` / any other consumers.
- `frozenkrill-core/src/lib.rs` — `generate_encrypted_encoded_singlesig_wallet`,
  `generate_encrypted_encoded_multisig_wallet`,
  `generate_encrypted_encoded_vss_wallet` — these are the three copies
  to unify.
- `frozenkrill-core/src/secret_sharing.rs` — call sites that pattern-
  match on `original_wallet`. Should only need light type-driven
  edits after the enum is dropped.

Probable touch (light edits):
- `src/commands/split_secret.rs` — possibly references the enum
  variant when constructing shares.
- `src/commands/combine_secret.rs` — possibly references the enum
  when reading metadata.
- `src/main.rs` — unlikely, but check.

### Refactor ordering

Do them in this order to minimize churn:

1. **Finding 1 first** (drop tagged enum). Touches more files but
   each touch is mechanical (`OriginalWalletJson::Singlesig(m)` →
   `m`). After this lands, the file shapes are simpler.
2. **Finding 2** (unify envelope). Self-contained in `lib.rs` once
   you decide on the helper signature.

### Cryptographic semantics — DO NOT change

- The on-disk byte layout of the AEAD-encrypted wrapper, header,
  and padding rules must be identical before and after.
- The on-disk JSON layout of `VssJsonWalletDescriptionV0` MAY
  simplify (the `original_wallet` field's serde tag/variant
  wrapping goes away), but this is acceptable because the
  secret-sharing feature has not been released yet (still PR #33
  against master).
- All Pedersen verification, threshold reconstruction, and
  fail-closed authentication invariants from the codex hardening
  loop must still hold.

### Test surface

- `frozenkrill-core/src/secret_sharing.rs::tests` — many tests
  construct `VssJsonWalletDescriptionV0` values; they'll need
  trivial `OriginalWalletJson::Singlesig(m)` → `m` updates after
  the enum is dropped.
- `frozenkrill-core/src/lib.rs` may have envelope round-trip tests
  that need to keep passing through the unified helper.
- `frozenkrill-core/tests/integration.rs` — should be unchanged
  (it tests through the public encrypt/decrypt API, not the
  internal envelope structure).

## IMPORTANT: Exclude orchestration state from review scope

Files under `.ralph-burning/`, `.ralph/`, and `.beads/` are live
orchestration / issue-tracking state and MUST NOT be reviewed or
flagged. Only review source code under `src/`,
`frozenkrill-core/src/`, `tests/`, `docs/`, and config files
(`Cargo.toml`, `Cargo.lock`, etc.).

## Acceptance criteria

- `nix develop --command cargo build --workspace` clean
- `nix develop --command cargo test --workspace` green —
  every existing test passes after type-driven edits to remove
  the `OriginalWalletJson::Singlesig(...)` wrapping
- `nix develop --command cargo clippy --workspace --all-targets -- -D warnings` clean
- `nix develop --command cargo fmt --check` clean
- `nix build` passes
- **Net line reduction across `wallet_description.rs` and `lib.rs`
  of at least 100 lines combined.** Measure via
  `git diff --stat origin/feature/pedersen-secret-sharing..HEAD --
  frozenkrill-core/src/wallet_description.rs frozenkrill-core/src/lib.rs`.
- Cryptographic / on-disk encrypted format semantics unchanged
  (header bytes, padding rules, AEAD envelope).

## Out of scope

- Anything in `secret_sharing.rs` beyond what's strictly needed for
  the type-system to accept the dropped enum (handled by the
  previous bead `frozenkrill-hd8`, which has merged).
- Adding multisig support — the simplification is precisely about
  not building speculative multisig infrastructure.
- Renaming or restructuring beyond what's needed for these two
  specific simplifications.

## How this bead is tracked

- Bead ID: `frozenkrill-x2z`
- Branch: `feat/frozenkrill-x2z-drop-tagged-enum-unify-envelope`
- Base branch: `feature/pedersen-secret-sharing` (now containing
  the merged hd8 simplifications)
- After merge: `br close --actor assistant frozenkrill-x2z --reason "..."`
