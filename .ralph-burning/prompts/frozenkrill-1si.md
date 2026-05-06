# Test-only path removal + CLI preflight dedupe + stale comment trim (bead frozenkrill-1si)

## Problem

Three smaller simplifications from the second codex review, grouped
because they're all P3 cleanups touching CLI / wallet_description
boundaries that the previous bead (`frozenkrill-ugd`) deliberately
left alone.

The previous bead just collapsed the internal `Share` schema and
dropped redundant verifier fields. With those gone, this bead can
focus on the cross-file leftovers.

### Finding 1: Remove test-only `to_singlesig` rebuild path (~40-50 lines)

`SinglesigShareMetadataV0::to_singlesig()` (around
`frozenkrill-core/src/wallet_description.rs:1391-1397`, but verify
the exact line range against the current file — it may have shifted
after the ugd merge) is `#[cfg(test)]` and reimplements most of
`VssRecovery::rebuild_singlesig()`:

- Empty-passphrase normalization (`Some("")` → `None`)
- `network` / `script_type` parsing
- No-passphrase witness generation
- xpub mismatch check

Every caller is a test in `secret_sharing.rs::tests` (also possibly
elsewhere; grep first). Route those tests through
`VssRecovery::rebuild_singlesig` (or a tiny shared helper if one
rebuild path argues for it).

The trade-off: tests get slightly noisier setup (build a
`VssRecovery` first), but only one recovery policy lives in the
codebase.

### Finding 2: Deduplicate split-secret preflight checks (~20-30 lines)

`commands::split_secret::split_singlesig_wallet()` (around
`src/commands/split_secret.rs:70-76`, may have shifted) runs M-of-N
and output-dir validation that `Commands::SplitSecret` in
`src/main.rs` already runs *before* any prompt is shown. Now that
`split_singlesig_wallet()` is `pub(crate)` and only called from
that one CLI path, the second copy is defensive scaffolding.

Either:
- **Drop the duplicate `ensure!`s entirely** (rely on the CLI-side
  preflight), OR
- **Extract a `preflight_split_secret(...)` helper** both can call
  (if the CLI ever needs to skip a check, this gives a single knob).

Prefer the simpler "drop the duplicate" option unless extracting
the helper provides immediate clarity. **Do NOT introduce the
helper speculatively** — that just trades duplication for indirection
without simplification gain.

### Finding 3: Trim stale post-combine comment (~15 lines)

`src/commands/combine_secret.rs:146-149` (verify against current
file) carries a multi-paragraph comment describing a "cross-check /
warn and still print the seed" local flow, but the code below no
longer does any of that — authentication now lives entirely inside
`combine_vss_wallets()`. Collapse the comment to a one-liner pointing
at the library function (or remove it if the function name + the
preceding short comment make the source of authentication obvious).

## Implementation hints

### Where to look

- `frozenkrill-core/src/wallet_description.rs` — the `to_singlesig`
  test-only function. Search for its definition AND every test
  that calls it.
- `frozenkrill-core/src/secret_sharing.rs::tests` — the most
  likely callers of `to_singlesig`. Each one needs to be migrated
  to `VssRecovery::rebuild_singlesig`.
- `src/commands/split_secret.rs` — the duplicate preflight `ensure!`s
  near the top of `split_singlesig_wallet`.
- `src/main.rs` — the `Commands::SplitSecret` arm that already runs
  the same preflight before the prompts. Confirm the duplication
  before dropping anything.
- `src/commands/combine_secret.rs` — the stale comment block.

### Refactor ordering

These three findings are mostly independent and can be done in
any order. Suggested sequence (smallest to largest blast radius):

1. **Finding 3 first** (comment trim). Single-file, no functional
   change. Smallest possible risk.
2. **Finding 2 second** (preflight dedupe). Single-file (CLI
   helper), no functional change.
3. **Finding 1 last** (test-only `to_singlesig` removal). Touches
   multiple test files; do this with the file shape clear from
   the earlier two cleanups.

Run the test suite after each finding to catch regressions early.

### What MUST stay correct

- The recovery-authentication path in `combine_vss_wallets` is the
  one and only `(seed → no-passphrase wallet → xpub match)` check
  in the codebase by the end of this bead.
- All existing test coverage on the share-recovery / metadata-tamper
  guards must remain. **Do NOT delete tests** to make migration
  easier — adapt them to use `VssRecovery::rebuild_singlesig`
  instead of `to_singlesig`.
- Cryptographic / on-disk format semantics unchanged.

## IMPORTANT: Exclude orchestration state from review scope

Files under `.ralph-burning/`, `.ralph/`, and `.beads/` are live
orchestration / issue-tracking state and MUST NOT be reviewed or
flagged. Only review source code under `src/`,
`frozenkrill-core/src/`, `tests/`, `docs/`, and config files
(`Cargo.toml`, `Cargo.lock`, etc.).

## Acceptance criteria

- `nix develop --command cargo build --workspace` clean
- `nix develop --command cargo test --workspace` green —
  every existing test passes (some test setup may shift from
  `to_singlesig` to `rebuild_singlesig`)
- `nix develop --command cargo clippy --workspace --all-targets -- -D warnings` clean
- `nix develop --command cargo fmt --check` clean
- `nix build` passes
- **Net line reduction across `wallet_description.rs`,
  `split_secret.rs`, and `combine_secret.rs` of at least 60 lines
  combined.** Measure via
  `git diff --stat origin/feature/pedersen-secret-sharing..HEAD --
  frozenkrill-core/src/wallet_description.rs
  src/commands/split_secret.rs
  src/commands/combine_secret.rs`.
- `to_singlesig` is gone from `wallet_description.rs` (or, if the
  removal proved infeasible, the bead is left in_progress with a
  short note explaining why).

## Out of scope

- Anything in the core split/combine path of `secret_sharing.rs`
  beyond what's strictly needed to keep tests passing after the
  `to_singlesig` removal (that file was just simplified by
  bead `frozenkrill-ugd`).
- Functional behavior changes — these are pure cleanups.
- Adding new tests beyond what's needed to maintain coverage.

## How this bead is tracked

- Bead ID: `frozenkrill-1si`
- Branch: `feat/frozenkrill-1si-p3-cleanup-trio`
- Base branch: `feature/pedersen-secret-sharing` (containing the
  merged ugd simplifications)
- After merge: `br close --actor assistant frozenkrill-1si --reason "..."`
