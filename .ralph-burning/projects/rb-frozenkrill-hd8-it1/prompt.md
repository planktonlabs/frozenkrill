# Simplify `secret_sharing.rs` (bead frozenkrill-hd8)

## Problem

`frozenkrill-core/src/secret_sharing.rs` is currently ~2700 lines. A
codex simplification review identified four overlapping refactors that
together should remove **at least 250 lines** without changing
behavior:

1. **Combine candidates without cloning `Share`s.** `combine_vss_wallets`
   iterates one Pedersen verifier candidate at a time, but every input
   wallet still gets cloned into a synthetic `Share` so
   `combine_shares_to_mnemonic` can regroup them by the same verifier
   strings. Fold that helper into a candidate-specific combine over
   `VssJsonWalletDescriptionV0` directly. Drop the cloning round-trip.
2. **Drop the test-only `Share` checksum from production.** The
   `Share::checksum` field and `compute_checksum()` method are now
   exercised only from tests, but production split/combine still
   carries the field and recomputes it for synthetic shares built
   during recovery. Either gate `checksum` + `compute_checksum` /
   `verify_checksum` behind `#[cfg(test)]`, OR drop them entirely
   and adapt the small set of tests that assert on them. Prefer the
   drop-entirely option if the test surface is small.
3. **Single verifier-check helper.** The `verifies_lo` / `verifies_hi`
   closures inside `combine_vss_wallets` repeat the hex-decode +
   share-pair verification work that `derive_metadata` reimplements a
   few lines later. Extract `wallet_verifies_against_candidate(...)`
   (or similar) and have both call sites use it.
4. **Trim Pedersen/Shamir tutorial text.** The file opens with a
   tutorial-style module preface and repeats 10–20 line threat-model
   explanations beside many individual branches. Most of the
   long-form rationale is duplicated in `docs/secret_sharing.md`
   (added during the codex hardening loop). Trim the inline comments
   to short intent statements; lean on the doc for the security
   narrative.

## Implementation hints

### Where to look

- `frozenkrill-core/src/secret_sharing.rs` — the only file that needs
  to change for findings 1–3. Finding 4 is also entirely in this file.
- `frozenkrill-core/src/wallet_description.rs` — only as a reader of
  the `VssJsonWalletDescriptionV0` API; **do not** modify it for this
  bead (cross-file API cleanup is a separate bead, frozenkrill-x2z).
- `docs/secret_sharing.md` — the reference doc the trimmed comments
  defer to. Skim it once so you know what to leave inline vs cut.

### Comment-trim policy (finding 4)

**KEEP** comments that:
- Document a non-obvious invariant the code itself doesn't show.
- Explain *why* a particular fail-closed branch was added (the
  codex-loop letter-tagged findings preserved the WHY — that's
  load-bearing context for future readers).
- Reference a specific bug, attack, or edge case that motivated a
  guard (e.g. "fail closed on tied vote: hybrid-attack guard,
  see YY-1").

**TRIM** comments that:
- Restate Pedersen / Shamir definitions or the threat model in
  general terms — `docs/secret_sharing.md` covers it.
- Repeat "this is hardened against X" notes when the test suite
  + docs already make X explicit.
- Bullet-list explanations longer than the code they annotate.
- Tutorial-style preludes that introduce concepts already in the
  doc.

### Refactor ordering

Do them in this order to minimize churn:

1. Finding 4 first (comment trim) — no behavior change, biggest
   line savings, lets you see the file shape clearly before
   structural moves.
2. Finding 3 (verifier-check helper) — small, self-contained.
3. Finding 2 (drop / gate `Share` checksum) — small,
   self-contained.
4. Finding 1 last (collapse `Share` regroup) — the structural
   change. Easier to reason about once the surrounding noise is
   gone.

### Cryptographic semantics — DO NOT change

- Pedersen blind-commitment verification (`g^a · h^b` per share).
- Threshold reconstruction (M-of-N Shamir).
- Fail-closed authentication in `combine_vss_wallets` (refuses
  recoveries with empty / tied metadata; cross-validates seed
  against the share metadata's xpub).
- Candidate cross-product enumeration for split lo/hi verifier
  corruption (the GGG-1 fix).
- Strict-majority `is_duress` aggregation; abstain on tie.
- Per-share verifier-corruption tolerance (verify against the
  winning verifier, not the share's own copy).

If a comment trim or refactor would silently weaken any of these,
back it out. Run the test suite after each finding to catch
regressions early.

## IMPORTANT: Exclude orchestration state from review scope

Files under `.ralph-burning/`, `.ralph/`, and `.beads/` are live
orchestration / issue-tracking state and MUST NOT be reviewed or
flagged. Only review source code under `src/`,
`frozenkrill-core/src/`, `tests/`, `docs/`, and config files
(`Cargo.toml`, `Cargo.lock`, etc.).

## Acceptance criteria

- All existing tests in `frozenkrill-core/src/secret_sharing.rs::tests`
  still pass (currently 68+ tests after the vsss-rs 5.x migration).
- `nix develop --command cargo build --workspace` clean
- `nix develop --command cargo test --workspace` green
- `nix develop --command cargo clippy --workspace --all-targets -- -D warnings` clean
- `nix develop --command cargo fmt --check` clean
- `nix build` passes
- **Net line reduction in `frozenkrill-core/src/secret_sharing.rs`
  of at least 250 lines.** Measure via
  `git diff --stat origin/feature/pedersen-secret-sharing..HEAD --
  frozenkrill-core/src/secret_sharing.rs`. If the reduction is below
  250 lines, you have not finished this bead.
- All cryptographic semantics preserved (see "DO NOT change" above).

## Out of scope

- Anything in `wallet_description.rs` or `lib.rs` beyond what's
  strictly needed to satisfy the type-system after the
  secret_sharing.rs refactors. (Dropping `OriginalWalletJson` and
  unifying the encryption envelope are handled by the next bead,
  `frozenkrill-x2z`.)
- Changing the on-disk format of `VssJsonWalletDescriptionV0`.
- Adding new tests beyond what's needed to maintain coverage of
  refactored code paths.

## How this bead is tracked

- Bead ID: `frozenkrill-hd8`
- Branch: `feat/frozenkrill-hd8-simplify-secret-sharing`
- Base branch: `feature/pedersen-secret-sharing`
- After merge: `br close --actor assistant frozenkrill-hd8 --reason "..."`
