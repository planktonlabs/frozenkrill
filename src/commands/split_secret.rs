use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use frozenkrill_core::{
    PaddingParams,
    anyhow::{self, Context},
    bitcoin::secp256k1::{All, Secp256k1},
    generate_encrypted_encoded_vss_wallet, get_padder, hex,
    key_derivation::{KeyDerivationDifficulty, default_derive_key},
    random_generation_utils::{self, get_random_key},
    secrecy::{ExposeSecret, SecretBox, SecretString},
    secret_sharing::split_singlesig_wallet as split_singlesig_wallet_core,
    wallet_description::{
        EncryptedWalletVersion, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
    },
};

use crate::progress_bar::get_spinner;

/// Split a wallet's seed phrase into shares using Pedersen secret sharing.
#[allow(clippy::too_many_arguments)]
pub(crate) fn split_singlesig_wallet(
    secp: &Secp256k1<All>,
    wallet: &SingleSigWalletDescriptionV0,
    threshold: u8,
    total_shares: u8,
    output_dir: &Path,
    password: &Arc<SecretString>,
    keyfiles: &[PathBuf],
    difficulty: KeyDerivationDifficulty,
    padding_params: &PaddingParams,
    encrypted_version: EncryptedWalletVersion,
    rng: &mut (impl frozenkrill_core::rand::RngCore + frozenkrill_core::rand::CryptoRng),
) -> anyhow::Result<()> {
    // VSS share decryption only handles V0Standard; reject anything else
    // up front so we never write shares that combine-secret cannot reopen.
    anyhow::ensure!(
        matches!(encrypted_version, EncryptedWalletVersion::V0Standard),
        "VSS shares require V0Standard encrypted wallet version (got {encrypted_version:?}); the compact format cannot be decrypted"
    );

    // The "do you understand the risks?" confirmation prompt now runs
    // in `main.rs::Commands::SplitSecret` BEFORE we ask the user for
    // any password, so cancelling at the warning doesn't
    // waste a credential prompt. By the time we get here the user has
    // already acknowledged the M-of-N reconstruction trade-off and the
    // irreversibility note. We deliberately don't repeat the prompt
    // here — duplicate prompts train users to confirm reflexively.

    // Convert wallet to JSON format for splitting
    let spinner = get_spinner("Preparing wallet for splitting...");
    let wallet_json = SinglesigJsonWalletDescriptionV0::from_wallet_description(wallet, secp)?;
    spinner.finish_with_message("✓ Wallet prepared");

    // Create a spinner for the splitting operation
    let spinner = get_spinner("Splitting seed into shares using Pedersen scheme...");

    // Perform the split using the core function
    let vss_wallets =
        split_singlesig_wallet_core(wallet_json.expose_secret(), threshold, total_shares, rng)
            .context("Failed to split wallet into shares")?;

    spinner.finish_with_message("✓ Seed successfully split into shares");

    // Write the share set all-or-nothing.
    //
    // Phase 1 (streaming): for each share, encrypt → open `<final>.partial`
    //   with O_CREAT|O_EXCL → write ciphertext → sync_all → drop the
    //   ciphertext buffer. Peak memory stays at one ciphertext at a time,
    //   not `total_shares × max_padding`, so a large `--max-additional-
    //   padding-bytes` can't OOM us before any file lands on disk.
    //
    // Phase 2 (atomic finalize): for each share, `hard_link(partial,
    //   final)` → `remove_file(partial)`. `hard_link` fails if the final
    //   path already exists, which is the atomic no-replace guarantee
    //   `std::fs::rename` does NOT give on Unix (where rename overwrites).
    //   So a racing process that creates a colliding final file can never
    //   be clobbered by us.
    //
    // On any failure at any point: best-effort delete every `.partial`
    // file we created AND every final file we already linked, so the user
    // sees either a complete share set or no leftovers from this run.
    let spinner = get_spinner("Encrypting and writing shares to files...");
    // Filenames embed a UTC timestamp + a short random suffix. The
    // timestamp is for human readability ("which backup is this?"), and
    // the random suffix avoids collisions when two `split-secret` runs
    // happen to land in the same wall-clock second with the same
    // `total_shares` (e.g. a retry, or a parallel invocation pointed at
    // a shared output directory). 8 hex chars = 32 bits of entropy ⇒
    // collision probability is vanishing in practice.
    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let mut filename_suffix_bytes = [0u8; 4];
    frozenkrill_core::rand::RngCore::fill_bytes(rng, &mut filename_suffix_bytes);
    let filename_suffix = hex::encode(filename_suffix_bytes);

    struct PendingShare {
        partial: PathBuf,
        final_path: PathBuf,
    }

    let cleanup = |partials: &[PathBuf], finals: &[PathBuf]| {
        for p in partials {
            let _ = std::fs::remove_file(p);
        }
        for p in finals {
            let _ = std::fs::remove_file(p);
        }
    };

    // Phase 1: encrypt + write each share's `.partial`, one at a time.
    //
    // Every error path inside the loop must roll back the `.partial`
    // files we have created so far (key-derive failure on a later
    // share, RNG/padder failure under memory pressure, encrypt failure,
    // short write, ENOSPC, sync_all error, …). We also distinguish "we
    // created this iteration's `.partial`" from "we tried to create it
    // but `create_new` returned `AlreadyExists` because another
    // concurrent split-secret run got there first" — only the former
    // should be unlinked, otherwise we would clobber that other run's
    // work and break its no-replace guarantee.
    let mut pending: Vec<PendingShare> = Vec::with_capacity(vss_wallets.len());
    for vss_wallet in &vss_wallets {
        let filename = format!(
            "share-{}-of-{}-{}-{}.frozenkrill",
            vss_wallet.share_index, vss_wallet.total_shares, timestamp, filename_suffix
        );
        let final_path = output_dir.join(&filename);
        let partial = output_dir.join(format!("{filename}.partial"));

        // Tracks whether THIS iteration successfully called create_new on
        // `partial`. Set to true only after the open succeeds; used to
        // decide whether the rollback below should unlink `partial`.
        let mut created_this_iter = false;

        let iter_result: anyhow::Result<()> = (|| {
            let salt = random_generation_utils::get_random_salt(rng)?;
            let nonce = random_generation_utils::get_random_nonce(rng)?;
            let header_nonce = random_generation_utils::get_random_nonce(rng)?;
            let padder = get_padder(rng, padding_params)?;
            let key = default_derive_key(password, keyfiles, &salt, &difficulty)?;
            let header_key = SecretBox::from(Box::new(get_random_key(rng)?));

            let ciphertext = generate_encrypted_encoded_vss_wallet(
                &key,
                header_key,
                vss_wallet,
                salt,
                nonce,
                header_nonce,
                padder,
                encrypted_version,
            )
            .context("Failed to encrypt share")?;

            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&partial)
                .with_context(|| {
                    format!(
                        "Failed to create partial share file (already exists or unwritable): {}",
                        partial.display()
                    )
                })?;
            // From here on the `.partial` exists on disk — record that
            // so the rollback can clean it up if a later step fails.
            created_this_iter = true;

            file.write_all(&ciphertext).with_context(|| {
                format!("Failed to write encrypted share to {}", partial.display())
            })?;
            file.sync_all().with_context(|| {
                format!("Failed to flush share file to disk: {}", partial.display())
            })?;
            // Drop the ciphertext as soon as we're done with it — the
            // next iteration will allocate the next share. Keeps peak
            // RAM at O(one ciphertext) instead of O(N × ciphertext).
            drop(ciphertext);
            Ok(())
        })();

        if let Err(e) = iter_result {
            let mut partials: Vec<PathBuf> = pending.iter().map(|p| p.partial.clone()).collect();
            if created_this_iter {
                partials.push(partial.clone());
            }
            cleanup(&partials, &[]);
            return Err(e);
        }

        pending.push(PendingShare {
            partial,
            final_path,
        });
    }

    // Phase 2: finalize each `.partial` into its final name with a
    // no-replace primitive, so a racing writer can never be clobbered.
    // First try `hard_link` (cheap, atomic, no-replace on every platform);
    // if the filesystem doesn't support hard links (exFAT/FAT32 USB,
    // many network shares), fall back to `OpenOptions::create_new` +
    // `io::copy`, which keeps the same no-replace guarantee but works
    // anywhere basic file IO does.
    let mut finals_renamed: Vec<PathBuf> = Vec::with_capacity(pending.len());
    let mut saved_files: Vec<PathBuf> = Vec::with_capacity(pending.len());
    for share in pending.iter() {
        if let Err(e) = finalize_share(&share.partial, &share.final_path) {
            // Roll back EVERY partial we created in phase 1, not just
            // the ones from this index onward. `finalize_share`'s
            // best-effort `remove_file(partial)` for already-finalized
            // shares can transiently fail (e.g. another process briefly
            // holding the file open on Windows); a later finalize error
            // would otherwise leak those earlier `.partial` files —
            // encrypted-share artifacts that should not stay on disk
            // after a failed run. The deletes are idempotent: paths
            // that were already cleaned simply fail silently.
            let all_partials: Vec<PathBuf> = pending.iter().map(|p| p.partial.clone()).collect();
            cleanup(&all_partials, &finals_renamed);
            return Err(e);
        }
        finals_renamed.push(share.final_path.clone());
        saved_files.push(share.final_path.clone());
    }

    spinner.finish_with_message(format!(
        "✓ {} encrypted shares written successfully",
        vss_wallets.len()
    ));

    // Display results
    println!("\n✓ Secret sharing completed successfully!");
    println!("\nShare files created:");
    for (idx, path) in saved_files.iter().enumerate() {
        println!("  {}. {}", idx + 1, path.display());
    }

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("NEXT STEPS - Share Distribution Checklist:");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  ☐ Verify all {} share files were created", total_shares);
    println!(
        "  ☐ Test reconstruction with {} shares (see 'combine-secret' command)",
        threshold
    );
    println!("  ☐ Store each share in a DIFFERENT physical location");
    println!("  ☐ Consider geographic distribution (different cities/countries)");
    println!("  ☐ Document where each share is stored (without storing shares together)");
    println!("  ☐ Securely delete shares from this computer after distribution");
    println!("  ☐ Keep your original wallet safe until shares are distributed");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Echo non-default share-encryption parameters back to the user.
    // Keyfiles and difficulty are NOT recorded inside the share files
    // (they're inputs to key derivation, not part of the encrypted
    // payload) — `combine-secret` cannot decrypt the shares without
    // the same flags. If the user walks away with custom values that
    // they only had on this command line, recovery silently fails
    // months later. Print them now in copy-paste-ready form, mirroring
    // what `inform_custom_generate_params` does for wallet generation.
    let custom_keyfiles = !keyfiles.is_empty();
    let custom_difficulty =
        difficulty != frozenkrill_core::key_derivation::DEFAULT_DIFFICULTY_LEVEL;
    if custom_keyfiles || custom_difficulty {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("⚠️  RECORD THESE PARAMETERS — required to decrypt the shares later:");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        for k in keyfiles {
            println!("    --keyfile {}", k.display());
        }
        if custom_difficulty {
            println!("    --difficulty {}", difficulty.as_str().to_lowercase());
        }
        println!(
            "(`combine-secret` cannot read these from the share files; without the\n\
             above flags, share decryption will fail with a generic 'wrong password' error.)"
        );
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    }

    Ok(())
}

/// Finalize a `.partial` share file to its final name with atomic
/// no-replace semantics, falling back from `hard_link` to a buffered copy
/// when the destination filesystem does not support hard links.
///
/// Returns Err if the final path already exists (the no-replace guarantee
/// is preserved in both branches: `hard_link` returns AlreadyExists and
/// `OpenOptions::create_new` likewise refuses to open an existing path).
fn finalize_share(partial: &Path, final_path: &Path) -> anyhow::Result<()> {
    use std::io::ErrorKind;
    match std::fs::hard_link(partial, final_path) {
        Ok(()) => {
            // Best-effort: drop the .partial alias. If this fails the
            // final file is still correct; the leftover .partial does
            // not match `share-*.frozenkrill` and so won't be picked up
            // by combine-secret.
            let _ = std::fs::remove_file(partial);
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Err(anyhow::anyhow!(
            "Final share path already exists, refusing to overwrite: {}",
            final_path.display()
        )),
        Err(_) => {
            // Likely an unsupported-link error (FAT32/exFAT/some network
            // shares) or a permission issue. Fall back to a no-replace
            // copy: open the destination with O_CREAT|O_EXCL, which
            // refuses to clobber an existing file just like hard_link
            // does, then stream the bytes across.
            //
            // If anything fails after the destination has been created
            // (short copy, ENOSPC mid-write, sync_all error, …), we must
            // unlink the half-written destination so the all-or-nothing
            // contract still holds and the outer rollback in `split-secret`
            // doesn't leave a truncated `share-*.frozenkrill` behind.
            let mut src = std::fs::File::open(partial)
                .with_context(|| format!("opening partial share file: {}", partial.display()))?;
            let mut dst = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(final_path)
                .with_context(|| {
                    format!(
                        "creating final share file (already exists or unwritable): {}",
                        final_path.display()
                    )
                })?;
            let copy_result = (|| -> anyhow::Result<()> {
                std::io::copy(&mut src, &mut dst).with_context(|| {
                    format!("copying {} → {}", partial.display(), final_path.display())
                })?;
                dst.sync_all().with_context(|| {
                    format!("syncing final share file: {}", final_path.display())
                })?;
                Ok(())
            })();
            // Drop the file handles before any unlink — required on Windows.
            drop(dst);
            drop(src);
            if let Err(e) = copy_result {
                let _ = std::fs::remove_file(final_path);
                return Err(e);
            }
            let _ = std::fs::remove_file(partial);
            Ok(())
        }
    }
}

/// Get share files from a directory or list of paths.
///
/// When a directory is supplied, only files matching the share naming
/// convention written by `split-secret` are picked up — specifically
/// `share-{idx}-of-{total}-...frozenkrill` where `idx` and `total`
/// parse as `u8`. This is stricter than a plain `share-*.frozenkrill`
/// glob: combine-secret's decrypt loop fails closed on any
/// undecryptable input, so a stray file like `share-backup.frozenkrill`
/// (a renamed wallet backup, an unrelated note, etc.) would otherwise
/// abort recovery even when enough real shares are present.
/// Explicitly-passed file paths are still accepted as-is — the user
/// asking for them by name is consent.
pub(crate) fn collect_share_files(share_paths: &[String]) -> anyhow::Result<Vec<PathBuf>> {
    let mut share_files: Vec<PathBuf> = Vec::new();

    for path_str in share_paths {
        let path = PathBuf::from(path_str);

        if path.is_file() {
            share_files.push(path);
        } else if path.is_dir() {
            for entry in std::fs::read_dir(&path)
                .with_context(|| format!("Failed to read directory: {}", path.display()))?
            {
                let entry = entry?;
                let file_path = entry.path();

                if !file_path.is_file() {
                    continue;
                }
                let is_frozenkrill = file_path
                    .extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.eq_ignore_ascii_case("frozenkrill"));
                let looks_like_share = file_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(looks_like_share_filename);
                if is_frozenkrill && looks_like_share {
                    share_files.push(file_path);
                }
            }
        } else {
            anyhow::bail!("Path does not exist: {}", path.display());
        }
    }

    anyhow::ensure!(
        !share_files.is_empty(),
        "No share files found in the provided paths (expected files matching `share-{{idx}}-of-{{total}}-...frozenkrill`)"
    );

    Ok(share_files)
}

/// Returns true iff `name` matches the filename pattern that
/// `split-secret` writes — `share-{idx}-of-{total}-{rest}.frozenkrill`
/// (or `.FROZENKRILL`) where `idx` and `total` parse as `u8`. This is
/// used to filter directory listings so a stray
/// `share-backup.frozenkrill` (or any non-share `.frozenkrill` file
/// the user happens to keep alongside their share set) doesn't get
/// fed into the fail-closed decrypt loop.
fn looks_like_share_filename(name: &str) -> bool {
    // Strip .frozenkrill (case-insensitive) suffix.
    let stem = name
        .strip_suffix(".frozenkrill")
        .or_else(|| name.strip_suffix(".FROZENKRILL"))
        .unwrap_or(name);
    // Strip the literal "share-" prefix.
    let Some(rest) = stem.strip_prefix("share-") else {
        return false;
    };
    // Expect at least four `-`-separated fields:
    //   {idx}-of-{total}-{timestamp-and-rest}
    // splitn(4, '-') keeps the trailing fields together, so a missing
    // trailing field (e.g. just "1-of-3") fails this check.
    let mut parts = rest.splitn(4, '-');
    let (Some(idx), Some(of_lit), Some(total), Some(_tail)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    of_lit == "of" && idx.parse::<u8>().is_ok() && total.parse::<u8>().is_ok()
}

#[cfg(test)]
mod looks_like_share_filename_tests {
    use super::looks_like_share_filename;

    #[test]
    fn accepts_split_secret_emitted_pattern() {
        // Matches what split-secret actually writes:
        //   share-{idx}-of-{total}-{YYYYMMDD-HHMMSS}-{8 hex}.frozenkrill
        assert!(looks_like_share_filename(
            "share-1-of-3-20260501-123456-deadbeef.frozenkrill"
        ));
        assert!(looks_like_share_filename(
            "share-12-of-50-20991231-235959-cafebabe.frozenkrill"
        ));
        // Case-insensitive extension is fine.
        assert!(looks_like_share_filename(
            "share-1-of-2-20260501-000000-aabbccdd.FROZENKRILL"
        ));
    }

    #[test]
    fn rejects_lookalike_non_share_files() {
        // A renamed wallet backup that just happens to start with
        // "share-" — the failure mode that motivated the tighter check.
        assert!(!looks_like_share_filename("share-backup.frozenkrill"));
        assert!(!looks_like_share_filename("share-old-wallet.frozenkrill"));
        // Missing the "of" literal in the slot where it should appear.
        assert!(!looks_like_share_filename(
            "share-1-OF-3-20260501-123456-deadbeef.frozenkrill"
        ));
        // idx not numeric.
        assert!(!looks_like_share_filename(
            "share-one-of-3-20260501-123456-deadbeef.frozenkrill"
        ));
        // total not numeric.
        assert!(!looks_like_share_filename(
            "share-1-of-three-20260501-123456-deadbeef.frozenkrill"
        ));
        // Truncated — no trailing tail field after `{idx}-of-{total}-`.
        assert!(!looks_like_share_filename("share-1-of-3.frozenkrill"));
        // Wrong prefix.
        assert!(!looks_like_share_filename(
            "wallet-1-of-3-20260501-123456-deadbeef.frozenkrill"
        ));
    }

    #[test]
    fn rejects_idx_or_total_overflowing_u8() {
        // u8 max is 255; 256 must be rejected so we don't accidentally
        // accept arbitrary wide-numeric prefixes that aren't real
        // share files. (Real splits cap at 255 shares already.)
        assert!(!looks_like_share_filename(
            "share-256-of-3-20260501-123456-deadbeef.frozenkrill"
        ));
        assert!(!looks_like_share_filename(
            "share-1-of-256-20260501-123456-deadbeef.frozenkrill"
        ));
    }
}
