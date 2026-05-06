use std::{path::PathBuf, sync::Arc};

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow::{self, Context},
    bip39::Mnemonic,
    key_derivation::{KeyDerivationDifficulty, default_derive_key},
    secrecy::{ExposeSecret, SecretBox, SecretString},
    secret_sharing::combine_vss_wallets,
    wallet_description::read_decode_wallet,
};

use crate::progress_bar::get_spinner;

use super::split_secret::collect_share_files;

/// Combine shares to reconstruct the original wallet.
///
/// Returns a `SecretBox<Mnemonic>` so the recovered seed phrase is never
/// materialized as a plain heap-allocated `String` (which would not be
/// zeroized on drop and could leak via crash dumps or memory inspection).
pub(crate) fn combine_shares(
    theme: &dyn Theme,
    term: &Term,
    share_paths: &[String],
    display_mnemonic: bool,
    keyfiles: &[PathBuf],
    difficulty: KeyDerivationDifficulty,
    password: Option<SecretString>,
) -> anyhow::Result<SecretBox<Mnemonic>> {
    // Collect share files from the supplied paths and/or directories.
    let share_files = collect_share_files(share_paths)?;

    println!("\nFound {} share files:", share_files.len());
    for (idx, path) in share_files.iter().enumerate() {
        println!("  {}. {}", idx + 1, path.display());
    }

    // Use the caller-supplied password (from --password / env) when set;
    // otherwise prompt interactively. The interactive prompt accepts an
    // empty string (Enter-to-skip) so that share sets written with an
    // empty `--share-password` (passwordless / keyfile-only flows) are
    // recoverable through the default UX too — the regular
    // `ask_password` rejects empty input.
    let password = match password {
        Some(p) => Arc::new(p),
        None => {
            println!("\nTo decrypt the shares, please provide the password used during splitting");
            println!(
                "(leave blank if the shares were created with no password, e.g. keyfile-only):"
            );
            let typed = dialoguer::Password::with_theme(theme)
                .with_prompt("Share password")
                .allow_empty_password(true)
                .interact_on(term)
                .context("failure reading share password")?;
            Arc::new(SecretString::new(typed.into()))
        }
    };

    // Decrypt every share file. ANY decrypt failure is fatal — we do not
    // silently skip files (whether they came from a directory expansion or
    // an explicit shell glob like `share-*.frozenkrill`). Skipping would
    // be unsafe: the intended shares could be the ones that failed to
    // decrypt (mistyped password, wrong keyfile/difficulty), and any
    // *other* shares in the same input that happen to decrypt under the
    // typed credentials could then drive a false-success recovery of an
    // unrelated wallet. Failing closed forces the user to either supply
    // the correct credentials or curate the input list.
    let spinner = get_spinner("Decrypting share files...");
    let mut decrypted_shares = Vec::new();
    let mut failures: Vec<(PathBuf, String)> = Vec::new();

    for share_file in &share_files {
        let attempt = (|| -> anyhow::Result<_> {
            let encrypted_wallet = read_decode_wallet(share_file)
                .with_context(|| format!("read/decode failed: {}", share_file.display()))?;
            let key = default_derive_key(&password, keyfiles, &encrypted_wallet.salt, &difficulty)
                .context("key derivation failed")?;
            encrypted_wallet
                .decrypt_vss(&key)
                .context("decrypt failed (wrong password/keyfiles/difficulty?)")
        })();
        match attempt {
            Ok(d) => decrypted_shares.push(d),
            Err(e) => failures.push((share_file.clone(), format!("{e:#}"))),
        }
    }

    spinner.finish_with_message(format!(
        "✓ Decrypted {} share(s); {} failed",
        decrypted_shares.len(),
        failures.len()
    ));

    // Fail closed when ANY share file failed to decrypt. The
    // alternative — silently skipping and recovering whatever
    // remains — risks emitting an unrelated wallet's mnemonic when
    // the input mixes shares from multiple wallets that happen to
    // use the same share credentials, since the CLI does not
    // currently print the recovered xpub/address for the user to
    // spot-check. Forcing the user to either fix the failing files
    // or re-run with the specific share file paths they want is the
    // safer default; M-of-N redundancy against genuine corruption is
    // recovered by passing only the intact files explicitly.
    if !failures.is_empty() {
        eprintln!(
            "\n{} share file(s) failed to decrypt with the given inputs:",
            failures.len()
        );
        for (path, reason) in &failures {
            eprintln!("  • {} — {}", path.display(), reason);
        }
        anyhow::bail!(
            "Refusing to recover when some share files failed to decrypt — the \
             intended shares may be among the failures, and proceeding could silently \
             recover the wrong wallet from any unrelated shares that did decrypt. \
             Check the password / --keyfile / --difficulty match what was used during \
             split, or re-run with the specific share file paths for the wallet you \
             want (skipping the corrupted / unrelated ones)."
        );
    }

    anyhow::ensure!(
        !decrypted_shares.is_empty(),
        "No share files could be decrypted. Check that the password, --keyfile and --difficulty match what was used during split."
    );

    // Display informational counts only — do not enforce threshold here.
    // The decrypted files may belong to multiple split sets (or include
    // stale shares); `combine_vss_wallets` is responsible for picking a
    // threshold-compatible subset and will return a precise error if no
    // such subset exists.
    println!(
        "\nDecrypted {} share file(s); selecting a compatible subset…",
        decrypted_shares.len()
    );

    // Combine shares to reconstruct mnemonic
    let spinner =
        get_spinner("Verifying shares using Pedersen commitments and reconstructing wallet...");

    let reconstructed = combine_vss_wallets(&decrypted_shares)
        .context("Failed to combine shares. Shares may be from different wallets or corrupted.")?;

    // `combine_vss_wallets` authenticates the recovered seed against
    // the group's wallet metadata before returning.

    spinner.finish_with_message("✓ Shares verified and combined successfully");

    // The point of `combine-secret` is to surface the recovered seed
    // somewhere the user can act on it. Without a display flag the
    // command would otherwise print a "success" line and exit, leaving
    // the user with nothing usable. We always print the mnemonic — the
    // surrounding warning makes the screen-leak risk explicit, and the
    // user can redirect or clear their terminal as needed.
    let _ = display_mnemonic; // kept for backwards-compat with the CLI flag

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("⚠️  RECONSTRUCTED MNEMONIC (KEEP THIS SECRET!)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("\n{}\n", reconstructed.mnemonic.expose_secret());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("SECURITY REMINDER:");
    println!("  • Anyone with this mnemonic can access your funds");
    println!("  • Write it down in a secure location");
    println!("  • Clear your terminal history after viewing");
    println!("  • Do not share or photograph this mnemonic");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    Ok(reconstructed.mnemonic)
}
