use std::{fs, path::PathBuf};

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow,
    bitcoin::secp256k1::{All, Secp256k1},
    key_derivation::KeyDerivationDifficulty,
    log, parse_keyfiles_paths,
    wallet_description::{read_decode_wallet, EncryptedWalletDescription},
};

use crate::{commands::interactive::get_ask_difficulty, handle_input_path, InternetChecker};

use super::{choose_keyfiles, duress_wallet_explanation};

mod export_public_info;
mod show_receiving_qr_code;
mod show_secrets;
mod sign_psbt;

#[derive(Copy, Clone)]
enum InteractiveOpenActions {
    ShowReceivingQrCode,
    ExportPublicInfo,
    ShowSecrets,
    SignPsbt,
}

impl ToString for InteractiveOpenActions {
    fn to_string(&self) -> String {
        match self {
            InteractiveOpenActions::ShowReceivingQrCode => "Show receiving QR code",
            InteractiveOpenActions::ExportPublicInfo => "Export public info json",
            InteractiveOpenActions::ShowSecrets => "Show secrets",
            InteractiveOpenActions::SignPsbt => "Sign a PSBT",
        }
        .into()
    }
}

const INTERACTIVE_OPEN_ACTIONS: [InteractiveOpenActions; 4] = [
    InteractiveOpenActions::ShowReceivingQrCode,
    InteractiveOpenActions::ExportPublicInfo,
    InteractiveOpenActions::ShowSecrets,
    InteractiveOpenActions::SignPsbt,
];

fn ask_interactive_open_action(
    theme: &dyn Theme,
    term: &Term,
) -> anyhow::Result<Option<InteractiveOpenActions>> {
    let action = dialoguer::Select::with_theme(theme)
        .with_prompt("Pick an option")
        .items(&INTERACTIVE_OPEN_ACTIONS)
        .default(0)
        .interact_on_opt(term)?;
    let action = match action {
        Some(v) => v,
        None => return Ok(None),
    };
    Ok(Some(INTERACTIVE_OPEN_ACTIONS[action]))
}

fn ask_select_another_action(theme: &dyn Theme, term: &Term) -> anyhow::Result<bool> {
    Ok(dialoguer::Confirm::with_theme(theme)
        .with_prompt("Select another action?")
        .default(true)
        .interact_on(term)?)
}

pub(super) fn singlesig_interactive_open(
    theme: &dyn Theme,
    term: &Term,
    secp: &mut Secp256k1<All>,
    ic: impl InternetChecker,
    keyfiles: Vec<PathBuf>,
    difficulty: Option<KeyDerivationDifficulty>,
    enable_duress_wallet: bool,
) -> anyhow::Result<()> {
    let (input_file_path, encrypted_wallet) = ask_wallet_input_file(theme, term)?;
    let keyfiles = if keyfiles.is_empty() {
        ask_for_keyfiles_open(theme, term)?
    } else {
        keyfiles
    };
    let difficulty = get_ask_difficulty(theme, term, difficulty)?;
    let (wallet, non_duress_password) = crate::commands::common::singlesig::singlesig_core_open(
        theme,
        term,
        secp,
        Some(ic),
        &encrypted_wallet,
        &keyfiles,
        &difficulty,
        enable_duress_wallet || ask_to_open_duress(theme, term)?,
        None,
    )?;
    loop {
        match ask_interactive_open_action(theme, term)? {
            Some(InteractiveOpenActions::ShowReceivingQrCode) => {
                show_receiving_qr_code::singlesig_show(
                    theme,
                    term,
                    secp,
                    &wallet,
                    &non_duress_password,
                )?;
            }
            Some(InteractiveOpenActions::ExportPublicInfo) => {
                export_public_info::singlesig_export(
                    theme,
                    term,
                    secp,
                    &wallet,
                    &input_file_path,
                    &non_duress_password,
                )?;
            }
            Some(InteractiveOpenActions::ShowSecrets) => {
                show_secrets::singlesig_show(theme, term, secp, &wallet, &non_duress_password)?;
            }
            Some(InteractiveOpenActions::SignPsbt) => {
                sign_psbt::singlesig_sign(theme, term, secp, &wallet, &non_duress_password)?;
            }
            None => break,
        };
        if !ask_select_another_action(theme, term)? {
            break;
        }
    }
    log::info!("Done!");
    Ok(())
}

pub(super) fn multisig_interactive_open(
    theme: &dyn Theme,
    term: &Term,
    secp: &mut Secp256k1<All>,
    ic: impl InternetChecker,
    keyfiles: Vec<PathBuf>,
    difficulty: Option<KeyDerivationDifficulty>,
) -> anyhow::Result<()> {
    ic.check()?;
    let (input_file_path, encrypted_wallet) = ask_wallet_input_file(theme, term)?;
    let keyfiles = if keyfiles.is_empty() {
        ask_for_keyfiles_open(theme, term)?
    } else {
        keyfiles
    };
    let difficulty = get_ask_difficulty(theme, term, difficulty)?;
    let wallet = crate::commands::common::multisig::multisig_core_open(
        theme,
        term,
        secp,
        &encrypted_wallet,
        &keyfiles,
        &difficulty,
        None,
        None,
    )?;
    loop {
        match ask_interactive_open_action(theme, term)? {
            Some(InteractiveOpenActions::ShowReceivingQrCode) => {
                show_receiving_qr_code::multisig_show(theme, term, secp, &wallet)?;
            }
            Some(InteractiveOpenActions::ExportPublicInfo) => {
                export_public_info::multisig_export(theme, term, secp, &wallet, &input_file_path)?;
            }
            Some(InteractiveOpenActions::ShowSecrets) => {
                show_secrets::multisig_show(secp, &wallet)?;
            }
            Some(InteractiveOpenActions::SignPsbt) => {
                if wallet.has_signers() {
                    sign_psbt::multisig_sign(theme, term, secp, &wallet)?;
                } else {
                    log::error!("No signers added, impossible to sign a PSBT")
                }
            }
            None => break,
        };
        if !ask_select_another_action(theme, term)? {
            break;
        }
    }
    log::info!("Done!");
    Ok(())
}

pub(crate) fn ask_to_open_duress(theme: &dyn Theme, term: &Term) -> anyhow::Result<bool> {
    duress_wallet_explanation();
    Ok(dialoguer::Confirm::with_theme(theme)
        .default(false)
        .with_prompt("Enable duress feature for this wallet? (advanced usage, be careful)")
        .interact_on(term)?)
}

pub(crate) fn ask_for_keyfiles_open(
    theme: &dyn Theme,
    term: &Term,
) -> anyhow::Result<Vec<PathBuf>> {
    if dialoguer::Confirm::with_theme(theme)
        .with_prompt("Have you used a keyfile when generating this wallet?")
        .interact_on(term)?
    {
        let mut files = fs::read_dir(".")?
            .map(|i| i.map(|i| i.path().display().to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        files.sort();
        if files.is_empty() {
            eprintln!("You can't pick a keyfile because there are no files or directories in the current directory");
            anyhow::bail!("Copy the keyfiles or directories to current directory or change the current directory or use the --keyfile argument on command line to load keyfiles from other places");
        }
        loop {
            let chosen_files = choose_keyfiles(theme, term, &files)?;
            let chosen_files: Vec<_> = chosen_files
                .into_iter()
                .map(|i| files[i].to_owned())
                .collect();
            if chosen_files.is_empty() {
                eprintln!("No keyfile selected, you won't be able to open the wallet if it was created with a keyfile");
                if dialoguer::Confirm::with_theme(theme)
                    .with_prompt("Proceed without a keyfile?")
                    .interact_on(term)?
                {
                    return Ok(Vec::new());
                }
            } else {
                let keyfiles = parse_keyfiles_paths(&chosen_files)?;
                return Ok(keyfiles);
            }
        }
    } else {
        Ok(Vec::new())
    }
}

pub(crate) fn ask_wallet_input_file(
    theme: &dyn Theme,
    term: &Term,
) -> anyhow::Result<(PathBuf, EncryptedWalletDescription)> {
    let mut files = fs::read_dir(".")?
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .filter(|i| i.file_type().is_ok() && i.file_type().unwrap().is_file())
        .map(|i| i.path().display().to_string())
        .collect::<Vec<_>>();
    files.sort();
    if files.is_empty() {
        eprintln!("You can't pick a wallet file because there are no files in current directory");
        anyhow::bail!("Copy some files or directories to current directory or change the current directory so you can load a wallet");
    }
    loop {
        let file = dialoguer::Select::with_theme(theme)
            .with_prompt("Select")
            .items(&files)
            .interact_on(term)?;
        let file = handle_input_path(&files[file])?.into_owned();
        match read_decode_wallet(&file) {
            Ok(w) => return Ok((file, w)),
            Err(e) => {
                eprintln!("Error reading wallet: {e:?}");
                if !dialoguer::Confirm::with_theme(theme)
                    .with_prompt("The selected file is invalid, do you want to pick another file?")
                    .default(true)
                    .interact_on(term)?
                {
                    anyhow::bail!("No valid wallet file selected");
                }
            }
        }
    }
}
