use std::{fs, path::PathBuf, sync::Arc};

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow::{self, bail},
    bitcoin::secp256k1::{All, Secp256k1},
    key_derivation::KeyDerivationDifficulty,
    log::{self, debug},
    parse_keyfiles_paths,
    rand_core::CryptoRngCore,
    secrecy::{Secret, SecretString},
    wallet_description::read_decode_wallet,
};

use crate::{
    commands::{
        common::{
            multisig::MultisigCoreOpenWalletParam, try_open_as_json_input, ParsedWalletInputFile,
            PublicInfoInput,
        },
        interactive::get_ask_difficulty,
    },
    handle_input_path, InternetChecker,
};

use super::{choose_keyfiles, duress_wallet_explanation};

mod export_public_info;
mod reencode;
mod show_receiving_qr_code;
mod show_secrets;
mod sign_psbt;

#[derive(Copy, Clone)]
enum InteractiveOpenActions {
    ShowReceivingQrCode,
    ExportPublicInfo,
    ShowSecrets,
    SignPsbt,
    Reencode,
}

impl ToString for InteractiveOpenActions {
    fn to_string(&self) -> String {
        match self {
            InteractiveOpenActions::ShowReceivingQrCode => "Show receiving QR code",
            InteractiveOpenActions::ExportPublicInfo => "Export public info json",
            InteractiveOpenActions::ShowSecrets => "Show secrets",
            InteractiveOpenActions::SignPsbt => "Sign a PSBT",
            InteractiveOpenActions::Reencode => "Reencode the wallet",
        }
        .into()
    }
}

const INTERACTIVE_OPEN_ACTIONS: [InteractiveOpenActions; 5] = [
    InteractiveOpenActions::ShowReceivingQrCode,
    InteractiveOpenActions::ExportPublicInfo,
    InteractiveOpenActions::ShowSecrets,
    InteractiveOpenActions::SignPsbt,
    InteractiveOpenActions::Reencode,
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

#[allow(clippy::too_many_arguments)]
pub(super) fn singlesig_interactive_open(
    theme: &dyn Theme,
    term: &Term,
    secp: &mut Secp256k1<All>,
    rng: &mut impl CryptoRngCore,
    ic: impl InternetChecker,
    keyfiles: Vec<PathBuf>,
    difficulty: Option<KeyDerivationDifficulty>,
    enable_duress_wallet: bool,
    password: Option<Arc<SecretString>>,
) -> anyhow::Result<()> {
    let (input_file_path, wallet_input) = ask_wallet_input_file(theme, term)?;
    let ParsedWalletInputFile::Encrypted(encrypted_wallet) = wallet_input else {
        bail!("Expected an encrypted wallet but got a different format: {wallet_input:?}")
    };
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
        Some(ic.clone()),
        &encrypted_wallet,
        &keyfiles,
        &difficulty,
        enable_duress_wallet || ask_to_open_duress(theme, term)?,
        password,
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
            Some(InteractiveOpenActions::Reencode) => {
                reencode::singlesig_reencode(
                    theme,
                    term,
                    secp,
                    rng,
                    ic.clone(),
                    &wallet,
                    &input_file_path,
                )?;
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
    mut ic: impl InternetChecker,
    keyfiles: Vec<PathBuf>,
    difficulty: Option<KeyDerivationDifficulty>,
) -> anyhow::Result<()> {
    ic.check()?;
    let (input_file_path, wallet_input) = ask_wallet_input_file(theme, term)?;
    let input_wallet = match wallet_input {
        ParsedWalletInputFile::Encrypted(encrypted_wallet) => {
            let keyfiles = if keyfiles.is_empty() {
                ask_for_keyfiles_open(theme, term)?
            } else {
                keyfiles
            };
            let difficulty = get_ask_difficulty(theme, term, difficulty)?;
            MultisigCoreOpenWalletParam::Encrypted {
                input_wallet: encrypted_wallet,
                password: None,
                keyfiles,
                difficulty,
            }
        }
        ParsedWalletInputFile::PublicInfo(public_info) => match public_info {
            PublicInfoInput::MultisigJson(json) => {
                MultisigCoreOpenWalletParam::Json(Secret::new(json))
            }
        },
    };
    let wallet = crate::commands::common::multisig::multisig_core_open(
        theme,
        term,
        secp,
        input_wallet,
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
            Some(InteractiveOpenActions::Reencode) => {
                unimplemented!("Reencode for multisig is not implemented yet")
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
            bail!("Copy the keyfiles or directories to current directory or change the current directory or use the --keyfile argument on command line to load keyfiles from other places");
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
) -> anyhow::Result<(PathBuf, ParsedWalletInputFile)> {
    let mut files = fs::read_dir(".")?
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .filter(|i| i.file_type().is_ok() && i.file_type().unwrap().is_file())
        .map(|i| i.path().display().to_string())
        .collect::<Vec<_>>();
    files.sort();
    if files.is_empty() {
        eprintln!("You can't pick a wallet file because there are no files in current directory");
        bail!("Copy some files or directories to current directory or change the current directory so you can load a wallet");
    }
    loop {
        let file = dialoguer::Select::with_theme(theme)
            .with_prompt("Select")
            .items(&files)
            .interact_on(term)?;
        let file = handle_input_path(&files[file])?.into_owned();
        debug!("Will try to open {file:?}");
        let json_result = try_open_as_json_input(&file);
        match json_result {
            Ok(result) => return Ok((file, ParsedWalletInputFile::PublicInfo(result))),
            Err(json_error) => match read_decode_wallet(&file) {
                Ok(w) => return Ok((file, ParsedWalletInputFile::Encrypted(w))),
                Err(e) => {
                    eprintln!("Error reading wallet as encrypted: {e} and as json: {json_error}");
                    if !dialoguer::Confirm::with_theme(theme)
                        .with_prompt(
                            "The selected file is invalid, do you want to pick another file?",
                        )
                        .default(true)
                        .interact_on(term)?
                    {
                        bail!("No valid wallet file selected");
                    }
                }
            },
        }
    }
}
