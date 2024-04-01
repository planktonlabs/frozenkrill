use std::{fs, path::PathBuf, sync::Arc};

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow,
    bitcoin::{
        psbt::Psbt,
        secp256k1::{All, Secp256k1},
    },
    psbt::open_psbt_file,
    secrecy::SecretString,
    wallet_description::{MultiSigWalletDescriptionV0, SingleSigWalletDescriptionV0},
};
use path_absolutize::Absolutize;

use crate::{
    commands::{
        common::{double_check_non_duress_password, from_input_to_signed_psbt},
        interactive::ValidateOutputFile,
        psbt::{ask_sign_non_duress, validated_input_psbt_sign},
    },
    handle_input_path, handle_output_path,
};

pub(super) fn singlesig_sign(
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
    wallet: &SingleSigWalletDescriptionV0,
    non_duress_password: &Option<Arc<SecretString>>,
) -> anyhow::Result<()> {
    let (input_path, psbt) = ask_psbt_input_file(theme, term)?;
    let suggested_output_psbt_path = from_input_to_signed_psbt(&input_path)?;
    let output_psbt_path = ask_psbt_output_file(theme, term, &suggested_output_psbt_path)?;
    let non_duress_wallet = match non_duress_password {
        Some(non_duress_password) => {
            if ask_sign_non_duress(theme, term)? {
                double_check_non_duress_password(theme, term, non_duress_password)?;
                Some(wallet.change_seed_password(&Some(Arc::clone(non_duress_password)), secp)?)
            } else {
                None
            }
        }
        None => None,
    };
    let wallet = non_duress_wallet.as_ref().unwrap_or(wallet);
    crate::commands::psbt::sign_core(
        theme,
        term,
        secp,
        wallet,
        psbt,
        &output_psbt_path,
        wallet.network,
    )
}

pub(super) fn multisig_sign(
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
    wallet: &MultiSigWalletDescriptionV0,
) -> anyhow::Result<()> {
    let (input_path, psbt) = ask_psbt_input_file(theme, term)?;
    let suggested_output_psbt_path = from_input_to_signed_psbt(&input_path)?;
    let output_psbt_path = ask_psbt_output_file(theme, term, &suggested_output_psbt_path)?;
    crate::commands::psbt::sign_core(
        theme,
        term,
        secp,
        wallet,
        psbt,
        &output_psbt_path,
        wallet.network,
    )
}

fn ask_psbt_input_file(theme: &dyn Theme, term: &Term) -> anyhow::Result<(PathBuf, Psbt)> {
    let mut files = fs::read_dir(".")?
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .filter(|i| i.file_type().is_ok() && i.file_type().unwrap().is_file())
        .map(|i| i.path().display().to_string())
        .filter(|i| i.to_lowercase().ends_with(".psbt"))
        .collect::<Vec<_>>();
    files.sort();
    if files.is_empty() {
        eprintln!(
            "You can't pick a PSBT file because there are no .psbt files in current directory"
        );
        anyhow::bail!("Copy some .psbt file to current directory or change the current directory so you can load the PSBT");
    }
    loop {
        let file = dialoguer::Select::with_theme(theme)
            .with_prompt("Select a .psbt file")
            .items(&files)
            .interact_on(term)?;
        let file = handle_input_path(&files[file])?.into_owned();
        match open_psbt_file(&file).and_then(|psbt| validated_input_psbt_sign(&psbt).map(|_| psbt))
        {
            Ok(w) => return Ok((file, w)),
            Err(e) => {
                eprintln!("Error reading PSBT: {e:?}");
                if !dialoguer::Confirm::with_theme(theme)
                    .with_prompt("The selected file is invalid, do you want to pick another file?")
                    .default(true)
                    .interact_on(term)?
                {
                    anyhow::bail!("No valid PSBT file selected");
                }
            }
        }
    }
}

fn ask_psbt_output_file(
    theme: &dyn Theme,
    term: &Term,
    suggested: &PathBuf,
) -> anyhow::Result<PathBuf> {
    let suggested = suggested.absolutize()?.display().to_string();
    let name = dialoguer::Input::with_theme(theme)
        .with_prompt("Where to save the signed PSBT?")
        .with_initial_text(suggested)
        .validate_with(ValidateOutputFile)
        .interact_text_on(term)?;
    Ok(handle_output_path(&name)?.into_owned())
}
