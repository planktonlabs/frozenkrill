use std::path::PathBuf;

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow::{self, bail},
    bitcoin::{
        secp256k1::{All, Secp256k1},
        Address, Network, Psbt,
    },
    itertools::Itertools,
    log::{self, debug},
    psbt::{open_psbt_file, save_psbt_file},
    wallet_description::PsbtWallet,
};

use crate::open_multisig_wallet_non_interactive;
use crate::open_singlesig_wallet_non_interactive;

use crate::{
    handle_input_path, handle_output_path, InternetChecker, MultisigOpenArgs, SignPsbtArgs,
    SinglesigOpenArgs,
};

use super::common::{double_check_non_duress_password, from_input_to_signed_psbt};

pub(super) fn validated_input_psbt_sign(psbt: &Psbt) -> anyhow::Result<()> {
    anyhow::ensure!(
        !psbt.outputs.is_empty(),
        "The PSBT has no outputs, better avoid signing that"
    );
    Ok(())
}

pub(super) fn ask_sign_non_duress(theme: &dyn Theme, term: &Term) -> anyhow::Result<bool> {
    let items = [
        "Sign using default duress (decoy) wallet",
        "Sign using non duress (real) wallet",
    ];
    let item = dialoguer::Select::with_theme(theme)
        .items(items)
        .default(1)
        .with_prompt("Pick an option")
        .interact_on(term)?;
    Ok(item == 1)
}

pub(super) fn sign_core(
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
    wallet: &impl PsbtWallet,
    mut psbt: Psbt,
    signed_psbt_output_file_path: &PathBuf,
    network: Network,
) -> anyhow::Result<()> {
    validated_input_psbt_sign(&psbt)?;
    let partial_sigs_count_before: usize = psbt.inputs.iter().map(|i| i.partial_sigs.len()).sum();
    if wallet.sign_psbt(&mut psbt, secp)? == 0 {
        bail!(
            "This PSBT file has not input matching our fingerprints {}",
            wallet.get_pub_fingerprints().iter().join(" ")
        )
    }
    let partial_sigs_count_after: usize = psbt.inputs.iter().map(|i| i.partial_sigs.len()).sum();
    if partial_sigs_count_before == partial_sigs_count_after {
        log::warn!("The PSBT file has been already signed!");
        if !dialoguer::Confirm::with_theme(theme)
            .with_prompt("Sign again?")
            .default(false)
            .interact_on(term)?
        {
            return Ok(());
        }
    }
    let new_sigs = partial_sigs_count_after - partial_sigs_count_before;

    let fee = psbt.fee()?;
    let change_addresses = wallet.derive_change_addresses(0, 100, secp)?;
    for (output_index, (output, psbt_output)) in psbt
        .unsigned_tx
        .output
        .iter()
        .zip(&psbt.outputs)
        .enumerate()
    {
        let address = Address::from_script(output.script_pubkey.as_script(), network);
        let s = address
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|_| output.script_pubkey.as_script().to_string());
        let is_change = address.is_ok() && change_addresses.contains(address.as_ref().unwrap());
        let maybe_change = address.is_ok()
            && !(psbt_output.bip32_derivation.is_empty() && psbt_output.tap_key_origins.is_empty());
        let output_string = if is_change {
            "Change"
        } else if maybe_change {
            "Change?"
        } else {
            "Output"
        };
        let address_type = match address.as_ref().map(|a| a.address_type()) {
            Ok(Some(address_type)) => address_type.to_string(),
            other => {
                debug!("Got {other:?} while trying to figure address type");
                "unknown".to_string()
            }
        };
        eprintln!(
            "- {output_index}: {output_string} {s} ({address_type}): {:.8} BTC",
            output.value.to_btc()
        )
    }
    eprintln!("Fee: {fee} sats");
    if dialoguer::Confirm::with_theme(theme)
        .with_prompt("Sign the transaction with the above outputs?")
        .interact_on(term)?
    {
        save_psbt_file(&psbt, signed_psbt_output_file_path)?;
        log::info!("Saved signed PSBT to {signed_psbt_output_file_path:?}");
        log::info!("Added {new_sigs} new signatures");
        Ok(())
    } else {
        Ok(())
    }
}

pub(crate) fn singlesig_sign_non_interactive(
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
    ic: impl InternetChecker,
    open_args: &SinglesigOpenArgs,
    args: &SignPsbtArgs,
) -> anyhow::Result<()> {
    let input_psbt_file_path = handle_input_path(&args.input_psbt_file)?;
    let psbt = open_psbt_file(&input_psbt_file_path)?;
    validated_input_psbt_sign(&psbt)?;
    let signed_psbt_output_file_path = match &args.signed_output_psbt_file {
        Some(s) => s.to_owned(),
        None => from_input_to_signed_psbt(&input_psbt_file_path)?
            .display()
            .to_string(),
    };
    let signed_psbt_output_file_path =
        handle_output_path(&signed_psbt_output_file_path)?.to_path_buf();
    let (wallet, non_duress_password) =
        open_singlesig_wallet_non_interactive(theme, term, secp, ic, open_args)?;
    let wallet = match non_duress_password {
        Some(non_duress_password) => {
            if ask_sign_non_duress(theme, term)? {
                double_check_non_duress_password(theme, term, &non_duress_password)?;
                wallet.change_seed_password(&Some(non_duress_password), secp)?
            } else {
                wallet
            }
        }
        None => wallet,
    };
    sign_core(
        theme,
        term,
        secp,
        &wallet,
        psbt,
        &signed_psbt_output_file_path,
        wallet.network,
    )
}

pub(crate) fn multisig_sign_non_interactive(
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
    ic: impl InternetChecker,
    open_args: &MultisigOpenArgs,
    args: &SignPsbtArgs,
) -> anyhow::Result<()> {
    let input_psbt_file_path = handle_input_path(&args.input_psbt_file)?;
    let psbt = open_psbt_file(&input_psbt_file_path)?;
    validated_input_psbt_sign(&psbt)?;
    let signed_psbt_output_file_path = match &args.signed_output_psbt_file {
        Some(s) => s.to_owned(),
        None => from_input_to_signed_psbt(&input_psbt_file_path)?
            .display()
            .to_string(),
    };
    let signed_psbt_output_file_path =
        handle_output_path(&signed_psbt_output_file_path)?.to_path_buf();
    let wallet = open_multisig_wallet_non_interactive(theme, term, secp, ic, open_args)?;
    sign_core(
        theme,
        term,
        secp,
        &wallet,
        psbt,
        &signed_psbt_output_file_path,
        wallet.network,
    )
}
