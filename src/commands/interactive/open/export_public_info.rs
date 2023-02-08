use std::{path::Path, sync::Arc};

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow,
    bitcoin::secp256k1::{All, Secp256k1},
    secrecy::SecretString,
    wallet_description::{MultiSigWalletDescriptionV0, SingleSigWalletDescriptionV0},
};

use crate::commands::{
    common::AddressGenerationParams,
    generate::DuressPublicInfoParams,
    interactive::{
        ask_addresses_quantity, ask_non_duress_public_info_json_output,
        ask_public_info_json_output_required,
    },
};

pub(super) fn singlesig_export(
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
    wallet: &SingleSigWalletDescriptionV0,
    wallet_input_file: &Path,
    non_duress_password: &Option<Arc<SecretString>>,
) -> anyhow::Result<()> {
    let output_file_path = ask_public_info_json_output_required(theme, term, wallet_input_file)?;
    let quantity = ask_addresses_quantity(theme, term)?;
    let first_index = if quantity > 0 {
        ask_address_index_export(theme, term)?
    } else {
        0
    };
    let params = AddressGenerationParams {
        first_index,
        quantity,
    };
    let duress_params = match non_duress_password {
        Some(non_duress_password) => Some(DuressPublicInfoParams {
            non_duress_password: non_duress_password.to_owned(),
            non_duress_public_info_json_output: ask_non_duress_public_info_json_output(
                theme,
                term,
                &output_file_path,
            )?,
        }),
        None => None,
    };
    crate::commands::export_public_info::export_singlesig(
        theme,
        term,
        secp,
        wallet,
        &output_file_path,
        &duress_params,
        &params,
    )
}

pub(super) fn multisig_export(
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
    wallet: &MultiSigWalletDescriptionV0,
    wallet_input_file: &Path,
) -> anyhow::Result<()> {
    let output_file_path = ask_public_info_json_output_required(theme, term, wallet_input_file)?;
    let quantity = ask_addresses_quantity(theme, term)?;
    let first_index = if quantity > 0 {
        ask_address_index_export(theme, term)?
    } else {
        0
    };
    let params = AddressGenerationParams {
        first_index,
        quantity,
    };
    crate::commands::export_public_info::export_multisig(secp, wallet, &output_file_path, &params)
}

fn ask_address_index_export(theme: &dyn Theme, term: &Term) -> anyhow::Result<u32> {
    let n = dialoguer::Input::with_theme(theme)
        .allow_empty(false)
        .with_initial_text("0")
        .with_prompt("Start exporting at what receiving address index? (first is zero)")
        .interact_text_on(term)?;
    Ok(n)
}
