use std::path::{Path, PathBuf};

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow::{self},
    bitcoin::secp256k1::{All, Secp256k1},
    wallet_description::MultiSigWalletDescriptionV0,
};

use frozenkrill_core::wallet_description::SingleSigWalletDescriptionV0;

use crate::{
    commands::generate::export_singlesig_public_infos, handle_input_path, handle_output_path,
    CommonExportPublicInfoArgs, CommonOpenArgs,
};

use super::{
    common::{from_wallet_to_public_info_json_path, AddressGenerationParams},
    generate::{export_multisig_public_infos, DuressPublicInfoParams},
};

pub(crate) fn export_public_info_parse_args(
    common_open_args: &CommonOpenArgs,
    common_args: &CommonExportPublicInfoArgs,
) -> anyhow::Result<(PathBuf, AddressGenerationParams)> {
    let input_file_path = handle_input_path(&common_open_args.wallet_input_file)?;
    let output_file_path = match &common_args.output_file_json {
        Some(p) => handle_output_path(p)?.into_owned(),
        None => handle_output_path(
            from_wallet_to_public_info_json_path(&input_file_path)?
                .display()
                .to_string()
                .as_str(),
        )?
        .into_owned(),
    };
    let address_generation_params = AddressGenerationParams {
        first_index: common_args.first_index,
        quantity: common_args.quantity,
    };
    Ok((output_file_path, address_generation_params))
}

pub(crate) fn export_singlesig(
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
    wallet_description: &SingleSigWalletDescriptionV0,
    public_info_json_output: &Path,
    duress_params: &Option<DuressPublicInfoParams>,
    address_generation_params: &AddressGenerationParams,
) -> anyhow::Result<()> {
    export_singlesig_public_infos(
        theme,
        term,
        secp,
        wallet_description,
        public_info_json_output,
        duress_params,
        address_generation_params,
    )?;
    Ok(())
}

pub(crate) fn export_multisig(
    secp: &Secp256k1<All>,
    wallet_description: &MultiSigWalletDescriptionV0,
    public_info_json_output: &Path,
    address_generation_params: &AddressGenerationParams,
) -> anyhow::Result<()> {
    export_multisig_public_infos(
        secp,
        wallet_description,
        public_info_json_output,
        address_generation_params,
    )?;
    Ok(())
}
