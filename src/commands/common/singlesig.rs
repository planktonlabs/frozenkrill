use std::{path::PathBuf, sync::Arc};

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow::{self, Context},
    bitcoin::secp256k1::{All, Secp256k1},
    key_derivation::KeyDerivationDifficulty,
    parse_keyfiles_paths,
    secrecy::SecretString,
    wallet_description::{
        read_decode_wallet, EncryptedWalletDescription, SingleSigWalletDescriptionV0,
    },
    wallet_export::SinglesigJsonWalletPublicExportV0,
};

use crate::{
    ask_non_duress_password, ask_password, handle_input_path, ui_derive_key,
    ui_get_singlesig_wallet_description, InternetChecker, SinglesigOpenArgs,
};

pub(crate) fn open_singlesig_wallet_non_interactive(
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
    ic: impl InternetChecker,
    args: &SinglesigOpenArgs,
) -> anyhow::Result<(SingleSigWalletDescriptionV0, Option<Arc<SecretString>>)> {
    let input_file_path = handle_input_path(&args.common.wallet_input_file)?;
    let encrypted_wallet = read_decode_wallet(&input_file_path)?;
    let keyfiles = parse_keyfiles_paths(&args.common.keyfile)?;
    let password = args
        .common
        .password
        .clone()
        .map(|s| SecretString::new(s.into()))
        .map(Arc::new);
    singlesig_core_open(
        theme,
        term,
        secp,
        Some(ic),
        &encrypted_wallet,
        &keyfiles,
        &args.common.difficulty,
        args.enable_duress_wallet,
        password,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn singlesig_core_open(
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
    ic: Option<impl InternetChecker>,
    encrypted_wallet: &EncryptedWalletDescription,
    keyfiles: &[PathBuf],
    difficulty: &KeyDerivationDifficulty,
    enable_duress_wallet: bool,
    password: Option<Arc<SecretString>>,
) -> anyhow::Result<(SingleSigWalletDescriptionV0, Option<Arc<SecretString>>)> {
    ic.map(|mut i| i.check()).transpose()?;
    let password = password
        .map(Result::Ok)
        .unwrap_or_else(|| ask_password(theme, term).map(Arc::new))?;
    let non_duress_password = if enable_duress_wallet {
        Some(ask_non_duress_password(theme, term)?)
    } else {
        None
    };
    let key = ui_derive_key(&password, keyfiles, &encrypted_wallet.salt, difficulty)?;
    let seed_password = &None;
    let json_wallet = encrypted_wallet.decrypt_singlesig(&key, seed_password, secp)?;
    let wallet = ui_get_singlesig_wallet_description(&json_wallet, seed_password, secp)?;
    Ok((wallet, non_duress_password))
}

pub(crate) fn generate_singlesig_public_info(
    secp: &Secp256k1<All>,
    wallet: &SingleSigWalletDescriptionV0,
    first_index: u32,
    quantity: u32,
) -> anyhow::Result<Vec<u8>> {
    let addresses = wallet
        .derive_receiving_addresses(first_index, quantity, secp)
        .context("failure deriving receive addresses")?;
    let change_addresses = wallet
        .derive_change_addresses(first_index, quantity, secp)
        .context("failure deriving change addresses")?;
    let public_export =
        SinglesigJsonWalletPublicExportV0::generate(wallet, addresses, change_addresses)?;
    public_export.to_vec_pretty()
}
