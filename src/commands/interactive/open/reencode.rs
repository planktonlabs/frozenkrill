use std::path::{Path, PathBuf};

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow,
    bitcoin::secp256k1::{All, Secp256k1},
    rand_core::{CryptoRng, RngCore},
    wallet_description::{MultiSigWalletDescriptionV0, SingleSigWalletDescriptionV0},
    PaddingParams,
};
use path_absolutize::Absolutize;

use crate::{
    commands::{
        common::from_input_to_reencoded,
        interactive::{
            ask_for_keyfiles_generate, ask_network, ask_wallet_file_type, get_ask_difficulty,
            ValidateOutputFile,
        },
        reencode::{MultisigCoreReencodeArgs, SinglesigCoreReencodeArgs},
    },
    handle_output_path, InternetChecker,
};

pub(super) fn singlesig_reencode(
    theme: &dyn Theme,
    term: &Term,
    secp: &mut Secp256k1<All>,
    rng: &mut (impl CryptoRng + RngCore),
    ic: impl InternetChecker,
    wallet: &SingleSigWalletDescriptionV0,
    input_path: &Path,
) -> anyhow::Result<()> {
    let keyfiles = ask_for_keyfiles_generate(theme, term)?;
    let wallet_file_type = ask_wallet_file_type(theme, term)?;
    let suggested_output_path = from_input_to_reencoded(input_path)?;
    let output_file_path = ask_output_file(theme, term, &suggested_output_path)?;
    let difficulty = get_ask_difficulty(theme, term, None)?;
    let network = ask_network(theme, term)?;
    let script_type = frozenkrill_core::wallet_description::ScriptType::SegwitNative;
    let args = SinglesigCoreReencodeArgs {
        password: None,
        output_file_path,
        keyfiles,
        script_type,
        network,
        difficulty,
        padding_params: PaddingParams::default(),
        encrypted_wallet_version: wallet_file_type
            .to_encrypted_wallet_version(network, script_type)?,
    };

    crate::commands::reencode::singlesig_core_reencode(theme, term, secp, rng, ic, wallet, args)
}

pub(super) fn multisig_reencode(
    theme: &dyn Theme,
    term: &Term,
    secp: &mut Secp256k1<All>,
    rng: &mut (impl CryptoRng + RngCore),
    ic: impl InternetChecker,
    wallet: &MultiSigWalletDescriptionV0,
    input_path: &Path,
) -> anyhow::Result<()> {
    let keyfiles = ask_for_keyfiles_generate(theme, term)?;
    let wallet_file_type = ask_wallet_file_type(theme, term)?;
    let suggested_output_path = from_input_to_reencoded(input_path)?;
    let output_file_path = ask_output_file(theme, term, &suggested_output_path)?;
    let difficulty = get_ask_difficulty(theme, term, None)?;
    let network = ask_network(theme, term)?;
    let script_type = frozenkrill_core::wallet_description::ScriptType::SegwitNative;
    let args = MultisigCoreReencodeArgs {
        password: None,
        output_file_path,
        keyfiles,
        script_type,
        network,
        difficulty,
        padding_params: PaddingParams::default(),
        encrypted_wallet_version: wallet_file_type
            .to_encrypted_wallet_version(network, script_type)?,
    };

    crate::commands::reencode::multisig_core_reencode(theme, term, secp, rng, ic, wallet, args)
}

fn ask_output_file(theme: &dyn Theme, term: &Term, suggested: &PathBuf) -> anyhow::Result<PathBuf> {
    let suggested = suggested.absolutize()?.display().to_string();
    let name = dialoguer::Input::with_theme(theme)
        .with_prompt("Where to save the reencoded wallet?")
        .with_initial_text(suggested)
        .validate_with(ValidateOutputFile)
        .interact_text_on(term)?;
    Ok(handle_output_path(&name)?.into_owned())
}
