use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::random_generation_utils::*;
use frozenkrill_core::{
    anyhow::{self, Context},
    bitcoin::{
        secp256k1::{All, Secp256k1},
        Network,
    },
    generate_encrypted_encoded_singlesig_wallet, get_padder,
    key_derivation::KeyDerivationDifficulty,
    log, parse_keyfiles_paths,
    rand_core::CryptoRngCore,
    secrecy::{ExposeSecret, Secret, SecretString},
    utils::create_file,
    wallet_description::{
        read_decode_wallet, EncryptedWalletVersion, ScriptType, SingleSigWalletDescriptionV0,
        SinglesigJsonWalletDescriptionV0,
    },
    PaddingParams,
};

use crate::{
    commands::{
        common::CONTEXT_CORRUPTION_WARNING,
        generate::{core::generate_ask_password, inform_custom_generate_params},
    },
    handle_output_path, ui_derive_key, warn_difficulty_level, InternetChecker, ReencodeArgs,
    SinglesigOpenArgs,
};

use super::common::from_input_to_reencoded;

pub(crate) fn singlesig_reencode_parse_args(
    open_args: &SinglesigOpenArgs,
    args: &ReencodeArgs,
) -> anyhow::Result<SinglesigCoreReencode> {
    let output_file_path = match &args.wallet_output_file {
        Some(p) => handle_output_path(p)?.into_owned(),
        None => from_input_to_reencoded(Path::new(&open_args.common.wallet_input_file))?,
    };
    let output_file_path = handle_output_path(&output_file_path)?.into_owned();
    let keyfiles = parse_keyfiles_paths(&args.common.keyfile)?;
    let network = if args.common.use_testnet {
        Network::Testnet
    } else {
        Network::Bitcoin
    };
    let script_type = ScriptType::SegwitNative;
    let password = args
        .common
        .password
        .clone()
        .map(SecretString::new)
        .map(Arc::new);
    Ok(SinglesigCoreReencode {
        password,
        output_file_path,
        keyfiles,
        script_type,
        network,
        difficulty: args.common.difficulty,
        padding_params: PaddingParams::new(
            args.common.disable_all_padding,
            Some(args.common.min_additional_padding_bytes),
            Some(args.common.max_additional_padding_bytes),
        )?,
        encrypted_wallet_version: args
            .common
            .wallet_file_type
            .to_encrypted_wallet_version(network, script_type)?,
    })
}

pub(crate) struct SinglesigCoreReencode {
    pub(crate) password: Option<Arc<SecretString>>,
    pub(crate) output_file_path: PathBuf,
    pub(crate) keyfiles: Vec<PathBuf>,
    pub(crate) script_type: ScriptType,
    pub(crate) network: Network,
    pub(crate) difficulty: KeyDerivationDifficulty,
    pub(crate) padding_params: PaddingParams,
    pub(crate) encrypted_wallet_version: EncryptedWalletVersion,
}

pub(crate) fn singlesig_core_reencode(
    theme: &dyn Theme,
    term: &Term,
    secp: &mut Secp256k1<All>,
    mut rng: &mut impl CryptoRngCore,
    ic: impl InternetChecker,
    wallet: &SingleSigWalletDescriptionV0,
    args: SinglesigCoreReencode,
) -> anyhow::Result<()> {
    warn_difficulty_level(&args.difficulty);
    let output_file_path = &args.output_file_path;
    log::info!("Will generate a new wallet saving to {output_file_path:?}");
    let password = args
        .password
        .map(Result::Ok)
        .unwrap_or_else(|| generate_ask_password(theme, term, Some(ic)))?;

    let salt = get_random_salt(&mut rng)?;
    let key = ui_derive_key(&password, &args.keyfiles, &salt, &args.difficulty)?;
    let nonce = get_random_nonce(&mut rng)?;
    let header_nonce = get_random_nonce(&mut rng)?;
    let header_key = Secret::new(get_random_key(&mut rng)?);
    let padder = get_padder(&mut rng, &args.padding_params)?;
    let mnemonic = Arc::clone(&wallet.mnemonic);
    let seed_password = &None;
    let encrypted_wallet = generate_encrypted_encoded_singlesig_wallet(
        &key,
        header_key,
        mnemonic,
        seed_password,
        salt,
        nonce,
        header_nonce,
        padder,
        args.script_type,
        args.network,
        args.encrypted_wallet_version,
        secp,
    )?;
    // Write file
    create_file(&encrypted_wallet, output_file_path)
        .with_context(|| format!("failure saving encrypted wallet to {output_file_path:?}"))?;
    log::info!("Wallet saved to {output_file_path:?}");
    secp.randomize(&mut rng);
    // If no public info will be exported right now, then we can just check using the existing key because additional commands will be required to export the public info later
    // So we are delaying the key derivation to the future
    let encrypted_wallet = read_decode_wallet(output_file_path)?;
    let read_json_wallet_description = encrypted_wallet
        .decrypt_singlesig(&key, seed_password, secp)
        .context(CONTEXT_CORRUPTION_WARNING)?;
    let wallet_description = read_json_wallet_description
        .expose_secret()
        .to(seed_password, secp)
        .context("failure parsing generated wallet")?;
    // Sanity check
    SinglesigJsonWalletDescriptionV0::validate_same(
        &read_json_wallet_description,
        &wallet_description,
        secp,
    )?
    .context("failure checking generated wallet")?;
    inform_custom_generate_params(&args.keyfiles, &args.difficulty, false);
    log::info!("Finished successfully!");
    log::info!("Now run again with the other commands to retrieve the receiving addresses and/or public keys");
    Ok(())
}
