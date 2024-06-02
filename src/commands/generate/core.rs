use std::{path::PathBuf, sync::Arc};

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow::{self, Context},
    bip39::Mnemonic,
    bitcoin::{
        secp256k1::{All, Secp256k1},
        Network,
    },
    generate_encrypted_encoded_multisig_wallet, generate_encrypted_encoded_singlesig_wallet,
    get_padder, get_random_key, get_random_nonce, get_random_salt,
    key_derivation::{default_derive_key, KeyDerivationDifficulty},
    log,
    rand_core::CryptoRngCore,
    secrecy::{Secret, SecretString},
    utils::create_file,
    wallet_description::{
        generate_seeds, EncryptedWalletVersion, MultiSigWalletDescriptionV0,
        MultisigJsonWalletDescriptionV0, MultisigType, ScriptType,
    },
    MultisigInputs, PaddingParams,
};

use frozenkrill_core::secrecy::ExposeSecret;

use frozenkrill_core::wallet_description::{
    read_decode_wallet, SinglesigJsonWalletDescriptionV0, WordCount,
};

use crate::{
    ask_non_duress_password, ask_password,
    commands::{
        common::{
            calculate_non_duress_output, AddressGenerationParams, CONTEXT_CORRUPTION_WARNING,
        },
        generate::{
            export_multisig_public_infos, export_singlesig_public_infos,
            inform_custom_generate_params,
        },
    },
    get_derivation_key_spinner, ui_derive_key, warn_difficulty_level, InternetChecker,
    InternetCheckerImpl, ENGLISH,
};

use super::DuressPublicInfoParams;

pub(crate) struct DuressInputArgs {
    pub(crate) enable_duress_wallet: bool,
    pub(crate) non_duress_output_file_json: Option<PathBuf>,
    pub(crate) public_json_file_path: Option<PathBuf>,
}

pub(crate) struct SinglesigCoreGenerateArgs<'a> {
    pub(crate) password: Option<Arc<SecretString>>,
    pub(crate) output_file_path: PathBuf,
    pub(crate) public_info_json_output: Option<PathBuf>,
    pub(crate) duress_input_args: DuressInputArgs,
    pub(crate) keyfiles: &'a [PathBuf],
    pub(crate) user_mnemonic: Option<Arc<Secret<Mnemonic>>>,
    pub(crate) word_count: WordCount,
    pub(crate) script_type: ScriptType,
    pub(crate) network: Network,
    pub(crate) difficulty: &'a KeyDerivationDifficulty,
    pub(crate) addresses_quantity: u32,
    pub(crate) padding_params: PaddingParams,
    pub(crate) encrypted_wallet_version: EncryptedWalletVersion,
}

pub(crate) struct MultisigCoreGenerateArgs<'a> {
    pub(crate) password: Option<Arc<SecretString>>,
    pub(crate) configuration: MultisigType,
    pub(crate) inputs: MultisigInputs,
    pub(crate) output_file_path_encrypted: PathBuf,
    pub(crate) output_file_path_json: Option<PathBuf>,
    pub(crate) keyfiles: &'a [PathBuf],
    pub(crate) network: Network,
    pub(crate) difficulty: &'a KeyDerivationDifficulty,
    pub(crate) addresses_quantity: u32,
    pub(crate) padding_params: PaddingParams,
}

pub(crate) fn singlesig_core_generate(
    theme: &dyn Theme,
    term: &Term,
    secp: &mut Secp256k1<All>,
    mut rng: &mut impl CryptoRngCore,
    ic: impl InternetChecker,
    args: SinglesigCoreGenerateArgs,
) -> anyhow::Result<()> {
    warn_difficulty_level(args.difficulty);
    let output_file_path = &args.output_file_path;
    log::info!("Will generate a new wallet saving to {output_file_path:?}");
    let password = args
        .password
        .map(Result::Ok)
        .unwrap_or_else(|| generate_ask_password(theme, term, Some(ic)))?;

    let duress_params = ask_non_duress_params(theme, term, args.duress_input_args)?;
    let salt = get_random_salt(&mut rng)?;
    let key = ui_derive_key(&password, args.keyfiles, &salt, args.difficulty)?;
    let nonce = get_random_nonce(&mut rng)?;
    let header_nonce = get_random_nonce(&mut rng)?;
    let header_key = Secret::new(get_random_key(&mut rng)?);
    let padder = get_padder(&mut rng, &args.padding_params)?;
    let mnemonic = if let Some(ref mnemonic) = args.user_mnemonic {
        Arc::clone(mnemonic)
    } else {
        Arc::new(generate_seeds(&mut rng, args.word_count, ENGLISH)?)
    };
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
    // If we are going to export the public info then we will derive the key again to make sure everything is okay and no bit flip happened somewhere
    if let Some(ref public_info_json_output) = args.public_info_json_output {
        let encrypted_wallet = read_decode_wallet(output_file_path)?;
        log::info!("Will derive the key again to double check against bit flips...");
        let pb = get_derivation_key_spinner();
        let key = default_derive_key(
            &password,
            args.keyfiles,
            &encrypted_wallet.salt,
            args.difficulty,
        )
        .context("failure trying to derive the same key again")?;
        pb.finish_using_style();
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
        let address_params = AddressGenerationParams {
            first_index: 0,
            quantity: args.addresses_quantity,
        };
        export_singlesig_public_infos(
            theme,
            term,
            secp,
            &wallet_description,
            public_info_json_output,
            &duress_params,
            &address_params,
        )?;
        inform_custom_generate_params(args.keyfiles, args.difficulty, duress_params.is_some());
        log::info!("Finished successfully!");
    } else {
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
        inform_custom_generate_params(args.keyfiles, args.difficulty, duress_params.is_some());
        log::info!("Finished successfully!");
        log::info!("Now run again with the other commands to retrieve the receiving addresses and/or public keys");
    }
    Ok(())
}

pub(crate) fn multisig_core_generate(
    theme: &dyn Theme,
    term: &Term,
    secp: &mut Secp256k1<All>,
    mut rng: &mut impl CryptoRngCore,
    args: MultisigCoreGenerateArgs,
) -> anyhow::Result<()> {
    warn_difficulty_level(args.difficulty);
    let script_type = ScriptType::SegwitNative;
    let output_file_path_encrypted = &args.output_file_path_encrypted;
    args.inputs.validate(&args.configuration)?;
    log::info!("Will generate a multisig wallet saving to {output_file_path_encrypted:?}");
    let password = args
        .password
        .map(Result::Ok)
        .unwrap_or_else(|| generate_ask_password(theme, term, None::<InternetCheckerImpl>))?;
    let salt = get_random_salt(&mut rng)?;
    let key = ui_derive_key(&password, args.keyfiles, &salt, args.difficulty)?;
    let nonce = get_random_nonce(&mut rng)?;
    let header_nonce = get_random_nonce(&mut rng)?;
    let header_key = Secret::new(get_random_key(&mut rng)?);
    let padder = get_padder(&mut rng, &args.padding_params)?;
    let encrypted_wallet = generate_encrypted_encoded_multisig_wallet(
        args.configuration,
        args.inputs,
        &key,
        header_key,
        salt,
        nonce,
        header_nonce,
        padder,
        script_type,
        args.network,
        secp,
    )?;
    // Write file
    create_file(&encrypted_wallet, output_file_path_encrypted).with_context(|| {
        format!("failure saving encrypted wallet to {output_file_path_encrypted:?}")
    })?;
    log::info!("Wallet saved to {output_file_path_encrypted:?}");
    secp.randomize(&mut rng);
    if let Some(ref output_file_path_json) = args.output_file_path_json {
        let read_encrypted_wallet = read_decode_wallet(output_file_path_encrypted)?;
        log::info!("Will derive the key again to double check against bit flips...");
        let pb = get_derivation_key_spinner();
        let key = default_derive_key(
            &password,
            args.keyfiles,
            &read_encrypted_wallet.salt,
            args.difficulty,
        )
        .context("failure trying to derive the same key again")?;
        pb.finish_using_style();
        let read_json_wallet_description = read_encrypted_wallet
            .decrypt_multisig(&key)
            .context(CONTEXT_CORRUPTION_WARNING)?;
        let read_wallet_description = MultiSigWalletDescriptionV0::generate(
            vec![],
            read_json_wallet_description
                .expose_secret()
                .receiving_output_descriptor()?,
            read_json_wallet_description
                .expose_secret()
                .change_output_descriptor()?,
            read_json_wallet_description
                .expose_secret()
                .configuration()?,
            read_json_wallet_description.expose_secret().network()?,
            read_json_wallet_description.expose_secret().script_type()?,
        )
        .context("failure parsing generated wallet")?;
        // Sanity check
        MultisigJsonWalletDescriptionV0::validate_same(
            &read_json_wallet_description,
            &read_wallet_description,
            secp,
        )?
        .context("failure checking generated wallet")?;
        let address_params = AddressGenerationParams {
            first_index: 0,
            quantity: args.addresses_quantity,
        };
        export_multisig_public_infos(
            secp,
            &read_wallet_description,
            output_file_path_json,
            &address_params,
        )?;
        inform_custom_generate_params(args.keyfiles, args.difficulty, false);
        log::info!("Finished successfully!");
    } else {
        // If no public info will be exported right now, then we can just check using the existing key because additional commands will be required to export the public info later
        // So we are delaying the key derivation to the future
        let read_encrypted_wallet = read_decode_wallet(output_file_path_encrypted)?;
        let read_json_wallet_description = read_encrypted_wallet
            .decrypt_multisig(&key)
            .context(CONTEXT_CORRUPTION_WARNING)?;
        let read_wallet_description = MultiSigWalletDescriptionV0::generate(
            vec![],
            read_json_wallet_description
                .expose_secret()
                .receiving_output_descriptor()?,
            read_json_wallet_description
                .expose_secret()
                .change_output_descriptor()?,
            read_json_wallet_description
                .expose_secret()
                .configuration()?,
            read_json_wallet_description.expose_secret().network()?,
            read_json_wallet_description.expose_secret().script_type()?,
        )
        .context("failure parsing generated wallet")?;
        // Sanity check
        MultisigJsonWalletDescriptionV0::validate_same(
            &read_json_wallet_description,
            &read_wallet_description,
            secp,
        )?
        .context("failure checking generated wallet")?;
        inform_custom_generate_params(args.keyfiles, args.difficulty, false);
        log::info!("Finished successfully!");
        log::info!("Now run again with the other commands to retrieve the receiving addresses and/or public keys");
    };
    Ok(())
}

fn ask_non_duress_params(
    theme: &dyn Theme,
    term: &Term,
    args: DuressInputArgs,
) -> anyhow::Result<Option<DuressPublicInfoParams>> {
    let duress_params = match calculate_non_duress_output(
        args.enable_duress_wallet,
        &args.non_duress_output_file_json,
        &args.public_json_file_path,
    )? {
        Some(non_duress_public_info_json_output) => Some(DuressPublicInfoParams {
            non_duress_password: ask_non_duress_password(theme, term)?,
            non_duress_public_info_json_output,
        }),
        None => None,
    };
    Ok(duress_params)
}

pub(crate) fn generate_ask_password(
    theme: &dyn Theme,
    term: &Term,
    ic: Option<impl InternetChecker>,
) -> anyhow::Result<Arc<SecretString>> {
    ic.map(|mut i| i.check()).transpose()?;
    log::info!("Enter a new password to encrypt the wallet:");
    loop {
        let password = Arc::new(ask_password(theme, term)?);
        let password_strength = zxcvbn::zxcvbn(password.expose_secret(), &[])?;
        if password_strength.score() < 3 {
            if let Some(feedback) = password_strength.feedback() {
                for suggestion in feedback.suggestions() {
                    log::info!("Suggestion: {suggestion}");
                }
            }
            if dialoguer::Confirm::with_theme(theme)
                .with_prompt(format!(
                    "This password is very weak (score of {}, from 0 to 4), continue?",
                    password_strength.score()
                ))
                .interact_on(term)?
            {
                return Ok(password);
            }
        } else {
            return Ok(password);
        }
    }
}
