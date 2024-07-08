use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow::{self, Context},
    bitcoin::{
        secp256k1::{All, Secp256k1},
        Network,
    },
    key_derivation::{self, KeyDerivationDifficulty},
    log, parse_keyfiles_paths,
    rand_core::CryptoRngCore,
    secrecy::Secret,
    utils::create_file,
    wallet_description::{MultiSigWalletDescriptionV0, SingleSigWalletDescriptionV0},
    wallet_export::MultisigJsonWalletPublicExportV0,
    PaddingParams,
};

use crate::commands::common::{
    multisig::parse_multisig_inputs, singlesig::generate_singlesig_public_info,
};

use frozenkrill_core::wallet_description::WordCount;

use crate::commands::common::generate_random_name;

use crate::{
    commands::common::double_check_non_duress_password, handle_output_path,
    ui_ask_manually_seed_input, InternetChecker, SinglesigGenerateArgs,
};

use self::core::{
    multisig_core_generate, singlesig_core_generate, DuressInputArgs, MultisigCoreGenerateArgs,
    SinglesigCoreGenerateArgs,
};

use super::{
    common::{from_wallet_to_public_info_json_path, AddressGenerationParams},
    interactive::ask_for_keyfiles_generate,
};

pub mod core;

pub(crate) struct DuressPublicInfoParams {
    pub(crate) non_duress_password: Arc<Secret<String>>,
    pub(crate) non_duress_public_info_json_output: PathBuf,
}

pub(super) fn export_singlesig_public_infos(
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
    wallet_description: &SingleSigWalletDescriptionV0,
    public_info_json_output: &Path,
    duress_params: &Option<DuressPublicInfoParams>,
    params: &AddressGenerationParams,
) -> Result<(), anyhow::Error> {
    let json = generate_singlesig_public_info(
        secp,
        wallet_description,
        params.first_index,
        params.quantity,
    )
    .context("failure exporting public info")?;
    if let Some(ref duress_params) = duress_params {
        double_check_non_duress_password(theme, term, &duress_params.non_duress_password)?;
    }
    create_file(&json, public_info_json_output).with_context(|| {
        anyhow::anyhow!("failure exporting public info to {public_info_json_output:?}")
    })?;
    log::info!("Exported public info to {public_info_json_output:?}");
    log::info!(
        "First generated address: {}",
        wallet_description.first_receiving_address(secp)?
    );
    if let Some(ref duress_params) = duress_params {
        let non_duress_wallet_description = wallet_description
            .change_seed_password(&Some(Arc::clone(&duress_params.non_duress_password)), secp)
            .context("failure generating non duress wallet")?;
        let json = generate_singlesig_public_info(
            secp,
            &non_duress_wallet_description,
            params.first_index,
            params.quantity,
        )
        .context("failure exporting public info")?;
        create_file(&json, &duress_params.non_duress_public_info_json_output).with_context(
            || {
                anyhow::anyhow!(
                    "failure exporting non duress public info to {:?}",
                    duress_params.non_duress_public_info_json_output
                )
            },
        )?;
        log::info!(
            "Exported non duress public info to {:?}",
            duress_params.non_duress_public_info_json_output
        );
        log::info!(
            "First non duress generated address: {}",
            non_duress_wallet_description.first_receiving_address(secp)?
        );
    };
    Ok(())
}

fn generate_multisig_public_info(
    secp: &Secp256k1<All>,
    wallet: &MultiSigWalletDescriptionV0,
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
        MultisigJsonWalletPublicExportV0::generate(wallet, addresses, change_addresses);
    public_export.to_vec_pretty()
}

pub(super) fn export_multisig_public_infos(
    secp: &Secp256k1<All>,
    wallet_description: &MultiSigWalletDescriptionV0,
    public_info_json_output: &Path,
    params: &AddressGenerationParams,
) -> Result<(), anyhow::Error> {
    let json = generate_multisig_public_info(
        secp,
        wallet_description,
        params.first_index,
        params.quantity,
    )
    .context("failure exporting public info")?;
    create_file(&json, public_info_json_output).with_context(|| {
        anyhow::anyhow!("failure exporting public info to {public_info_json_output:?}")
    })?;
    log::info!("Exported public info to {public_info_json_output:?}");
    log::info!(
        "First generated address: {}",
        wallet_description.first_receiving_address(secp)?.address
    );
    Ok(())
}

pub(super) fn inform_custom_generate_params(
    keyfiles: &[PathBuf],
    difficulty: &KeyDerivationDifficulty,
    enable_duress_wallet: bool,
) {
    let custom_keyfiles = !keyfiles.is_empty();
    let custom_difficulty = *difficulty != key_derivation::DEFAULT_DIFFICULTY_LEVEL;
    if custom_keyfiles || custom_difficulty || enable_duress_wallet {
        eprintln!(
            "{}",
            termimad::inline(
                "**Note:** non default parameters **required** to open the wallet in future:"
            )
        );
        for k in keyfiles {
            eprintln!("\t--keyfile {k:?}");
        }
        if custom_difficulty {
            eprintln!("\t--difficulty {}", difficulty.as_str().to_lowercase());
        }
        if enable_duress_wallet {
            eprintln!("\t--enable-duress-wallet");
            // eprintln!("Your wallet now have two set of addresses:");
            // eprintln!("- Default duress addresses using the empty seed password");
            // eprintln!("- And non duress addresses using the non duress seed password");
            // eprintln!(
            //     "Note that a non empty seed password isn't supported by wallets like Electrum"
            // );
            // eprintln!("Now you have plausible deniability under coercion (duress)");
            // eprintln!("You should transfer low amounts to the default duress addresses");
            // eprintln!("And keep most of your bitcoin under the non duress adresses");
            // eprintln!("But if you forget or wrongly type you non duress password you may easily loose funds");
            // eprintln!("There is no way to check if the password is correct");
            // eprintln!("It'll just generate different addresses for different passwords");
        }
    }
}

pub(crate) fn generate_check_keyfiles(
    theme: &dyn Theme,
    term: &Term,
    keyfiles: Vec<PathBuf>,
) -> anyhow::Result<Vec<PathBuf>> {
    if keyfiles.is_empty() {
        ask_for_keyfiles_generate(theme, term)
    } else {
        Ok(keyfiles)
    }
}

pub(crate) fn singlesig_generate(
    theme: &dyn Theme,
    term: &Term,
    secp: &mut Secp256k1<All>,
    mut rng: &mut impl CryptoRngCore,
    ic: impl InternetChecker,
    args: SinglesigGenerateArgs,
) -> anyhow::Result<()> {
    let output_file_path = match args.wallet_output_file {
        Some(p) => p,
        None => generate_random_name("wallet_", "", rng)?,
    };
    let output_file_path = handle_output_path(&output_file_path)?.into_owned();
    let public_info_json_output = match args.public_info_json_output {
        Some(p) if p.trim().is_empty() => None,
        Some(p) => Some(handle_output_path(&p)?.into_owned()),
        None => Some(from_wallet_to_public_info_json_path(&output_file_path)?),
    };

    let keyfiles = parse_keyfiles_paths(&args.common.keyfile)?;
    let keyfiles = generate_check_keyfiles(theme, term, keyfiles)?;
    let word_count = if args.use_12_words {
        WordCount::W12
    } else {
        WordCount::W24
    };
    let network = if args.common.use_testnet {
        Network::Testnet
    } else {
        Network::Bitcoin
    };
    let user_mnemonic = if args.user_generated_seed {
        Some(Arc::new(ui_ask_manually_seed_input(
            &mut rng,
            theme,
            term,
            &word_count,
            args.always_hide_typed_seed,
        )?))
    } else if args.always_hide_typed_seed {
        anyhow::bail!(
            "The --always-hide-typed-seed flag only makes sense when used with --user-generated-seed"
        );
    } else {
        None
    };
    let duress_input_args = DuressInputArgs {
        enable_duress_wallet: args.enable_duress_wallet,
        non_duress_output_file_json: None,
        public_json_file_path: public_info_json_output.clone(),
    };
    let script_type = frozenkrill_core::wallet_description::ScriptType::SegwitNative;
    let args = SinglesigCoreGenerateArgs {
        password: None,
        output_file_path,
        public_info_json_output,
        keyfiles: &keyfiles,
        user_mnemonic,
        duress_input_args,
        word_count,
        script_type,
        network,
        difficulty: &args.common.difficulty,
        addresses_quantity: args.common.addresses_quantity,
        padding_params: PaddingParams::new(
            args.common.disable_all_padding,
            Some(args.common.min_additional_padding_bytes),
            Some(args.common.max_additional_padding_bytes),
        )?,
        encrypted_wallet_version: args
            .common
            .wallet_file_type
            .to_encrypted_wallet_version(network, script_type)?,
    };
    singlesig_core_generate(theme, term, secp, rng, ic, args)?;
    Ok(())
}

pub(crate) fn multisig_generate(
    theme: &dyn Theme,
    term: &Term,
    secp: &mut Secp256k1<All>,
    rng: &mut impl CryptoRngCore,
    ic: impl InternetChecker,
    args: crate::MultisigGenerateArgs,
) -> anyhow::Result<()> {
    let output_file_path = match args.encrypted_wallet_output_file {
        Some(p) => p,
        None => generate_random_name("wallet_", "", rng)?,
    };
    let output_file_path_encrypted = handle_output_path(&output_file_path)?.into_owned();
    let output_file_path_json = match args.json_output_file {
        Some(p) if p.trim().is_empty() => None,
        Some(p) => Some(handle_output_path(&p)?.into_owned()),
        None => Some(from_wallet_to_public_info_json_path(
            &output_file_path_encrypted,
        )?),
    };
    let keyfiles = parse_keyfiles_paths(&args.common.keyfile)?;
    let keyfiles = generate_check_keyfiles(theme, term, keyfiles)?;
    let network = if args.common.use_testnet {
        Network::Testnet
    } else {
        Network::Bitcoin
    };
    let inputs = parse_multisig_inputs(theme, term, secp, ic, &args.input_files)?;
    let script_type = frozenkrill_core::wallet_description::ScriptType::SegwitNative;
    let args = MultisigCoreGenerateArgs {
        password: None,
        keyfiles: &keyfiles,
        network,
        script_type,
        difficulty: &args.common.difficulty,
        addresses_quantity: args.common.addresses_quantity,
        padding_params: PaddingParams::new(
            args.common.disable_all_padding,
            Some(args.common.min_additional_padding_bytes),
            Some(args.common.max_additional_padding_bytes),
        )?,
        configuration: args.configuration,
        inputs,
        output_file_path_encrypted,
        output_file_path_json,
        encrypted_wallet_version: args
            .common
            .wallet_file_type
            .to_encrypted_wallet_version(network, script_type)?,
    };
    multisig_core_generate(theme, term, secp, rng, args)?;
    Ok(())
}
