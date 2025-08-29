use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    sync::Arc,
};

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    PaddingParams,
    anyhow::{self, Context, bail},
    bitcoin::{
        Network,
        secp256k1::{All, Secp256k1},
    },
    generate_encrypted_encoded_singlesig_wallet, get_padder, itertools,
    key_derivation::{KeyDerivationDifficulty, default_derive_key},
    log, parse_keyfiles_paths,
    rand_core::{CryptoRng, RngCore},
    secrecy::{ExposeSecret, SecretBox, SecretString},
    utils::create_file,
    wallet_description::{
        EncryptedWalletVersion, KEY_SIZE, NONCE_SIZE, SALT_SIZE, ScriptType,
        calculate_seed_entropy_bytes, generate_entropy_for_seeds, generate_seeds_from_entropy,
    },
};

use crate::commands::{
    common::singlesig::generate_singlesig_public_info, generate::core::generate_ask_password,
};
use frozenkrill_core::wallet_description::{
    SinglesigJsonWalletDescriptionV0, WordCount, read_decode_wallet,
};

use crate::{
    ENGLISH, InternetChecker, SinglesigBatchGenerateExportArgs, ask_non_duress_password,
    commands::common::{
        CONTEXT_CORRUPTION_WARNING, double_check_non_duress_password,
        from_public_info_json_path_to_non_duress, from_wallet_to_public_info_json_path,
        generate_name,
    },
    progress_bar::get_prefixed_progress_bar,
    warn_difficulty_level,
};

use super::generate::{generate_check_keyfiles, inform_custom_generate_params};

type Secret<T> = SecretBox<T>;

pub(super) struct CoreBatchGenerateExportArgs<'a> {
    pub(super) password: Option<Arc<SecretString>>,
    pub(super) keyfiles: &'a [PathBuf],
    pub(super) word_count: WordCount,
    pub(super) network: Network,
    pub(super) script_type: ScriptType,
    pub(super) wallets_quantity: usize,
    pub(super) output_prefix: &'a str,
    pub(super) enable_duress_wallet: bool,
    pub(super) difficulty: &'a KeyDerivationDifficulty,
    pub(super) disable_public_info_export: bool,
    pub(super) addresses_quantity: u32,
    pub(super) padding_params: PaddingParams,
    pub(super) encrypted_wallet_version: EncryptedWalletVersion,
}

pub(super) fn core_batch_generate_export(
    theme: &dyn Theme,
    term: &Term,
    secp: &mut Secp256k1<All>,
    rng: &mut (impl CryptoRng + RngCore),
    ic: impl InternetChecker,
    args: CoreBatchGenerateExportArgs,
) -> anyhow::Result<()> {
    if args.enable_duress_wallet && args.disable_public_info_export {
        bail!("--enable-duress-wallet is incompatible with --disable-public-info-export")
    }
    warn_difficulty_level(args.difficulty);
    let output_prefix = args.output_prefix;
    let wallets_quantity = args.wallets_quantity;
    let keyfiles = args.keyfiles;
    let difficulty = args.difficulty;
    let mut name_salt = [0u8; KEY_SIZE];
    rng.fill_bytes(&mut name_salt);
    let output_prefix = match output_prefix.trim() {
        "" => "".into(),
        other => {
            if Path::new(other).is_dir() {
                "".into()
            } else {
                format!("{other}_")
            }
        }
    };
    use frozenkrill_core::rayon::prelude::*;
    let pb = Arc::new(get_prefixed_progress_bar(
        wallets_quantity,
        "Output paths",
        "Generating...",
    ));
    let output_paths: Vec<_> = (0..wallets_quantity)
        .into_par_iter()
        .map(|i| generate_name(&output_prefix, &name_salt, i, ""))
        .map(|name| {
            pb.inc(1);
            Path::new(&name).to_owned()
        })
        .collect();
    pb.finish_using_style();
    // pb.finish_and_clear(); // May overlap with the password prompt below if we don't clear
    if let Some(path) = output_paths.first() {
        let _ = OpenOptions::new().read(false).write(true).create_new(true).open(path).with_context(|| anyhow::anyhow!("failure creating test file {path:?}, check if all directories exist and the permissions are ok"))?;
        fs::remove_file(path)
            .with_context(|| anyhow::anyhow!("failure deleting test file {path:?}"))?;
    }
    let password = args
        .password
        .clone()
        .map(Result::Ok)
        .unwrap_or_else(|| generate_ask_password(theme, term, Some(ic)))?;

    let non_duress_password = if args.enable_duress_wallet {
        Some(ask_non_duress_password(theme, term)?)
    } else {
        None
    };
    let pb = get_prefixed_progress_bar(wallets_quantity, "Nonces", "Generating...");
    let mut nonces = HashSet::with_capacity(wallets_quantity * 2);
    while nonces.len() < wallets_quantity * 2 {
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce);
        nonces.insert(nonce);
        pb.set_position(nonces.len().try_into()?);
    }
    let nonces: Vec<(_, _)> = itertools::Itertools::tuples(nonces.into_iter()).collect();
    pb.finish_using_style();
    let pb = get_prefixed_progress_bar(wallets_quantity, "Salts", "Generating...");
    let mut salts = HashSet::with_capacity(wallets_quantity);
    while salts.len() < wallets_quantity {
        let mut salt = [0u8; SALT_SIZE];
        rng.fill_bytes(&mut salt);
        salts.insert(salt);
        pb.set_position(salts.len().try_into()?);
    }
    let salts: Vec<_> = salts.into_iter().collect();
    pb.finish_using_style();
    let pb = get_prefixed_progress_bar(wallets_quantity, "Header keys", "Generating...");
    let mut header_keys = HashSet::with_capacity(wallets_quantity);
    while header_keys.len() < wallets_quantity {
        let mut header_key = [0u8; KEY_SIZE];
        rng.fill_bytes(&mut header_key);
        header_keys.insert(header_key);
        pb.set_position(header_keys.len().try_into()?);
    }
    let header_keys: Vec<_> = header_keys
        .into_iter()
        .map(|k| Secret::from(Box::new(k)))
        .collect();
    pb.finish_using_style();
    let pb = get_prefixed_progress_bar(wallets_quantity, "Paddings", "Generating...");
    let paddings = (0..wallets_quantity)
        .map(|_| {
            let padder = get_padder(rng, &args.padding_params);
            pb.inc(1);
            padder
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    pb.finish_using_style();
    let pb = get_prefixed_progress_bar(wallets_quantity, "Seeds", "Generating...");
    let entropy_bytes = calculate_seed_entropy_bytes(args.word_count);
    let mut seeds_entropy = HashSet::with_capacity(wallets_quantity);
    while seeds_entropy.len() < wallets_quantity {
        match generate_entropy_for_seeds(entropy_bytes, rng) {
            Ok(seed_entropy) => {
                seeds_entropy.insert(seed_entropy);
            }
            Err(e) => {
                log::warn!(
                    "While getting entropy for a seed got {e:?}, try to generate more entropy for the operating system (seeds generated: {})",
                    seeds_entropy.len()
                )
            }
        }
        pb.set_position(seeds_entropy.len().try_into()?);
    }
    let seeds = seeds_entropy
        .par_iter()
        .map(|entropy| generate_seeds_from_entropy(entropy_bytes, entropy, ENGLISH))
        .collect::<anyhow::Result<Vec<_>>>()
        .context("failure generating seeds from entropy")?;
    pb.finish_using_style();
    let pb = Arc::new(get_prefixed_progress_bar(
        wallets_quantity,
        "Derived keys",
        "Generating...",
    ));
    let derived_keys = salts
        .par_iter()
        .map(|salt| {
            let key = default_derive_key(&password, keyfiles, salt, difficulty);
            pb.inc(1);
            key
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    pb.finish_using_style();
    let pb = Arc::new(get_prefixed_progress_bar(
        wallets_quantity,
        "Wallet files",
        "Encrypting...",
    ));
    let seed_password = &None; // Not supported under batch mode
    let encrypted_wallets: anyhow::Result<Vec<_>> = seeds
        .into_par_iter()
        .zip(header_keys)
        .zip(paddings)
        .zip(salts)
        .zip(nonces)
        .zip(derived_keys)
        .map(
            |(((((mnemonic, header_key), padding), salt), (nonce, header_nonce)), key)| {
                let encrypted_wallet = generate_encrypted_encoded_singlesig_wallet(
                    &key,
                    header_key,
                    Arc::new(mnemonic),
                    seed_password,
                    salt,
                    nonce,
                    header_nonce,
                    padding,
                    args.script_type,
                    args.network,
                    args.encrypted_wallet_version,
                    secp,
                );
                pb.inc(1);
                encrypted_wallet
            },
        )
        .collect();
    let encrypted_wallets = encrypted_wallets?;
    pb.finish_using_style();
    let pb = Arc::new(get_prefixed_progress_bar(
        wallets_quantity,
        "Wallet files",
        "Saving...",
    ));
    for (encrypted_wallet, output_path) in encrypted_wallets.iter().zip(&output_paths) {
        create_file(encrypted_wallet, output_path)
            .with_context(|| format!("failure saving encrypted wallet {output_path:?}"))?;
    }
    pb.finish_using_style();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    secp.seeded_randomize(&seed);
    let pb = Arc::new(get_prefixed_progress_bar(
        wallets_quantity,
        "Wallet files",
        "Reading...",
    ));
    let read_wallets: anyhow::Result<Vec<_>> =
        output_paths.iter().map(|o| read_decode_wallet(o)).collect();
    let read_wallets = read_wallets?;
    pb.finish_using_style();
    let pb = Arc::new(get_prefixed_progress_bar(
        wallets_quantity,
        "Derived keys",
        "Double-checking...",
    ));
    let derived_keys: anyhow::Result<Vec<_>> = read_wallets
        .par_iter()
        .map(|w| {
            let key = default_derive_key(&password, keyfiles, &w.salt, difficulty);
            pb.inc(1);
            key
        })
        .collect();
    let derived_keys = derived_keys?;
    pb.finish_using_style();
    let pb = Arc::new(get_prefixed_progress_bar(
        wallets_quantity,
        "Wallet files",
        "Decrypting...",
    ));
    let decrypted_json_read_wallets = read_wallets
        .par_iter()
        .zip(derived_keys)
        .map(|(w, k)| {
            let decrypted_json = w
                .decrypt_singlesig(&k, seed_password, secp)
                .context(CONTEXT_CORRUPTION_WARNING);
            pb.inc(1);
            decrypted_json
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    pb.finish_using_style();
    let pb = Arc::new(get_prefixed_progress_bar(
        wallets_quantity,
        "Wallet files",
        "Checking...",
    ));
    let decrypted_read_wallets: anyhow::Result<Vec<_>> = decrypted_json_read_wallets
        .par_iter()
        .map(|w| {
            let decrypted = w.expose_secret().to(seed_password, secp);
            if let Ok(d) = &decrypted {
                // Sanity check
                SinglesigJsonWalletDescriptionV0::validate_same(w, d, secp)?
                    .context("failure checking generated wallet")
                    .expect("to not be a bug");
            }
            pb.inc(1);
            decrypted
        })
        .collect();
    let decrypted_read_wallets = decrypted_read_wallets?;
    pb.finish_using_style();
    if !args.disable_public_info_export {
        let pb = Arc::new(get_prefixed_progress_bar(
            wallets_quantity,
            "Public info",
            "Generating...",
        ));
        let public_infos = decrypted_read_wallets
            .par_iter()
            .map(|w| generate_singlesig_public_info(secp, w, 0, args.addresses_quantity))
            .collect::<anyhow::Result<Vec<_>>>()?;
        pb.finish_using_style();
        let non_duress_public_infos = if let Some(non_duress_password) = &non_duress_password {
            double_check_non_duress_password(theme, term, non_duress_password)?;
            let pb = Arc::new(get_prefixed_progress_bar(
                wallets_quantity,
                "Non Duress",
                "Preparing...",
            ));
            let non_duress_wallets = decrypted_read_wallets
                .par_iter()
                .map(|w| w.change_seed_password(&Some(Arc::clone(non_duress_password)), secp))
                .collect::<anyhow::Result<Vec<_>>>()?;
            pb.finish_using_style();
            let pb = Arc::new(get_prefixed_progress_bar(
                wallets_quantity,
                "Non Duress",
                "Generating...",
            ));
            let public_infos = non_duress_wallets
                .par_iter()
                .map(|w| generate_singlesig_public_info(secp, w, 0, args.addresses_quantity))
                .collect::<anyhow::Result<Vec<_>>>()?;
            pb.finish_using_style();
            Some(public_infos)
        } else {
            None
        };
        let pb = Arc::new(get_prefixed_progress_bar(
            wallets_quantity,
            "Public info",
            "Saving...",
        ));
        for (public_info, output_path) in public_infos.into_iter().zip(&output_paths) {
            let output_path = from_wallet_to_public_info_json_path(output_path)?;
            create_file(&public_info, &output_path)?;
        }
        pb.finish_using_style();
        if let Some(non_duress_public_infos) = non_duress_public_infos {
            let pb = Arc::new(get_prefixed_progress_bar(
                wallets_quantity,
                "Non Duress",
                "Saving...",
            ));
            for (public_info, output_path) in non_duress_public_infos.into_iter().zip(output_paths)
            {
                let output_path = from_public_info_json_path_to_non_duress(
                    &from_wallet_to_public_info_json_path(&output_path)?,
                )?;
                create_file(&public_info, &output_path)?;
            }
            pb.finish_using_style();
        }
        log::info!(
            "Note: public information (containing xpub, receiving addresses and other params) have a .json extension. The encrypted wallets have no extension"
        );
    }
    inform_custom_generate_params_batch(&args);
    log::info!("Finished successfully!");
    Ok(())
}

fn inform_custom_generate_params_batch(args: &CoreBatchGenerateExportArgs) {
    inform_custom_generate_params(args.keyfiles, args.difficulty, args.enable_duress_wallet);
}

pub(crate) fn batch_generate_export(
    theme: &dyn Theme,
    term: &Term,
    secp: &mut Secp256k1<All>,
    rng: &mut (impl CryptoRng + RngCore),
    ic: impl InternetChecker,
    args: &SinglesigBatchGenerateExportArgs,
) -> anyhow::Result<()> {
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
    let script_type = ScriptType::SegwitNative;
    let password = args
        .common
        .password
        .clone()
        .map(|s| SecretString::new(s.into()))
        .map(Arc::new);
    let args = CoreBatchGenerateExportArgs {
        password,
        keyfiles: &keyfiles,
        word_count,
        network,
        script_type,
        wallets_quantity: args.wallets_quantity,
        output_prefix: &args.output_prefix,
        enable_duress_wallet: args.enable_duress_wallet,
        difficulty: &args.common.difficulty,
        disable_public_info_export: args.disable_public_info_export,
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
    core_batch_generate_export(theme, term, secp, rng, ic, args)
}
