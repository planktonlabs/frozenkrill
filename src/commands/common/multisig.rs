use std::{
    collections::HashSet,
    io::Read,
    path::{Path, PathBuf},
    str::{from_utf8, FromStr},
    sync::Arc,
};

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow::{self, ensure, Context},
    bitcoin::secp256k1::{All, Secp256k1},
    key_derivation::KeyDerivationDifficulty,
    log::{self, debug, info},
    miniscript::DescriptorPublicKey,
    parse_keyfiles_paths,
    secrecy::{ExposeSecret, Secret, SecretString},
    serde_json,
    utils::{self, buf_open_file},
    wallet_description::{
        self, read_decode_wallet, EncryptedWalletDescription, MultiSigWalletDescriptionV0,
        MultisigJsonWalletDescriptionV0, MultisigType, SigType, SingleSigWalletDescriptionV0,
    },
    wallet_export::{GenericOutputExportJson, SinglesigJsonWalletPublicExportV0},
    MultisigInputs,
};

use crate::{
    ask_password,
    commands::{
        common::{
            ask_try_open_again_multisig_parse_multisig_input, singlesig::singlesig_core_open,
        },
        interactive::{
            get_ask_difficulty,
            open::{ask_for_keyfiles_open, ask_to_open_duress, ask_wallet_input_file},
        },
    },
    handle_input_path, ui_derive_key, InternetChecker, InternetCheckerImpl, MultisigOpenArgs,
};

use super::ask_try_decrypt;

pub(crate) fn open_multisig_wallet_non_interactive(
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
    ic: impl InternetChecker,
    args: &MultisigOpenArgs,
) -> anyhow::Result<MultiSigWalletDescriptionV0> {
    log::info!(
        "Trying to open multisig wallet {:?}",
        args.common.wallet_input_file
    );
    let input_file_path = handle_input_path(&args.common.wallet_input_file)?;
    let encrypted_wallet = read_decode_wallet(&input_file_path)?;
    let keyfiles = parse_keyfiles_paths(&args.common.keyfile)?;
    let inputs = parse_multisig_inputs(theme, term, secp, ic, &args.input_files)?;
    if args.input_files.len() != inputs.signers.len() {
        anyhow::bail!(
            "Given {} files but only {} signers found",
            args.input_files.len(),
            inputs.signers.len()
        )
    }
    multisig_core_open(
        theme,
        term,
        secp,
        &encrypted_wallet,
        &keyfiles,
        &args.common.difficulty,
        Some(inputs.signers),
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn multisig_core_open(
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
    encrypted_wallet: &EncryptedWalletDescription,
    keyfiles: &[PathBuf],
    difficulty: &KeyDerivationDifficulty,
    signers: Option<Vec<SingleSigWalletDescriptionV0>>,
    password: Option<Arc<SecretString>>,
) -> anyhow::Result<MultiSigWalletDescriptionV0> {
    let password = password
        .map(Result::Ok)
        .unwrap_or_else(|| ask_password(theme, term).map(Arc::new))?;
    let key = ui_derive_key(&password, keyfiles, &encrypted_wallet.salt, difficulty)?;
    let json_wallet = encrypted_wallet.decrypt_multisig(&key)?;
    let wallet = ui_get_multisig_wallet_description(theme, term, &json_wallet, signers, secp)?;
    Ok(wallet)
}

pub(crate) fn parse_multisig_input(
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
    i: &Path,
) -> anyhow::Result<MultisigInputs> {
    let mut receiving_descriptors = HashSet::new();
    let mut change_descriptors = HashSet::new();
    let mut signers = Vec::new();
    match GenericOutputExportJson::deserialize(utils::buf_open_file(i)?) {
        Ok(g) => match g.version_sigtype()? {
            (Some(wallet_description::ZERO_SINGLESIG_WALLET_VERSION), Some(SigType::Singlesig)) => {
                let v = SinglesigJsonWalletPublicExportV0::from_path(i)?;
                receiving_descriptors.insert(v.receiving_multisig_public_descriptor()?);
                change_descriptors.insert(v.change_multisig_public_descriptor()?);
            }
            (Some(_), Some(SigType::Multisig(_))) => {
                anyhow::bail!("A multisig export isn't a valid input file")
            }
            _ => anyhow::bail!("Unrecognized json file {i:?}"),
        },
        Err(e) => {
            debug!("Failed to parse {i:?} as public info export json: {e:?}");
            match try_parse_input_as_simple_descriptor(i) {
                Ok((receiving, change)) => {
                    receiving_descriptors.extend(receiving);
                    change_descriptors.extend(change);
                }
                Err(e) => {
                    debug!("Failed to parse {i:?} as a simple multisig descriptor: {e:?}");
                    match try_parse_input_as_coldcard_json(i) {
                        Ok((receiving, change)) => {
                            receiving_descriptors.extend(receiving);
                            change_descriptors.extend(change);
                        }
                        Err(e) => {
                            debug!("Failed to parse {i:?} as a coldcard json export: {e:?}");
                            let e = EncryptedWalletDescription::from_path(i)?;
                            let v = loop {
                                match ask_try_decrypt(i, &e, theme, term, secp) {
                                    Ok(r) => break r,
                                    Err(e) => {
                                        info!("{e:?}");
                                        if !ask_try_open_again_multisig_parse_multisig_input(
                                            theme, term,
                                        )? {
                                            anyhow::bail!(
                                                "Aborting because we couldn't open all desired signers"
                                            )
                                        }
                                    }
                                }
                            };
                            receiving_descriptors.insert(v.receiving_multisig_public_descriptor());
                            change_descriptors.insert(v.change_multisig_public_descriptor());
                            signers.push(v);
                        }
                    }
                }
            }
        }
    };
    Ok(MultisigInputs {
        receiving_descriptors,
        change_descriptors,
        signers,
    })
}

fn try_parse_input_as_simple_descriptor(
    input: &Path,
) -> anyhow::Result<(HashSet<DescriptorPublicKey>, HashSet<DescriptorPublicKey>)> {
    let mut input = buf_open_file(input)?;
    let mut buffer = [0u8; 256]; // a valid descriptor is certainly less than 200 bytes
    let n = input.read(&mut buffer)?;
    let s = from_utf8(&buffer[0..n])?.trim();
    let receiving = DescriptorPublicKey::from_str(&s.replace("/<0;1>/*", "/0/*"))?;
    let change =
        DescriptorPublicKey::from_str(&s.replace("/<0;1>/*", "/1/*").replace("/0/*", "/1/*"))?;

    Ok((HashSet::from([receiving]), HashSet::from([change])))
}

// Coldcard generic/sparrow json export, only the relevant parts
#[derive(serde::Deserialize)]
struct ColdcardJsonExport {
    xfp: String, // 73C5DA0A
    bip48_2: ColdcardBipDetails,
}

#[derive(serde::Deserialize)]
struct ColdcardBipDetails {
    name: String,  // p2wsh
    deriv: String, // m/48'/1'/0'/2'
    xpub: String, // tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ
}

fn try_parse_input_as_coldcard_json(
    input: &Path,
) -> anyhow::Result<(HashSet<DescriptorPublicKey>, HashSet<DescriptorPublicKey>)> {
    let json = serde_json::from_reader::<_, ColdcardJsonExport>(buf_open_file(input)?)?;

    ensure!(
        json.bip48_2.name == "p2wsh",
        format!(
            "expected bip48_2 to contain a p2wsh, but found: {}",
            json.bip48_2.name
        )
    );
    let derivation_path = json.bip48_2.deriv.replace("m/", &format!("{}/", json.xfp));
    let base_descriptor = format!("[{derivation_path}]{}", json.bip48_2.xpub);
    let receiving = DescriptorPublicKey::from_str(&format!("{base_descriptor}/0/*"))
        .with_context(|| format!("while building receiving from {base_descriptor}"))?;
    let change = DescriptorPublicKey::from_str(&format!("{base_descriptor}/1/*"))
        .with_context(|| format!("while building change from {base_descriptor}"))?;

    Ok((HashSet::from([receiving]), HashSet::from([change])))
}

pub(crate) fn parse_multisig_inputs(
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
    ic: impl InternetChecker,
    inputs: &[String],
) -> anyhow::Result<MultisigInputs> {
    ic.check()?;
    let mut receiving_descriptors = HashSet::new();
    let mut change_descriptors = HashSet::new();
    let mut signers = Vec::new();
    let inputs = inputs
        .iter()
        .map(|i| handle_input_path(i))
        .collect::<anyhow::Result<Vec<_>>>()?;
    for i in inputs {
        let result = parse_multisig_input(theme, term, secp, &i)?;
        receiving_descriptors.extend(result.receiving_descriptors);
        change_descriptors.extend(result.change_descriptors);
        signers.extend(result.signers);
    }
    Ok(MultisigInputs {
        receiving_descriptors,
        change_descriptors,
        signers,
    })
}

fn ui_get_multisig_wallet_description(
    theme: &dyn Theme,
    term: &Term,
    j: &Secret<MultisigJsonWalletDescriptionV0>,
    signers: Option<Vec<SingleSigWalletDescriptionV0>>,
    secp: &Secp256k1<All>,
) -> anyhow::Result<MultiSigWalletDescriptionV0> {
    let receiving = j.expose_secret().receiving_output_descriptor()?;
    let change = j.expose_secret().change_output_descriptor()?;
    let configuration = j.expose_secret().configuration()?;
    let signers = signers
        .map(Result::Ok)
        .unwrap_or_else(|| ask_open_signers(theme, term, &configuration, secp))?;
    let w = MultiSigWalletDescriptionV0::generate(
        signers,
        receiving,
        change,
        configuration,
        j.expose_secret().network()?,
        j.expose_secret().script_type()?,
    )?;
    match MultisigJsonWalletDescriptionV0::validate_same(j, &w, secp)? {
        Ok(()) => Ok(w),
        Err(e) => anyhow::bail!("Validation error: {e:?}"),
    }
}

fn ask_open_signers(
    theme: &dyn Theme,
    term: &Term,
    configuration: &MultisigType,
    secp: &Secp256k1<All>,
) -> anyhow::Result<Vec<SingleSigWalletDescriptionV0>> {
    eprintln!("A signer is a singlesig wallet that can sign a PSBT");
    let n: u32 = dialoguer::Input::with_theme(theme)
        .with_prompt(
            "How many signers would you like to open? (only useful if going to sign a PSBT)",
        )
        .default(0)
        .allow_empty(false)
        .validate_with(|v: &u32| {
            if *v <= configuration.required {
                Ok(())
            } else {
                Err(format!(
                    "This wallet requires only {} keys, you can't load more than that",
                    configuration.required
                ))
            }
        })
        .interact_on(term)?;
    let mut signers = Vec::with_capacity(n.try_into()?);
    for _ in 0..n {
        let (wallet, non_duress_password) = loop {
            let (_, encrypted_wallet) = ask_wallet_input_file(theme, term)?;
            let keyfiles = ask_for_keyfiles_open(theme, term)?;
            let difficulty = get_ask_difficulty(theme, term, None)?;
            match singlesig_core_open(
                theme,
                term,
                secp,
                None::<InternetCheckerImpl>,
                &encrypted_wallet,
                &keyfiles,
                &difficulty,
                ask_to_open_duress(theme, term)?,
                None,
            ) {
                Ok(r) => break r,
                Err(e) => {
                    eprintln!("{e:?}");
                    if !ask_try_open_again_multisig_parse_multisig_input(theme, term)? {
                        anyhow::bail!("Aborting because we couldn't open all desired signers")
                    }
                }
            }
        };
        let wallet = wallet.change_seed_password(&non_duress_password, secp)?;
        signers.push(wallet);
    }
    Ok(signers)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use frozenkrill_core::{
        anyhow, get_secp, miniscript::DescriptorPublicKey, rand, utils::create_file,
    };

    use crate::get_term_theme;

    use super::*;

    #[test]
    fn test_parse_multisig_inputs() -> anyhow::Result<()> {
        use pretty_assertions::assert_eq;
        let tempdir = tempdir::TempDir::new("test-parse-multisig-inputs")?;
        let mut rng = rand::thread_rng();
        let mut secp = get_secp(&mut rng);
        let (term, theme) = get_term_theme(true);

        // simple descriptor using /<0;1>/ syntax
        let input_file = create_file(
            r#" [7f4d5c70/48'/1'/0'/2']tpubDFHGoJYXaCkKaEDP9Tt5mQA9uCuXdLeXqbJGagwKsffJJbfMGoBfzgrJtAu4oWLsxJFSytQhzpBE74jQ77eJZPwtags3yEqZ7DEp7VGfSvz/<0;1>/* "#.as_bytes(),
            &tempdir.path().join("descriptor1.txt"),
        )?.to_path_buf();
        let input = parse_multisig_input(theme.as_ref(), &term, &mut secp, &input_file)?;
        assert_eq!(
            input.receiving_descriptors,
            HashSet::from([DescriptorPublicKey::from_str(
                r#"[7f4d5c70/48'/1'/0'/2']tpubDFHGoJYXaCkKaEDP9Tt5mQA9uCuXdLeXqbJGagwKsffJJbfMGoBfzgrJtAu4oWLsxJFSytQhzpBE74jQ77eJZPwtags3yEqZ7DEp7VGfSvz/0/*"#
            )?])
        );
        assert_eq!(
            input.change_descriptors,
            HashSet::from([DescriptorPublicKey::from_str(
                r#"[7f4d5c70/48'/1'/0'/2']tpubDFHGoJYXaCkKaEDP9Tt5mQA9uCuXdLeXqbJGagwKsffJJbfMGoBfzgrJtAu4oWLsxJFSytQhzpBE74jQ77eJZPwtags3yEqZ7DEp7VGfSvz/1/*"#
            )?])
        );
        assert!(input.signers.is_empty());

        // simple descriptor only referring to /0/ path (but we'll generate a change descriptor anyway)
        let input_file = create_file(
            r#" [7f4d5c70/48'/1'/0'/2']tpubDFHGoJYXaCkKaEDP9Tt5mQA9uCuXdLeXqbJGagwKsffJJbfMGoBfzgrJtAu4oWLsxJFSytQhzpBE74jQ77eJZPwtags3yEqZ7DEp7VGfSvz/0/* "#.as_bytes(),
            &tempdir.path().join("descriptor2.txt"),
        )?.to_path_buf();
        let input = parse_multisig_input(theme.as_ref(), &term, &mut secp, &input_file)?;
        assert_eq!(
            input.receiving_descriptors,
            HashSet::from([DescriptorPublicKey::from_str(
                r#"[7f4d5c70/48'/1'/0'/2']tpubDFHGoJYXaCkKaEDP9Tt5mQA9uCuXdLeXqbJGagwKsffJJbfMGoBfzgrJtAu4oWLsxJFSytQhzpBE74jQ77eJZPwtags3yEqZ7DEp7VGfSvz/0/*"#
            )?])
        );
        assert_eq!(
            input.change_descriptors,
            HashSet::from([DescriptorPublicKey::from_str(
                r#"[7f4d5c70/48'/1'/0'/2']tpubDFHGoJYXaCkKaEDP9Tt5mQA9uCuXdLeXqbJGagwKsffJJbfMGoBfzgrJtAu4oWLsxJFSytQhzpBE74jQ77eJZPwtags3yEqZ7DEp7VGfSvz/1/*"#
            )?])
        );
        assert!(input.signers.is_empty());

        // This is coldcard/sparrow json export
        let input_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources/tests/73C5DA0A_coldcard-generic-export.json");
        let input = parse_multisig_input(theme.as_ref(), &term, &mut secp, &input_file)?;
        assert_eq!(
            input.receiving_descriptors,
            HashSet::from([DescriptorPublicKey::from_str(
                r#"[73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/0/*"#
            )?])
        );
        assert_eq!(
            input.change_descriptors,
            HashSet::from([DescriptorPublicKey::from_str(
                r#"[73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/1/*"#
            )?])
        );
        assert!(input.signers.is_empty());
        Ok(())
    }
}
