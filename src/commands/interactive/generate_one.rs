use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow::{self},
    bitcoin::secp256k1::{All, Secp256k1},
    key_derivation::KeyDerivationDifficulty,
    rand_core::CryptoRngCore,
    secrecy::SecretString,
    wallet_description::{MultisigType, ScriptType, MAX_TOTAL_SIGS_MULTISIG},
    MultisigInputs, PaddingParams,
};
use path_absolutize::Absolutize;

use crate::commands::common::{generate_random_name, multisig::parse_multisig_input};

use crate::{
    commands::{
        common::ask_try_open_again_multisig_parse_multisig_input,
        generate::core::{DuressInputArgs, MultisigCoreGenerateArgs, SinglesigCoreGenerateArgs},
    },
    handle_input_path, handle_output_path, ui_ask_manually_seed_input, InternetChecker,
};

use super::{
    ask_addresses_quantity, ask_for_keyfiles_generate, ask_network, ask_non_duress_wallet_generate,
    ask_public_info_json_output, ask_user_generated_seed, ask_wallet_file_type, ask_word_count,
    get_ask_difficulty, ValidateOutputFile,
};

#[allow(clippy::too_many_arguments)]
pub(super) fn singlesig_interactive_generate_one(
    theme: &dyn Theme,
    term: &Term,
    secp: &mut Secp256k1<All>,
    mut rng: &mut impl CryptoRngCore,
    ic: impl InternetChecker,
    keyfiles: Vec<PathBuf>,
    difficulty: Option<KeyDerivationDifficulty>,
    enable_duress_wallet: bool,
    password: Option<Arc<SecretString>>,
) -> anyhow::Result<()> {
    let output_file_path = ask_generate_wallet_output_file(theme, term, rng)?;
    let keyfiles = if keyfiles.is_empty() {
        ask_for_keyfiles_generate(theme, term)?
    } else {
        keyfiles
    };
    let public_info_json_output = ask_public_info_json_output(theme, term, &output_file_path)?;
    let addresses_quantity = match public_info_json_output {
        Some(_) => ask_addresses_quantity(theme, term)?,
        None => 0,
    };
    let word_count = ask_word_count(theme, term)?;
    let wallet_file_type = ask_wallet_file_type(theme, term)?;
    let user_mnemonic = if ask_user_generated_seed(theme, term)? {
        Some(Arc::new(ui_ask_manually_seed_input(
            &mut rng,
            theme,
            term,
            &word_count,
            false,
        )?))
    } else {
        None
    };
    let difficulty = get_ask_difficulty(theme, term, difficulty)?;
    let network = ask_network(theme, term)?;
    let duress_input_args = DuressInputArgs {
        enable_duress_wallet: enable_duress_wallet || ask_non_duress_wallet_generate(theme, term)?,
        non_duress_output_file_json: None,
        public_json_file_path: public_info_json_output.clone(),
    };
    let script_type = ScriptType::SegwitNative;
    let args = SinglesigCoreGenerateArgs {
        password,
        output_file_path,
        public_info_json_output,
        keyfiles: &keyfiles,
        user_mnemonic,
        duress_input_args,
        word_count,
        script_type,
        network,
        difficulty: &difficulty,
        addresses_quantity,
        padding_params: PaddingParams::default(),
        encrypted_wallet_version: wallet_file_type
            .to_encrypted_wallet_version(network, script_type)?,
    };
    crate::commands::generate::core::singlesig_core_generate(theme, term, secp, rng, ic, args)?;
    Ok(())
}

enum MultisigConfigurationOptions {
    Some(MultisigType),
    Other,
}

impl FromStr for MultisigConfigurationOptions {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "other" => Ok(Self::Other),
            other => MultisigType::from_str(other).map(Self::Some),
        }
    }
}

impl ToString for MultisigConfigurationOptions {
    fn to_string(&self) -> String {
        match self {
            MultisigConfigurationOptions::Some(o) => o.to_string(),
            MultisigConfigurationOptions::Other => "Other".into(),
        }
    }
}

fn ask_multisig_configuration(theme: &dyn Theme, term: &Term) -> anyhow::Result<MultisigType> {
    let options = [
        MultisigConfigurationOptions::Some(MultisigType::new(2, 3)?),
        MultisigConfigurationOptions::Some(MultisigType::new(3, 5)?),
        MultisigConfigurationOptions::Other,
    ];
    let option = dialoguer::Select::with_theme(theme)
        .items(&options)
        .default(0)
        .interact_on(term)?;
    match options[option] {
        MultisigConfigurationOptions::Some(conf) => Ok(conf),
        MultisigConfigurationOptions::Other => {
            let total: u32 = dialoguer::Input::with_theme(theme).with_prompt(format!("How many total signatures in the multisig? (max {MAX_TOTAL_SIGS_MULTISIG})")).default(3).validate_with(|n: &u32| {
                    if *n > 0 && *n <= MAX_TOTAL_SIGS_MULTISIG {
                        Ok(())
                    } else {
                        Err(format!("At least one signature is required and a maximum of {MAX_TOTAL_SIGS_MULTISIG} is allowed"))
                    }
                }
            ).interact_on(term)?;
            let required: u32 = dialoguer::Input::with_theme(theme).with_prompt(format!("How many required signatures in the multisig? (max {total})")).default(total).validate_with(|n: &u32| {
                if *n > 0 && *n <= total {
                    Ok(())
                } else {
                    Err(format!("At least one signature is required and a maximum of total = {total} is allowed"))
                }
            }
        ).interact_on(term)?;
            MultisigType::new(required, total)
        }
    }
}

pub(crate) fn ask_create_multisig_inputs(
    theme: &dyn Theme,
    term: &Term,
    secp: &mut Secp256k1<All>,
    configuration: &MultisigType,
) -> anyhow::Result<MultisigInputs> {
    let mut files = fs::read_dir(".")?
        .map(|i| i.map(|i| i.path().display().to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    files.sort();
    anyhow::ensure!(!files.is_empty(),
        "You can't pick a wallet or pub key from a json file because there are no files in current directory. Copy some files or change the current directory and try again"
    );
    let total = configuration.total;
    eprintln!("We are going to open {total} files to get the public keys for the {configuration} multisig");
    let mut result = MultisigInputs::default();
    for i in 1..=total {
        loop {
            let file_index = dialoguer::Select::with_theme(theme)
                .with_prompt(format!(
                    "Select a encrypted singlesig wallet or a json with the public keys ({i}/{total})"
                ))
                .items(&files)
                .interact_on(term)?;
            let parsed =
                parse_multisig_input(theme, term, secp, &handle_input_path(&files[file_index])?);
            let parsed = parsed.and_then(|input| {
                    let descriptors_added = result.merge(input)?;
                    if descriptors_added != 1 {
                        anyhow::bail!("Expected to read one new descriptor but got {descriptors_added} new descriptors, perhaps a duplicated file was selected?")
                    }
                    Ok(())
                });
            match parsed {
                Ok(()) => break,
                Err(e) => {
                    eprintln!("{e:?}");
                    if !ask_try_open_again_multisig_parse_multisig_input(theme, term)? {
                        anyhow::bail!("You need valid encrypted singlesig wallets or a json with the public keys to create a multisig")
                    }
                }
            }
        }
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn multisig_interactive_generate_single(
    theme: &dyn Theme,
    term: &Term,
    secp: &mut Secp256k1<All>,
    rng: &mut impl CryptoRngCore,
    mut ic: impl InternetChecker,
    keyfiles: Vec<PathBuf>,
    difficulty: Option<KeyDerivationDifficulty>,
    password: Option<Arc<SecretString>>,
) -> anyhow::Result<()> {
    let configuration = ask_multisig_configuration(theme, term)?;
    ic.check()?;
    let inputs = ask_create_multisig_inputs(theme, term, secp, &configuration)?;
    let output_file_path_encrypted = ask_generate_wallet_output_file(theme, term, rng)?;
    let keyfiles = if keyfiles.is_empty() {
        ask_for_keyfiles_generate(theme, term)?
    } else {
        keyfiles
    };
    let output_file_path_json =
        ask_public_info_json_output(theme, term, &output_file_path_encrypted)?;
    let addresses_quantity = match output_file_path_json {
        Some(_) => ask_addresses_quantity(theme, term)?,
        None => 0,
    };
    let difficulty = get_ask_difficulty(theme, term, difficulty)?;
    let network = ask_network(theme, term)?;
    let wallet_file_type = ask_wallet_file_type(theme, term)?;
    let script_type = ScriptType::SegwitNative;
    let args = MultisigCoreGenerateArgs {
        password,
        keyfiles: &keyfiles,
        network,
        script_type,
        difficulty: &difficulty,
        addresses_quantity,
        padding_params: PaddingParams::default(),
        configuration,
        inputs,
        output_file_path_encrypted,
        output_file_path_json,
        encrypted_wallet_version: wallet_file_type
            .to_encrypted_wallet_version(network, script_type)?,
    };
    crate::commands::generate::core::multisig_core_generate(theme, term, secp, rng, args)?;
    Ok(())
}

fn ask_generate_wallet_output_file(
    theme: &dyn Theme,
    term: &Term,
    rng: &mut impl CryptoRngCore,
) -> anyhow::Result<PathBuf> {
    let suggested = Path::new(&generate_random_name("wallet_", "", rng)?)
        .absolutize()?
        .display()
        .to_string();
    let name = dialoguer::Input::with_theme(theme)
        .with_prompt("Where to save the encrypted output file?")
        .with_initial_text(suggested)
        .validate_with(ValidateOutputFile)
        .interact_text_on(term)?;
    Ok(handle_output_path(&name)?.into_owned())
}
