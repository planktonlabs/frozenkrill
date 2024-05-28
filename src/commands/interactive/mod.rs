use std::{
    fs,
    path::{Path, PathBuf},
};

use dialoguer::{console::Term, theme::Theme, Validator};
use frozenkrill_core::{
    anyhow,
    bitcoin::{
        secp256k1::{All, Secp256k1},
        Network,
    },
    key_derivation::{self, KeyDerivationDifficulty},
    parse_keyfiles_paths,
    rand_core::CryptoRngCore,
    wallet_description::WordCount,
};

use crate::{handle_output_path, InteractiveArgs, InternetChecker, WalletFileType};

use self::{
    generate_batch::interactive_generate_batch,
    generate_one::{multisig_interactive_generate_single, singlesig_interactive_generate_one},
    open::{multisig_interactive_open, singlesig_interactive_open},
};

use super::common::{
    from_public_info_json_path_to_non_duress, from_wallet_to_public_info_json_path,
    keyfiles_elevator_pitch,
};

mod generate_batch;
mod generate_one;
pub(crate) mod open;

enum MainActions {
    SinglesigCreateNewSingle,
    MultisigCreateNewSingle,
    CreateNewBatch,
    OpenSinglesig,
    OpenMultisig,
}

impl ToString for MainActions {
    fn to_string(&self) -> String {
        match self {
            MainActions::SinglesigCreateNewSingle => "singlesig: create wallet",
            MainActions::MultisigCreateNewSingle => " multisig: create wallet",
            MainActions::OpenSinglesig => "singlesig: open wallet",
            MainActions::OpenMultisig => " multisig: open wallet",
            MainActions::CreateNewBatch => "singlesig: create multiple wallets (batch mode)",
        }
        .into()
    }
}

pub(crate) fn interactive(
    theme: &dyn Theme,
    term: &Term,
    secp: &mut Secp256k1<All>,
    rng: &mut impl CryptoRngCore,
    ic: impl InternetChecker,
    args: &InteractiveArgs,
) -> anyhow::Result<()> {
    let keyfiles = parse_keyfiles_paths(&args.keyfile)?;
    let actions = [
        MainActions::SinglesigCreateNewSingle,
        MainActions::MultisigCreateNewSingle,
        MainActions::OpenSinglesig,
        MainActions::OpenMultisig,
        MainActions::CreateNewBatch,
    ];
    let action = dialoguer::Select::with_theme(theme)
        .with_prompt("Pick an option")
        .items(&actions)
        .default(0)
        .interact_on_opt(term)?;
    let action = match action {
        Some(v) => v,
        None => {
            return Ok(());
        }
    };
    match &actions[action] {
        MainActions::SinglesigCreateNewSingle => singlesig_interactive_generate_one(
            theme,
            term,
            secp,
            rng,
            ic,
            keyfiles,
            args.difficulty.to_owned(),
            args.enable_duress_wallet,
        )?,
        MainActions::MultisigCreateNewSingle => multisig_interactive_generate_single(
            theme,
            term,
            secp,
            rng,
            ic,
            keyfiles,
            args.difficulty.to_owned(),
        )?,
        MainActions::CreateNewBatch => {
            interactive_generate_batch(
                theme,
                term,
                secp,
                rng,
                ic,
                keyfiles,
                args.difficulty.to_owned(),
                args.enable_duress_wallet,
            )?;
        }
        MainActions::OpenSinglesig => singlesig_interactive_open(
            theme,
            term,
            secp,
            ic,
            keyfiles,
            args.difficulty.to_owned(),
            args.enable_duress_wallet,
        )?,
        MainActions::OpenMultisig => {
            multisig_interactive_open(theme, term, secp, ic, keyfiles, args.difficulty.to_owned())?
        }
    };
    Ok(())
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct KeyDerivationDifficultyDisplay(KeyDerivationDifficulty);

impl ToString for KeyDerivationDifficultyDisplay {
    fn to_string(&self) -> String {
        format!(
            "{} ({}, {})",
            self.0,
            self.0.estimate_time(),
            self.0.estimate_memory()
        )
    }
}

pub(crate) fn get_ask_difficulty(
    theme: &dyn Theme,
    term: &Term,
    v: Option<KeyDerivationDifficulty>,
) -> anyhow::Result<KeyDerivationDifficulty> {
    if let Some(v) = v {
        Ok(v)
    } else {
        let levels: Vec<_> = key_derivation::DIFFICULTY_LEVELS
            .into_iter()
            .map(KeyDerivationDifficultyDisplay)
            .collect();
        let default_level = levels
            .iter()
            .position(|l| l.0 == key_derivation::DEFAULT_DIFFICULTY_LEVEL)
            .expect("code to be correct");
        eprintln!("The difficulty level controls how hard will be to break the derived key");
        eprintln!("It should be the same when generating and when opening the wallet");
        let level = dialoguer::Select::with_theme(theme)
            .with_prompt("Select one (leave the default if unsure)")
            .items(&levels)
            .default(default_level)
            .interact_on(term)?;
        Ok(levels[level].0.to_owned())
    }
}

fn ask_continue_without_a_keyfile(theme: &dyn Theme, term: &Term) -> anyhow::Result<bool> {
    keyfiles_elevator_pitch();
    Ok(dialoguer::Confirm::with_theme(theme)
        .with_prompt("Continue without a keyfile? (strongly discouraged)")
        .interact_on(term)?)
}

pub(crate) fn ask_for_keyfiles_generate(
    theme: &dyn Theme,
    term: &Term,
) -> anyhow::Result<Vec<PathBuf>> {
    let mut files = fs::read_dir(".")?
        .map(|i| i.map(|i| i.path().display().to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    files.sort();
    if files.is_empty() {
        keyfiles_elevator_pitch();
        if dialoguer::Confirm::with_theme(theme)
            .with_prompt("You can't pick a keyfile because there are no files in current directory, continue without keyfiles?").interact_on(term)? {
                return Ok(Vec::new())
            } else {
                anyhow::bail!("Copy some files or directories to current directory or change the current directory so you can load a keyfile or give a --keyfile as argument on the command line");
            }
    }
    if !dialoguer::Confirm::with_theme(theme)
        .with_prompt("Do you want to pick one or more keyfiles?")
        .interact_on(term)?
        && ask_continue_without_a_keyfile(theme, term)?
    {
        Ok(Vec::new())
    } else {
        loop {
            let chosen_files = choose_keyfiles(theme, term, &files)?;
            let chosen_files: Vec<_> = chosen_files
                .into_iter()
                .map(|i| files[i].to_owned())
                .collect();
            if chosen_files.is_empty() {
                if ask_continue_without_a_keyfile(theme, term)? {
                    return Ok(Vec::new());
                }
            } else {
                let keyfiles = parse_keyfiles_paths(&chosen_files)?;
                return Ok(keyfiles);
            }
        }
    }
}

fn choose_keyfiles(theme: &dyn Theme, term: &Term, files: &[String]) -> anyhow::Result<Vec<usize>> {
    let chosen_files = dialoguer::MultiSelect::with_theme(theme)
        .with_prompt(
            "Select the keyfiles by pressing \"space\" on each item, press \"enter\" to finish",
        )
        .items(files)
        .interact_on(term)?;
    Ok(chosen_files)
}

struct ValidateOutputFile;

impl Validator<String> for ValidateOutputFile {
    type Err = anyhow::Error;
    fn validate(&mut self, input: &String) -> Result<(), Self::Err> {
        if !input.is_empty() {
            handle_output_path(input)?;
        }
        Ok(())
    }
}

fn ask_public_info_json_output(
    theme: &dyn Theme,
    term: &Term,
    wallet_output_file: &Path,
) -> anyhow::Result<Option<PathBuf>> {
    let suggested_path = from_wallet_to_public_info_json_path(wallet_output_file)?;
    let name = dialoguer::Input::with_theme(theme)
        .with_prompt("Where to save the public info json?")
        .with_initial_text(suggested_path.display().to_string())
        .validate_with(ValidateOutputFile)
        .allow_empty(true)
        .interact_text_on(term)?;
    if name.is_empty() {
        Ok(None)
    } else {
        Ok(Some(handle_output_path(&name)?.into_owned()))
    }
}

fn duress_wallet_explanation() {
    eprintln!("A duress wallet makes plausible deniability possible under coercion (duress)");
    eprintln!("It works as follows:");
    eprintln!(
        "- The main wallet will become a duress (decoy/fake) one\n\t-> so it should receive small bitcoin amounts"
    );
    eprintln!(
        "- A custom seed password will be asked to create the non duress (real)\n\t-> this wallet will receive most of the funds"
    );
    eprintln!(
        "- So two public infos will be available:\n\t1) the default duress with fake receiving addresses"
    );
    eprintln!(
        "\t2) the non default (using the non duress password)\n\twith real receiving addresses"
    );
    eprintln!("- This is an advanced feature, enable only if know what you're doing");
    eprintln!("- The risk of losing funds is very high, only use it after careful testing");
}

fn ask_non_duress_wallet_generate(theme: &dyn Theme, term: &Term) -> anyhow::Result<bool> {
    duress_wallet_explanation();
    let items = [
        "Standard Wallet (recommended)",
        "Duress Wallet (standard duress + non duress public info)",
    ];
    let item = dialoguer::Select::with_theme(theme)
        .items(&items)
        .default(0)
        .with_prompt("Pick an option")
        .interact_on(term)?;
    Ok(item == 1)
}

fn ask_non_duress_public_info_json_output(
    theme: &dyn Theme,
    term: &Term,
    wallet_output_file: &Path,
) -> anyhow::Result<PathBuf> {
    let suggested_path = from_public_info_json_path_to_non_duress(wallet_output_file)?;
    let name = dialoguer::Input::with_theme(theme)
        .with_prompt("Where to save the non duress (i.e real) public info json?")
        .with_initial_text(suggested_path.display().to_string())
        .validate_with(ValidateOutputFile)
        .interact_text_on(term)?;
    Ok(handle_output_path(&name)?.into_owned())
}

fn ask_public_info_json_output_required(
    theme: &dyn Theme,
    term: &Term,
    wallet_output_file: &Path,
) -> anyhow::Result<PathBuf> {
    let suggested_path = from_wallet_to_public_info_json_path(wallet_output_file)?;
    let name = dialoguer::Input::with_theme(theme)
        .with_prompt("Where to save the public info json?")
        .with_initial_text(suggested_path.display().to_string())
        .validate_with(ValidateOutputFile)
        .interact_text_on(term)?;
    Ok(handle_output_path(&name)?.into_owned())
}

fn ask_word_count(theme: &dyn Theme, term: &Term) -> anyhow::Result<WordCount> {
    let items = ["12 words", "24 words (recommended)"];
    let item = dialoguer::Select::with_theme(theme)
        .items(&items)
        .default(1)
        .with_prompt("How many words for the seed?")
        .interact_on(term)?;
    if item == 0 {
        Ok(WordCount::W12)
    } else {
        Ok(WordCount::W24)
    }
}

fn ask_wallet_file_type(theme: &dyn Theme, term: &Term) -> anyhow::Result<WalletFileType> {
    let items = ["Standard (recommended)", "Compact"];
    let item = dialoguer::Select::with_theme(theme)
        .items(&items)
        .default(0)
        .with_prompt(
            r#"What's the type of the encrypted file?
Only pick compact if you really need it (e.g if you want to store it on a QR code)"#,
        )
        .interact_on(term)?;
    if item == 0 {
        Ok(WalletFileType::Standard)
    } else {
        Ok(WalletFileType::Compact)
    }
}

fn ask_user_generated_seed(theme: &dyn Theme, term: &Term) -> anyhow::Result<bool> {
    let items = [
        "Randomly generate the seed phrase (recommended)",
        "Manually input the seed phrase",
    ];
    Ok(dialoguer::Select::with_theme(theme)
        .with_prompt("Pick an option")
        .items(&items)
        .default(0)
        .interact_on(term)?
        == 1)
}

fn ask_network(theme: &dyn Theme, term: &Term) -> anyhow::Result<Network> {
    let items = ["Bitcoin mainnet (recommended)", "Bitcoin testnet"];
    if dialoguer::Select::with_theme(theme)
        .with_prompt("Pick a network")
        .items(&items)
        .default(0)
        .interact_on(term)?
        == 0
    {
        Ok(Network::Bitcoin)
    } else {
        Ok(Network::Testnet)
    }
}

fn ask_addresses_quantity(theme: &dyn Theme, term: &Term) -> anyhow::Result<u32> {
    let n = dialoguer::Input::<u32>::with_theme(theme)
        .allow_empty(false)
        .with_initial_text("100")
        .with_prompt("How many receiving addresses to include in the public info json?")
        .interact_text_on(term)?;
    Ok(n)
}
