use std::path::{Path, PathBuf};

use base32::Alphabet;
use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow::{self, Context},
    bitcoin::secp256k1::{All, Secp256k1},
    blake3,
    log::{self, debug},
    rand_core::CryptoRngCore,
    utils,
    wallet_description::{self, EncryptedWalletDescription, SigType, KEY_SIZE},
    wallet_export::{
        GenericOutputExportJson, MultisigJsonWalletPublicExportV0,
        SinglesigJsonWalletPublicExportV0,
    },
};

use frozenkrill_core::secrecy::{ExposeSecret, SecretString};
use frozenkrill_core::wallet_description::SingleSigWalletDescriptionV0;

use crate::{ask_password, handle_output_path, ui_derive_key};

pub(crate) mod multisig;
pub(crate) mod singlesig;

pub(crate) const CONTEXT_CORRUPTION_WARNING: &str = "failure decrypting wallet, some data has been corrupted on disk or memory, change the destination disk or check the ram memory";

const PUB_FILE_SUFFIX: &str = "_pub.json";
const PUB_NON_DURESS_FILE_SUFFIX: &str = "_non_duress.json";
const SIGNED_PSBT_FILE_SUFFIX: &str = "_signed.psbt";

pub(crate) fn ask_try_open_again_multisig_parse_multisig_input(
    theme: &dyn Theme,
    term: &Term,
) -> anyhow::Result<bool> {
    Ok(dialoguer::Confirm::with_theme(theme)
        .with_prompt("Got an error, try to open another file?")
        .default(true)
        .interact_on_opt(term)?
        .unwrap_or_default())
}

pub(crate) fn keyfiles_elevator_pitch() {
    eprintln!("It's highly recommended to use at least one keyfile");
    eprintln!("If the password is really strong, it's easy to be forgotten");
    eprintln!("If it's weak, it can be brute forced");
    eprintln!("A keyfile provides a complementary strong password that is easy to remember");
    eprintln!("The keyfile can be any file that you are always able to retrieve on demand");
    eprintln!("For instance, it can be a publicly available picture, song or book. Be creative!");
}

pub(crate) struct AddressGenerationParams {
    pub first_index: u32,
    pub quantity: u32,
}

pub(crate) fn generate_random_name(
    prefix: &str,
    suffix: &str,
    rng: &mut impl CryptoRngCore,
) -> anyhow::Result<String> {
    let mut name_salt = [0u8; KEY_SIZE];
    rng.try_fill_bytes(&mut name_salt)?;
    Ok(generate_name(prefix, &name_salt, 0, suffix))
}

pub(crate) fn generate_name(
    prefix: &str,
    name_salt: &[u8; KEY_SIZE],
    index: usize,
    suffix: &str,
) -> String {
    let mut hasher = blake3::Hasher::new_keyed(name_salt);
    hasher.update(prefix.as_bytes());
    hasher.update(&index.to_ne_bytes());
    let mut output = [0; 10];
    let mut output_reader = hasher.finalize_xof();
    output_reader.fill(&mut output);
    let hash = base32::encode(Alphabet::Crockford, &output).to_lowercase();
    format!("{prefix}{hash}{suffix}")
}

pub(crate) fn from_wallet_to_public_info_json_path(
    wallet_output_path: &Path,
) -> anyhow::Result<PathBuf> {
    extend_base_name_with_suffix(wallet_output_path, PUB_FILE_SUFFIX)
}

pub(crate) fn from_input_to_signed_psbt(file: &Path) -> anyhow::Result<PathBuf> {
    extend_base_name_with_suffix(file, SIGNED_PSBT_FILE_SUFFIX)
}

pub(crate) fn from_public_info_json_path_to_non_duress(file: &Path) -> anyhow::Result<PathBuf> {
    extend_base_name_with_suffix(file, PUB_NON_DURESS_FILE_SUFFIX)
}

pub(crate) fn double_check_non_duress_password(
    theme: &dyn Theme,
    term: &Term,
    non_duress_password: &SecretString,
) -> anyhow::Result<()> {
    eprintln!("We will ask again for the non duress password");
    eprintln!("If you forget or misstype it your funds will be lost");
    eprintln!("So let's double check it");
    loop {
        let again = dialoguer::Password::with_theme(theme)
            .with_prompt("Enter the non duress seed password again")
            .interact_on(term)
            .context("failure reading password")?;
        if non_duress_password.expose_secret() == &again {
            return Ok(());
        } else {
            log::error!("Passwords don't match. Type the same password as used before")
        }
    }
}

fn extend_base_name_with_suffix(base_name: &Path, suffix: &str) -> anyhow::Result<PathBuf> {
    let mut output_name = base_name
        .file_stem()
        .ok_or_else(|| anyhow::anyhow!("Output path {base_name:?} isn't a file"))?
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Output path {base_name:?} has a invalid name"))?
        .to_string();
    output_name.push_str(suffix);
    Ok(base_name.with_file_name(output_name.as_str()))
}

fn ask_try_decrypt(
    path: &Path,
    encrypted_wallet: &EncryptedWalletDescription,
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
) -> anyhow::Result<SingleSigWalletDescriptionV0> {
    eprintln!("Trying to open singlesig wallet {path:?}");
    let keyfiles = crate::commands::interactive::open::ask_for_keyfiles_open(theme, term)?;
    let difficulty = crate::commands::interactive::get_ask_difficulty(theme, term, None)?;
    let password = ask_password(theme, term)?;
    let non_duress_password =
        if crate::commands::interactive::open::ask_to_open_duress(theme, term)? {
            Some(crate::ask_non_duress_password(theme, term)?)
        } else {
            None
        };
    let key = ui_derive_key(&password, &keyfiles, &encrypted_wallet.salt, &difficulty)?;
    let json_wallet = encrypted_wallet.decrypt_singlesig(&key)?;
    let wallet = crate::ui_get_singlesig_wallet_description(&json_wallet, &None, secp)?;
    wallet.change_seed_password(&non_duress_password, secp)
}

pub(crate) fn calculate_non_duress_output(
    enable_duress_wallet: bool,
    non_duress_output_file_json: &Option<PathBuf>,
    public_json_file_path: &Option<PathBuf>,
) -> anyhow::Result<Option<PathBuf>> {
    let non_duress_output_file_json = match (
        enable_duress_wallet,
        non_duress_output_file_json,
        public_json_file_path,
    ) {
        (_, Some(p), _) => Some(handle_output_path(p)?.into_owned()),
        (true, None, Some(public_json_file_path)) => Some(
            handle_output_path(
                from_public_info_json_path_to_non_duress(public_json_file_path)?
                    .display()
                    .to_string()
                    .as_str(),
            )?
            .into_owned(),
        ),
        (true, None, None) => {
            anyhow::bail!("If duress wallet is enabled a public json must be specified")
        }
        (false, None, _) => None,
    };
    Ok(non_duress_output_file_json)
}

#[derive(Debug)]
pub(crate) enum ParsedWalletInputFile {
    Encrypted(EncryptedWalletDescription),
    PublicInfo(PublicInfoInput),
}

#[derive(Debug)]
pub(crate) enum PublicInfoInput {
    // TODO: add single sig pub support
    // TODO: add plain output descriptors (using something like try_parse_input_as_simple_descriptor)
    MultisigJson(MultisigJsonWalletPublicExportV0),
}

pub fn try_open_as_json_input(file: &Path) -> anyhow::Result<PublicInfoInput> {
    match GenericOutputExportJson::deserialize(utils::buf_open_file(file)?) {
        Ok(g) => match g.version_sigtype()? {
            (Some(wallet_description::ZERO_SINGLESIG_WALLET_VERSION), Some(SigType::Singlesig)) => {
                let _v = SinglesigJsonWalletPublicExportV0::from_path(file)?;
                let message = "Using a singlesig json pub export isn't supported right now";
                debug!("{message}");
                anyhow::bail!("{message}")
            }
            (
                Some(wallet_description::ZERO_MULTISIG_WALLET_VERSION),
                Some(SigType::Multisig(_)),
            ) => {
                let v = MultisigJsonWalletPublicExportV0::from_path(file)?;
                debug!("Will open {file:?} as multisig pub json");
                Ok(PublicInfoInput::MultisigJson(v))
            }
            _ => {
                let message = format!("Unrecognized json file {file:?}");
                debug!("{message}");
                anyhow::bail!("{message}")
            }
        },
        Err(e) => Err(e),
    }
}
