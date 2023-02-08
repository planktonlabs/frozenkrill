use std::path::{Path, PathBuf};

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow,
    bitcoin::secp256k1::{All, Secp256k1},
    key_derivation::KeyDerivationDifficulty,
    rand_core::CryptoRngCore,
    PaddingParams,
};
use path_absolutize::Absolutize;

use crate::{commands::batch_generate_export::CoreBatchGenerateExportArgs, InternetChecker};

use super::{
    ask_addresses_quantity, ask_for_keyfiles_generate, ask_network, ask_non_duress_wallet_generate,
    ask_word_count, get_ask_difficulty,
};

#[allow(clippy::too_many_arguments)]
pub(super) fn interactive_generate_batch(
    theme: &dyn Theme,
    term: &Term,
    secp: &mut Secp256k1<All>,
    rng: &mut impl CryptoRngCore,
    ic: impl InternetChecker,
    keyfiles: Vec<PathBuf>,
    difficulty: Option<KeyDerivationDifficulty>,
    enable_duress_wallet: bool,
) -> anyhow::Result<()> {
    let wallets_quantity = ask_batch_wallets_quantity(theme, term)?;
    let output_prefix = ask_batch_generate_wallet_prefix(theme, term)?;
    let keyfiles = if keyfiles.is_empty() {
        ask_for_keyfiles_generate(theme, term)?
    } else {
        keyfiles
    };
    let disable_public_info_export = !ask_batch_public_info_export(theme, term)?;
    let addresses_quantity = if disable_public_info_export {
        0
    } else {
        ask_addresses_quantity(theme, term)?
    };
    let word_count = ask_word_count(theme, term)?;
    let difficulty = get_ask_difficulty(theme, term, difficulty)?;
    let network = ask_network(theme, term)?;
    let args = CoreBatchGenerateExportArgs {
        keyfiles: &keyfiles,
        word_count,
        network,
        wallets_quantity,
        output_prefix: &output_prefix,
        enable_duress_wallet: enable_duress_wallet || ask_non_duress_wallet_generate(theme, term)?,
        difficulty: &difficulty,
        disable_public_info_export,
        addresses_quantity,
        padding_params: PaddingParams::default(),
    };
    crate::commands::batch_generate_export::core_batch_generate_export(
        theme, term, secp, rng, ic, args,
    )
}

fn ask_batch_public_info_export(theme: &dyn Theme, term: &Term) -> anyhow::Result<bool> {
    Ok(dialoguer::Confirm::with_theme(theme)
        .with_prompt("Export public info json?")
        .default(true)
        .interact_on(term)?)
}

fn ask_batch_wallets_quantity(theme: &dyn Theme, term: &Term) -> anyhow::Result<usize> {
    let n = dialoguer::Input::with_theme(theme)
        .allow_empty(false)
        .with_prompt("How many wallets to create?")
        .with_initial_text("10")
        .interact_text_on(term)?;
    Ok(n)
}

fn ask_batch_generate_wallet_prefix(theme: &dyn Theme, term: &Term) -> anyhow::Result<String> {
    let suggested = Path::new("wallet").absolutize()?.display().to_string();
    let prefix = dialoguer::Input::with_theme(theme)
        .with_prompt("Enter the path prefix for the multiple wallets")
        .with_initial_text(suggested)
        .interact_text_on(term)?;
    Ok(prefix)
}
