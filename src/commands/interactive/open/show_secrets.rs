use std::sync::Arc;

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow,
    bitcoin::secp256k1::{All, Secp256k1},
    log,
    secrecy::SecretString,
    wallet_description::{MultiSigWalletDescriptionV0, SingleSigWalletDescriptionV0},
};

pub(super) fn singlesig_show(
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
    wallet: &SingleSigWalletDescriptionV0,
    non_duress_password: &Option<Arc<SecretString>>,
) -> anyhow::Result<()> {
    if ask_acknowledge_dangerous_show_secrets(theme, term)? {
        crate::commands::show_secrets::singlesig_show_secrets(
            theme,
            term,
            secp,
            wallet,
            non_duress_password,
        )?;
    }
    Ok(())
}

pub(super) fn multisig_show(
    secp: &Secp256k1<All>,
    wallet: &MultiSigWalletDescriptionV0,
) -> anyhow::Result<()> {
    crate::commands::show_secrets::multisig_show_secrets(secp, wallet)
}

fn ask_acknowledge_dangerous_show_secrets(theme: &dyn Theme, term: &Term) -> anyhow::Result<bool> {
    log::warn!(
        "{}",
        termimad::inline("This will expose the secrets in **plaintext**")
    );
    log::warn!(
        "{}",
        termimad::inline("This is a **very dangerous operation**")
    );
    log::warn!(
        "{}",
        termimad::inline("**Funds may be lost** if it leaks to third parties")
    );
    Ok(dialoguer::Confirm::with_theme(theme)
        .with_prompt("Do you really want do this?")
        .interact_on(term)?)
}
