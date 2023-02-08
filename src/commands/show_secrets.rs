use std::sync::Arc;

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow::{self},
    bitcoin::secp256k1::{All, Secp256k1},
    secrecy::SecretString,
    wallet_description::{MultiSigWalletDescriptionV0, MultisigJsonWalletDescriptionV0},
};

use frozenkrill_core::secrecy::ExposeSecret;

use frozenkrill_core::wallet_description::{
    SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
};

use crate::{commands::common::double_check_non_duress_password, SinglesigShowSecretsArgs};

pub(crate) fn singlesig_show_secrets_parse_args(
    args: &SinglesigShowSecretsArgs,
) -> anyhow::Result<()> {
    if !args.acknowledge_dangerous_operation {
        anyhow::bail!("This operation will expose secrets in plaintext, run the command again adding the --acknowledge-dangerous-operation flag if you know what you're doing");
    }
    Ok(())
}

fn ask_show_non_duress(theme: &dyn Theme, term: &Term) -> anyhow::Result<bool> {
    let items = [
        "Show default duress (decoy) wallet",
        "Show non duress (real) wallet",
    ];
    let item = dialoguer::Select::with_theme(theme)
        .items(&items)
        .default(1)
        .with_prompt("Pick an option")
        .interact_on(term)?;
    Ok(item == 1)
}

pub(crate) fn singlesig_show_secrets(
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
    wallet: &SingleSigWalletDescriptionV0,
    non_duress_password: &Option<Arc<SecretString>>,
) -> anyhow::Result<()> {
    let non_duress_wallet = match non_duress_password {
        Some(non_duress_password) => {
            if ask_show_non_duress(theme, term)? {
                double_check_non_duress_password(theme, term, non_duress_password)?;
                Some(wallet.change_seed_password(&Some(Arc::clone(non_duress_password)), secp)?)
            } else {
                None
            }
        }
        None => None,
    };
    let wallet = non_duress_wallet.as_ref().unwrap_or(wallet);
    let json_wallet_description =
        SinglesigJsonWalletDescriptionV0::from_wallet_description(wallet, secp)?;
    println!(
        "{}",
        json_wallet_description
            .expose_secret()
            .to_string_pretty()?
            .expose_secret()
    );
    Ok(())
}

pub(crate) fn multisig_show_secrets(
    secp: &Secp256k1<All>,
    wallet: &MultiSigWalletDescriptionV0,
) -> anyhow::Result<()> {
    let json_wallet_description =
        MultisigJsonWalletDescriptionV0::from_wallet_description(wallet, secp)?;
    println!(
        "{}",
        json_wallet_description
            .expose_secret()
            .to_string_pretty()?
            .expose_secret()
    );
    Ok(())
}
