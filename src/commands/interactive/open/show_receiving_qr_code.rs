use std::{fmt::Display, str::FromStr, sync::Arc};

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow,
    bitcoin::{
        Amount,
        secp256k1::{All, Secp256k1},
    },
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
    let amount_receive = ask_amount_receive(theme, term)?;
    let address_index = ask_address_index_receive(theme, term)?;
    crate::commands::show_receiving_qr_code::singlesig_show_receiving_qr_code(
        theme,
        term,
        secp,
        wallet,
        amount_receive,
        address_index,
        non_duress_password,
    )
}

pub(super) fn multisig_show(
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
    wallet: &MultiSigWalletDescriptionV0,
) -> anyhow::Result<()> {
    let amount_receive = ask_amount_receive(theme, term)?;
    let address_index = ask_address_index_receive(theme, term)?;
    crate::commands::show_receiving_qr_code::multisig_show_receiving_qr_code(
        secp,
        wallet,
        amount_receive,
        address_index,
    )
}

#[derive(Clone)]
struct ReceiveAmountInput(Option<Amount>);

impl Display for ReceiveAmountInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(a) = &self.0 {
            f.write_str(&a.to_string())
        } else {
            f.write_str("")
        }
    }
}

impl FromStr for ReceiveAmountInput {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.trim().is_empty() {
            Ok(Self(None))
        } else {
            Ok(Self(Some(
                crate::commands::show_receiving_qr_code::parse_amount(s)?,
            )))
        }
    }
}

fn ask_amount_receive(theme: &dyn Theme, term: &Term) -> anyhow::Result<Option<Amount>> {
    eprintln!("Amount can be like 2.3 btc or 1500 sats");
    let amount: ReceiveAmountInput = dialoguer::Input::with_theme(theme)
        .with_prompt("How much to receive? (empty to leave unspecified)")
        .allow_empty(true)
        .interact_text_on(term)?;
    Ok(amount.0)
}

fn ask_address_index_receive(theme: &dyn Theme, term: &Term) -> anyhow::Result<u32> {
    let n = dialoguer::Input::with_theme(theme)
        .allow_empty(false)
        .with_initial_text("0")
        .with_prompt("Which address index to receive on (first is zero)")
        .interact_text_on(term)?;
    Ok(n)
}
