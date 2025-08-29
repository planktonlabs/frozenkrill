use std::{str::FromStr, sync::Arc};

use dialoguer::{console::Term, theme::Theme};
use frozenkrill_core::{
    anyhow::{self, Context},
    bitcoin::{
        Amount,
        secp256k1::{All, Secp256k1},
    },
    secrecy::SecretString,
    wallet_description::MultiSigWalletDescriptionV0,
};

use frozenkrill_core::wallet_description::SingleSigWalletDescriptionV0;

use crate::ShowReceivingQrCodeArgs;

use super::common::double_check_non_duress_password;

pub(super) fn parse_amount(s: &str) -> anyhow::Result<Amount> {
    let s = s.trim();
    match s.parse::<f64>() {
        Ok(v) => Ok(Amount::from_btc(v)?),
        Err(_) => Ok(Amount::from_str(s)?),
    }
}

pub(crate) fn show_receiving_qr_code_parse_args(
    args: &ShowReceivingQrCodeArgs,
) -> anyhow::Result<(Option<Amount>, u32)> {
    let amount = args
        .amount
        .as_ref()
        .map(|s| parse_amount(s))
        .transpose()
        .context("failure parsing amount")?;
    Ok((amount, args.address_index))
}

fn ask_received_qr_code_non_duress(theme: &dyn Theme, term: &Term) -> anyhow::Result<bool> {
    let items = [
        "Fake receiving addresses for default duress wallet",
        "Real receiving addresses for non duress wallet",
    ];
    let item = dialoguer::Select::with_theme(theme)
        .items(items)
        .default(1)
        .with_prompt("Pick an option")
        .interact_on(term)?;
    Ok(item == 1)
}

pub(crate) fn singlesig_show_receiving_qr_code(
    theme: &dyn Theme,
    term: &Term,
    secp: &Secp256k1<All>,
    wallet: &SingleSigWalletDescriptionV0,
    amount: Option<Amount>,
    address_index: u32,
    non_duress_password: &Option<Arc<SecretString>>,
) -> anyhow::Result<()> {
    let non_duress_wallet = match non_duress_password {
        Some(non_duress_password) => {
            if ask_received_qr_code_non_duress(theme, term)? {
                double_check_non_duress_password(theme, term, non_duress_password)?;
                Some(wallet.change_seed_password(&Some(Arc::clone(non_duress_password)), secp)?)
            } else {
                None
            }
        }
        None => None,
    };
    let wallet = non_duress_wallet.as_ref().unwrap_or(wallet);
    let address = wallet.derive_receiving_address(address_index, secp)?;
    print_qr_info(amount, address)?;
    Ok(())
}

pub(crate) fn multisig_show_receiving_qr_code(
    secp: &Secp256k1<All>,
    wallet: &MultiSigWalletDescriptionV0,
    amount: Option<Amount>,
    address_index: u32,
) -> anyhow::Result<()> {
    let address = wallet.derive_receiving_address(address_index, secp)?;
    print_qr_info(amount, address)?;
    Ok(())
}

fn print_qr_info(
    amount: Option<Amount>,
    address: frozenkrill_core::bitcoin::Address,
) -> Result<(), anyhow::Error> {
    let suffix = amount
        .map(|a| format!("?amount={}", a.to_btc()))
        .unwrap_or_default();
    let qrcode = format!("{}{suffix}", address.to_qr_uri());
    qr2term::print_qr(&qrcode)?;
    println!("{qrcode}");
    println!("Address: {address}");
    if let Some(amount) = amount {
        println!("Amount: {amount}")
    };
    Ok(())
}
