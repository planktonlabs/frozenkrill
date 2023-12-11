use anyhow::Context;
use bitcoin::{
    psbt::serialize::{Deserialize, Serialize},
    util::bip32::DerivationPath,
    XpubIdentifier,
};
use secp256k1::{All, Secp256k1};
use secrecy::{ExposeSecret, Secret};
use std::{fs::OpenOptions, io::Read, path::Path};
use wallet::psbt::sign::SignAll;

use crate::{utils::create_file, wallet_description::WExtendedPrivKey};

pub fn open_psbt_file(p: &Path) -> anyhow::Result<wallet::psbt::Psbt> {
    let raw = {
        let mut f = OpenOptions::new()
            .read(true)
            .open(p)
            .context("failure opening PSBT file")?;
        let mut buffer = Vec::new();
        f.read_to_end(&mut buffer)
            .context("failure reading PSBT file")?;
        buffer
    };
    let p = wallet::psbt::Psbt::deserialize(&raw).context("failure deserializing PSBT file")?;
    Ok(p)
}

pub fn save_psbt_file<'a>(psbt: &wallet::psbt::Psbt, path: &'a Path) -> anyhow::Result<&'a Path> {
    create_file(&psbt.serialize(), path)
}

pub(super) fn sign_psbt(
    psbt: &mut wallet::psbt::Psbt,
    keys: &[(&Secret<WExtendedPrivKey>, &DerivationPath, XpubIdentifier)],
    secp: &Secp256k1<All>,
) -> anyhow::Result<usize> {
    if keys.is_empty() {
        anyhow::bail!("No keys given for sign psbt")
    }
    let mut provider = wallet::psbt::sign::MemoryKeyProvider::with(secp, false);
    for (k, derivation_path, identifier) in keys {
        let account = wallet::psbt::sign::MemorySigningAccount::with(
            secp,
            *identifier,
            (*derivation_path).to_owned(),
            k.expose_secret().0.to_owned(),
        );
        provider.add_account(account);
    }
    Ok(psbt.sign_all(&provider)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        get_secp,
        wallet_description::{get_singlesig_v0_derivation_path, ScriptType},
    };
    use bitcoin::util::bip32::ExtendedPrivKey;
    use slip132::FromSlip132;

    #[test]
    fn test_sign() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        let tempdir = tempdir::TempDir::new("psbt-test")?;
        let psbt_path = tempdir.path().join("psbt.psbt");
        create_file(&hex::decode("70736274ff010071020000000187ca9152f3540a73cfd51115277667e91a548fcf0544276f05fba9628c27fc5c0000000000fdffffff022a6203000000000016001487b78396f6f85213bce62e3374661bc578ae39d610560d00000000001600145c217d465b15f3c3041f9eac8ae88133485d4f6ae6340b00000100710200000001aa20bc793370fb83dba9a87753969fd3b9d7fd361be40a55d302f0d6fa1ddc410000000000feffffff02a8b81000000000001600149ef71340cba5b463069cfa4d781390cc9eefadb234de14d4010000001600140f4a26ef5174291b5c02b258a605d33944081b9f27cd240001011fa8b81000000000001600149ef71340cba5b463069cfa4d781390cc9eefadb2010304010000002206037a0f324d4c7baccc4da3bb2594cee6ee9f3b0771231fa7ce89b14ae191232bab0ccee87ee50000000001000000002202029402da79dd8b0d4f4d8eb625aaa79908088d0b1e10fbf70ab70fd5c84fbabbeb0ccee87ee501000000000000000000")?, &psbt_path)?;
        let mut p = open_psbt_file(&psbt_path)?;
        let spriv = "vprv9Ks2HJ9nwsjejp3mbQnSKEEZfN9jNNAEvrBvZP6N3P473Q2u6Noskm5nSu7wyoyNZB6T4e9U5FWYPjcQFsFKFoATH6hWYkrr2GShCuAwfYs";
        let xpriv = Secret::new(WExtendedPrivKey(ExtendedPrivKey::from_slip132_str(spriv)?));
        let xpub = bitcoin::util::bip32::ExtendedPubKey::from_priv(&secp, &xpriv.expose_secret().0);
        let derivation_path =
            get_singlesig_v0_derivation_path(&ScriptType::SegwitNative, &bitcoin::Network::Testnet);
        assert!(!p.inputs.is_empty());
        for i in &p.inputs {
            assert!(i.partial_sigs.is_empty())
        }
        let n = sign_psbt(
            &mut p,
            &[(&xpriv, &derivation_path, xpub.identifier())],
            &secp,
        )?;
        assert_eq!(n, 1);
        for i in &p.inputs {
            assert!(!i.partial_sigs.is_empty())
        }
        Ok(())
    }
}
