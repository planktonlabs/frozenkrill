use std::{
    io::{BufReader, Read},
    path::Path,
    str::FromStr,
};

use anyhow::Context;
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPubKey, Fingerprint};
use miniscript::DescriptorPublicKey;
use secrecy::Zeroize;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::wallet_description::{
    self, slip132_decode_pub, AddressInfo, DerivedAddress, MultiSigWalletDescriptionV0, ScriptType,
    SigType, SingleSigWalletDescriptionV0, ZERO_MULTISIG_WALLET_VERSION,
    ZERO_SINGLESIG_WALLET_VERSION,
};

pub const FROZENKRILL_WALLET: &str = "frozenkrill";

#[derive(serde::Deserialize)]
pub struct GenericOutputExportJson {
    wallet: Option<String>,
    version: Option<u32>,
    sigtype: Option<String>,
}

impl GenericOutputExportJson {
    pub fn deserialize(data: BufReader<impl Read>) -> anyhow::Result<Self> {
        let d = serde_json::from_reader::<_, Self>(data)?;

        match d.wallet.as_ref() {
            Some(w) if w.as_str() != FROZENKRILL_WALLET => {
                anyhow::bail!("Not a json generated by frozenkrill because wallet {w} != {FROZENKRILL_WALLET}")
            }
            Some(_) => {}
            None => anyhow::bail!(
                "Not a json generated by frozenkrill because there is no wallet field"
            ),
        }
        Ok(d)
    }

    pub fn version_sigtype(
        &self,
    ) -> anyhow::Result<(Option<u32>, Option<wallet_description::SigType>)> {
        Ok((
            self.version,
            self.sigtype
                .as_ref()
                .map(|s| wallet_description::SigType::from_str(s))
                .transpose()?,
        ))
    }
}

#[derive(Debug, Default, Zeroize, ZeroizeOnDrop, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonDerivedAddressInfo {
    address: String,
    derivation_path: String,
}

impl From<DerivedAddress> for JsonDerivedAddressInfo {
    fn from(v: DerivedAddress) -> Self {
        Self {
            address: v.address.to_string(),
            derivation_path: v.derivation_path.to_string(),
        }
    }
}

#[derive(Debug, Default, Zeroize, ZeroizeOnDrop, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonAddressInfo {
    address: String,
    index: u32,
}

impl From<AddressInfo> for JsonAddressInfo {
    fn from(v: AddressInfo) -> Self {
        Self {
            address: v.address.to_string(),
            index: v.index,
        }
    }
}

#[derive(Debug, Default, Zeroize, ZeroizeOnDrop, Serialize, Deserialize, PartialEq, Eq)]
pub struct SinglesigJsonWalletPublicExportV0 {
    wallet: String,
    version: u32,
    sigtype: String,
    master_fingerprint: String,
    singlesig_xpub: String,
    singlesig_derivation_path: String,
    multisig_xpub: String,
    multisig_derivation_path: String,
    singlesig_receiving_output_descriptor: String,
    singlesig_change_output_descriptor: String,
    multisig_receiving_output_descriptor_key: String,
    multisig_change_output_descriptor_key: String,
    script_type: String,
    network: String,
    receiving_addresses: Vec<JsonDerivedAddressInfo>,
    change_addresses: Vec<JsonDerivedAddressInfo>,
}

impl SinglesigJsonWalletPublicExportV0 {
    pub fn generate(
        w: &SingleSigWalletDescriptionV0,
        receiving_addresses: Vec<DerivedAddress>,
        change_addresses: Vec<DerivedAddress>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            wallet: FROZENKRILL_WALLET.to_owned(),
            version: ZERO_SINGLESIG_WALLET_VERSION,
            sigtype: SigType::Singlesig.to_string(),
            master_fingerprint: w.master_fingerprint.to_string(),
            singlesig_xpub: w.encoded_singlesig_xpub(),
            singlesig_derivation_path: w.singlesig_derivation_path.to_string(),
            multisig_xpub: w.encoded_multisig_xpub(),
            multisig_derivation_path: w.multisig_derivation_path.to_string(),
            singlesig_receiving_output_descriptor: w
                .receiving_singlesig_output_descriptor()?
                .to_string(),
            singlesig_change_output_descriptor: w.change_singlesig_output_descriptor()?.to_string(),
            multisig_receiving_output_descriptor_key: w
                .receiving_multisig_public_descriptor()
                .to_string(),
            multisig_change_output_descriptor_key: w
                .change_multisig_public_descriptor()
                .to_string(),
            script_type: w.script_type.to_string(),
            network: w.network.to_string(),
            receiving_addresses: receiving_addresses.into_iter().map(Into::into).collect(),
            change_addresses: change_addresses.into_iter().map(Into::into).collect(),
        })
    }

    fn script_type(&self) -> anyhow::Result<ScriptType> {
        ScriptType::from_str(&self.script_type)
    }

    pub fn deserialize(reader: BufReader<impl Read>) -> anyhow::Result<Self> {
        let d: Self = serde_json::from_reader(reader).context("failure parsing json")?;
        if d.wallet.as_str() != FROZENKRILL_WALLET {
            anyhow::bail!(
                "Trying to deserialize singlesig export, got wallet {} != {FROZENKRILL_WALLET}",
                d.wallet
            )
        }
        if d.version != ZERO_SINGLESIG_WALLET_VERSION {
            anyhow::bail!("Trying to deserialize singlesig export, got version {} != {ZERO_SINGLESIG_WALLET_VERSION}", d.version)
        }
        let sigtype = SigType::from_str(&d.sigtype)?;
        if sigtype != SigType::Singlesig {
            anyhow::bail!(
                "Trying to deserialize singlesig export, got sigtype {} != {}",
                d.sigtype,
                SigType::Singlesig
            )
        }
        Ok(d)
    }

    pub fn to_vec_pretty(&self) -> anyhow::Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).context("failure serializing json")
    }

    pub fn to_string_pretty(&self) -> anyhow::Result<String> {
        serde_json::to_string_pretty(self).context("failure serializing json")
    }

    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let data = crate::utils::buf_open_file(path)
            .with_context(|| format!("failure opening output file {path:?}"))?;
        Self::deserialize(data).with_context(|| format!("failure decoding output file {path:?}"))
    }

    fn multisig_xpub(&self) -> anyhow::Result<ExtendedPubKey> {
        match self.script_type()? {
            ScriptType::SegwitNative => slip132_decode_pub(&self.multisig_xpub),
        }
    }

    fn master_fingerprint(&self) -> anyhow::Result<Fingerprint> {
        Ok(Fingerprint::from_str(&self.master_fingerprint)?)
    }

    fn multisig_derivation_path(&self) -> anyhow::Result<DerivationPath> {
        Ok(DerivationPath::from_str(&self.multisig_derivation_path)?)
    }

    fn multisig_public_descriptor(
        &self,
        child: ChildNumber,
    ) -> anyhow::Result<DescriptorPublicKey> {
        match self.script_type()? {
            ScriptType::SegwitNative => Ok(DescriptorPublicKey::XPub(
                miniscript::descriptor::DescriptorXKey {
                    origin: Some((self.master_fingerprint()?, self.multisig_derivation_path()?)),
                    xkey: self.multisig_xpub()?,
                    derivation_path: vec![child].into(),
                    wildcard: miniscript::descriptor::Wildcard::Unhardened,
                },
            )),
        }
    }

    pub fn receiving_multisig_public_descriptor(&self) -> anyhow::Result<DescriptorPublicKey> {
        match self.script_type()? {
            ScriptType::SegwitNative => {
                self.multisig_public_descriptor(ChildNumber::Normal { index: 0 })
            }
        }
    }

    pub fn change_multisig_public_descriptor(&self) -> anyhow::Result<DescriptorPublicKey> {
        match self.script_type()? {
            ScriptType::SegwitNative => {
                self.multisig_public_descriptor(ChildNumber::Normal { index: 1 })
            }
        }
    }
}

#[derive(Debug, Default, Zeroize, ZeroizeOnDrop, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultisigJsonWalletPublicExportV0 {
    pub wallet: String,
    pub version: u32,
    pub sigtype: String,
    pub script_type: String,
    pub network: String,
    pub receiving_output_descriptor: String,
    pub change_output_descriptor: String,
    pub receiving_addresses: Vec<JsonAddressInfo>,
    pub change_addresses: Vec<JsonAddressInfo>,
}

impl MultisigJsonWalletPublicExportV0 {
    pub fn generate(
        w: &MultiSigWalletDescriptionV0,
        receiving_addresses: Vec<AddressInfo>,
        change_addresses: Vec<AddressInfo>,
    ) -> Self {
        Self {
            wallet: FROZENKRILL_WALLET.to_owned(),
            version: ZERO_MULTISIG_WALLET_VERSION,
            sigtype: w.configuration.to_string(),
            script_type: w.script_type.to_string(),
            network: w.network.to_string(),
            receiving_output_descriptor: w.receiving_descriptor.to_string(),
            change_output_descriptor: w.change_descriptor.to_string(),
            receiving_addresses: receiving_addresses.into_iter().map(Into::into).collect(),
            change_addresses: change_addresses.into_iter().map(Into::into).collect(),
        }
    }

    pub fn deserialize(reader: BufReader<impl Read>) -> anyhow::Result<Self> {
        let d: Self = serde_json::from_reader(reader).context("failure parsing json")?;
        if d.wallet.as_str() != FROZENKRILL_WALLET {
            anyhow::bail!(
                "Trying to deserialize singlesig export, got wallet {} != {FROZENKRILL_WALLET}",
                d.wallet
            )
        }
        if d.version != ZERO_MULTISIG_WALLET_VERSION {
            anyhow::bail!("Trying to deserialize multisig export, got version {} != {ZERO_MULTISIG_WALLET_VERSION}", d.version)
        }
        let sigtype = SigType::from_str(&d.sigtype)?;
        if !matches!(sigtype, SigType::Multisig(_)) {
            anyhow::bail!(
                "Trying to deserialize multisig export, got sigtype {sigtype} not multisig"
            )
        }
        Ok(d)
    }

    pub fn to_vec_pretty(&self) -> anyhow::Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).context("failure serializing json")
    }

    pub fn to_string_pretty(&self) -> anyhow::Result<String> {
        serde_json::to_string_pretty(self).context("failure serializing json")
    }

    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let data = crate::utils::buf_open_file(path)
            .with_context(|| format!("failure opening output file {path:?}"))?;
        Self::deserialize(data).with_context(|| format!("failure decoding output file {path:?}"))
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Arc};

    use secrecy::Secret;

    use super::*;
    use crate::get_secp;

    #[test]
    fn test_json_public_export() -> anyhow::Result<()> {
        use pretty_assertions::assert_eq;

        // TODO: also test using https://github.com/satoshilabs/slips/blob/master/slip-0014.md
        let seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Secret::new(bip39::Mnemonic::from_str(seed_phrase)?);
        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        let w = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )?;
        let receiving = w.derive_receiving_addresses(0, 2, &secp)?;
        let change = w.derive_change_addresses(0, 2, &secp)?;
        let generated = SinglesigJsonWalletPublicExportV0::generate(&w, receiving, change)?;
        let expected = SinglesigJsonWalletPublicExportV0 {
            wallet: FROZENKRILL_WALLET.to_owned(),
            version: ZERO_SINGLESIG_WALLET_VERSION,
            sigtype: "singlesig".into(),
            script_type: "segwit-native".into(),
            singlesig_xpub: "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs".into(),
            singlesig_derivation_path: "m/84'/0'/0'".into(),
            singlesig_receiving_output_descriptor: "wpkh([73c5da0a/84'/0'/0']xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/0/*)#wc3n3van".into(),
            singlesig_change_output_descriptor: "wpkh([73c5da0a/84'/0'/0']xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/1/*)#lv5jvedt".into(),
            multisig_receiving_output_descriptor_key: "[73c5da0a/48'/0'/0'/2']xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf/0/*".into(),
            multisig_change_output_descriptor_key: "[73c5da0a/48'/0'/0'/2']xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf/1/*".into(),
            network: "bitcoin".into(),
            receiving_addresses: vec![
                JsonDerivedAddressInfo {
                    address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu".into(),
                    derivation_path: "m/84'/0'/0'/0/0".into(),
                },
                JsonDerivedAddressInfo {
                    address: "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g".into(),
                    derivation_path: "m/84'/0'/0'/0/1".into(),
                },
            ],
            change_addresses: vec![
                JsonDerivedAddressInfo {
                    address: "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el".into(),
                    derivation_path: "m/84'/0'/0'/1/0".into(),
                },
                JsonDerivedAddressInfo {
                    address: "bc1qggnasd834t54yulsep6fta8lpjekv4zj6gv5rf".into(),
                    derivation_path: "m/84'/0'/0'/1/1".into(),
                }
            ],
            master_fingerprint: "73c5da0a".into(),
            multisig_xpub: "Zpub74Jru6aftwwHxCUCWEvP6DgrfFsdA4U6ZRtQ5i8qJpMcC39yZGv3egBhQfV3MS9pZtH5z8iV5qWkJsK6ESs6mSzt4qvGhzJxPeeVS2e1zUG".into(),
            multisig_derivation_path: "m/48'/0'/0'/2'".into(),
        };
        assert_eq!(generated, expected);
        Ok(())
    }
}
