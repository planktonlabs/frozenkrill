use std::{
    collections::HashSet,
    io::{BufReader, BufWriter, Read, Write},
    mem::size_of,
    path::Path,
    str::FromStr,
    sync::Arc,
};

use anyhow::{Context, bail, ensure};
use bip39::Mnemonic;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{
    Address, Network,
    bip32::{ChildNumber, DerivationPath, Fingerprint},
    psbt::Psbt,
};
use itertools::Itertools;
use log::debug;
use miniscript::{Descriptor, DescriptorPublicKey};
use rand_core::{CryptoRng, RngCore};
use regex::Regex;
use secrecy::{CloneableSecret, ExposeSecret, SecretBox, SecretString};
type Secret<T> = SecretBox<T>;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    MultisigInputs,
    compression::uncompress,
    encoding::VarInt,
    encryption::{MAC_LENGTH, default_decrypt},
    ms_ddpk_to_dpks, ms_dpks_to_ddpk,
    psbt::sign_psbt,
    utils,
};
use once_cell::sync::Lazy;

/// The maximum number of words in a mnemonic.
const MAX_NB_WORDS: usize = 24;

pub type WalletVersionType = u32;

pub const ZERO_MULTISIG_WALLET_VERSION: WalletVersionType = 0;
pub const ZERO_SINGLESIG_WALLET_VERSION: WalletVersionType = 0;
pub const STANDARD_ENCRYPTED_WALLET_VERSION: HeaderVersionType = 0;
pub const COMPACT_ENCRYPTED_MAINNET_WALLET_VERSION: HeaderVersionType = 1;
pub const COMPACT_ENCRYPTED_TESTNET_WALLET_VERSION: HeaderVersionType = 2;

pub const MAX_TOTAL_SIGS_MULTISIG: u32 = 15;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct MultisigType {
    // M-of-N
    pub required: u32, // M
    pub total: u32,    // N
}

impl MultisigType {
    pub fn new(required: u32, total: u32) -> anyhow::Result<Self> {
        anyhow::ensure!(
            required > 0,
            "Required signatures must be greater than zero"
        );
        anyhow::ensure!(
            required <= total,
            "Required ({required}) must be less than or equal to total ({total})"
        );
        anyhow::ensure!(
            total <= MAX_TOTAL_SIGS_MULTISIG,
            "Total {total} is greater than {MAX_TOTAL_SIGS_MULTISIG}"
        );
        Ok(Self { required, total })
    }
}

impl FromStr for MultisigType {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        static MULTISIGTYPE_RE: Lazy<Regex> =
            Lazy::new(|| Regex::new("([0-9]+)[ -]?of[ -]?([0-9]+)").unwrap());
        let s = s.to_lowercase();
        let mut captures = MULTISIGTYPE_RE.captures_iter(s.as_str());
        let capture = captures.next().with_context(|| {
            format!("Invalid format ({s}), use a something like \"2-of-3\" or \"3-of-5\" (M-of-N)")
        })?;
        let required = capture
            .get(1)
            .context("Missing required value (M)")?
            .as_str()
            .parse()
            .map_err(|e| anyhow::anyhow!("Error parsing required (M) value: {e}"))?;
        let total = capture
            .get(2)
            .context("Missing total value (N)")?
            .as_str()
            .parse()
            .map_err(|e| anyhow::anyhow!("Error parsing total (N) value: {e}"))?;
        Self::new(required, total)
    }
}

impl std::fmt::Display for MultisigType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let m = self.required;
        let n = self.total;
        f.write_fmt(format_args!("{m}-of-{n}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigType {
    Singlesig,
    Multisig(MultisigType),
}

impl std::fmt::Display for SigType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigType::Singlesig => f.write_str("singlesig"),
            SigType::Multisig(v) => f.write_str(&v.to_string()),
        }
    }
}

impl FromStr for SigType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "singlesig" => Ok(Self::Singlesig),
            multi if multi.contains("of") => Ok(Self::Multisig(MultisigType::from_str(multi)?)),
            _ => bail!("Invalid sigtype: {s}"),
        }
    }
}

#[derive(Clone, Copy)]
pub enum ScriptType {
    SegwitNative,
    // Taproot, // TODO: implement
}

impl FromStr for ScriptType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "segwit-native" => Ok(Self::SegwitNative),
            // "taproot" => Ok(Self::Taproot),
            _ => bail!("Got unknown script type: {s}"),
        }
    }
}

impl std::fmt::Display for ScriptType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScriptType::SegwitNative => f.write_str("segwit-native"),
        }
    }
}

#[derive(Debug)]
pub struct EncryptedWalletDescription {
    nonce: [u8; NONCE_SIZE],
    pub salt: [u8; SALT_SIZE],
    encrypted_header: [u8; ENCRYPTED_HEADER_LENGTH],
    ciphertext: Vec<u8>,
}

impl EncryptedWalletDescription {
    pub fn new(
        nonce: [u8; NONCE_SIZE],
        salt: [u8; SALT_SIZE],
        encrypted_header: [u8; ENCRYPTED_HEADER_LENGTH],
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            nonce,
            salt,
            encrypted_header,
            ciphertext,
        }
    }

    pub fn serialize(&self) -> anyhow::Result<Vec<u8>> {
        let mut writer = BufWriter::new(Vec::new());
        writer.write_all(&self.nonce)?;
        writer.write_all(&self.salt)?;
        writer.write_all(&self.encrypted_header)?;
        writer.write_all(&self.ciphertext)?;
        Ok(writer.into_inner()?)
    }

    pub fn deserialize(mut reader: BufReader<impl Read>) -> anyhow::Result<Self> {
        let mut nonce = [0u8; NONCE_SIZE];
        reader
            .read_exact(&mut nonce)
            .context("failure reading nonce")?;
        let mut salt = [0u8; SALT_SIZE];
        reader
            .read_exact(&mut salt)
            .context("failure reading salt")?;
        let mut encrypted_header = [0u8; ENCRYPTED_HEADER_LENGTH];
        reader
            .read_exact(&mut encrypted_header)
            .context("failure reading encrypted header")?;
        let mut ciphertext = Vec::new();
        reader
            .read_to_end(&mut ciphertext)
            .context("failure reading ciphertext")?;
        Ok(Self {
            nonce,
            salt,
            encrypted_header,
            ciphertext,
        })
    }

    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let encrypted_wallet = utils::buf_open_file(path)
            .with_context(|| format!("failure opening output file {path:?}"))?;
        Self::deserialize(encrypted_wallet)
            .with_context(|| format!("failure decoding output file {path:?}"))
    }

    pub fn decrypt_singlesig(
        &self,
        key: &SecretBox<[u8; KEY_SIZE]>,
        seed_password: &Option<Arc<SecretString>>,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<Secret<SinglesigJsonWalletDescriptionV0>> {
        decrypt_wallet_singlesig(&self.nonce, &self.encrypted_header, &self.ciphertext, key, seed_password,secp)
            .context("failed to decrypt the wallet, check if you have used the correct password, keyfiles and difficulty parameter")
    }

    pub fn decrypt_multisig(
        &self,
        key: &SecretBox<[u8; KEY_SIZE]>,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<Secret<MultisigJsonWalletDescriptionV0>> {
        decrypt_wallet_multisig(&self.nonce, &self.encrypted_header, &self.ciphertext, key, secp)
            .context("failed to decrypt the wallet, check if you have used the correct password, keyfiles and difficulty parameter")
    }
}

pub(super) fn get_singlesig_v0_derivation_path(
    script_type: &ScriptType,
    network: &Network,
) -> DerivationPath {
    let s = match (script_type, network) {
        (ScriptType::SegwitNative, Network::Bitcoin) => "84'/0'/0'",
        (ScriptType::SegwitNative, _) => "84'/1'/0'",
    };
    DerivationPath::from_str(s).expect("code to be correct")
}

pub(super) fn get_multisig_v0_derivation_path(
    script_type: &ScriptType,
    network: &Network,
) -> DerivationPath {
    let s = match (script_type, network) {
        (ScriptType::SegwitNative, Network::Bitcoin) => "48'/0'/0'/2'",
        (ScriptType::SegwitNative, _) => "48'/1'/0'/2'",
    };
    DerivationPath::from_str(s).expect("code to be correct")
}

#[derive(Debug, thiserror::Error)]
pub enum SingleSigValidationError {
    #[error("Seed phrases are different")]
    SeedMismatch,
    #[error("Private keys are different")]
    PrivateKeyMismatch,
    #[error("Public keys are different")]
    PublicKeyMismatch,
    #[error("Derivation paths are different")]
    DerivationPathMismatch,
    #[error("First address is different")]
    FirstAddressMismatch,
    #[error("Versions don't match")]
    VersionMismatch,
    #[error("Signature types don't match")]
    SigTypeMismatch,
    #[error("Script types don't match")]
    ScriptTypeMismatch,
    #[error("Fingerprints don't match")]
    MasterFingerprintMismatch,
}

#[derive(Debug, thiserror::Error)]
pub enum MultiSigValidationError {
    #[error("Output descriptors are different")]
    OutputDescriptorMismatch,
    #[error("Configuration mismatch")]
    ConfigurationMismatch,
    #[error("First address is different")]
    FirstAddressMismatch,
    #[error("Script types don't match")]
    ScriptTypeMismatch,
    #[error("Versions don't match")]
    VersionMismatch,
    #[error("Networks don't match")]
    NetworkMismatch,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DerivedAddress {
    pub address: Address,
    pub derivation_path: DerivationPath,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AddressInfo {
    pub address: Address,
    pub index: u32,
}

type PsbtKeyInfo<'a> = &'a Secret<WExtendedPrivKey>;

#[derive(Clone)]
pub struct SingleSigWalletDescriptionV0 {
    pub mnemonic: Arc<Secret<bip39::Mnemonic>>,
    pub master_fingerprint: Fingerprint,
    root_key: Secret<WExtendedPrivKey>,
    singlesig_xpriv: Secret<WExtendedPrivKey>,
    singlesig_xpub: bitcoin::bip32::Xpub,
    pub singlesig_derivation_path: bitcoin::bip32::DerivationPath,
    multisig_xpriv: Secret<WExtendedPrivKey>,
    multisig_xpub: bitcoin::bip32::Xpub,
    pub multisig_derivation_path: bitcoin::bip32::DerivationPath,
    pub network: Network,
    pub script_type: ScriptType,
}

impl SingleSigWalletDescriptionV0 {
    pub fn generate(
        mnemonic: Arc<Secret<bip39::Mnemonic>>,
        seed_password: &Option<Arc<SecretString>>,
        network: bitcoin::Network,
        script_type: ScriptType,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<Self> {
        let empty_password = Arc::new(SecretString::new("".into()));
        let seed_password = seed_password.as_ref().unwrap_or(&empty_password);
        let root_key = get_root_key(&mnemonic, seed_password, network)?;
        let singlesig_derivation_path = get_singlesig_v0_derivation_path(&script_type, &network);
        let singlesig_xpriv = Secret::from(Box::new(WExtendedPrivKey(
            root_key
                .expose_secret()
                .0
                .derive_priv(secp, &singlesig_derivation_path)?,
        )));
        let singlesig_xpub =
            bitcoin::bip32::Xpub::from_priv(secp, &singlesig_xpriv.expose_secret().0);
        let multisig_derivation_path = get_multisig_v0_derivation_path(&script_type, &network);
        let multisig_xpriv = Secret::from(Box::new(WExtendedPrivKey(
            root_key
                .expose_secret()
                .0
                .derive_priv(secp, &multisig_derivation_path)?,
        )));
        let multisig_xpub =
            bitcoin::bip32::Xpub::from_priv(secp, &multisig_xpriv.expose_secret().0);
        let master_fingerprint = root_key.expose_secret().0.fingerprint(secp);
        Ok(Self {
            mnemonic,
            root_key,
            singlesig_xpriv,
            singlesig_xpub,
            singlesig_derivation_path,
            multisig_xpriv,
            multisig_xpub,
            multisig_derivation_path,
            master_fingerprint,
            network,
            script_type,
        })
    }

    pub fn change_seed_password(
        &self,
        seed_password: &Option<Arc<SecretString>>,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<Self> {
        Self::generate(
            Arc::clone(&self.mnemonic),
            seed_password,
            self.network,
            self.script_type,
            secp,
        )
    }

    fn derive_addresses(
        &self,
        start: u32,
        quantity: u32,
        child_number: bitcoin::bip32::ChildNumber,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<Vec<DerivedAddress>> {
        use rayon::prelude::*;
        (start..(start + quantity))
            .into_par_iter()
            .map(|i| {
                let i = bitcoin::bip32::ChildNumber::from_normal_idx(i)?;
                let public_key = self
                    .singlesig_xpub
                    .derive_pub(secp, &[child_number, i])?
                    .public_key;
                let address = match self.script_type {
                    ScriptType::SegwitNative => bitcoin::Address::p2wpkh(
                        &bitcoin::PublicKey::new(public_key).try_into()?,
                        self.network,
                    ),
                };
                let full_path = self
                    .singlesig_derivation_path
                    .child(child_number)
                    .into_child(i);
                Ok(DerivedAddress {
                    derivation_path: full_path,
                    address,
                })
            })
            .collect()
    }

    pub fn derive_receiving_addresses(
        &self,
        start: u32,
        quantity: u32,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<Vec<DerivedAddress>> {
        match self.script_type {
            ScriptType::SegwitNative => {
                let zero = bitcoin::bip32::ChildNumber::from_normal_idx(0)?;
                self.derive_addresses(start, quantity, zero, secp)
            }
        }
    }

    pub fn derive_change_addresses(
        &self,
        start: u32,
        quantity: u32,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<Vec<DerivedAddress>> {
        match self.script_type {
            ScriptType::SegwitNative => {
                let one = bitcoin::bip32::ChildNumber::from_normal_idx(1)?;
                self.derive_addresses(start, quantity, one, secp)
            }
        }
    }

    pub fn derive_receiving_address(
        &self,
        index: u32,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<Address> {
        let mut addresses = self.derive_receiving_addresses(index, 1, secp)?;
        let derived_address = addresses
            .pop()
            .ok_or_else(|| anyhow::anyhow!("Unexpected empty list"))?;
        Ok(derived_address.address)
    }

    pub fn first_receiving_address(&self, secp: &Secp256k1<All>) -> anyhow::Result<Address> {
        Ok(self
            .derive_receiving_addresses(0, 1, secp)?
            .into_iter()
            .next()
            .expect("code to be correct")
            .address)
    }

    fn encoded_singlesig_xpriv(&self) -> SecretString {
        match self.script_type {
            ScriptType::SegwitNative => {
                SecretString::new(m84_slip132_encode_priv(&self.singlesig_xpriv).into())
            }
        }
    }

    pub fn encoded_singlesig_xpub(&self) -> String {
        match self.script_type {
            ScriptType::SegwitNative => m84_slip132_encode_pub(&self.singlesig_xpub),
        }
    }

    fn encoded_multisig_xpriv(&self) -> SecretString {
        match self.script_type {
            ScriptType::SegwitNative => {
                SecretString::new(m48_slip132_encode_priv(&self.multisig_xpriv).into())
            }
        }
    }

    pub fn encoded_multisig_xpub(&self) -> String {
        match self.script_type {
            ScriptType::SegwitNative => m48_slip132_encode_pub(&self.multisig_xpub),
        }
    }

    pub fn get_singlesig_pub_fingerprint(&self) -> Fingerprint {
        self.singlesig_xpub.fingerprint()
    }

    pub fn get_multisig_pub_fingerprint(&self) -> Fingerprint {
        self.multisig_xpub.fingerprint()
    }

    fn singlesig_public_descriptor(&self, child: ChildNumber) -> DescriptorPublicKey {
        match self.script_type {
            ScriptType::SegwitNative => {
                DescriptorPublicKey::XPub(miniscript::descriptor::DescriptorXKey {
                    origin: Some((
                        self.master_fingerprint,
                        self.singlesig_derivation_path.to_owned(),
                    )),
                    xkey: self.singlesig_xpub,
                    derivation_path: vec![child].into(),
                    wildcard: miniscript::descriptor::Wildcard::Unhardened,
                })
            }
        }
    }

    fn receiving_singlesig_public_descriptor(&self) -> DescriptorPublicKey {
        match self.script_type {
            ScriptType::SegwitNative => {
                self.singlesig_public_descriptor(ChildNumber::Normal { index: 0 })
            }
        }
    }

    fn change_singlesig_public_descriptor(&self) -> DescriptorPublicKey {
        match self.script_type {
            ScriptType::SegwitNative => {
                self.singlesig_public_descriptor(ChildNumber::Normal { index: 1 })
            }
        }
    }

    pub fn receiving_singlesig_output_descriptor(
        &self,
    ) -> anyhow::Result<Descriptor<DescriptorPublicKey>> {
        match self.script_type {
            ScriptType::SegwitNative => Ok(Descriptor::new_wpkh(
                self.receiving_singlesig_public_descriptor(),
            )?),
        }
    }

    pub fn change_singlesig_output_descriptor(
        &self,
    ) -> anyhow::Result<Descriptor<DescriptorPublicKey>> {
        match self.script_type {
            ScriptType::SegwitNative => Ok(Descriptor::new_wpkh(
                self.change_singlesig_public_descriptor(),
            )?),
        }
    }

    fn multisig_public_descriptor(&self, child: ChildNumber) -> DescriptorPublicKey {
        match self.script_type {
            ScriptType::SegwitNative => {
                DescriptorPublicKey::XPub(miniscript::descriptor::DescriptorXKey {
                    origin: Some((
                        self.master_fingerprint,
                        self.multisig_derivation_path.to_owned(),
                    )),
                    xkey: self.multisig_xpub,
                    derivation_path: vec![child].into(),
                    wildcard: miniscript::descriptor::Wildcard::Unhardened,
                })
            }
        }
    }

    pub fn receiving_multisig_public_descriptor(&self) -> DescriptorPublicKey {
        match self.script_type {
            ScriptType::SegwitNative => {
                self.multisig_public_descriptor(ChildNumber::Normal { index: 0 })
            }
        }
    }

    pub fn change_multisig_public_descriptor(&self) -> DescriptorPublicKey {
        match self.script_type {
            ScriptType::SegwitNative => {
                self.multisig_public_descriptor(ChildNumber::Normal { index: 1 })
            }
        }
    }

    pub(super) fn get_psbt_singlesig_keys(&self) -> Vec<PsbtKeyInfo> {
        vec![&self.root_key, &self.singlesig_xpriv]
    }

    pub(super) fn get_psbt_multisig_keys(&self) -> Vec<PsbtKeyInfo> {
        vec![&self.root_key, &self.multisig_xpriv]
    }
}

impl PsbtWallet for SingleSigWalletDescriptionV0 {
    fn sign_psbt(&self, psbt: &mut Psbt, secp: &Secp256k1<All>) -> anyhow::Result<usize> {
        let mut n = 0;
        for keys in [
            self.get_psbt_singlesig_keys(),
            self.get_psbt_multisig_keys(),
        ] {
            n += sign_psbt(psbt, &keys, secp)?;
        }
        Ok(n)
    }

    fn get_pub_fingerprints(&self) -> Vec<Fingerprint> {
        vec![
            self.get_singlesig_pub_fingerprint(),
            self.get_multisig_pub_fingerprint(),
        ]
    }

    fn derive_change_addresses(
        &self,
        start: u32,
        quantity: u32,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<Vec<Address>> {
        Ok(self
            .derive_change_addresses(start, quantity, secp)?
            .into_iter()
            .map(|a| a.address)
            .collect())
    }
}

#[derive(Default, Zeroize, ZeroizeOnDrop, Serialize, Deserialize, PartialEq, Eq)]
pub struct SinglesigJsonWalletDescriptionV0 {
    pub version: WalletVersionType,
    pub sigtype: String,
    pub seed_phrase: String,
    pub master_fingerprint: String,
    singlesig_xpriv: String,
    pub singlesig_xpub: String,
    pub singlesig_derivation_path: String,
    multisig_xpriv: String,
    pub multisig_xpub: String,
    pub multisig_derivation_path: String,
    pub singlesig_first_address: String,
    pub singlesig_receiving_output_descriptor: String,
    pub singlesig_change_output_descriptor: String,
    pub network: String,
    pub script_type: String,
}

impl SinglesigJsonWalletDescriptionV0 {
    pub fn from_wallet_description(
        w: &SingleSigWalletDescriptionV0,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<Secret<Self>> {
        Ok(Secret::from(Box::new(Self {
            version: ZERO_SINGLESIG_WALLET_VERSION,
            sigtype: SigType::Singlesig.to_string(),
            seed_phrase: w.mnemonic.expose_secret().to_string(),
            master_fingerprint: w.master_fingerprint.to_string(),
            singlesig_xpriv: w.encoded_singlesig_xpriv().expose_secret().to_owned(),
            singlesig_xpub: w.encoded_singlesig_xpub(),
            singlesig_derivation_path: w.singlesig_derivation_path.to_string(),
            multisig_xpriv: w.encoded_multisig_xpriv().expose_secret().to_owned(),
            multisig_xpub: w.encoded_multisig_xpub(),
            multisig_derivation_path: w.multisig_derivation_path.to_string(),
            singlesig_first_address: w.first_receiving_address(secp)?.to_string(),
            singlesig_receiving_output_descriptor: w
                .receiving_singlesig_output_descriptor()?
                .to_string(),
            singlesig_change_output_descriptor: w.change_singlesig_output_descriptor()?.to_string(),
            network: w.network.to_string(),
            script_type: w.script_type.to_string(),
        })))
    }

    pub fn to(
        &self,
        seed_password: &Option<Arc<SecretString>>,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<SingleSigWalletDescriptionV0> {
        let mnemonic = Secret::from(Box::new(bip39::Mnemonic::from_str(&self.seed_phrase)?));
        let network = Network::from_str(&self.network)?;
        let script_type = ScriptType::from_str(&self.script_type)?;
        SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            seed_password,
            network,
            script_type,
            secp,
        )
    }

    pub fn validate_same(
        source: &Secret<SinglesigJsonWalletDescriptionV0>,
        w: &SingleSigWalletDescriptionV0,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<Result<(), SingleSigValidationError>> {
        let source = source.expose_secret();
        let w = Self::from_wallet_description(w, secp)?;
        let generated = w.expose_secret();
        if generated != source {
            if generated.seed_phrase != source.seed_phrase {
                Ok(Err(SingleSigValidationError::SeedMismatch))
            } else if generated.singlesig_xpriv != source.singlesig_xpriv {
                Ok(Err(SingleSigValidationError::PrivateKeyMismatch))
            } else if generated.singlesig_xpub != source.singlesig_xpub {
                Ok(Err(SingleSigValidationError::PublicKeyMismatch))
            } else if generated.master_fingerprint != source.master_fingerprint {
                Ok(Err(SingleSigValidationError::MasterFingerprintMismatch))
            } else if generated.singlesig_first_address != source.singlesig_first_address {
                Ok(Err(SingleSigValidationError::FirstAddressMismatch))
            } else if generated.version != source.version {
                Ok(Err(SingleSigValidationError::VersionMismatch))
            } else if generated.sigtype != source.sigtype {
                Ok(Err(SingleSigValidationError::SigTypeMismatch))
            } else if generated.script_type != source.script_type {
                Ok(Err(SingleSigValidationError::ScriptTypeMismatch))
            } else if generated.singlesig_derivation_path != source.singlesig_derivation_path {
                if generated.singlesig_derivation_path.replace("m/", "")
                    != source.singlesig_derivation_path.replace("m/", "")
                {
                    Ok(Err(SingleSigValidationError::DerivationPathMismatch))
                } else {
                    debug!(
                        "Derivation paths are using different conventions for the m/ prefix, but that's ok: {} and {}",
                        generated.singlesig_derivation_path, source.singlesig_derivation_path
                    );
                    Ok(Ok(()))
                }
            } else {
                unreachable!(
                    "Generated wallet is different from source but every field is the same!?"
                )
            }
        } else {
            Ok(Ok(()))
        }
    }

    pub fn deserialize(data: BufReader<impl Read>) -> anyhow::Result<Secret<Self>> {
        let w = serde_json::from_reader::<_, Self>(data).context("failure parsing wallet json")?;
        anyhow::ensure!(
            w.version == ZERO_SINGLESIG_WALLET_VERSION,
            "Version {} isn't {ZERO_SINGLESIG_WALLET_VERSION}",
            w.version
        );
        Ok(Secret::from(Box::new(w)))
    }

    pub fn to_vec(&self) -> anyhow::Result<SecretBox<Vec<u8>>> {
        Ok(SecretBox::from(Box::new(
            serde_json::to_vec(self).context("failure serializing json")?,
        )))
    }

    pub fn to_vec_pretty(&self) -> anyhow::Result<SecretBox<Vec<u8>>> {
        Ok(SecretBox::from(Box::new(
            serde_json::to_vec_pretty(self).context("failure serializing json")?,
        )))
    }

    pub fn to_string_pretty(&self) -> anyhow::Result<SecretString> {
        Ok(SecretString::new(
            serde_json::to_string_pretty(self)
                .context("failure serializing json")?
                .into(),
        ))
    }
}

#[derive(Clone)]
pub struct SingleSigCompactWalletDescriptionV0 {
    mnemonic: Arc<Secret<bip39::Mnemonic>>,
}

impl SingleSigCompactWalletDescriptionV0 {
    pub fn new(mnemonic: Arc<Secret<bip39::Mnemonic>>) -> anyhow::Result<Self> {
        Ok(Self { mnemonic })
    }

    pub fn serialize(&self) -> SecretBox<Vec<u8>> {
        let entropy = self.mnemonic.expose_secret().to_entropy();
        SecretBox::from(Box::new(entropy))
    }

    pub fn deserialize(mut data: BufReader<impl Read>) -> anyhow::Result<Self> {
        let mut entropy = Vec::with_capacity(32);
        data.read_to_end(&mut entropy)?;
        let mnemonic = Mnemonic::from_entropy(&entropy)?;
        Ok(Self {
            mnemonic: Arc::new(Secret::from(Box::new(mnemonic))),
        })
    }

    pub fn to_description(
        self,
        seed_password: &Option<Arc<SecretString>>,
        network: bitcoin::Network,
        script_type: ScriptType,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<SingleSigWalletDescriptionV0> {
        SingleSigWalletDescriptionV0::generate(
            self.mnemonic,
            seed_password,
            network,
            script_type,
            secp,
        )
    }
}

pub struct MultiSigWalletDescriptionV0 {
    pub inputs: MultisigInputs,
    pub receiving_descriptor: miniscript::Descriptor<DescriptorPublicKey>,
    pub change_descriptor: miniscript::Descriptor<DescriptorPublicKey>,
    pub configuration: MultisigType,
    pub network: Network,
    pub script_type: ScriptType,
}

impl MultiSigWalletDescriptionV0 {
    pub fn generate_from_dpks(
        inputs: MultisigInputs,
        configuration: MultisigType,
        network: bitcoin::Network,
        script_type: ScriptType,
    ) -> anyhow::Result<Self> {
        let receiving_descriptor = ms_dpks_to_ddpk(
            inputs.receiving_descriptors.clone(),
            &configuration,
            script_type,
        )?;
        let change_descriptor = ms_dpks_to_ddpk(
            inputs.change_descriptors.clone(),
            &configuration,
            script_type,
        )?;
        Self::validate_descriptors(
            &[&change_descriptor, &receiving_descriptor],
            &configuration,
            &inputs.signers,
            &script_type,
        )?;
        Ok(Self {
            inputs,
            receiving_descriptor,
            change_descriptor,
            configuration,
            network,
            script_type,
        })
    }

    pub fn generate_from_ddpks(
        signers: Vec<SingleSigWalletDescriptionV0>,
        receiving_descriptor: miniscript::Descriptor<DescriptorPublicKey>,
        change_descriptor: miniscript::Descriptor<DescriptorPublicKey>,
        configuration: MultisigType,
        network: bitcoin::Network,
        script_type: ScriptType,
    ) -> anyhow::Result<Self> {
        let receiving_descriptors =
            ms_ddpk_to_dpks(&receiving_descriptor, &configuration, &script_type)?;
        let change_descriptors = ms_ddpk_to_dpks(&change_descriptor, &configuration, &script_type)?;
        Self::validate_descriptors(
            &[&change_descriptor, &receiving_descriptor],
            &configuration,
            &signers,
            &script_type,
        )?;
        Ok(Self {
            inputs: MultisigInputs {
                receiving_descriptors,
                change_descriptors,
                signers,
            },
            receiving_descriptor,
            change_descriptor,
            configuration,
            network,
            script_type,
        })
    }

    fn derive_addresses(
        &self,
        start: u32,
        quantity: u32,
        descriptor: &miniscript::Descriptor<DescriptorPublicKey>,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<Vec<AddressInfo>> {
        use rayon::prelude::*;
        (start..(start + quantity))
            .into_par_iter()
            .map(|i| {
                let w = descriptor.derived_descriptor(secp, i)?;
                w.sanity_check()?;
                let address = w.address(self.network)?;
                Ok(AddressInfo { address, index: i })
            })
            .collect()
    }

    pub fn derive_receiving_addresses(
        &self,
        start: u32,
        quantity: u32,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<Vec<AddressInfo>> {
        self.derive_addresses(start, quantity, &self.receiving_descriptor, secp)
    }

    pub fn derive_change_addresses(
        &self,
        start: u32,
        quantity: u32,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<Vec<AddressInfo>> {
        self.derive_addresses(start, quantity, &self.change_descriptor, secp)
    }

    pub fn derive_receiving_address(
        &self,
        index: u32,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<Address> {
        let mut addresses = self.derive_receiving_addresses(index, 1, secp)?;
        let derived_address = addresses
            .pop()
            .ok_or_else(|| anyhow::anyhow!("Unexpected empty list"))?;
        Ok(derived_address.address)
    }

    pub fn first_receiving_address(&self, secp: &Secp256k1<All>) -> anyhow::Result<AddressInfo> {
        Ok(self
            .derive_receiving_addresses(0, 1, secp)?
            .into_iter()
            .next()
            .expect("code to be correct"))
    }

    pub fn has_signers(&self) -> bool {
        !self.inputs.signers.is_empty()
    }

    fn validate_descriptors(
        values: &[&miniscript::Descriptor<DescriptorPublicKey>],
        configuration: &MultisigType,
        signers: &[SingleSigWalletDescriptionV0],
        script_type: &ScriptType,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            signers.len() <= configuration.total.try_into()?,
            "Got {} signers but there are only {} signatures",
            signers.len(),
            configuration.total
        );
        let mut all_public_keys = HashSet::new();
        for v in values {
            match (script_type, v) {
                (
                    ScriptType::SegwitNative,
                    d @ (miniscript::Descriptor::Bare(_)
                    | miniscript::Descriptor::Pkh(_)
                    | miniscript::Descriptor::Wpkh(_)
                    | miniscript::Descriptor::Sh(_)),
                ) => {
                    bail!("Descriptor type {:?} isn't supported", d.desc_type())
                }
                (ScriptType::SegwitNative, miniscript::Descriptor::Wsh(v)) => match v.as_inner() {
                    miniscript::descriptor::WshInner::SortedMulti(v) => {
                        let required: usize = configuration.required.try_into()?;
                        anyhow::ensure!(
                            v.k() == required,
                            "Different required on descriptor and configuration: {} and {}",
                            v.k(),
                            configuration.required
                        );
                        all_public_keys.extend(v.pks());
                    }
                    miniscript::descriptor::WshInner::Ms(_) => {
                        bail!("A non sorted wsh descriptor isn't supported")
                    }
                },
                (ScriptType::SegwitNative, miniscript::Descriptor::Tr(_)) => {
                    bail!("Taproot isn't currently supported")
                }
            };
        }
        for signer in signers {
            for descriptor in [
                signer.receiving_multisig_public_descriptor(),
                signer.change_multisig_public_descriptor(),
            ] {
                anyhow::ensure!(
                    all_public_keys.contains(&descriptor),
                    "Wrong signer added: descriptor public key {descriptor} not found on list {}",
                    all_public_keys.iter().join(", ")
                );
            }
        }
        Ok(())
    }
}

impl PsbtWallet for MultiSigWalletDescriptionV0 {
    fn sign_psbt(&self, psbt: &mut Psbt, secp: &Secp256k1<All>) -> anyhow::Result<usize> {
        let keys = self
            .inputs
            .signers
            .iter()
            .flat_map(|s| s.get_psbt_multisig_keys())
            .collect_vec();
        let n = sign_psbt(psbt, &keys, secp)?;
        Ok(n)
    }

    fn get_pub_fingerprints(&self) -> Vec<Fingerprint> {
        self.inputs
            .signers
            .iter()
            .map(|s| s.get_multisig_pub_fingerprint())
            .collect()
    }

    fn derive_change_addresses(
        &self,
        start: u32,
        quantity: u32,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<Vec<Address>> {
        Ok(self
            .derive_change_addresses(start, quantity, secp)?
            .into_iter()
            .map(|i| i.address)
            .collect())
    }
}

#[derive(Clone)]
pub struct MultiSigCompactWalletDescriptionV0 {
    configuration: MultisigType,
    receiving_descriptors: HashSet<DescriptorPublicKey>,
    change_descriptors: HashSet<DescriptorPublicKey>,
}

impl MultiSigCompactWalletDescriptionV0 {
    pub fn new(
        configuration: MultisigType,
        receiving_descriptor: HashSet<DescriptorPublicKey>,
        change_descriptor: HashSet<DescriptorPublicKey>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            configuration,
            receiving_descriptors: receiving_descriptor,
            change_descriptors: change_descriptor,
        })
    }

    pub fn serialize(&self) -> anyhow::Result<Vec<u8>> {
        let mut w = BufWriter::new(Vec::new());
        VarInt::from(self.configuration.required).serialize(&mut w)?;
        VarInt::from(self.configuration.total).serialize(&mut w)?;
        VarInt(2).serialize(&mut w)?; // two descriptors coming
        for descriptor_set in [&self.receiving_descriptors, &self.change_descriptors] {
            assert_eq!(
                descriptor_set.len(),
                usize::try_from(self.configuration.total)?
            );
            for d in descriptor_set {
                crate::encoding::wallet::serialize_descriptor_pk(d, &mut w)?;
            }
        }
        Ok(w.into_inner()?)
    }

    pub fn deserialize(mut data: BufReader<impl Read>) -> anyhow::Result<Self> {
        fn get_u32(data: &mut BufReader<impl Read>) -> anyhow::Result<u32> {
            Ok(VarInt::deserialize(data)?.0.try_into()?)
        }
        let required = get_u32(&mut data)
            .context("error decoding 'required' field from multisig configuration")?;
        let total = get_u32(&mut data)
            .context("error decoding 'total' field from multisig configuration")?;
        fn get_descriptors(
            n: u32,
            data: &mut BufReader<impl Read>,
        ) -> anyhow::Result<HashSet<DescriptorPublicKey>> {
            let mut descriptors = HashSet::with_capacity(n.try_into()?);
            for _ in 0..n {
                descriptors.insert(crate::encoding::wallet::deserialize_descriptor_pk(data)?);
            }
            Ok(descriptors)
        }
        let descriptors_len = VarInt::deserialize(&mut data)?;
        ensure!(
            descriptors_len == VarInt(2),
            "Found unexpected number of descriptors: {descriptors_len:?}"
        );
        let receiving_descriptors = get_descriptors(total, &mut data)
            .context("error decoding receiving descriptor from multisig")?;
        let change_descriptors = get_descriptors(total, &mut data)
            .context("error decoding change descriptor from multisig")?;
        Ok(Self {
            configuration: MultisigType { required, total },
            receiving_descriptors,
            change_descriptors,
        })
    }

    pub fn to_description(
        self,
        signers: Vec<SingleSigWalletDescriptionV0>,
        network: bitcoin::Network,
        script_type: ScriptType,
    ) -> anyhow::Result<MultiSigWalletDescriptionV0> {
        MultiSigWalletDescriptionV0::generate_from_dpks(
            MultisigInputs {
                receiving_descriptors: self.receiving_descriptors,
                change_descriptors: self.change_descriptors,
                signers,
            },
            self.configuration,
            network,
            script_type,
        )
    }
}

#[derive(Default, Zeroize, ZeroizeOnDrop, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultisigJsonWalletDescriptionV0 {
    pub version: WalletVersionType,
    pub sigtype: String,
    pub receiving_output_descriptor: String,
    pub change_output_descriptor: String,
    pub first_address: String,
    pub network: String,
    pub script_type: String,
}

impl MultisigJsonWalletDescriptionV0 {
    pub fn from_wallet_description(
        w: &MultiSigWalletDescriptionV0,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<Secret<Self>> {
        Ok(Secret::from(Box::new(Self {
            version: ZERO_MULTISIG_WALLET_VERSION,
            sigtype: SigType::Multisig(w.configuration).to_string(),
            receiving_output_descriptor: w.receiving_descriptor.to_string(),
            change_output_descriptor: w.change_descriptor.to_string(),
            first_address: w.first_receiving_address(secp)?.address.to_string(),
            network: w.network.to_string(),
            script_type: w.script_type.to_string(),
        })))
    }

    pub fn network_from_str(s: &str) -> anyhow::Result<Network> {
        Ok(Network::from_str(s)?)
    }

    pub fn network(&self) -> anyhow::Result<Network> {
        Self::network_from_str(&self.network)
    }

    pub fn script_type_from_str(s: &str) -> anyhow::Result<ScriptType> {
        ScriptType::from_str(s)
    }

    pub fn script_type(&self) -> anyhow::Result<ScriptType> {
        Self::script_type_from_str(&self.script_type)
    }

    pub fn descriptor_from_str(
        s: &str,
    ) -> anyhow::Result<miniscript::descriptor::Descriptor<DescriptorPublicKey>> {
        Ok(miniscript::descriptor::Descriptor::<DescriptorPublicKey>::from_str(s)?)
    }

    pub fn receiving_output_descriptor(
        &self,
    ) -> anyhow::Result<miniscript::descriptor::Descriptor<DescriptorPublicKey>> {
        Self::descriptor_from_str(&self.receiving_output_descriptor)
    }

    pub fn change_output_descriptor(
        &self,
    ) -> anyhow::Result<miniscript::descriptor::Descriptor<DescriptorPublicKey>> {
        Self::descriptor_from_str(&self.change_output_descriptor)
    }

    pub fn configuration_from_str(s: &str) -> anyhow::Result<MultisigType> {
        MultisigType::from_str(s)
    }

    pub fn configuration(&self) -> anyhow::Result<MultisigType> {
        Self::configuration_from_str(&self.sigtype)
    }

    pub fn validate_same(
        source: &Secret<MultisigJsonWalletDescriptionV0>,
        w: &MultiSigWalletDescriptionV0,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<Result<(), MultiSigValidationError>> {
        let source = source.expose_secret();
        let w = Self::from_wallet_description(w, secp)?;
        let generated = w.expose_secret();
        if generated.receiving_output_descriptor != source.receiving_output_descriptor {
            Ok(Err(MultiSigValidationError::OutputDescriptorMismatch))
        } else if generated.version != source.version {
            Ok(Err(MultiSigValidationError::VersionMismatch))
        } else if generated.network != source.network {
            Ok(Err(MultiSigValidationError::NetworkMismatch))
        } else if generated.sigtype != source.sigtype {
            Ok(Err(MultiSigValidationError::ConfigurationMismatch))
        } else if generated.script_type != source.script_type {
            Ok(Err(MultiSigValidationError::ScriptTypeMismatch))
        } else if generated.first_address != source.first_address {
            Ok(Err(MultiSigValidationError::FirstAddressMismatch))
        } else {
            Ok(Ok(()))
        }
    }

    pub fn deserialize<R: Read>(data: R) -> anyhow::Result<Secret<Self>> {
        let w = serde_json::from_reader::<_, Self>(data).context("failure parsing wallet json")?;
        anyhow::ensure!(
            w.version == ZERO_MULTISIG_WALLET_VERSION,
            "Version {} isn't {ZERO_MULTISIG_WALLET_VERSION}",
            w.version
        );
        Ok(Secret::from(Box::new(w)))
    }

    pub fn to_vec(&self) -> anyhow::Result<SecretBox<Vec<u8>>> {
        Ok(SecretBox::from(Box::new(
            serde_json::to_vec(self).context("failure serializing json")?,
        )))
    }

    pub fn to_vec_pretty(&self) -> anyhow::Result<SecretBox<Vec<u8>>> {
        Ok(SecretBox::from(Box::new(
            serde_json::to_vec_pretty(self).context("failure serializing json")?,
        )))
    }

    pub fn to_string_pretty(&self) -> anyhow::Result<SecretString> {
        Ok(SecretString::new(
            serde_json::to_string_pretty(self)
                .context("failure serializing json")?
                .into(),
        ))
    }
}

pub trait PsbtWallet {
    fn sign_psbt(&self, psbt: &mut Psbt, secp: &Secp256k1<All>) -> anyhow::Result<usize>;

    fn get_pub_fingerprints(&self) -> Vec<Fingerprint>;

    fn derive_change_addresses(
        &self,
        start: u32,
        quantity: u32,
        secp: &Secp256k1<All>,
    ) -> anyhow::Result<Vec<Address>>;
}

#[derive(Clone)]
pub struct WExtendedPrivKey(pub bitcoin::bip32::Xpriv);

impl Zeroize for WExtendedPrivKey {
    fn zeroize(&mut self) {
        // TODO: find a safe way to do it
        // self.0.private_key.as_ref().zeroize();
        // self.0.chain_code.as_bytes().zeroize();
    }
}

impl CloneableSecret for WExtendedPrivKey {}

#[derive(Copy, Clone)]
pub enum WordCount {
    W12,
    W24,
}

impl WordCount {
    pub fn to_integer(&self) -> u8 {
        match self {
            WordCount::W12 => 12,
            WordCount::W24 => 24,
        }
    }
}

pub fn generate_entropy_for_seeds<Rng: CryptoRng + RngCore>(
    entropy_bytes: usize,
    rng: &mut Rng,
) -> Result<[u8; (MAX_NB_WORDS / 3) * 4], anyhow::Error> {
    let mut entropy = [0u8; (MAX_NB_WORDS / 3) * 4];
    rng.fill_bytes(&mut entropy[0..entropy_bytes]);
    Ok(entropy)
}

pub fn calculate_seed_entropy_bytes(word_count: WordCount) -> usize {
    let word_count: usize = word_count.to_integer().into();
    (word_count / 3) * 4
}

pub fn generate_seeds_from_entropy(
    entropy_bytes: usize,
    entropy: &[u8; (MAX_NB_WORDS / 3) * 4],
    language: bip39::Language,
) -> anyhow::Result<Secret<bip39::Mnemonic>> {
    let mnemonic = bip39::Mnemonic::from_entropy_in(language, &entropy[0..entropy_bytes])?;
    Ok(Secret::from(Box::new(mnemonic)))
}

pub fn generate_seeds<Rng: CryptoRng + RngCore>(
    rng: &mut Rng,
    word_count: WordCount,
    language: bip39::Language,
) -> anyhow::Result<Secret<bip39::Mnemonic>> {
    let entropy_bytes = calculate_seed_entropy_bytes(word_count);
    let entropy = generate_entropy_for_seeds(entropy_bytes, rng)?;
    generate_seeds_from_entropy(entropy_bytes, &entropy, language)
}

fn get_root_key(
    mnemonic: &Secret<bip39::Mnemonic>,
    passphrase: &SecretString,
    network: bitcoin::Network,
) -> anyhow::Result<Secret<WExtendedPrivKey>> {
    let seed = Secret::from(Box::new(
        mnemonic.expose_secret().to_seed(passphrase.expose_secret()),
    ));
    let root = Secret::from(Box::new(WExtendedPrivKey(
        bitcoin::bip32::Xpriv::new_master(network, seed.expose_secret())?,
    )));
    Ok(root)
}

// See https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki and https://github.com/satoshilabs/slips/blob/master/slip-0132.md
fn m84_slip132_encode_priv(key: &Secret<WExtendedPrivKey>) -> String {
    crate::slip132::ToSlip132::to_slip132_string(
        &key.expose_secret().0,
        crate::slip132::KeyApplication::SegWit,
        key.expose_secret().0.network,
    )
}

fn m84_slip132_encode_pub(key: &bitcoin::bip32::Xpub) -> String {
    crate::slip132::ToSlip132::to_slip132_string(
        key,
        crate::slip132::KeyApplication::SegWit,
        key.network,
    )
}

// See https://github.com/bitcoin/bips/blob/master/bip-0048.mediawiki
fn m48_slip132_encode_priv(key: &Secret<WExtendedPrivKey>) -> String {
    crate::slip132::ToSlip132::to_slip132_string(
        &key.expose_secret().0,
        crate::slip132::KeyApplication::SegWitMultisig,
        key.expose_secret().0.network,
    )
}

fn m48_slip132_encode_pub(key: &bitcoin::bip32::Xpub) -> String {
    crate::slip132::ToSlip132::to_slip132_string(
        key,
        crate::slip132::KeyApplication::SegWitMultisig,
        key.network,
    )
}

pub(crate) fn slip132_decode_pub(key: &str) -> anyhow::Result<bitcoin::bip32::Xpub> {
    crate::slip132::FromSlip132::from_slip132_str(key)
}

pub fn read_decode_wallet(output_file_path: &Path) -> anyhow::Result<EncryptedWalletDescription> {
    EncryptedWalletDescription::from_path(output_file_path)
        .context("the given file is invalid or the wallet has been corrupted, try another file")
}

pub const NONCE_SIZE: usize = 24;
pub const KEY_SIZE: usize = 32;
pub const SALT_SIZE: usize = 16;

pub enum DecryptedWallet {
    SingleSig(Secret<SinglesigJsonWalletDescriptionV0>),
    MultiSig(Secret<MultisigJsonWalletDescriptionV0>),
}

impl DecryptedWallet {
    pub fn singlesig(self) -> Option<Secret<SinglesigJsonWalletDescriptionV0>> {
        match self {
            Self::SingleSig(v) => Some(v),
            Self::MultiSig(_) => None,
        }
    }

    pub fn multisig(self) -> Option<Secret<MultisigJsonWalletDescriptionV0>> {
        match self {
            Self::MultiSig(v) => Some(v),
            Self::SingleSig(_) => None,
        }
    }
}

fn decrypt_header<'a>(
    nonce: &[u8; NONCE_SIZE],
    encrypted_header: &[u8; ENCRYPTED_HEADER_LENGTH],
    ciphertext: &'a [u8],
    key: &SecretBox<[u8; KEY_SIZE]>,
) -> anyhow::Result<(DecodedHeaderV0, &'a [u8])> {
    let header =
        default_decrypt(key, nonce, encrypted_header).context("failure decrypting header")?;
    let header = DecodedHeaderV0::deserialize(BufReader::new(header.expose_secret().as_slice()))?;
    let ciphertext_length: usize = header.length.try_into()?;
    anyhow::ensure!(
        ciphertext_length <= ciphertext.len(),
        "ciphertext is too small: only {} instead of at least {} bytes",
        ciphertext.len(),
        header.length
    );
    let ciphertext = &ciphertext[0..ciphertext_length];
    Ok((header, ciphertext))
}

fn get_uncompressed_wallet(
    header: &DecodedHeaderV0,
    ciphertext: &[u8],
) -> anyhow::Result<SecretBox<Vec<u8>>> {
    let compressed = default_decrypt(&header.key, &header.nonce, ciphertext)
        .context("failure decrypting data")?;
    let uncompressed = SecretBox::from(Box::new(
        uncompress(compressed.expose_secret()).context("failure uncompressing decrypted data")?,
    ));
    Ok(uncompressed)
}

fn from_compact_wallet(
    header: &DecodedHeaderV0,
    ciphertext: &[u8],
) -> anyhow::Result<SingleSigCompactWalletDescriptionV0> {
    let ciphertext = default_decrypt(&header.key, &header.nonce, ciphertext)
        .context("failure decrypting data")?;
    let reader = BufReader::new(ciphertext.expose_secret().as_slice());
    let compact = SingleSigCompactWalletDescriptionV0::deserialize(reader)?;
    Ok(compact)
}

// TODO: perhaps the best would be to return the wallet description here
fn decrypt_wallet_singlesig(
    nonce: &[u8; NONCE_SIZE],
    encrypted_header: &[u8; ENCRYPTED_HEADER_LENGTH],
    ciphertext: &[u8],
    key: &SecretBox<[u8; KEY_SIZE]>,
    seed_password: &Option<Arc<SecretString>>,
    secp: &Secp256k1<All>,
) -> anyhow::Result<Secret<SinglesigJsonWalletDescriptionV0>> {
    let (decrypted_header, ciphertext) = decrypt_header(nonce, encrypted_header, ciphertext, key)?;
    match decrypted_header.version {
        EncryptedWalletVersion::V0Standard => {
            let uncompressed = get_uncompressed_wallet(&decrypted_header, ciphertext)?;
            SinglesigJsonWalletDescriptionV0::deserialize(BufReader::new(
                uncompressed.expose_secret().as_slice(),
            ))
        }
        EncryptedWalletVersion::V0CompactMainnet | EncryptedWalletVersion::V0CompactTestnet => {
            let script_type = ScriptType::SegwitNative;
            let network = if decrypted_header.version == EncryptedWalletVersion::V0CompactMainnet {
                Network::Bitcoin
            } else {
                Network::Testnet
            };
            let compact = from_compact_wallet(&decrypted_header, ciphertext)?;
            // TODO: this intermediate wallet description is a bit unnecessary, try to optimize this whole process
            let wallet = compact.to_description(seed_password, network, script_type, secp)?;
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, secp)
        }
    }
}

fn decrypt_wallet_multisig(
    nonce: &[u8; NONCE_SIZE],
    encrypted_header: &[u8; ENCRYPTED_HEADER_LENGTH],
    ciphertext: &[u8],
    key: &SecretBox<[u8; KEY_SIZE]>,
    secp: &Secp256k1<All>,
) -> anyhow::Result<Secret<MultisigJsonWalletDescriptionV0>> {
    let (header, ciphertext) = decrypt_header(nonce, encrypted_header, ciphertext, key)?;
    match header.version {
        EncryptedWalletVersion::V0Standard => {
            let uncompressed = get_uncompressed_wallet(&header, ciphertext)?;
            MultisigJsonWalletDescriptionV0::deserialize(BufReader::new(
                uncompressed.expose_secret().as_slice(),
            ))
        }
        EncryptedWalletVersion::V0CompactMainnet | EncryptedWalletVersion::V0CompactTestnet => {
            let script_type = ScriptType::SegwitNative;
            let network = if header.version == EncryptedWalletVersion::V0CompactMainnet {
                Network::Bitcoin
            } else {
                Network::Testnet
            };
            let uncompressed = get_uncompressed_wallet(&header, ciphertext)?;
            let reader = BufReader::new(uncompressed.expose_secret().as_slice());
            let compact = MultiSigCompactWalletDescriptionV0::deserialize(reader)?;
            // TODO: this intermediate wallet description is a bit unnecessary, try to optimize this whole process
            let wallet = compact.to_description(vec![], network, script_type)?;
            MultisigJsonWalletDescriptionV0::from_wallet_description(&wallet, secp)
        }
    }
}

type HeaderVersionType = u32;
type HeaderLengthType = u32;

const HEADER_VERSION_SIZE: usize = size_of::<HeaderVersionType>();
const HEADER_LENGTH_SIZE: usize = size_of::<HeaderLengthType>();
const HEADER_LENGTH: usize = KEY_SIZE + NONCE_SIZE + HEADER_VERSION_SIZE + HEADER_LENGTH_SIZE;
pub(crate) const ENCRYPTED_HEADER_LENGTH: usize = HEADER_LENGTH + MAC_LENGTH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedWalletVersion {
    V0Standard,
    V0CompactMainnet,
    V0CompactTestnet,
}

impl EncryptedWalletVersion {
    fn from_bytes(bytes: [u8; HEADER_VERSION_SIZE]) -> anyhow::Result<Self> {
        let version = HeaderVersionType::from_le_bytes(bytes);
        match version {
            STANDARD_ENCRYPTED_WALLET_VERSION => Ok(Self::V0Standard),
            COMPACT_ENCRYPTED_MAINNET_WALLET_VERSION => Ok(Self::V0CompactMainnet),
            COMPACT_ENCRYPTED_TESTNET_WALLET_VERSION => Ok(Self::V0CompactTestnet),
            other => bail!("Got header version {other}, which isn't supported"),
        }
    }

    fn to_bytes(self) -> [u8; HEADER_VERSION_SIZE] {
        let version: HeaderVersionType = match self {
            EncryptedWalletVersion::V0Standard => STANDARD_ENCRYPTED_WALLET_VERSION,
            EncryptedWalletVersion::V0CompactMainnet => COMPACT_ENCRYPTED_MAINNET_WALLET_VERSION,
            EncryptedWalletVersion::V0CompactTestnet => COMPACT_ENCRYPTED_TESTNET_WALLET_VERSION,
        };
        version.to_le_bytes()
    }
}

pub(crate) struct DecodedHeaderV0 {
    key: SecretBox<[u8; KEY_SIZE]>,
    nonce: [u8; NONCE_SIZE],
    version: EncryptedWalletVersion,
    length: HeaderLengthType,
}

impl DecodedHeaderV0 {
    pub(crate) fn new(
        key: SecretBox<[u8; KEY_SIZE]>,
        nonce: [u8; NONCE_SIZE],
        version: EncryptedWalletVersion,
        length: u32,
    ) -> Self {
        Self {
            key,
            nonce,
            version,
            length,
        }
    }

    fn deserialize(mut reader: BufReader<impl Read>) -> anyhow::Result<Self> {
        let mut key = [0u8; KEY_SIZE];
        reader.read_exact(&mut key).context("failure reading key")?;
        let mut nonce = [0u8; NONCE_SIZE];
        reader
            .read_exact(&mut nonce)
            .context("failure reading nonce")?;
        let mut version = [0u8; HEADER_VERSION_SIZE];
        reader
            .read_exact(&mut version)
            .context("failure reading version")?;
        let version =
            EncryptedWalletVersion::from_bytes(version).context("failure decoding version")?;
        let mut length = [0u8; HEADER_LENGTH_SIZE];
        reader
            .read_exact(&mut length)
            .context("failure reading length")?;
        let length = HeaderLengthType::from_le_bytes(length);
        anyhow::ensure!(length > 0, "Got zero on header length");
        Ok(Self {
            nonce,
            key: Secret::from(Box::new(key)),
            version,
            length,
        })
    }

    pub(crate) fn serialize(&self) -> anyhow::Result<Secret<Vec<u8>>> {
        let mut writer = BufWriter::new(Vec::with_capacity(HEADER_LENGTH));
        writer.write_all(self.key.expose_secret())?;
        writer.write_all(&self.nonce)?;
        writer.write_all(&self.version.to_bytes())?;
        writer.write_all(&self.length.to_le_bytes())?;
        let secret = writer.into_inner()?;
        assert_eq!(secret.len(), HEADER_LENGTH);
        Ok(Secret::from(Box::new(secret)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random_generation_utils::{get_random_key, get_random_nonce, get_secp};

    #[test]
    fn test_seed_address_generation() -> anyhow::Result<()> {
        use pretty_assertions::assert_eq;
        // BIP 84 test vectors
        let seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Secret::from(Box::new(bip39::Mnemonic::from_str(seed_phrase)?));
        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        let w = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )?;
        assert_eq!(
            w.first_receiving_address(&secp)?.to_string(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        let second_address = w.derive_receiving_address(1, &secp)?;
        assert_eq!(
            second_address.to_string(),
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
        );
        let jsonw = SinglesigJsonWalletDescriptionV0::from_wallet_description(&w, &secp)?;
        assert_eq!(
            jsonw.expose_secret().singlesig_xpriv,
            "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE"
        );
        assert_eq!(
            jsonw.expose_secret().singlesig_xpub,
            "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
        );

        Ok(())
    }

    // #[test]
    // fn test_multi() -> anyhow::Result<()> {
    //     let seed_phrase =
    //         "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    //     let mnemonic = Secret::new(bip39::Mnemonic::from_str(seed_phrase)?);
    //     let root_key = get_root_key(&mnemonic, &SecretString::new("".into()), Network::Bitcoin)?;
    //     let mut rng = rand::thread_rng();
    //     let secp = get_secp(&mut rng);
    //     let derivation_path = DerivationPath::from_str("48'/0'/0'/2'")?;
    //     let xpriv = Secret::new(WExtendedPrivKey(
    //         root_key
    //             .expose_secret()
    //             .0
    //             .derive_priv(&secp, &derivation_path)?,
    //     ));
    //     let xpub = bitcoin::bip32::Xpub::from_priv(&secp, &xpriv.expose_secret().0);
    //     println!("{xpub}");
    //     println!(
    //         "master fp {}",
    //         root_key.expose_secret().0.fingerprint(&secp)
    //     );
    //     println!(
    //         "slip {}",
    //         slip132::ToSlip132::to_slip132_string(
    //             &xpub,
    //             slip132::KeyApplication::SegWitMultisig,
    //             Network::Bitcoin,
    //         )
    //     );
    //     let zero = bitcoin::bip32::ChildNumber::from_normal_idx(0)?;
    //     let public_key = xpub.derive_pub(&secp, &vec![zero, zero])?.public_key;
    //     let w = miniscript::descriptor::Wsh::new_sortedmulti(1, vec![public_key])?;
    //     println!("{}", w.to_string());
    //     let first = w.address(Network::Bitcoin);
    //     let key = miniscript::DescriptorPublicKey::from_str("[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/*")?;
    //     // key.at_derivation_index(0)
    //     let w = miniscript::descriptor::Wsh::new_sortedmulti(1, vec![key])?;
    //     println!("{}", w.to_string());
    //     use bitcoin::bip32;
    //     miniscript::DescriptorPublicKey::XPub(miniscript::descriptor::DescriptorXKey {
    //         origin: Some((
    //             bip32::Fingerprint::from(&[0x78, 0x41, 0x2e, 0x3a][..]),
    //             (&[
    //                 bip32::ChildNumber::from_hardened_idx(44).unwrap(),
    //                 bip32::ChildNumber::from_hardened_idx(0).unwrap(),
    //                 bip32::ChildNumber::from_hardened_idx(0).unwrap(),
    //             ][..])
    //             .into(),
    //         )),
    //         xkey: bip32::ExtendedPubKey::from_str("xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL").unwrap(),
    //         derivation_path: (&[bip32::ChildNumber::from_normal_idx(1).unwrap()][..]).into(),
    //         wildcard: miniscript::descriptor::Wildcard::Unhardened,
    //     });
    //     Ok(())
    // }

    #[test]
    fn test_header_encoding_decoding() -> anyhow::Result<()> {
        use pretty_assertions::assert_eq;

        println!("header length: {ENCRYPTED_HEADER_LENGTH}");
        let mut rng = rand::thread_rng();

        let key = Secret::from(Box::new(get_random_key(&mut rng)?));
        let nonce = get_random_nonce(&mut rng)?;

        let original =
            DecodedHeaderV0::new(key, nonce, EncryptedWalletVersion::V0CompactMainnet, 123);
        let decoded = DecodedHeaderV0::deserialize(BufReader::new(
            original.serialize()?.expose_secret().as_slice(),
        ))?;
        assert_eq!(original.key.expose_secret(), decoded.key.expose_secret());
        assert_eq!(original.nonce, decoded.nonce);
        assert_eq!(original.version, decoded.version);
        assert_eq!(original.length, decoded.length);
        Ok(())
    }

    #[test]
    fn test_parse_sigtype() -> anyhow::Result<()> {
        use pretty_assertions::assert_eq;
        assert_eq!(SigType::from_str("singlesig")?, SigType::Singlesig);
        assert!(SigType::from_str("multisig").is_err());
        assert!(SigType::from_str("0-of-0").is_err());
        assert!(SigType::from_str("0-of-1").is_err());
        assert_eq!(
            SigType::from_str("1-of-1")?,
            SigType::Multisig(MultisigType {
                required: 1,
                total: 1
            })
        );
        assert_eq!(
            SigType::from_str("1-of-2")?,
            SigType::Multisig(MultisigType {
                required: 1,
                total: 2
            })
        );
        assert!(SigType::from_str("2-of-1").is_err());
        assert_eq!(
            SigType::from_str("2-of-2")?,
            SigType::Multisig(MultisigType {
                required: 2,
                total: 2
            })
        );
        assert_eq!(
            SigType::from_str("2-of-3")?,
            SigType::Multisig(MultisigType {
                required: 2,
                total: 3
            })
        );
        assert_eq!(
            SigType::from_str("3 OF 5")?,
            SigType::Multisig(MultisigType {
                required: 3,
                total: 5
            })
        );
        assert_eq!(
            SigType::from_str("10 Of15")?,
            SigType::Multisig(MultisigType {
                required: 10,
                total: 15
            })
        );
        assert!(SigType::from_str("3of16").is_err());
        assert!(SigType::from_str("m-of-n").is_err());
        Ok(())
    }
}
