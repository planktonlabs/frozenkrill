use std::{collections::HashSet, path::PathBuf, sync::Arc};

use anyhow::{bail, ensure, Context};
use bip39::Mnemonic;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{
    bip32::{DerivationPath, Fingerprint},
    Network,
};
use compression::compress;
use encryption::default_encrypt;
use itertools::Itertools;
use log::debug;
use miniscript::{Descriptor, DescriptorPublicKey};
use rand_core::{CryptoRng, RngCore};
use secrecy::{ExposeSecret, SecretBox, SecretString};
type Secret<T> = SecretBox<T>;
type SecretVec<T> = SecretBox<Vec<T>>;
use wallet_description::{
    EncryptedWalletDescription, EncryptedWalletVersion, MultiSigCompactWalletDescriptionV0,
    MultisigType, ScriptType, SingleSigCompactWalletDescriptionV0, SingleSigWalletDescriptionV0,
    SinglesigJsonWalletDescriptionV0, KEY_SIZE, NONCE_SIZE, SALT_SIZE,
};

use crate::wallet_description::{
    DecodedHeaderV0, MultiSigWalletDescriptionV0, MultisigJsonWalletDescriptionV0,
    ENCRYPTED_HEADER_LENGTH,
};

pub mod compression;
pub mod custom_logger;
pub mod encoding;
pub mod encryption;
pub mod key_derivation;
pub mod mnemonic_utils;
pub mod psbt;
pub mod random_generation_utils;
pub mod slip132;
pub mod utils;
pub mod wallet_description;
pub mod wallet_export;

pub use {
    anyhow, bip39, bitcoin, blake3, env_logger, hex, itertools, log, miniscript, rand, rand_core,
    rayon, secrecy, serde, serde_json,
};

pub struct PaddingParams {
    disable_all_padding: bool,
    min: u32,
    max: u32,
}

impl Default for PaddingParams {
    fn default() -> Self {
        Self::new(false, None, None).expect("default to be consistent")
    }
}

impl PaddingParams {
    pub fn new(
        disable_all_padding: bool,
        min: Option<u32>,
        max: Option<u32>,
    ) -> anyhow::Result<Self> {
        let min = min.unwrap_or(DEFAULT_MIN_ADDITIONAL_PADDING);
        let max = max.unwrap_or_else(|| Ord::max(min, DEFAULT_MAX_ADDITIONAL_PADDING));
        anyhow::ensure!(
            min <= max,
            "Minimum padding {min} is greater than max padding {max}"
        );
        anyhow::ensure!(
            max <= MAX_ADDITIONAL_PADDING,
            "Given max padding bytes {max} is greater than limit {MAX_ADDITIONAL_PADDING}"
        );
        Ok(Self {
            disable_all_padding,
            min,
            max,
        })
    }
}

#[derive(Clone)]
pub struct CiphertextPadder {
    base_padding_bytes: Option<[u8; MAX_BASE_PADDING_BYTES]>,
    additional_padding_bytes: Option<Vec<u8>>,
}

impl CiphertextPadder {
    pub fn pad(self, ciphertext: &mut Vec<u8>) -> anyhow::Result<()> {
        if let Some(base_padding_bytes) = self.base_padding_bytes {
            anyhow::ensure!(
                ciphertext.len() <= MINIMUM_CIPHERTEXT_SIZE_BYTES,
                "Pre padded ciphertext size {} is already greater than {MINIMUM_CIPHERTEXT_SIZE_BYTES}",
                ciphertext.len()
            );
            ciphertext.extend_from_slice(&base_padding_bytes);
            anyhow::ensure!(
                ciphertext.len() >= MINIMUM_CIPHERTEXT_SIZE_BYTES,
                "Not enough padding bytes to bring ciphertext size from {} to at least {MINIMUM_CIPHERTEXT_SIZE_BYTES}",
                ciphertext.len()
            );
            ciphertext.truncate(MINIMUM_CIPHERTEXT_SIZE_BYTES);
        }
        if let Some(mut additional_padding_bytes) = self.additional_padding_bytes {
            ciphertext.append(&mut additional_padding_bytes);
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn generate_encrypted_encoded_singlesig_wallet(
    key: &SecretBox<[u8; KEY_SIZE]>,
    header_key: SecretBox<[u8; KEY_SIZE]>,
    mnemonic: Arc<Secret<Mnemonic>>,
    seed_password: &Option<Arc<SecretString>>,
    salt: [u8; SALT_SIZE],
    nonce: [u8; NONCE_SIZE],
    header_nonce: [u8; NONCE_SIZE],
    padder: CiphertextPadder,
    script_type: ScriptType,
    network: Network,
    encrypted_version: EncryptedWalletVersion,
    secp: &Secp256k1<All>,
) -> anyhow::Result<Vec<u8>> {
    match encrypted_version {
        EncryptedWalletVersion::V0Standard => generate_encrypted_encoded_singlesig_wallet_standard(
            key,
            header_key,
            mnemonic,
            seed_password,
            salt,
            nonce,
            header_nonce,
            padder,
            script_type,
            network,
            secp,
        ),
        EncryptedWalletVersion::V0CompactMainnet | EncryptedWalletVersion::V0CompactTestnet => {
            generate_encrypted_encoded_singlesig_wallet_compact(
                key,
                header_key,
                mnemonic,
                salt,
                nonce,
                header_nonce,
                encrypted_version,
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn generate_encrypted_encoded_singlesig_wallet_standard(
    key: &SecretBox<[u8; KEY_SIZE]>,
    header_key: SecretBox<[u8; KEY_SIZE]>,
    mnemonic: Arc<Secret<Mnemonic>>,
    seed_password: &Option<Arc<SecretString>>,
    salt: [u8; SALT_SIZE],
    nonce: [u8; NONCE_SIZE],
    header_nonce: [u8; NONCE_SIZE],
    padder: CiphertextPadder,
    script_type: ScriptType,
    network: Network,
    secp: &Secp256k1<All>,
) -> anyhow::Result<Vec<u8>> {
    let compressed: SecretBox<Vec<u8>> = {
        let json: SecretBox<Vec<u8>> = {
            let wallet_description = SingleSigWalletDescriptionV0::generate(
                mnemonic,
                seed_password,
                network,
                script_type,
                secp,
            )
            .context("failure generating wallet")?;
            let json_wallet_description =
                SinglesigJsonWalletDescriptionV0::from_wallet_description(
                    &wallet_description,
                    secp,
                )?;
            json_wallet_description.expose_secret().to_vec()?
        };
        SecretBox::from(Box::new(
            compress(json.expose_secret()).context("failure compressing json")?,
        ))
    };
    let mut ciphertext = default_encrypt(&header_key, &header_nonce, &compressed)
        .context("failure encrypting compressed json")?;
    let header = DecodedHeaderV0::new(
        header_key,
        header_nonce,
        EncryptedWalletVersion::V0Standard,
        ciphertext.len().try_into().with_context(|| {
            format!(
                "resulting ciphertext is too big: {} bytes",
                ciphertext.len()
            )
        })?,
    );
    let mut encrypted_header = [0u8; ENCRYPTED_HEADER_LENGTH];
    encrypted_header.copy_from_slice(
        &default_encrypt(
            key,
            &nonce,
            &header.serialize().context("failure encoding header")?,
        )
        .context("failure encrypting header")?,
    );
    padder.pad(&mut ciphertext)?;
    EncryptedWalletDescription::new(nonce, salt, encrypted_header, ciphertext)
        .serialize()
        .context("failure encoding encrypted wallet")
}

#[allow(clippy::too_many_arguments)]
pub fn generate_encrypted_encoded_singlesig_wallet_compact(
    key: &SecretBox<[u8; KEY_SIZE]>,
    header_key: SecretBox<[u8; KEY_SIZE]>,
    mnemonic: Arc<Secret<Mnemonic>>,
    salt: [u8; SALT_SIZE],
    nonce: [u8; NONCE_SIZE],
    header_nonce: [u8; NONCE_SIZE],
    header_version: EncryptedWalletVersion,
) -> anyhow::Result<Vec<u8>> {
    let wallet_description =
        SingleSigCompactWalletDescriptionV0::new(mnemonic).context("failure generating wallet")?;
    let ciphertext = default_encrypt(&header_key, &header_nonce, &wallet_description.serialize())
        .context("failure encrypting wallet")?;
    let header = DecodedHeaderV0::new(
        header_key,
        header_nonce,
        header_version,
        ciphertext.len().try_into().with_context(|| {
            format!(
                "resulting ciphertext is too big: {} bytes",
                ciphertext.len()
            )
        })?,
    );
    let mut encrypted_header = [0u8; ENCRYPTED_HEADER_LENGTH];
    encrypted_header.copy_from_slice(
        &default_encrypt(
            key,
            &nonce,
            &header.serialize().context("failure encoding header")?,
        )
        .context("failure encrypting header")?,
    );
    EncryptedWalletDescription::new(nonce, salt, encrypted_header, ciphertext)
        .serialize()
        .context("failure encoding encrypted wallet")
}

pub fn ms_dpks_to_ddpk(
    descriptors: HashSet<DescriptorPublicKey>,
    configuration: &MultisigType,
    script_type: ScriptType,
) -> anyhow::Result<Descriptor<DescriptorPublicKey>> {
    match script_type {
        ScriptType::SegwitNative => Ok(miniscript::Descriptor::new_wsh_sortedmulti(
            configuration.required.try_into()?,
            descriptors.into_iter().sorted_by(Ord::cmp).collect(),
        )?),
    }
}

pub fn ms_ddpk_to_dpks(
    descriptors: &Descriptor<DescriptorPublicKey>,
    configuration: &MultisigType,
    script_type: &ScriptType,
) -> anyhow::Result<HashSet<DescriptorPublicKey>> {
    match script_type {
        ScriptType::SegwitNative => match descriptors {
            Descriptor::Wsh(d) => match d.as_inner() {
                miniscript::descriptor::WshInner::SortedMulti(dpks) => {
                    let k = dpks.k();
                    let required = usize::try_from(configuration.required)?;
                    ensure!(
                        k == required,
                        "expected required keys to be {required} but got {k}"
                    );
                    let n = dpks.n();
                    let total = usize::try_from(configuration.total)?;
                    ensure!(n == total, "expected total keys to be {total} but got {n}");
                    Ok(dpks.pks().iter().cloned().collect())
                }
                _other => bail!("Expected sorted multi Wsh, got {descriptors:?}"),
            },
            other => bail!("Expected Wsh script type, got {other:?}"),
        },
    }
}

#[allow(clippy::too_many_arguments)]
pub fn generate_encrypted_encoded_multisig_wallet(
    configuration: MultisigType,
    inputs: MultisigInputs,
    key: &SecretBox<[u8; KEY_SIZE]>,
    header_key: SecretBox<[u8; KEY_SIZE]>,
    salt: [u8; SALT_SIZE],
    nonce: [u8; NONCE_SIZE],
    header_nonce: [u8; NONCE_SIZE],
    padder: CiphertextPadder,
    script_type: ScriptType,
    network: Network,
    encrypted_wallet_version: EncryptedWalletVersion,
    secp: &Secp256k1<All>,
) -> anyhow::Result<Vec<u8>> {
    let serialized = match encrypted_wallet_version {
        EncryptedWalletVersion::V0Standard => {
            debug!("Creating standard wallet");
            let wallet_description = MultiSigWalletDescriptionV0::generate_from_dpks(
                inputs,
                configuration,
                network,
                script_type,
            )
            .context("failure generating wallet")?;
            let json: SecretBox<Vec<u8>> = {
                let json_wallet_description =
                    MultisigJsonWalletDescriptionV0::from_wallet_description(
                        &wallet_description,
                        secp,
                    )?;
                json_wallet_description.expose_secret().to_vec()?
            };
            compress(json.expose_secret()).context("failure compressing json")?
        }
        EncryptedWalletVersion::V0CompactMainnet | EncryptedWalletVersion::V0CompactTestnet => {
            debug!("Creating compact wallet");
            let wallet = MultiSigCompactWalletDescriptionV0::new(
                configuration,
                inputs.receiving_descriptors,
                inputs.change_descriptors,
            )?;
            compress(&wallet.serialize()?).context("failure compressing compact wallet")?
        }
    };
    debug!("Serialized wallet with length {}", serialized.len());
    let serialized = SecretBox::from(Box::new(serialized));
    let mut ciphertext = default_encrypt(&header_key, &header_nonce, &serialized)
        .context("failure encrypting compressed json")?;
    let header = DecodedHeaderV0::new(
        header_key,
        header_nonce,
        encrypted_wallet_version,
        ciphertext.len().try_into().with_context(|| {
            format!(
                "resulting ciphertext is too big: {} bytes",
                ciphertext.len()
            )
        })?,
    );
    let mut encrypted_header = [0u8; ENCRYPTED_HEADER_LENGTH];
    encrypted_header.copy_from_slice(
        &default_encrypt(
            key,
            &nonce,
            &header.serialize().context("failure encoding header")?,
        )
        .context("failure encrypting header")?,
    );
    match encrypted_wallet_version {
        EncryptedWalletVersion::V0Standard => {
            padder.pad(&mut ciphertext)?;
        }
        EncryptedWalletVersion::V0CompactMainnet | EncryptedWalletVersion::V0CompactTestnet => {
            debug!("Ignoring padder as we are are generating a compact wallet");
        }
    };
    EncryptedWalletDescription::new(nonce, salt, encrypted_header, ciphertext)
        .serialize()
        .context("failure encoding encrypted wallet")
}

fn expand_keyfiles(keyfiles: &[String]) -> anyhow::Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    for keyfile in keyfiles {
        for k in walkdir::WalkDir::new(keyfile).follow_links(true) {
            let k = k?;
            log::debug!("Keyfile expansion walk: {k:?}");
            if k.file_type().is_file() {
                result.push(k.path().to_owned())
            }
        }
    }
    Ok(result)
}

pub fn parse_keyfiles_paths(keyfiles: &[String]) -> anyhow::Result<Vec<PathBuf>> {
    if keyfiles.is_empty() {
        Ok(Vec::new())
    } else {
        let keyfiles = expand_keyfiles(keyfiles).context("failure checking keyfiles paths")?;
        anyhow::ensure!(
            !keyfiles.is_empty(),
            "The expansion of the keyfiles yielded no files (probably an empty directory was given)"
        );
        Ok(keyfiles)
    }
}

pub const MAX_BASE_PADDING_BYTES: usize = 2000;
pub const MINIMUM_CIPHERTEXT_SIZE_BYTES: usize = 1200;

pub const DEFAULT_MIN_ADDITIONAL_PADDING: u32 = 0;
pub const DEFAULT_MAX_ADDITIONAL_PADDING: u32 = 1000;
pub const MAX_ADDITIONAL_PADDING: u32 = 1_000_000_000;

pub fn get_padder(
    rng: &mut (impl CryptoRng + RngCore),
    params: &PaddingParams,
) -> anyhow::Result<CiphertextPadder> {
    if params.disable_all_padding {
        Ok(CiphertextPadder {
            base_padding_bytes: None,
            additional_padding_bytes: None,
        })
    } else {
        Ok(CiphertextPadder {
            base_padding_bytes: Some(
                crate::random_generation_utils::get_base_random_padding_bytes(rng)?,
            ),
            additional_padding_bytes: Some(
                crate::random_generation_utils::get_additional_random_padding_bytes(rng, params)?,
            ),
        })
    }
}

#[derive(Default, Clone)]
pub struct MultisigInputs {
    pub receiving_descriptors: HashSet<DescriptorPublicKey>,
    pub change_descriptors: HashSet<DescriptorPublicKey>,
    pub signers: Vec<SingleSigWalletDescriptionV0>,
}

impl MultisigInputs {
    pub fn validate(&self, configuration: &MultisigType) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.receiving_descriptors.len() == self.change_descriptors.len(),
            "Different number of receiving public key descriptors and change public key descriptors: {} and {}",
            self.receiving_descriptors.len(),
            self.change_descriptors.len()
        );
        let total: usize = configuration.total.try_into()?;
        anyhow::ensure!(
            self.receiving_descriptors.len() == total,
            "Got {} public keys but expected {total}",
            self.receiving_descriptors.len()
        );
        Ok(())
    }

    // return quantity of new descriptors added
    pub fn merge(&mut self, other: MultisigInputs) -> anyhow::Result<u32> {
        let mut receiving_added = 0;
        let mut change_added = 0;
        for v in other.receiving_descriptors {
            if self.receiving_descriptors.insert(v) {
                receiving_added += 1;
            }
        }
        for v in other.change_descriptors {
            if self.change_descriptors.insert(v) {
                change_added += 1;
            }
        }
        self.signers.extend(other.signers);
        anyhow::ensure!(change_added == receiving_added,
            "Expected change descriptor added {change_added} to be the same as receiving descriptor added {receiving_added}"
        );
        Ok(receiving_added)
    }
}

pub type OptOrigin = Option<(Fingerprint, DerivationPath)>;

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_multisig_inputs_merge() -> anyhow::Result<()> {
        let input1 = MultisigInputs { change_descriptors: [DescriptorPublicKey::from_str("[0367a450/48'/0'/0'/2']xpub6DoVLmGBDv79Cf4zbmBejc3iUfGfBEq4hDkvTeLkK2nBCCJ72WpTfDamDziVwaa7YXRSxbJiiR88NMyjchdE7UD9Gj9oGRPE4mQVumkWZD2/1/*")?].into(), receiving_descriptors: [DescriptorPublicKey::from_str("[0367a450/48'/0'/0'/2']xpub6DoVLmGBDv79Cf4zbmBejc3iUfGfBEq4hDkvTeLkK2nBCCJ72WpTfDamDziVwaa7YXRSxbJiiR88NMyjchdE7UD9Gj9oGRPE4mQVumkWZD2/0/*")?].into(), signers: vec![] };
        let input1_ = MultisigInputs { change_descriptors: [DescriptorPublicKey::from_str("[0367a450/48'/0'/0'/2']xpub6DoVLmGBDv79Cf4zbmBejc3iUfGfBEq4hDkvTeLkK2nBCCJ72WpTfDamDziVwaa7YXRSxbJiiR88NMyjchdE7UD9Gj9oGRPE4mQVumkWZD2/1/*")?].into(), receiving_descriptors: [DescriptorPublicKey::from_str("[0367a450/48'/0'/0'/2']xpub6DoVLmGBDv79Cf4zbmBejc3iUfGfBEq4hDkvTeLkK2nBCCJ72WpTfDamDziVwaa7YXRSxbJiiR88NMyjchdE7UD9Gj9oGRPE4mQVumkWZD2/0/*")?].into(), signers: vec![] };
        let mut i = MultisigInputs::default();
        assert_eq!(1, i.merge(input1)?);
        assert_eq!(0, i.merge(input1_)?);
        Ok(())
    }
}
