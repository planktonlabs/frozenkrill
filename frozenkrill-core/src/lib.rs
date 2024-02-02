use std::{collections::HashSet, path::PathBuf, sync::Arc};

use anyhow::Context;
use bip39::Mnemonic;
use bitcoin::Network;
use compression::compress;
use encryption::default_encrypt;
use itertools::Itertools;
use miniscript::DescriptorPublicKey;
use rand_core::CryptoRngCore;
use secp256k1::{All, Secp256k1};
use secrecy::{ExposeSecret, Secret, SecretString, SecretVec};
use wallet_description::{
    EncryptedWalletDescription, MultisigType, ScriptType, SingleSigWalletDescriptionV0,
    SinglesigJsonWalletDescriptionV0, KEY_SIZE, NONCE_SIZE, SALT_SIZE,
};

use crate::wallet_description::{
    DecodedHeaderV0, MultiSigWalletDescriptionV0, MultisigJsonWalletDescriptionV0,
    ENCRYPTED_HEADER_LENGTH,
};

pub extern crate psbt as descriptor_wallet_psbt;

pub mod compression;
pub mod encryption;
pub mod key_derivation;
pub mod mnemonic_utils;
pub mod psbt;
pub mod utils;
pub mod wallet_description;
pub mod wallet_export;

pub use {
    anyhow, bip39, bitcoin, blake3, env_logger, hex, itertools, log, miniscript, rand, rand_core,
    rayon, secrecy, serde, serde_json,
};

pub fn get_secp<Rng: CryptoRngCore>(rng: &mut Rng) -> Secp256k1<All> {
    let mut s = Secp256k1::new();
    s.randomize(rng);
    s
}

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
        if min > max {
            anyhow::bail!("Minimum padding {min} is greater than max padding {max}")
        }
        if max > MAX_ADDITIONAL_PADDING {
            anyhow::bail!(
                "Given max padding bytes {max} is greater than limit {MAX_ADDITIONAL_PADDING}"
            )
        }
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
            if ciphertext.len() > MINIMUM_CIPHERTEXT_SIZE_BYTES {
                anyhow::bail!(
                "Pre padded ciphertext size {} is already greater than {MINIMUM_CIPHERTEXT_SIZE_BYTES}",
                ciphertext.len()
            )
            }
            ciphertext.extend_from_slice(&base_padding_bytes);
            if ciphertext.len() < MINIMUM_CIPHERTEXT_SIZE_BYTES {
                anyhow::bail!(
                "Not enough padding bytes to bring ciphertext size from {} to at least {MINIMUM_CIPHERTEXT_SIZE_BYTES}",
                ciphertext.len()
            )
            }
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
    key: &Secret<[u8; KEY_SIZE]>,
    header_key: Secret<[u8; KEY_SIZE]>,
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
    let compressed: SecretVec<u8> = {
        let json: SecretVec<u8> = {
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
        SecretVec::new(compress(json.expose_secret()).context("failure compressing json")?)
    };
    let mut ciphertext = default_encrypt(&header_key, &header_nonce, &compressed)
        .context("failure encrypting compressed json")?;
    let header = DecodedHeaderV0::new(
        header_key,
        header_nonce,
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
pub fn generate_encrypted_encoded_multisig_wallet(
    configuration: MultisigType,
    inputs: MultisigInputs,
    key: &Secret<[u8; KEY_SIZE]>,
    header_key: Secret<[u8; KEY_SIZE]>,
    salt: [u8; SALT_SIZE],
    nonce: [u8; NONCE_SIZE],
    header_nonce: [u8; NONCE_SIZE],
    padder: CiphertextPadder,
    script_type: ScriptType,
    network: Network,
    secp: &Secp256k1<All>,
) -> anyhow::Result<Vec<u8>> {
    let receiving_descriptor = match script_type {
        ScriptType::SegwitNative => miniscript::Descriptor::new_wsh_sortedmulti(
            configuration.required.try_into()?,
            inputs
                .receiving_descriptors
                .into_iter()
                .sorted_by(Ord::cmp)
                .collect(),
        )?,
    };
    let change_descriptor = match script_type {
        ScriptType::SegwitNative => miniscript::Descriptor::new_wsh_sortedmulti(
            configuration.required.try_into()?,
            inputs
                .change_descriptors
                .into_iter()
                .sorted_by(Ord::cmp)
                .collect(),
        )?,
    };
    let compressed: SecretVec<u8> = {
        let wallet_description = MultiSigWalletDescriptionV0::generate(
            inputs.signers,
            receiving_descriptor,
            change_descriptor,
            configuration,
            network,
            script_type,
        )
        .context("failure generating wallet")?;
        let json: SecretVec<u8> = {
            let json_wallet_description = MultisigJsonWalletDescriptionV0::from_wallet_description(
                &wallet_description,
                secp,
            )?;
            json_wallet_description.expose_secret().to_vec()?
        };
        SecretVec::new(compress(json.expose_secret()).context("failure compressing json")?)
    };
    let mut ciphertext = default_encrypt(&header_key, &header_nonce, &compressed)
        .context("failure encrypting compressed json")?;
    let header = DecodedHeaderV0::new(
        header_key,
        header_nonce,
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
        if keyfiles.is_empty() {
            anyhow::bail!(
                "The expansion of the keyfiles yielded no files (probably an empty directory was given)"
            )
        }
        Ok(keyfiles)
    }
}

pub fn get_random_salt(rng: &mut impl CryptoRngCore) -> anyhow::Result<[u8; SALT_SIZE]> {
    let mut salt = [0u8; SALT_SIZE];
    rng.try_fill_bytes(&mut salt)
        .context("failure getting entropy for salt")?;
    Ok(salt)
}
pub fn get_random_nonce(rng: &mut impl CryptoRngCore) -> anyhow::Result<[u8; NONCE_SIZE]> {
    let mut nonce = [0u8; NONCE_SIZE];
    rng.try_fill_bytes(&mut nonce)
        .context("failure getting entropy for nonce")?;
    Ok(nonce)
}

pub fn get_random_key(rng: &mut impl CryptoRngCore) -> anyhow::Result<[u8; KEY_SIZE]> {
    let mut key = [0u8; KEY_SIZE];
    rng.try_fill_bytes(&mut key)
        .context("failure getting entropy for key")?;
    Ok(key)
}

pub const MAX_BASE_PADDING_BYTES: usize = 2000;
pub const MINIMUM_CIPHERTEXT_SIZE_BYTES: usize = 1200;

pub const DEFAULT_MIN_ADDITIONAL_PADDING: u32 = 0;
pub const DEFAULT_MAX_ADDITIONAL_PADDING: u32 = 1000;
pub const MAX_ADDITIONAL_PADDING: u32 = 1_000_000_000;

pub fn get_additional_random_padding_bytes(
    rng: &mut impl CryptoRngCore,
    params: &PaddingParams,
) -> anyhow::Result<Vec<u8>> {
    let padding_size = Ord::max(rng.next_u32() % (params.max + 1), params.min);
    let padding_size = padding_size.try_into().expect("to be within usize");
    let mut padding = vec![0; padding_size];
    rng.try_fill_bytes(&mut padding)
        .context("failure getting entropy for additional padding")?;
    Ok(padding)
}

pub fn get_base_random_padding_bytes(
    rng: &mut impl CryptoRngCore,
) -> anyhow::Result<[u8; MAX_BASE_PADDING_BYTES]> {
    let mut padding = [0u8; MAX_BASE_PADDING_BYTES];
    rng.try_fill_bytes(&mut padding)
        .context("failure getting entropy for base padding")?;
    Ok(padding)
}

pub fn get_padder(
    rng: &mut impl CryptoRngCore,
    params: &PaddingParams,
) -> anyhow::Result<CiphertextPadder> {
    if params.disable_all_padding {
        Ok(CiphertextPadder {
            base_padding_bytes: None,
            additional_padding_bytes: None,
        })
    } else {
        Ok(CiphertextPadder {
            base_padding_bytes: Some(get_base_random_padding_bytes(rng)?),
            additional_padding_bytes: Some(get_additional_random_padding_bytes(rng, params)?),
        })
    }
}

#[derive(Default)]
pub struct MultisigInputs {
    pub receiving_descriptors: HashSet<DescriptorPublicKey>,
    pub change_descriptors: HashSet<DescriptorPublicKey>,
    pub signers: Vec<SingleSigWalletDescriptionV0>,
}

impl MultisigInputs {
    pub fn validate(&self, configuration: &MultisigType) -> anyhow::Result<()> {
        if self.receiving_descriptors.len() != self.change_descriptors.len() {
            anyhow::bail!(
                "Different number of receiving public key descriptors and change public key descriptors: {} and {}",
                self.receiving_descriptors.len(),
                self.change_descriptors.len()
            )
        }
        let total: usize = configuration.total.try_into()?;
        if self.receiving_descriptors.len() != total {
            anyhow::bail!(
                "Got {} public keys but expected {total}",
                self.receiving_descriptors.len()
            )
        }
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
        if change_added != receiving_added {
            anyhow::bail!("Expected change descriptor added {change_added} to be the same as receiving descriptor added {receiving_added}")
        }
        Ok(receiving_added)
    }
}

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
