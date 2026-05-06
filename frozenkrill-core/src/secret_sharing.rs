//! BIP-39 secret sharing with Pedersen VSS.
//!
//! See `docs/secret_sharing.md` for the user-facing model and security notes.

use crate::wallet_description::{
    SinglesigPublicMetadataV0, VssJsonWalletDescriptionV0, ZERO_VSS_WALLET_VERSION,
};
use anyhow::{Context, Result, anyhow, bail};
use bip39::Mnemonic;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use secrecy::{ExposeSecret, SecretBox};
use std::str::FromStr;
use vsss_rs::curve25519::{WrappedRistretto, WrappedScalar};
use vsss_rs::pedersen::{StdPedersenResult, split_secret};
use vsss_rs::{
    DefaultShare, IdentifierPrimeField, PedersenResult, PedersenVerifierSet, ReadableShareSet,
    Share as VsssShareTrait, ShareElement, ValueGroup,
};

type VsssScalar = IdentifierPrimeField<WrappedScalar>;
type VsssShare = DefaultShare<VsssScalar, VsssScalar>;
type VsssVerifier = ValueGroup<WrappedRistretto>;

/// Result of a successful `combine_vss_wallets`. Bundles the recovered
/// mnemonic with the chosen share group's public metadata so callers can
/// authenticate and rebuild the wallet described by the shares.
pub struct VssRecovery {
    pub mnemonic: SecretBox<Mnemonic>,
    pub metadata: SinglesigPublicMetadataV0,
}

impl VssRecovery {
    /// Rebuild a `SingleSigWalletDescriptionV0` from this recovery.
    ///
    /// This is the **safe** entry point for reconstructing a wallet
    /// from a successful `combine_vss_wallets`. Empty passphrases are
    /// normalized to no passphrase; non-empty passphrases are passed
    /// through to BIP-39 derivation after the recovered mnemonic is
    /// authenticated against the share metadata.
    pub fn rebuild_singlesig(
        &self,
        seed_password: &Option<std::sync::Arc<secrecy::SecretString>>,
        secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<crate::wallet_description::SingleSigWalletDescriptionV0> {
        use std::sync::Arc;
        // Normalize empty string to None per BIP-39 semantics.
        let effective_pw: Option<Arc<secrecy::SecretString>> = match seed_password {
            Some(pw) if !pw.expose_secret().is_empty() => Some(Arc::clone(pw)),
            _ => None,
        };

        // Clone the inner `Mnemonic` directly into a fresh
        // `SecretBox` instead of round-tripping through `to_string()
        // + Mnemonic::from_str`. The String round-trip would leave a
        // non-zeroizing copy of the seed phrase on the heap on every
        // successful recovery sanity-check.
        let mnemonic_arc: Arc<SecretBox<bip39::Mnemonic>> = Arc::new(SecretBox::new(Box::new(
            self.mnemonic.expose_secret().clone(),
        )));
        let network = bitcoin::Network::from_str(&self.metadata.network).with_context(|| {
            format!(
                "invalid network in recovery metadata: {}",
                self.metadata.network
            )
        })?;
        let script_type =
            crate::wallet_description::ScriptType::from_str(&self.metadata.script_type)
                .with_context(|| {
                    format!(
                        "invalid script type in recovery metadata: {}",
                        self.metadata.script_type
                    )
                })?;

        // Authenticate the metadata against the no-passphrase wallet
        // first (catches tampered network / script_type / xpub even
        // when a passphrase is supplied), then build and return the
        // wallet the caller actually asked for.
        let metadata_witness = crate::wallet_description::SingleSigWalletDescriptionV0::generate(
            Arc::clone(&mnemonic_arc),
            &None,
            network,
            script_type,
            secp,
        )?;
        anyhow::ensure!(
            metadata_witness.encoded_singlesig_xpub() == self.metadata.singlesig_xpub,
            "Reconstructed wallet xpub does not match recovery metadata: the share set \
             may have been tampered with"
        );
        if effective_pw.is_none() {
            return Ok(metadata_witness);
        }
        crate::wallet_description::SingleSigWalletDescriptionV0::generate(
            mnemonic_arc,
            &effective_pw,
            network,
            script_type,
            secp,
        )
    }
}
use zeroize::Zeroize;

/// Error types for secret sharing operations
#[derive(Debug, thiserror::Error)]
pub enum SecretSharingError {
    #[error("Total shares must be between 2 and 255")]
    InvalidShareCount,

    #[error("Threshold ({threshold}) cannot exceed total shares ({total})")]
    ThresholdExceedsTotal { threshold: u8, total: u8 },

    #[error("Mnemonic length must be 12 or 24 words")]
    InvalidMnemonicLength,

    #[error("Share verification failed - share may be corrupted or invalid")]
    VerificationFailed,

    #[error("Insufficient shares: need {threshold}, got {provided}")]
    InsufficientShares { threshold: u8, provided: usize },

    #[error("Invalid mnemonic checksum after reconstruction")]
    InvalidReconstructedChecksum,
}

/// Pack a 16-byte entropy half into a Curve25519 scalar.
///
/// 16 bytes (128 bits) is far below the scalar order (~2^252.4), so
/// `Scalar::from_bytes_mod_order` does not reduce and the round-trip is exact.
fn entropy_half_to_scalar(half: &[u8]) -> WrappedScalar {
    debug_assert_eq!(half.len(), 16);
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(half);
    let scalar = Scalar::from_bytes_mod_order(bytes);
    let wrapped = WrappedScalar(scalar);
    bytes.zeroize();
    wrapped
}

/// Unpack a scalar that holds at most 128 bits back into 16 entropy bytes.
fn scalar_to_entropy_half(scalar: &WrappedScalar) -> [u8; 16] {
    let bytes = scalar.0.to_bytes();
    let mut half = [0u8; 16];
    half.copy_from_slice(&bytes[..16]);
    half
}

fn vsss_share_to_bytes(share: &VsssShare) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(share.identifier().to_vec().as_slice());
    out.extend_from_slice(share.value().to_vec().as_slice());
    out
}

fn vsss_share_from_bytes(bytes: &[u8]) -> Result<VsssShare> {
    anyhow::ensure!(
        bytes.len() == 64,
        "vsss-rs 5 share must be 64 bytes: 32-byte identifier + 32-byte value (got {})",
        bytes.len()
    );
    let identifier = VsssScalar::from_slice(&bytes[..32])
        .map_err(|e| anyhow!("invalid vsss-rs share identifier: {:?}", e))?;
    let value = VsssScalar::from_slice(&bytes[32..])
        .map_err(|e| anyhow!("invalid vsss-rs share value: {:?}", e))?;
    Ok(VsssShare::with_identifier_and_value(identifier, value))
}

fn vsss_share_identifier_from_hex(hex_str: &str) -> Result<VsssScalar> {
    let bytes = hex::decode(hex_str).context("Failed to decode vsss-rs share hex")?;
    Ok(*vsss_share_from_bytes(&bytes)?.identifier())
}

fn complete_vsss_share_identifier(
    wallet: &VssJsonWalletDescriptionV0,
    has_hi: bool,
) -> Option<VsssScalar> {
    let lo_id = vsss_share_identifier_from_hex(&wallet.share_data).ok()?;
    if has_hi {
        let hi_id = vsss_share_identifier_from_hex(wallet.share_data_hi.as_deref()?).ok()?;
        if lo_id != hi_id {
            return None;
        }
    }
    Some(lo_id)
}

fn verify_vsss_share_pair(
    verifier_set: &Vec<VsssVerifier>,
    secret_bytes: &[u8],
    blinder_bytes: &[u8],
) -> bool {
    let Ok(secret_share) = vsss_share_from_bytes(secret_bytes) else {
        return false;
    };
    let Ok(blinder_share) = vsss_share_from_bytes(blinder_bytes) else {
        return false;
    };
    if secret_share.identifier() != blinder_share.identifier() {
        return false;
    }
    verifier_set
        .verify_share_and_blinder(&secret_share, &blinder_share)
        .is_ok()
}

fn wallet_verifies_against_candidate(
    wallet: &VssJsonWalletDescriptionV0,
    lo_set: &Vec<VsssVerifier>,
    hi_set: Option<&Vec<VsssVerifier>>,
) -> bool {
    let (Ok(lo_secret), Ok(lo_blinder)) = (
        hex::decode(&wallet.share_data),
        hex::decode(&wallet.blinder_share_data),
    ) else {
        return false;
    };
    if !verify_vsss_share_pair(lo_set, &lo_secret, &lo_blinder) {
        return false;
    }
    let Some(hi_set) = hi_set else {
        return true;
    };
    let (Some(hi_secret_hex), Some(hi_blinder_hex)) = (
        wallet.share_data_hi.as_deref(),
        wallet.blinder_share_data_hi.as_deref(),
    ) else {
        return false;
    };
    let (Ok(hi_secret), Ok(hi_blinder)) = (hex::decode(hi_secret_hex), hex::decode(hi_blinder_hex))
    else {
        return false;
    };
    verify_vsss_share_pair(hi_set, &hi_secret, &hi_blinder)
}

/// Reassemble entropy halves into a mnemonic of the requested word count.
fn entropy_to_mnemonic(
    lo: &[u8; 16],
    hi: Option<&[u8; 16]>,
    word_count: usize,
) -> Result<SecretBox<Mnemonic>> {
    let mut entropy: Vec<u8> = match (word_count, hi) {
        (12, None) => lo.to_vec(),
        (24, Some(h)) => {
            let mut v = Vec::with_capacity(32);
            v.extend_from_slice(lo);
            v.extend_from_slice(h);
            v
        }
        _ => bail!(SecretSharingError::InvalidMnemonicLength),
    };

    let mnemonic = Mnemonic::from_entropy(&entropy).map_err(|e| {
        anyhow!(SecretSharingError::InvalidReconstructedChecksum)
            .context(format!("Failed to create mnemonic: {}", e))
    })?;

    entropy.zeroize();
    Ok(SecretBox::new(Box::new(mnemonic)))
}

pub(crate) fn split_mnemonic<R: rand::RngCore + rand::CryptoRng>(
    mnemonic: &Mnemonic,
    threshold: u8,
    total_shares: u8,
    rng: &mut R,
) -> Result<Vec<VssJsonWalletDescriptionV0>> {
    if threshold < 2 || total_shares < 2 {
        bail!(SecretSharingError::InvalidShareCount);
    }

    if threshold > total_shares {
        bail!(SecretSharingError::ThresholdExceedsTotal {
            threshold,
            total: total_shares,
        });
    }

    let word_count = mnemonic.word_count();
    if word_count != 12 && word_count != 24 {
        bail!(SecretSharingError::InvalidMnemonicLength);
    }
    let mnemonic_length = u8::try_from(word_count).context("mnemonic length does not fit in u8")?;

    let entropy = SecretBox::new(Box::new(mnemonic.to_entropy()));
    let entropy_bytes = entropy.expose_secret();
    let lo_scalar = entropy_half_to_scalar(&entropy_bytes[..16]);
    let hi_scalar = if word_count == 24 {
        Some(entropy_half_to_scalar(&entropy_bytes[16..32]))
    } else {
        None
    };
    drop(entropy);

    let lo_split = split_one_scalar(lo_scalar, threshold, total_shares, rng)?;
    let hi_split = match hi_scalar {
        Some(s) => Some(split_one_scalar(s, threshold, total_shares, rng)?),
        None => None,
    };

    let timestamp = chrono::Utc::now().to_rfc3339();
    let mut shares = Vec::with_capacity(total_shares as usize);
    for idx in 0..(total_shares as usize) {
        let share_data = hex::encode(&lo_split.share_bytes[idx]);
        let blinder_share_data = hex::encode(&lo_split.blinder_bytes[idx]);
        let share_data_hi = hi_split.as_ref().map(|h| hex::encode(&h.share_bytes[idx]));
        let blinder_share_data_hi = hi_split
            .as_ref()
            .map(|h| hex::encode(&h.blinder_bytes[idx]));
        let verification_data_hi = hi_split.as_ref().map(|h| h.verification_data.clone());

        shares.push(VssJsonWalletDescriptionV0 {
            version: ZERO_VSS_WALLET_VERSION,
            share_index: (idx + 1) as u8,
            threshold,
            total_shares,
            mnemonic_length,
            share_data,
            blinder_share_data,
            verification_data: lo_split.verification_data.clone(),
            share_data_hi,
            blinder_share_data_hi,
            verification_data_hi,
            created_at: timestamp.clone(),
            original_wallet: SinglesigPublicMetadataV0::default(),
        });
    }

    Ok(shares)
}

struct VssOneScalar {
    share_bytes: Vec<Vec<u8>>,
    blinder_bytes: Vec<Vec<u8>>,
    verification_data: String,
}

fn split_one_scalar<R: rand::RngCore + rand::CryptoRng>(
    scalar: WrappedScalar,
    threshold: u8,
    total_shares: u8,
    rng: &mut R,
) -> Result<VssOneScalar> {
    let secret = IdentifierPrimeField(scalar);
    let result: StdPedersenResult<VsssShare, VsssVerifier> = split_secret(
        threshold as usize,
        total_shares as usize,
        &secret,
        None,
        None,
        None,
        rng,
    )
    .map_err(|e| anyhow!("Failed to split secret: {:?}", e))?;

    let share_bytes: Vec<Vec<u8>> = result
        .secret_shares()
        .iter()
        .map(vsss_share_to_bytes)
        .collect();
    let blinder_bytes: Vec<Vec<u8>> = result
        .blinder_shares()
        .iter()
        .map(vsss_share_to_bytes)
        .collect();
    debug_assert_eq!(share_bytes.len(), blinder_bytes.len());
    let pedersen_hex: Vec<String> = result
        .pedersen_verifier_set()
        .iter()
        .map(|v| hex::encode(v.0.0.compress().to_bytes()))
        .collect();

    Ok(VssOneScalar {
        share_bytes,
        blinder_bytes,
        verification_data: pedersen_hex.join(","),
    })
}

/// Parse a comma-separated list of hex-encoded Ristretto points back into a
/// `Vec<VsssVerifier>`. Used to deserialize the Pedersen verifier set.
fn parse_ristretto_points(s: &str) -> Result<Vec<VsssVerifier>> {
    let mut out = Vec::new();
    for hex_str in s.split(',') {
        let bytes = hex::decode(hex_str).context("Failed to decode verifier hex")?;
        anyhow::ensure!(
            bytes.len() == 32,
            "verifier point must be 32 bytes (got {})",
            bytes.len()
        );
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let compressed = CompressedRistretto(arr);
        let point = compressed
            .decompress()
            .ok_or_else(|| anyhow!("verifier point is not a valid Ristretto encoding"))?;
        out.push(ValueGroup(WrappedRistretto(point)));
    }
    Ok(out)
}

/// Verify share/blinder pairs and dedupe by typed share identifier.
fn verified_unique_share_pairs(
    secret_shares: &[Vec<u8>],
    blinder_shares: &[Vec<u8>],
    pedersen_hex: &str,
) -> Result<Vec<VsssShare>> {
    anyhow::ensure!(
        secret_shares.len() == blinder_shares.len(),
        "secret-share count ({}) does not match blinder-share count ({})",
        secret_shares.len(),
        blinder_shares.len()
    );
    let verifier_vec = parse_ristretto_points(pedersen_hex)?;
    anyhow::ensure!(
        verifier_vec.len() >= 3,
        "Pedersen verifier set must contain at least secret-generator + blinder-generator + 1 commitment (got {})",
        verifier_vec.len()
    );
    let mut seen_ids = std::collections::HashSet::new();
    let mut out: Vec<VsssShare> = Vec::new();
    let mut last_failure: Option<String> = None;
    for (secret_share_bytes, blinder_share_bytes) in secret_shares.iter().zip(blinder_shares.iter())
    {
        let secret_share = match vsss_share_from_bytes(secret_share_bytes) {
            Ok(s) => s,
            Err(e) => {
                last_failure = Some(format!("secret-share failed to parse: {e:#}"));
                continue;
            }
        };
        let blinder_share = match vsss_share_from_bytes(blinder_share_bytes) {
            Ok(s) => s,
            Err(e) => {
                last_failure = Some(format!("blinder-share failed to parse: {e:#}"));
                continue;
            }
        };
        let secret_id = *secret_share.identifier();
        let blinder_id = *blinder_share.identifier();
        if secret_id != blinder_id {
            last_failure = Some(format!(
                "secret-share/blinder-share identifier mismatch: {:?} vs {:?}",
                secret_id, blinder_id
            ));
            continue;
        }
        // verify_share_and_blinder rejects shares whose identifier is zero.
        if verifier_vec
            .verify_share_and_blinder(&secret_share, &blinder_share)
            .is_err()
        {
            last_failure = Some(format!(
                "share with identifier {:?} failed Pedersen verification",
                secret_id
            ));
            continue;
        }
        if seen_ids.insert(secret_id) {
            out.push(secret_share);
        }
    }
    if out.is_empty() {
        bail!(anyhow!(SecretSharingError::VerificationFailed).context(
            last_failure.unwrap_or_else(|| "no shares supplied for verification".to_string())
        ));
    }
    Ok(out)
}

/// Combine VSS share payloads to reconstruct the original mnemonic.
#[cfg(test)]
pub(crate) fn combine_shares_to_mnemonic(
    shares: &[VssJsonWalletDescriptionV0],
) -> Result<SecretBox<Mnemonic>> {
    if shares.is_empty() {
        bail!(anyhow!("No shares provided"));
    }

    // Group by Pedersen verifier identity; input order must not choose the
    // canonical share when verifier-copy corruption is present.
    type GroupKey<'a> = (&'a str, Option<&'a str>);
    let mut groups: std::collections::BTreeMap<GroupKey, Vec<&VssJsonWalletDescriptionV0>> =
        std::collections::BTreeMap::new();
    for s in shares {
        let key: GroupKey = (
            s.verification_data.as_str(),
            s.verification_data_hi.as_deref(),
        );
        groups.entry(key).or_default().push(s);
    }
    // Try the largest verifier group first; verification still decides safety.
    let chosen: Vec<&VssJsonWalletDescriptionV0> = groups
        .into_values()
        .max_by_key(|g| g.len())
        .expect("non-empty input ⇒ at least one group");
    let first = chosen[0];
    let lo_threshold = threshold_from_pedersen(&first.verification_data)?;
    if chosen.len() < lo_threshold as usize {
        bail!(SecretSharingError::InsufficientShares {
            threshold: lo_threshold,
            provided: chosen.len(),
        });
    }

    let mnemonic = combine_wallet_candidate_to_mnemonic(
        &chosen,
        &first.verification_data,
        first.verification_data_hi.as_deref(),
        lo_threshold,
    )?;
    // Advisory only: recovery already used the verifier-derived length.
    let derived_word_count = if first.verification_data_hi.is_some() {
        24
    } else {
        12
    };
    if usize::from(first.mnemonic_length) != derived_word_count {
        log::warn!(
            "Share metadata says mnemonic_length={} but Pedersen verifier set implies {}; \
             metadata may have been tampered with — recovered using the verifier-derived length",
            first.mnemonic_length,
            derived_word_count
        );
    }

    Ok(mnemonic)
}

fn threshold_from_pedersen(pedersen_hex: &str) -> Result<u8> {
    let count = pedersen_hex.split(',').count();
    anyhow::ensure!(
        count >= 4,
        "Pedersen verifier set must contain at least secret-generator + blinder-generator + 2 commitments (got {count} elements)"
    );
    let t = count - 2;
    u8::try_from(t).context("Pedersen verifier set encodes a threshold that does not fit in u8")
}

fn combine_one_half<T>(
    shares: &[&T],
    extract_secret: impl Fn(&T) -> Option<&str>,
    extract_blinder: impl Fn(&T) -> Option<&str>,
    pedersen_hex: &str,
    threshold: u8,
) -> Result<Option<WrappedScalar>> {
    let mut secret_bytes: Vec<Vec<u8>> = Vec::with_capacity(shares.len());
    let mut blinder_bytes: Vec<Vec<u8>> = Vec::with_capacity(shares.len());
    for share in shares {
        let (Some(s_hex), Some(b_hex)) = (extract_secret(share), extract_blinder(share)) else {
            continue;
        };
        let (Ok(sb), Ok(bb)) = (hex::decode(s_hex), hex::decode(b_hex)) else {
            continue;
        };
        secret_bytes.push(sb);
        blinder_bytes.push(bb);
    }
    if secret_bytes.is_empty() {
        return Ok(None);
    }
    let good = verified_unique_share_pairs(&secret_bytes, &blinder_bytes, pedersen_hex)?;
    anyhow::ensure!(
        good.len() >= threshold as usize,
        "Insufficient verified shares: needed at least {threshold}, got {}",
        good.len()
    );
    let combined: VsssScalar = good
        .combine()
        .map_err(|e| anyhow!("Failed to combine shares: {:?}", e))?;
    Ok(Some(combined.0))
}

fn combine_wallet_candidate_to_mnemonic(
    wallets: &[&VssJsonWalletDescriptionV0],
    lo_pedersen: &str,
    hi_pedersen: Option<&str>,
    threshold: u8,
) -> Result<SecretBox<Mnemonic>> {
    let lo_scalar = combine_one_half(
        wallets,
        |w| Some(w.share_data.as_str()),
        |w| Some(w.blinder_share_data.as_str()),
        lo_pedersen,
        threshold,
    )?
    .ok_or_else(|| anyhow!("missing low-half share data"))?;
    let lo_bytes = scalar_to_entropy_half(&lo_scalar);

    let hi_bytes = if let Some(hi_pedersen) = hi_pedersen {
        let hi_threshold = threshold_from_pedersen(hi_pedersen)?;
        anyhow::ensure!(
            hi_threshold == threshold,
            "Low-half and high-half Pedersen verifier sets imply different thresholds ({threshold} vs {hi_threshold})"
        );
        let hi_scalar = combine_one_half(
            wallets,
            |w| w.share_data_hi.as_deref(),
            |w| w.blinder_share_data_hi.as_deref(),
            hi_pedersen,
            hi_threshold,
        )?
        .ok_or_else(|| anyhow!("missing high-half share data"))?;
        Some(scalar_to_entropy_half(&hi_scalar))
    } else {
        None
    };

    entropy_to_mnemonic(
        &lo_bytes,
        hi_bytes.as_ref(),
        if hi_pedersen.is_some() { 24 } else { 12 },
    )
}

pub fn split_singlesig_wallet<R: rand::RngCore + rand::CryptoRng>(
    wallet: &crate::wallet_description::SinglesigJsonWalletDescriptionV0,
    threshold: u8,
    total_shares: u8,
    rng: &mut R,
) -> Result<Vec<VssJsonWalletDescriptionV0>> {
    use std::sync::Arc;

    let mnemonic =
        Mnemonic::parse(&wallet.seed_phrase).context("Failed to parse mnemonic from wallet")?;

    // Recovery authenticates against the no-passphrase xpub; refuse shares
    // whose metadata would be unrecoverable.
    {
        let secp_check = crate::random_generation_utils::get_secp(rng);
        let network = bitcoin::Network::from_str(&wallet.network)
            .with_context(|| format!("invalid network in wallet metadata: {}", wallet.network))?;
        let script_type = crate::wallet_description::ScriptType::from_str(&wallet.script_type)
            .with_context(|| {
                format!(
                    "invalid script type in wallet metadata: {}",
                    wallet.script_type
                )
            })?;
        let no_passphrase_witness =
            crate::wallet_description::SingleSigWalletDescriptionV0::generate(
                Arc::new(SecretBox::new(Box::new(mnemonic.clone()))),
                &None,
                network,
                script_type,
                &secp_check,
            )?;
        anyhow::ensure!(
            no_passphrase_witness.encoded_singlesig_xpub() == wallet.singlesig_xpub,
            "Refusing to split: wallet metadata's xpub does not match the no-passphrase \
             derivation of its seed phrase. VSS share metadata is authenticated against the \
             no-passphrase wallet at recovery time; passing a passphrase-derived wallet here \
             would render the share set unrecoverable (xpub mismatch on combine). Pass the \
             no-passphrase wallet instead."
        );
    }

    let mut shares = split_mnemonic(&mnemonic, threshold, total_shares, rng)?;
    // The VSS wrapper carries public metadata only; seed phrase and xprivs stay out.
    let metadata = SinglesigPublicMetadataV0::from_singlesig_json(wallet);
    for share in &mut shares {
        share.original_wallet = metadata.clone();
    }
    Ok(shares)
}

/// Combine VSS wallet shares into a mnemonic plus authenticated public metadata.
pub fn combine_vss_wallets(vss_wallets: &[VssJsonWalletDescriptionV0]) -> Result<VssRecovery> {
    if vss_wallets.is_empty() {
        bail!(anyhow!("No VSS wallets provided"));
    }

    // Do not prefilter mutable JSON metadata; Pedersen verification
    // decides which secret bytes belong to the candidate.
    let vss_wallets_owned: Vec<&VssJsonWalletDescriptionV0> = vss_wallets.iter().collect();
    let vss_wallets: &[&VssJsonWalletDescriptionV0] = &vss_wallets_owned;

    type CandidateVerifier<'a> = (&'a str, Option<&'a str>);
    // Cross-product enumeration tolerates independent lo/hi verifier-copy
    // corruption while keeping the candidate count bounded by O(N²).
    let mut distinct_los_set: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    let mut distinct_los: Vec<&str> = Vec::new();
    let mut distinct_his_set: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    let mut distinct_his: Vec<&str> = Vec::new();
    for w in vss_wallets {
        if distinct_los_set.insert(w.verification_data.as_str()) {
            distinct_los.push(w.verification_data.as_str());
        }
        if let Some(h) = w.verification_data_hi.as_deref()
            && distinct_his_set.insert(h)
        {
            distinct_his.push(h);
        }
    }
    let mut seen_candidates: std::collections::BTreeSet<CandidateVerifier> =
        std::collections::BTreeSet::new();
    let mut candidates: Vec<CandidateVerifier> = Vec::new();
    for lo in &distinct_los {
        // Pruned below when a hi companion exists for the same lo verifier.
        let key: CandidateVerifier = (lo, None);
        if seen_candidates.insert(key) {
            candidates.push(key);
        }
        for hi in &distinct_his {
            let key: CandidateVerifier = (lo, Some(hi));
            if seen_candidates.insert(key) {
                candidates.push(key);
            }
        }
    }
    // Drop `(lo, None)` when any share carries a hi half for that lo; this
    // fails closed against hi-stripped 24-word recoveries.
    let los_with_hi: std::collections::BTreeSet<&str> = vss_wallets
        .iter()
        .filter_map(|w| {
            w.verification_data_hi
                .as_deref()
                .map(|_| w.verification_data.as_str())
        })
        .collect();
    candidates.retain(|(lo, hi)| !(hi.is_none() && los_with_hi.contains(lo)));
    // Deterministic ordering only; ambiguity checks decide safety.
    candidates.sort_by(|a, b| {
        let a_count = vss_wallets
            .iter()
            .filter(|w| w.verification_data == *a.0 && w.verification_data_hi.as_deref() == a.1)
            .count();
        let b_count = vss_wallets
            .iter()
            .filter(|w| w.verification_data == *b.0 && w.verification_data_hi.as_deref() == b.1)
            .count();
        b_count.cmp(&a_count)
    });

    type SuccessEntry = (SecretBox<Mnemonic>, Vec<VssJsonWalletDescriptionV0>);
    let mut successes: Vec<SuccessEntry> = Vec::new();
    let mut last_err: Option<anyhow::Error> = None;
    let mut tried = 0usize;
    for candidate in &candidates {
        let &(lo_hex, hi_hex_opt) = candidate;
        let candidate_threshold = match threshold_from_pedersen(lo_hex) {
            Ok(t) => t,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        if vss_wallets.len() < candidate_threshold as usize {
            continue;
        }
        tried += 1;

        match combine_wallet_candidate_to_mnemonic(
            vss_wallets,
            lo_hex,
            hi_hex_opt,
            candidate_threshold,
        ) {
            Ok(secret) => {
                let lo_set = parse_ristretto_points(lo_hex).ok();
                let hi_set = hi_hex_opt.and_then(|h| parse_ristretto_points(h).ok());
                let verified_inputs: Vec<VssJsonWalletDescriptionV0> = vss_wallets
                    .iter()
                    .copied()
                    .filter(|w| match &lo_set {
                        Some(lo) => wallet_verifies_against_candidate(w, lo, hi_set.as_ref()),
                        None => false,
                    })
                    .map(|w| (*w).clone())
                    .collect();
                let complete_verified_ids: std::collections::HashSet<VsssScalar> = verified_inputs
                    .iter()
                    .filter_map(|w| complete_vsss_share_identifier(w, hi_hex_opt.is_some()))
                    .collect();
                if complete_verified_ids.len() >= candidate_threshold as usize {
                    let complete_verified_inputs = verified_inputs
                        .into_iter()
                        .filter(|w| {
                            complete_vsss_share_identifier(w, hi_hex_opt.is_some())
                                .is_some_and(|id| complete_verified_ids.contains(&id))
                        })
                        .collect();
                    successes.push((secret, complete_verified_inputs));
                } else {
                    last_err = Some(anyhow!(
                        "Candidate recovered mnemonic but only {} complete verified share identifier(s) were present; threshold is {candidate_threshold}",
                        complete_verified_ids.len()
                    ));
                }
            }
            Err(e) => last_err = Some(e),
        }
    }

    let derive_metadata = |group: &[VssJsonWalletDescriptionV0]| -> SinglesigPublicMetadataV0 {
        if group.is_empty() {
            return SinglesigPublicMetadataV0::default();
        }
        let mut by_id: std::collections::HashMap<VsssScalar, Vec<&VssJsonWalletDescriptionV0>> =
            std::collections::HashMap::new();
        for w in group {
            if let Ok(crypto_id) = vsss_share_identifier_from_hex(&w.share_data) {
                by_id.entry(crypto_id).or_default().push(w);
            }
        }
        let total_vote_ids = by_id.len();
        let deduped: Vec<&VssJsonWalletDescriptionV0> = by_id
            .into_values()
            .filter_map(|copies| {
                let first_meta = &copies[0].original_wallet;
                if copies.iter().all(|w| w.original_wallet == *first_meta) {
                    Some(copies[0])
                } else {
                    None
                }
            })
            .collect();
        if deduped.is_empty() {
            return SinglesigPublicMetadataV0::default();
        }
        let tally_source: &[&VssJsonWalletDescriptionV0] = &deduped;
        let mut counts: Vec<(usize, SinglesigPublicMetadataV0)> = Vec::new();
        for w in tally_source {
            let key = w.original_wallet.clone();
            if let Some(entry) = counts.iter_mut().find(|e| e.1 == key) {
                entry.0 += 1;
            } else {
                counts.push((1, key));
            }
        }
        // Identity metadata requires a strict majority; ties abstain.
        let top_count = counts.iter().map(|(c, _)| *c).max().unwrap_or(0);
        let top_groups = counts.iter().filter(|(c, _)| *c == top_count).count();
        let strict_majority = top_groups == 1 && top_count * 2 > total_vote_ids;
        if strict_majority {
            let majority = &counts
                .iter()
                .max_by_key(|(c, _)| *c)
                .expect("non-empty group")
                .1;
            majority.clone()
        } else {
            log::warn!(
                "Pedersen-verified share group has conflicting `original_wallet` metadata \
                 ({top_groups} variants tied at the top, top_count={top_count} of total_vote_ids={total_vote_ids}); \
                 no strict majority — returning empty metadata so callers don't trust an \
                 attacker-controlled xpub/network/script_type"
            );
            SinglesigPublicMetadataV0::default()
        }
    };

    let to_recovery = |successes: &mut Vec<SuccessEntry>| -> VssRecovery {
        let chosen = successes.pop().expect("non-empty successes");
        let metadata = derive_metadata(&chosen.1);
        VssRecovery {
            mnemonic: chosen.0,
            metadata,
        }
    };

    // Authenticate the recovered mnemonic against the voted wallet metadata.
    let authenticate = |recovery: VssRecovery| -> Result<VssRecovery> {
        if recovery.metadata.singlesig_xpub.is_empty() || recovery.metadata.network.is_empty() {
            bail!(
                "Recovered mnemonic could not be authenticated: the per-group share \
                 metadata vote tied across all candidates, leaving no authoritative \
                 xpub to cross-check the seed against. Re-run with the specific \
                 share files for the wallet you intend to recover, or remove \
                 conflicting / tampered share(s) and try again."
            );
        }
        let mut sanity_rng = rand::thread_rng();
        let sanity_secp = crate::random_generation_utils::get_secp(&mut sanity_rng);
        recovery.rebuild_singlesig(&None, &sanity_secp).context(
            "Recovered mnemonic does not match the share metadata's xpub — the \
                 share set may have been tampered with",
        )?;
        Ok(recovery)
    };

    match successes.len() {
        0 => Err(match last_err {
            Some(e) => e.context(format!(
                "All {tried} candidate share group(s) failed to combine ({} input(s) total)",
                vss_wallets.len()
            )),
            None => anyhow!(
                "No threshold-compatible subset of shares found among the {} input(s)",
                vss_wallets.len()
            ),
        }),
        1 => authenticate(to_recovery(&mut successes)),
        _ => {
            // Identical recovered mnemonics can collapse if metadata agrees.
            let first_mnemonic: &Mnemonic = successes[0].0.expose_secret();
            let all_identical = successes
                .iter()
                .skip(1)
                .all(|(s, _)| s.expose_secret() == first_mnemonic);
            if all_identical {
                // Empty metadata abstains; non-empty identities must agree
                // across candidates.
                let derived: Vec<SinglesigPublicMetadataV0> = successes
                    .iter()
                    .map(|(_, group)| derive_metadata(group))
                    .collect();
                let is_empty = |m: &SinglesigPublicMetadataV0| -> bool {
                    m.singlesig_xpub.is_empty() || m.network.is_empty()
                };
                let mut non_empty: Vec<&SinglesigPublicMetadataV0> =
                    derived.iter().filter(|m| !is_empty(m)).collect();
                let identity_agrees = match non_empty.len() {
                    0 => true,
                    _ => {
                        let first = non_empty.remove(0);
                        non_empty.iter().all(|m| **m == *first)
                    }
                };
                if identity_agrees {
                    // Prefer the candidate with non-empty metadata.
                    let prefer_idx = derived.iter().position(|m| !is_empty(m));
                    if let Some(idx) = prefer_idx {
                        let last = successes.len() - 1;
                        successes.swap(idx, last);
                    }
                    return authenticate(to_recovery(&mut successes));
                }
                // Metadata conflict falls through to the ambiguity error.
            }
            let n = successes.len();
            // Use voted per-group metadata for the disambiguation hint.
            let summary: Vec<String> = successes
                .iter()
                .map(|(_, group)| {
                    let derived = derive_metadata(group);
                    describe_share_group(group, &derived)
                })
                .collect();
            // Rejected SecretBox<Mnemonic> values zeroize on drop.
            Err(anyhow!(
                "Ambiguous input: {n} independent share sets recovered different wallets. Re-run with the specific share files for the wallet you want. Candidates:\n{}",
                summary.join("\n")
            ))
        }
    }
}

/// Build a one-line share-group description for disambiguation errors.
fn describe_share_group(
    group: &[VssJsonWalletDescriptionV0],
    derived: &SinglesigPublicMetadataV0,
) -> String {
    // Use voted metadata, not the first share's mutable metadata copy.
    let xpub_hint: &str = if derived.singlesig_xpub.is_empty() {
        "<unauthenticated — share metadata vote tied>"
    } else {
        derived.singlesig_xpub.as_str()
    };
    let mut indexes: Vec<u8> = group.iter().map(|w| w.share_index).collect();
    indexes.sort_unstable();
    indexes.dedup();
    let newest = group
        .iter()
        .map(|w| w.created_at.as_str())
        .max()
        .unwrap_or("<unknown>");
    let threshold = group.first().map(|w| w.threshold).unwrap_or(0);
    let total = group.first().map(|w| w.total_shares).unwrap_or(0);
    format!(
        "  • xpub={xpub_hint} threshold={threshold}/{total} share_indexes={indexes:?} newest={newest}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split_test_singlesig(
        phrase: &str,
        threshold: u8,
        total_shares: u8,
    ) -> Vec<VssJsonWalletDescriptionV0> {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
        let wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json =
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();
        split_singlesig_wallet(json.expose_secret(), threshold, total_shares, &mut rng).unwrap()
    }

    #[test]
    fn test_split_and_combine_12_words() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::thread_rng();

        let shares = split_mnemonic(&mnemonic, 2, 3, &mut rng).unwrap();
        assert_eq!(shares.len(), 3);

        // Combine with threshold shares
        let reconstructed = combine_shares_to_mnemonic(&shares[0..2]).unwrap();
        assert_eq!(
            reconstructed.expose_secret().to_string(),
            mnemonic.to_string()
        );
    }

    #[test]
    fn test_split_and_combine_24_words() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art").unwrap();
        let mut rng = rand::thread_rng();

        let shares = split_mnemonic(&mnemonic, 3, 5, &mut rng).unwrap();
        assert_eq!(shares.len(), 5);

        // Combine with threshold shares
        let reconstructed = combine_shares_to_mnemonic(&shares[1..4]).unwrap();
        assert_eq!(
            reconstructed.expose_secret().to_string(),
            mnemonic.to_string()
        );
    }

    #[test]
    fn test_insufficient_shares() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::thread_rng();

        let shares = split_mnemonic(&mnemonic, 3, 5, &mut rng).unwrap();

        // Try to combine with only 2 shares (need 3)
        let result = combine_shares_to_mnemonic(&shares[0..2]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_threshold() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::thread_rng();

        let result = split_mnemonic(&mnemonic, 5, 3, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_vsss_share_pair_rejects_mismatched_blinder_identifier() {
        let mnemonic = Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let mut rng = rand::thread_rng();

        let shares = split_mnemonic(&mnemonic, 2, 3, &mut rng).unwrap();
        let verifier_set = parse_ristretto_points(&shares[0].verification_data).unwrap();
        let secret_bytes = hex::decode(&shares[0].share_data).unwrap();
        let mut blinder_bytes = hex::decode(&shares[0].blinder_share_data).unwrap();
        let other_blinder_bytes = hex::decode(&shares[1].blinder_share_data).unwrap();

        assert!(verify_vsss_share_pair(
            &verifier_set,
            &secret_bytes,
            &blinder_bytes
        ));

        // vsss-rs 5 shares are `identifier || value`. Keep the blinder
        // value valid for share[0], but replace only its typed identifier
        // with share[1]'s identifier. Pedersen verification evaluates at
        // the secret share's identifier, so the helper must reject the
        // pair before calling into vsss-rs.
        blinder_bytes[..32].copy_from_slice(&other_blinder_bytes[..32]);
        assert_ne!(&secret_bytes[..32], &blinder_bytes[..32]);
        assert!(!verify_vsss_share_pair(
            &verifier_set,
            &secret_bytes,
            &blinder_bytes
        ));
    }

    /// Property test: 100 random 24-word mnemonics must each round-trip
    /// through split + combine exactly.
    ///
    /// This is the regression test for the Curve25519 mod-order reduction
    /// bug. Before the two-half split, ~91% of random 24-word entropies
    /// landed above the scalar order and silently round-tripped to a
    /// *different* valid mnemonic. With the entropy split into two 16-byte
    /// halves, each half is < 2^128 ≪ scalar order, so reduction is
    /// impossible.
    #[test]
    fn test_random_24_word_round_trip() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let mut entropy = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rng, &mut entropy);
            let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
            let shares = split_mnemonic(&mnemonic, 3, 5, &mut rng).unwrap();
            let recovered = combine_shares_to_mnemonic(&shares[1..4]).unwrap();
            assert_eq!(
                recovered.expose_secret().to_string(),
                mnemonic.to_string(),
                "24-word mnemonic failed to round-trip; entropy was {:x?}",
                entropy
            );
        }
    }

    /// Property test: same as above but for 12-word mnemonics, just to keep
    /// both lengths exercised on every CI run.
    #[test]
    fn test_random_12_word_round_trip() {
        let mut rng = rand::thread_rng();
        for _ in 0..50 {
            let mut entropy = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rng, &mut entropy);
            let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
            let shares = split_mnemonic(&mnemonic, 2, 3, &mut rng).unwrap();
            let recovered = combine_shares_to_mnemonic(&shares[0..2]).unwrap();
            assert_eq!(recovered.expose_secret().to_string(), mnemonic.to_string(),);
        }
    }

    /// End-to-end test of `split_singlesig_wallet` → `combine_vss_wallets` →
    /// `VssRecovery::rebuild_singlesig`, including the xpub re-validation.
    /// Also confirms that each VSS share file no longer carries the seed
    /// phrase or any xpriv.
    #[test]
    fn test_vss_singlesig_round_trip_no_secret_leak() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);

        let seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(seed_phrase).unwrap()));
        let wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json =
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();

        let vss_wallets = split_singlesig_wallet(json.expose_secret(), 2, 3, &mut rng).unwrap();
        assert_eq!(vss_wallets.len(), 3);

        // The serialized share must not contain the seed phrase or any xpriv —
        // those are exactly the secrets the threshold scheme exists to protect.
        let serialized = serde_json::to_string(&vss_wallets[0]).unwrap();
        assert!(
            !serialized.contains(seed_phrase),
            "VSS share leaked the seed phrase"
        );
        assert!(
            !serialized.contains("xprv"),
            "VSS share leaked an xpriv: {serialized}"
        );

        // Reconstruct via the public API.
        let recovered = combine_vss_wallets(&vss_wallets[0..2]).unwrap();
        let recovered_phrase = recovered.mnemonic.expose_secret().to_string();
        assert_eq!(recovered_phrase, seed_phrase);

        // rebuild_singlesig should rebuild the wallet from the recovered
        // mnemonic + group metadata, and pass the xpub re-validation.
        let rebuilt = recovered.rebuild_singlesig(&None, &secp).unwrap();
        assert_eq!(
            rebuilt.encoded_singlesig_xpub(),
            wallet.encoded_singlesig_xpub()
        );
    }

    /// The public `split_singlesig_wallet` API must refuse a wallet
    /// whose embedded xpub was derived from a non-default BIP-39
    /// passphrase. The recovery path authenticates against the
    /// no-passphrase derivation; a passphrase-derived xpub baked into
    /// shares would render them unrecoverable (xpub mismatch).
    /// The CLI happens to always pass the no-passphrase decoy, but a
    /// library caller could pass a passphrase-derived wallet and
    /// silently get unsafe shares — the core API enforces the
    /// invariant.
    #[test]
    fn test_split_singlesig_rejects_passphrase_derived_wallet() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
        // Build a wallet whose xpub is derived from a non-empty
        // BIP-39 passphrase. Its `seed_phrase` field still carries
        // the same (passphrase-independent) mnemonic, but its
        // `singlesig_xpub` is the passphrase-derived one.
        let real_password = Arc::new(secrecy::SecretString::from(
            "real wallet passphrase".to_string(),
        ));
        let passphrase_wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &Some(real_password),
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json =
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&passphrase_wallet, &secp)
                .unwrap();

        let err = match split_singlesig_wallet(json.expose_secret(), 2, 3, &mut rng) {
            Ok(_) => {
                panic!("expected split_singlesig_wallet to refuse a passphrase-derived wallet")
            }
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Refusing to split") && msg.contains("no-passphrase"),
            "expected refusal pointing at the no-passphrase invariant, got: {msg}"
        );
    }

    /// `generate_encrypted_encoded_vss_wallet` must succeed with the
    /// DEFAULT padding params for a 24-word share. The compressed VSS
    /// payload for a 24-word wallet routinely exceeds the 1200-byte
    /// minimum-ciphertext floor (extra share/blinder half plus a
    /// second Pedersen verifier set), so a padder that hard-errored on
    /// "pre-pad size > minimum" would block the common case.
    #[test]
    fn test_vss_encrypt_succeeds_with_default_padding_for_24_word() {
        use crate::random_generation_utils::{
            get_random_key, get_random_nonce, get_random_salt, get_secp,
        };
        use crate::wallet_description::{
            EncryptedWalletVersion, ScriptType, SingleSigWalletDescriptionV0,
            SinglesigJsonWalletDescriptionV0,
        };
        use crate::{
            PaddingParams, generate_encrypted_encoded_vss_wallet, get_padder,
            key_derivation::{KeyDerivationDifficulty, default_derive_key},
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        // 24-word fixture (largest standard mnemonic).
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon art";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
        let wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json =
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();
        let vss = split_singlesig_wallet(json.expose_secret(), 3, 5, &mut rng).unwrap();

        let salt = get_random_salt(&mut rng).unwrap();
        let nonce = get_random_nonce(&mut rng).unwrap();
        let header_nonce = get_random_nonce(&mut rng).unwrap();
        let padding_params = PaddingParams::default();
        let padder = get_padder(&mut rng, &padding_params).unwrap();
        let password = Arc::new(secrecy::SecretString::from("test password".to_string()));
        let key =
            default_derive_key(&password, &[], &salt, &KeyDerivationDifficulty::Easy).unwrap();
        let header_key = SecretBox::from(Box::new(get_random_key(&mut rng).unwrap()));

        // The actual smoke test: encryption must succeed even when the
        // VSS payload is already above the 1200-byte size floor.
        let encrypted = generate_encrypted_encoded_vss_wallet(
            &key,
            header_key,
            &vss[0],
            salt,
            nonce,
            header_nonce,
            padder,
            EncryptedWalletVersion::V0Standard,
        )
        .unwrap();
        assert!(!encrypted.is_empty());
    }

    /// Exact-threshold recovery (2-of-2) with one tampered share has
    /// no metadata majority. The chosen recovery must NOT return the
    /// attacker-controlled metadata just because it appeared first.
    /// With internal authentication (`combine_vss_wallets` rejects
    /// recoveries it cannot authenticate against an xpub), a tied
    /// metadata vote leaves no authoritative xpub to verify the seed
    /// against — combine must therefore Err out instead of returning
    /// an unauthenticated mnemonic. This test verifies that
    /// fail-closed behavior end-to-end.
    #[test]
    fn test_recovery_metadata_fails_closed_on_tie() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
        let wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json =
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();

        // 2-of-2 split: every share counts in the metadata vote.
        let mut vss = split_singlesig_wallet(json.expose_secret(), 2, 2, &mut rng).unwrap();
        // Tamper with one of the two shares' xpub. Now the vote is
        // 1 (real) vs 1 (forgery) — no strict majority.
        vss[0].original_wallet.singlesig_xpub = "zpub6tampered00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string();

        let err = match combine_vss_wallets(&vss) {
            Ok(_) => panic!("expected combine_vss_wallets to fail closed on tied metadata"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("could not be authenticated"),
            "expected fail-closed authentication error, got: {msg}"
        );
    }

    /// A single tampered share whose `original_wallet` metadata was
    /// rewritten to point at a *different* xpub must NOT be able to
    /// drive `VssRecovery.metadata` — otherwise a caller using that
    /// metadata to rebuild a wallet could be redirected to the
    /// attacker's chosen wallet. The chosen group's metadata is the
    /// majority across its shares, so a 1-of-N forgery cannot win.
    #[test]
    fn test_recovery_metadata_uses_majority_against_tampered_share() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
        let wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json =
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();
        let mut vss = split_singlesig_wallet(json.expose_secret(), 2, 5, &mut rng).unwrap();
        let real_xpub = vss[0].original_wallet.singlesig_xpub.clone();

        // Tamper with one share's xpub. Real metadata is in 4 of 5 shares
        // (majority); this forgery is in 1 of 5 (minority).
        vss[0].original_wallet.singlesig_xpub =
            "zpub6tampered00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string();

        let recovered = combine_vss_wallets(&vss).unwrap();
        assert_eq!(
            recovered.metadata.singlesig_xpub, real_xpub,
            "metadata followed the tampered minority share — majority must win"
        );
    }

    #[test]
    fn test_spliced_lo_hi_share_does_not_vote_on_metadata() {
        let mut vss = split_test_singlesig(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            2,
            3,
        );
        let mut splice = vss[0].clone();
        splice.share_data_hi = vss[1].share_data_hi.clone();
        splice.blinder_share_data_hi = vss[1].blinder_share_data_hi.clone();
        let mut conflicting_duplicate = vss[2].clone();
        conflicting_duplicate.original_wallet.sigtype = "tampered".to_string();
        let mixed = vec![vss.remove(1), vss.remove(1), conflicting_duplicate, splice];

        let err = match combine_vss_wallets(&mixed) {
            Ok(_) => panic!(
                "lo/hi-spliced shares must not contribute metadata votes for incomplete share ids"
            ),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("could not be authenticated"),
            "expected fail-closed authentication error, got: {msg}"
        );
    }

    /// A share whose embedded singlesig_xpub has been swapped for a different
    /// wallet's xpub must be rejected by `combine_vss_wallets`, even when the
    /// combined mnemonic is valid. This is the metadata-tamper guard.
    #[test]
    fn test_combine_vss_wallets_rejects_tampered_xpub() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);

        let seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(seed_phrase).unwrap()));
        let wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json =
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();

        let mut vss_wallets = split_singlesig_wallet(json.expose_secret(), 2, 3, &mut rng).unwrap();

        // Construct an unrelated wallet to source a valid-looking but wrong xpub.
        let other_phrase =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let other_mnemonic =
            SecretBox::new(Box::new(bip39::Mnemonic::from_str(other_phrase).unwrap()));
        let other_wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(other_mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let bad_xpub = other_wallet.encoded_singlesig_xpub();

        // Sanity: the legitimate xpub differs from the impostor.
        assert_ne!(vss_wallets[0].original_wallet.singlesig_xpub, bad_xpub);
        for share in &mut vss_wallets[0..2] {
            share.original_wallet.singlesig_xpub = bad_xpub.clone();
        }

        let err = match combine_vss_wallets(&vss_wallets[0..2]) {
            Ok(_) => panic!("expected combine_vss_wallets to reject the tampered xpub"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("xpub does not match"),
            "expected xpub-mismatch error, got: {msg}"
        );
    }

    /// If a directory contains two independent complete share sets that
    /// happen to back up the *same* wallet (e.g. the user re-ran
    /// `split-secret` on the same wallet and kept the older set), every
    /// candidate group recovers the same mnemonic and the result is
    /// unambiguous — `combine_vss_wallets` must collapse them and return
    /// that one mnemonic, not bail with an "ambiguous input" error.
    #[test]
    fn test_combine_collapses_identical_wallet_recoveries() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let mut split_same = || {
            let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
            let wallet = SingleSigWalletDescriptionV0::generate(
                Arc::new(mnemonic),
                &None,
                bitcoin::Network::Bitcoin,
                ScriptType::SegwitNative,
                &secp,
            )
            .unwrap();
            let json =
                SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();
            split_singlesig_wallet(json.expose_secret(), 2, 3, &mut rng).unwrap()
        };

        let set_old = split_same();
        let set_new = split_same();

        // Two independent complete 2-of-3 sets, each polynomial different
        // (different randomness) but reconstructing the same mnemonic.
        let mixed: Vec<_> = set_old
            .iter()
            .cloned()
            .chain(set_new.iter().cloned())
            .collect();

        let recovered = combine_vss_wallets(&mixed).unwrap();
        assert_eq!(recovered.mnemonic.expose_secret().to_string(), phrase);
    }

    /// `combine_vss_wallets` must:
    ///   (a) recover the only viable group when one set is complete and
    ///       the other has too few shares to combine; and
    ///   (b) refuse — with a disambiguation message — when more than one
    ///       independent share set is independently combinable AND they
    ///       recover *different* wallets, so the user cannot silently
    ///       recover the wrong wallet from a directory.
    #[test]
    fn test_combine_vss_wallets_handles_mixed_directories() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);

        let phrase_a = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let phrase_b =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";

        let mut make_wallets = |phrase: &str| {
            let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
            let wallet = SingleSigWalletDescriptionV0::generate(
                Arc::new(mnemonic),
                &None,
                bitcoin::Network::Bitcoin,
                ScriptType::SegwitNative,
                &secp,
            )
            .unwrap();
            let json =
                SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();
            split_singlesig_wallet(json.expose_secret(), 2, 3, &mut rng).unwrap()
        };

        let set_a = make_wallets(phrase_a);
        let set_b = make_wallets(phrase_b);

        // (a) Only one viable set: A has 1 share (below threshold=2), B has
        // 3 (above threshold). Recovery must yield B without ambiguity.
        let mixed_one_viable = vec![
            set_a[0].clone(),
            set_b[0].clone(),
            set_b[1].clone(),
            set_b[2].clone(),
        ];
        let recovered = combine_vss_wallets(&mixed_one_viable).unwrap();
        assert_eq!(recovered.mnemonic.expose_secret().to_string(), phrase_b);

        // (b) Two viable sets: both A and B have 2+ shares. Combine must
        // refuse rather than guess.
        let mixed_two_viable = vec![
            set_a[0].clone(),
            set_a[1].clone(),
            set_b[0].clone(),
            set_b[1].clone(),
        ];
        let err = match combine_vss_wallets(&mixed_two_viable) {
            Ok(_) => panic!("expected ambiguity error"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Ambiguous input"),
            "expected ambiguity error, got: {msg}"
        );
        // The disambiguation message should name xpubs so the user can pick.
        assert!(msg.contains("xpub="), "expected xpub hints, got: {msg}");

        // Insufficient shares of any compatible set must still fail.
        let neither_viable = vec![set_a[0].clone(), set_b[0].clone()];
        let err = match combine_vss_wallets(&neither_viable) {
            Ok(_) => panic!("expected insufficient-shares error"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("No threshold-compatible subset")
                || msg.contains("failed to combine")
                || msg.contains("Insufficient"),
            "got: {msg}"
        );
    }

    /// Exact-threshold (3-of-3) recovery where one share's verifier
    /// COPY is corrupted but its secret/blinder bytes are still valid
    /// for the real polynomial. The remaining shares carry the real
    /// verifier; we use it to verify ALL shares (including the one
    /// with the corrupted verifier copy). Recovery must succeed.
    #[test]
    fn test_combine_vss_wallets_tolerates_verifier_copy_corruption() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
        let wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json =
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();
        // 3-of-3: each share is mandatory.
        let mut vss = split_singlesig_wallet(json.expose_secret(), 3, 3, &mut rng).unwrap();
        // Corrupt the LO verifier on share[2] only — its share_data /
        // blinder_share_data stay intact.
        vss[2].verification_data = "deadbeef,deadbeef,deadbeef,deadbeef,deadbeef".to_string();

        let recovered = combine_vss_wallets(&vss).unwrap();
        assert_eq!(recovered.mnemonic.expose_secret().to_string(), phrase);
    }

    /// Exact-threshold 24-word recovery where the LO verifier is
    /// corrupted on one share AND the HI verifier is corrupted on a
    /// *different* share. The correct lo verifier and the correct hi
    /// verifier both still exist in the input, but they never coexist
    /// on the same share. Recovery must succeed by trying the
    /// cross-product of distinct lo verifiers × distinct hi verifiers,
    /// not just the (lo, hi) pairs that come together on one share.
    #[test]
    fn test_combine_vss_wallets_tolerates_split_lo_hi_verifier_corruption() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        // 24-word phrase so each share carries both lo and hi
        // verifiers / share data.
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
        let wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json =
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();
        // 2-of-2 (exact threshold): both shares are mandatory and
        // each carries both halves' verifiers. Corrupt LO verifier on
        // share[0] AND HI verifier on share[1] — the correct lo
        // verifier still exists on share[1], the correct hi verifier
        // still exists on share[0], but they never coexist on a
        // single share. Without cross-product candidate enumeration,
        // the only candidates would be
        //   (bad_lo,    good_hi_0)   ← from share[0]
        //   (good_lo_1, bad_hi)      ← from share[1]
        // both of which fail the Pedersen check. The cross-product
        // adds (good_lo_1, good_hi_0), which combines successfully.
        let mut vss = split_singlesig_wallet(json.expose_secret(), 2, 2, &mut rng).unwrap();
        vss[0].verification_data = "deadbeef,deadbeef,deadbeef,deadbeef".to_string();
        vss[1].verification_data_hi = Some("cafebabe,cafebabe,cafebabe,cafebabe".to_string());

        let recovered = combine_vss_wallets(&vss).unwrap();
        assert_eq!(recovered.mnemonic.expose_secret().to_string(), phrase);
    }

    /// A 24-word recovery must have threshold many complete share identities:
    /// the low half and high half may each be independently recoverable, but
    /// metadata is not authenticated unless the same threshold-sized set of
    /// cryptographic share identifiers verifies for both halves.
    #[test]
    fn test_combine_vss_wallets_rejects_below_threshold_complete_share_ids() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        fn bump_share_value(hex_share: &mut String) {
            let bytes = hex::decode(hex_share.as_str()).unwrap();
            let share = vsss_share_from_bytes(&bytes).unwrap();
            let value = IdentifierPrimeField(WrappedScalar(share.value().0.0 + Scalar::from(1u64)));
            let tampered = VsssShare::with_identifier_and_value(*share.identifier(), value);
            *hex_share = hex::encode(vsss_share_to_bytes(&tampered));
        }

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
        let wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json =
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();
        let mut vss = split_singlesig_wallet(json.expose_secret(), 3, 5, &mut rng).unwrap();

        // Low half can still recover from ids {1,2,3}; high half can
        // still recover from ids {3,4,5}. Their complete intersection is
        // only id {3}, below threshold=3, so metadata must not be accepted.
        for share in vss.iter_mut().skip(3) {
            bump_share_value(&mut share.share_data);
        }
        for share in vss.iter_mut().take(2) {
            bump_share_value(share.share_data_hi.as_mut().unwrap());
        }

        let err = match combine_vss_wallets(&vss) {
            Ok(_) => panic!("expected below-threshold complete-share intersection to be rejected"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("complete verified share identifier")
                || msg.contains("No threshold-compatible subset"),
            "expected complete-share threshold rejection, got: {msg}"
        );
    }

    /// Tamper the share_data hex of one share, then attempt to combine the
    /// threshold shares. Lagrange interpolation alone would happily produce
    /// *some* scalar (and thus *some* mnemonic) from any t consistent points,
    /// so without per-share verification a bad share would silently corrupt
    /// recovery. With Pedersen verification on the combine path, the tampered
    /// share must be rejected before reconstruction.
    #[test]
    fn test_tampered_share_is_rejected() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::thread_rng();

        let mut shares = split_mnemonic(&mnemonic, 2, 3, &mut rng).unwrap();

        // Flip the value half of share 0's share_data so it still parses
        // as hex but encodes a different field element. The first 32 bytes
        // encode the vsss-rs 5 typed identifier, so leave them intact.
        let mut bytes = hex::decode(&shares[0].share_data).unwrap();
        assert_eq!(bytes.len(), 64);
        for b in &mut bytes[32..] {
            *b ^= 0xAA;
        }
        shares[0].share_data = hex::encode(&bytes);

        let err = match combine_shares_to_mnemonic(&shares[0..2]) {
            Ok(_) => panic!("expected combine to reject the tampered share"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Pedersen")
                || msg.contains("verification")
                || msg.contains("Insufficient verified shares"),
            "expected verification failure, got: {msg}"
        );
    }

    /// If the largest compatible group fails verification (too many
    /// corrupt shares), `combine_vss_wallets` must fall back to a smaller
    /// group whose verified shares still meet threshold. Without iterative
    /// candidate selection, a noisy "big" group would block recovery even
    /// when a clean smaller group is also present.
    #[test]
    fn test_combine_falls_back_to_smaller_clean_group() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);

        let phrase_a = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let phrase_b =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";

        let mut split = |phrase: &str| {
            let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
            let wallet = SingleSigWalletDescriptionV0::generate(
                Arc::new(mnemonic),
                &None,
                bitcoin::Network::Bitcoin,
                ScriptType::SegwitNative,
                &secp,
            )
            .unwrap();
            let json =
                SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();
            split_singlesig_wallet(json.expose_secret(), 2, 3, &mut rng).unwrap()
        };

        let mut set_a = split(phrase_a); // larger group, but two shares get corrupted
        let set_b = split(phrase_b); // smaller-presence-but-clean group

        // Corrupt 2 of the 3 shares in set A so its verified count drops to
        // 1 (below threshold=2).
        for share in set_a.iter_mut().take(2) {
            let mut bytes = hex::decode(&share.share_data).unwrap();
            for b in &mut bytes[32..] {
                *b ^= 0xAA;
            }
            share.share_data = hex::encode(&bytes);
        }

        // Mix: 3 of A (largest by raw count) + 2 of B (smaller, still clean).
        let mixed = vec![
            set_a[0].clone(),
            set_a[1].clone(),
            set_a[2].clone(),
            set_b[0].clone(),
            set_b[1].clone(),
        ];

        let recovered = combine_vss_wallets(&mixed).unwrap();
        // A is biggest by input size; tried first, fails (2 corrupt). B is
        // tried next, succeeds. Recovered phrase must be B's.
        assert_eq!(recovered.mnemonic.expose_secret().to_string(), phrase_b);
    }

    /// Recovery must depend only on cryptographically authoritative data
    /// (Pedersen verifier set + share bytes). Tampering with the mutable
    /// `threshold` JSON field — either UP (e.g. claiming 5 instead of 2)
    /// or DOWN (claiming 2 instead of 3) — must not affect the outcome:
    ///   * "edit up": recovery still succeeds, because the real threshold
    ///     comes from the Pedersen set.
    ///   * "edit down": cannot trick combine into using fewer points,
    ///     because Lagrange interpolation needs the real polynomial degree
    ///     and per-share Pedersen verification rejects forged points; in
    ///     the all-genuine-shares case recovery again succeeds and the
    ///     downgraded metadata is harmless noise.
    #[test]
    fn test_combine_ignores_tampered_threshold_metadata() {
        use crate::random_generation_utils::get_secp;
        use crate::wallet_description::{
            ScriptType, SingleSigWalletDescriptionV0, SinglesigJsonWalletDescriptionV0,
        };
        use std::str::FromStr;
        use std::sync::Arc;

        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);

        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = SecretBox::new(Box::new(bip39::Mnemonic::from_str(phrase).unwrap()));
        let wallet = SingleSigWalletDescriptionV0::generate(
            Arc::new(mnemonic),
            &None,
            bitcoin::Network::Bitcoin,
            ScriptType::SegwitNative,
            &secp,
        )
        .unwrap();
        let json =
            SinglesigJsonWalletDescriptionV0::from_wallet_description(&wallet, &secp).unwrap();

        for tampered_threshold in [1u8, 5u8, 99u8] {
            let mut vss = split_singlesig_wallet(json.expose_secret(), 2, 3, &mut rng).unwrap();
            for w in vss.iter_mut() {
                w.threshold = tampered_threshold;
                w.total_shares = 99; // also corrupt this — should be ignored
            }
            let recovered = combine_vss_wallets(&vss).unwrap_or_else(|e| {
                panic!(
                    "combine_vss_wallets should ignore tampered threshold={tampered_threshold}, but failed: {e:#}"
                )
            });
            assert_eq!(recovered.mnemonic.expose_secret().to_string(), phrase);
        }
    }

    /// Lower-level mirror of the above: tampering the `threshold` field on
    /// every VSS payload of a genuine 3-of-5 split
    /// must NOT trick combine into accepting 2 shares — Lagrange + Pedersen
    /// still demand the real polynomial. With 3 genuine shares supplied,
    /// recovery succeeds despite the lying metadata.
    #[test]
    fn test_combine_shares_ignores_downgraded_threshold_metadata() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::thread_rng();

        let mut shares = split_mnemonic(&mnemonic, 3, 5, &mut rng).unwrap();
        for share in shares.iter_mut() {
            share.threshold = 2; // downgrade across the board
        }

        // 2 shares: must still fail because the Pedersen threshold is 3.
        let err = combine_shares_to_mnemonic(&shares[0..2]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Insufficient"),
            "expected insufficient-shares error, got: {msg}"
        );

        // 3 shares: recovery succeeds, downgraded metadata is harmless.
        let recovered = combine_shares_to_mnemonic(&shares[0..3]).unwrap();
        assert_eq!(recovered.expose_secret().to_string(), mnemonic.to_string());
    }

    /// An attacker who edits `mnemonic_length` from 24 down to 12 across
    /// every share must NOT be able to silently truncate the recovered
    /// seed to a different valid 12-word mnemonic. The combine path
    /// must determine 12-vs-24 from the *cryptographic* presence of
    /// the high-half verifier set, not from the mutable JSON field.
    ///
    /// Use 100 random 24-word mnemonics so a coincidental collision
    /// (where the lo-half-only mnemonic happens to equal the original)
    /// can't pass.
    #[test]
    fn test_combine_resists_24_to_12_metadata_downgrade() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let mut entropy = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rng, &mut entropy);
            let original = Mnemonic::from_entropy(&entropy).unwrap();

            let mut shares = split_mnemonic(&original, 3, 5, &mut rng).unwrap();
            // Tamper: rewrite the metadata across all shares.
            for s in &mut shares {
                s.mnemonic_length = 12;
            }

            let recovered = combine_shares_to_mnemonic(&shares[0..3]).unwrap();
            assert_eq!(
                recovered.expose_secret().to_string(),
                original.to_string(),
                "downgrade attack succeeded — recovery returned a 12-word phrase instead of the original 24"
            );
        }
    }

    /// Recovery must not depend on input order. Even when the
    /// corrupted-verifier share happens to be at index 0 (which the old
    /// "anchor on shares[0]" check used as canonical), the remaining
    /// shares must still reconstruct as long as a viable verifier-
    /// matching subset exists.
    #[test]
    fn test_combine_recovers_when_shares_zero_has_corrupt_verifier() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::thread_rng();
        // 2-of-3 split. Corrupt shares[0]'s verifier so it ends up in a
        // singleton group. shares[1..3] still have the real verifier and
        // form a 2-share group that meets threshold.
        let mut shares = split_mnemonic(&mnemonic, 2, 3, &mut rng).unwrap();
        shares[0].verification_data = "deadbeef,deadbeef,deadbeef,deadbeef".to_string();

        let recovered = combine_shares_to_mnemonic(&shares).unwrap();
        assert_eq!(recovered.expose_secret().to_string(), mnemonic.to_string());
    }

    /// A metadata-corrupted extra share must not strand a recoverable
    /// threshold set: a flipped `version` byte, a stripped high-half
    /// field, or other purely-metadata damage on one share is dropped
    /// per-share by combine_one_half, leaving the remaining good shares
    /// to reconstruct.
    #[test]
    fn test_combine_tolerates_metadata_corrupt_extra_share() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::thread_rng();
        // 2-of-3 split → corrupt the *third* share's metadata. We hand 2
        // good shares + 1 metadata-corrupt share to combine; recovery
        // must succeed because the threshold is still met by the good 2.
        let mut shares = split_mnemonic(&mnemonic, 2, 3, &mut rng).unwrap();
        // Flip the version on one share (metadata-only damage; doesn't
        // affect the cryptographic share data).
        shares[2].version = 9999;

        let recovered = combine_shares_to_mnemonic(&shares).unwrap();
        assert_eq!(recovered.expose_secret().to_string(), mnemonic.to_string());
    }

    /// Share files must not embed Feldman commitments (`g^a_i`). For our
    /// 16-byte halves the secret `a_0` is bounded to 128 bits, so a
    /// Feldman commitment `g^secret_half` would be vulnerable to a ~2^64
    /// discrete-log attack — an attacker who decrypts a single share could
    /// recover the half. The Pedersen blind commitments we DO store
    /// (`g^a * h^b` with random `b`) hide the secret information-
    /// theoretically.
    ///
    /// This is a structural test: we serialize a fresh share to JSON and
    /// assert no field contains a "feldman" key, plus that the verifier
    /// set length matches Pedersen layout (`threshold + 2`) and not
    /// Feldman layout (`threshold + 1`).
    #[test]
    fn test_share_does_not_leak_feldman_commitments() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::thread_rng();
        let shares = split_mnemonic(&mnemonic, 2, 3, &mut rng).unwrap();
        let json = serde_json::to_string(&shares[0]).unwrap();
        assert!(
            !json.to_lowercase().contains("feldman"),
            "share serialization must not include any Feldman field: {json}"
        );

        // Threshold = 2 → Pedersen verifier set should hold 2+2 = 4 hex
        // points (g, h, C_0, C_1). Anything else means we accidentally
        // serialized the wrong commitment set.
        let parts: Vec<&str> = shares[0].verification_data.split(',').collect();
        assert_eq!(
            parts.len(),
            4,
            "verification_data must be 4 points for 2-of-3 split: {parts:?}"
        );
    }

    /// One corrupted share among extra redundant shares must not block
    /// recovery — the verifier filters out the bad one and reconstruction
    /// succeeds from the remaining good ones.
    #[test]
    fn test_extra_share_redundancy_tolerates_one_corruption() {
        let mnemonic = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let mut rng = rand::thread_rng();

        // 2-of-3 split → corrupt share 0, but provide all 3 shares. Combine
        // should drop the bad one, keep shares 1 and 2, and recover the seed.
        let mut shares = split_mnemonic(&mnemonic, 2, 3, &mut rng).unwrap();
        let mut bytes = hex::decode(&shares[0].share_data).unwrap();
        for b in &mut bytes[32..] {
            *b ^= 0xAA;
        }
        shares[0].share_data = hex::encode(&bytes);

        let recovered = combine_shares_to_mnemonic(&shares).unwrap();
        assert_eq!(recovered.expose_secret().to_string(), mnemonic.to_string());
    }
}
