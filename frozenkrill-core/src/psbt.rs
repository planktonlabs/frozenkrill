use anyhow::Context;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{
    EcdsaSighashType, FeeRate, PrivateKey, Psbt, PublicKey, TapSighashType, Transaction, ecdsa,
    psbt::{
        Error, ExtractTxError, GetKey, GetKeyError, IndexOutOfBoundsError, Input, KeyRequest,
        OutputType, PsbtSighashType, SignError, SigningAlgorithm, SigningKeys, SigningKeysMap,
    },
    sighash::SighashCache,
};
use log::{debug, warn};
use secrecy::{ExposeSecret, SecretBox};
type Secret<T> = SecretBox<T>;
use std::{borrow::Borrow, fs::OpenOptions, io::Read, path::Path};

use crate::{utils::create_file, wallet_description::WExtendedPrivKey};

pub fn open_psbt_file(p: &Path) -> anyhow::Result<Psbt> {
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
    let p = Psbt::deserialize(&raw).context("failure deserializing PSBT file")?;
    Ok(p)
}

pub fn save_psbt_file<'a>(psbt: &Psbt, path: &'a Path) -> anyhow::Result<&'a Path> {
    create_file(&psbt.serialize(), path)
}

/// Refuses PSBTs whose inputs request a sighash type that doesn't commit to the whole
/// transaction.
///
/// With SIGHASH_NONE, SIGHASH_SINGLE or ANYONECANPAY the signature leaves some outputs or
/// inputs uncommitted, so whoever holds the signed PSBT can change them after the user
/// approved the outputs shown on screen.
pub fn ensure_sighash_all(psbt: &Psbt) -> anyhow::Result<()> {
    let allowed = [
        PsbtSighashType::from(EcdsaSighashType::All),
        // Taproot's default commits to the whole transaction just like SIGHASH_ALL
        PsbtSighashType::from(TapSighashType::Default),
    ];
    for (index, input) in psbt.inputs.iter().enumerate() {
        if let Some(sighash_type) = input.sighash_type {
            anyhow::ensure!(
                allowed.contains(&sighash_type),
                "Input {index} requests sighash type {sighash_type}, refusing to sign: only SIGHASH_ALL is supported because other types allow the transaction to be changed after it is signed"
            );
        }
    }
    Ok(())
}

pub(super) fn sign_psbt(
    psbt: &mut Psbt,
    input_keys: &[&Secret<WExtendedPrivKey>],
    secp: &Secp256k1<All>,
) -> anyhow::Result<usize> {
    anyhow::ensure!(!input_keys.is_empty(), "No keys given for sign psbt");
    ensure_sighash_all(psbt)?;
    let keys = input_keys
        .iter()
        .map(|k| k.expose_secret().0.to_owned())
        .collect::<Vec<_>>();
    let provider = SignerProvider { keys };
    let result = psbt.sign_partial(&provider, secp);
    // FIXME: do we want the number of outputs signed or the number of keys used?
    let inputs_signed = result
        .into_values()
        .map(|public_keys| match public_keys {
            SigningKeys::Ecdsa(v) => v.len(),
            SigningKeys::Schnorr(v) => v.len(),
        })
        .sum();

    Ok(inputs_signed)
}

struct SignerProvider {
    keys: Vec<bitcoin::bip32::Xpriv>,
}

impl GetKey for SignerProvider {
    type Error = GetKeyError;

    fn get_key<C: bitcoin::secp256k1::Signing>(
        &self,
        key_request: KeyRequest,
        secp: &bitcoin::secp256k1::Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::Pubkey(_) => Err(GetKeyError::NotSupported),
            KeyRequest::Bip32((fingerprint, path)) => {
                for xpriv in self.keys.iter() {
                    let xpriv_fingerprint = xpriv.fingerprint(secp);
                    debug!("Checking {xpriv_fingerprint} against {fingerprint} {path}");
                    if xpriv_fingerprint == fingerprint {
                        let k = xpriv.derive_priv(secp, &path)?;
                        return Ok(Some(k.to_priv()));
                    }
                }
                Ok(None)
            }
            other => {
                warn!("Unsupported key request: {other:?}");
                Err(GetKeyError::NotSupported)
            }
        }
    }
}

pub trait PsbtExt {
    fn sign_partial<C, K>(
        &mut self,
        k: &K,
        secp: &bitcoin::secp256k1::Secp256k1<C>,
    ) -> SigningKeysMap
    where
        C: bitcoin::secp256k1::Signing,
        K: GetKey;
    fn output_type(&self, input_index: usize) -> Result<OutputType, SignError>;
    fn signing_algorithm(&self, input_index: usize) -> Result<SigningAlgorithm, SignError>;
    fn check_index_is_within_bounds(&self, input_index: usize)
    -> Result<(), IndexOutOfBoundsError>;
    fn checked_input(&self, input_index: usize) -> Result<&Input, IndexOutOfBoundsError>;
    fn bip32_sign_ecdsa<C, K, T>(
        &mut self,
        k: &K,
        input_index: usize,
        cache: &mut SighashCache<T>,
        secp: &bitcoin::secp256k1::Secp256k1<C>,
    ) -> Result<Vec<PublicKey>, SignError>
    where
        C: bitcoin::secp256k1::Signing,
        T: Borrow<Transaction>,
        K: GetKey;

    #[allow(clippy::result_large_err)]
    fn internal_extract_tx_with_fee_rate_limit(
        self,
        max_fee_rate: FeeRate,
    ) -> Result<Transaction, ExtractTxError>;
    fn internal_extract_tx(self) -> Transaction;
    fn unsigned_tx_checks(&self) -> Result<(), Error>;
}

impl PsbtExt for Psbt {
    /// Checks that unsigned transaction does not have scriptSig's or witness data.
    fn unsigned_tx_checks(&self) -> Result<(), Error> {
        for txin in &self.unsigned_tx.input {
            if !txin.script_sig.is_empty() {
                return Err(Error::UnsignedTxHasScriptSigs);
            }

            if !txin.witness.is_empty() {
                return Err(Error::UnsignedTxHasScriptWitnesses);
            }
        }

        Ok(())
    }

    #[inline]
    fn internal_extract_tx(self) -> Transaction {
        let mut tx: Transaction = self.unsigned_tx;

        for (vin, psbtin) in tx.input.iter_mut().zip(self.inputs) {
            vin.script_sig = psbtin.final_script_sig.unwrap_or_default();
            vin.witness = psbtin.final_script_witness.unwrap_or_default();
        }

        tx
    }

    #[inline]
    fn internal_extract_tx_with_fee_rate_limit(
        self,
        max_fee_rate: FeeRate,
    ) -> Result<Transaction, ExtractTxError> {
        let fee = match self.fee() {
            Ok(fee) => fee,
            Err(Error::MissingUtxo) => {
                return Err(ExtractTxError::MissingInputValue {
                    tx: self.internal_extract_tx(),
                });
            }
            Err(Error::NegativeFee) => return Err(ExtractTxError::SendingTooMuch { psbt: self }),
            Err(Error::FeeOverflow) => {
                return Err(ExtractTxError::AbsurdFeeRate {
                    fee_rate: FeeRate::MAX,
                    tx: self.internal_extract_tx(),
                });
            }
            _ => unreachable!(),
        };

        // Note: Move prevents usage of &self from now on.
        let tx = self.internal_extract_tx();

        // Now that the extracted Transaction is made, decide how to return it.
        let fee_rate =
            FeeRate::from_sat_per_kwu(fee.to_sat().saturating_mul(1000) / tx.weight().to_wu());
        // Prefer to return an AbsurdFeeRate error when both trigger.
        if fee_rate > max_fee_rate {
            return Err(ExtractTxError::AbsurdFeeRate { fee_rate, tx });
        }

        Ok(tx)
    }

    /// Attempts to create all signatures required by this PSBT's `bip32_derivation` field, adding
    /// them to `partial_sigs`.
    ///
    /// # Returns
    ///
    /// - Ok: A list of the public keys used in signing.
    /// - Err: Error encountered trying to calculate the sighash AND we had the signing key.
    fn bip32_sign_ecdsa<C, K, T>(
        &mut self,
        k: &K,
        input_index: usize,
        cache: &mut SighashCache<T>,
        secp: &bitcoin::secp256k1::Secp256k1<C>,
    ) -> Result<Vec<PublicKey>, SignError>
    where
        C: bitcoin::secp256k1::Signing,
        T: Borrow<Transaction>,
        K: GetKey,
    {
        let msg_sighash_ty_res = self.sighash_ecdsa(input_index, cache);

        let input = &mut self.inputs[input_index]; // Index checked in call to `sighash_ecdsa`.

        let mut used = vec![]; // List of pubkeys used to sign the input.

        for (pk, key_source) in input.bip32_derivation.iter() {
            let sk = if let Ok(Some(sk)) = k.get_key(KeyRequest::Bip32(key_source.clone()), secp) {
                sk
            } else if let Ok(Some(sk)) = k.get_key(KeyRequest::Pubkey(PublicKey::new(*pk)), secp) {
                sk
            } else {
                continue;
            };

            // Only return the error if we have a secret key to sign this input.
            let (msg, sighash_ty) = match msg_sighash_ty_res {
                Err(e) => return Err(e),
                Ok((msg, sighash_ty)) => (msg, sighash_ty),
            };

            let sig = ecdsa::Signature {
                signature: secp.sign_ecdsa(&msg, &sk.inner),
                sighash_type: sighash_ty,
            };

            let pk = sk.public_key(secp);

            debug!("Signed input {input_index} with pubkey {pk}");
            input.partial_sigs.insert(pk, sig);
            used.push(pk);
        }

        debug!("Signed input {input_index} with {} keys", used.len());
        Ok(used)
    }

    /// Gets the input at `input_index` after checking that it is a valid index.
    fn checked_input(&self, input_index: usize) -> Result<&Input, IndexOutOfBoundsError> {
        self.check_index_is_within_bounds(input_index)?;
        Ok(&self.inputs[input_index])
    }

    /// Checks `input_index` is within bounds for the PSBT `inputs` array and
    /// for the PSBT `unsigned_tx` `input` array.
    fn check_index_is_within_bounds(
        &self,
        input_index: usize,
    ) -> Result<(), IndexOutOfBoundsError> {
        if input_index >= self.inputs.len() {
            return Err(IndexOutOfBoundsError::Inputs {
                index: input_index,
                length: self.inputs.len(),
            });
        }

        if input_index >= self.unsigned_tx.input.len() {
            return Err(IndexOutOfBoundsError::TxInput {
                index: input_index,
                length: self.unsigned_tx.input.len(),
            });
        }

        Ok(())
    }

    /// Returns the algorithm used to sign this PSBT's input at `input_index`.
    fn signing_algorithm(&self, input_index: usize) -> Result<SigningAlgorithm, SignError> {
        let output_type = self.output_type(input_index)?;
        Ok(output_type.signing_algorithm())
    }

    /// Returns the [`OutputType`] of the spend utxo for this PBST's input at `input_index`.
    fn output_type(&self, input_index: usize) -> Result<OutputType, SignError> {
        let input = self.checked_input(input_index)?;
        let utxo = self.spend_utxo(input_index)?;
        let spk = utxo.script_pubkey.clone();

        // Anything that is not segwit and is not p2sh is `Bare`.
        if !(spk.is_witness_program() || spk.is_p2sh()) {
            return Ok(OutputType::Bare);
        }

        if spk.is_p2wpkh() {
            return Ok(OutputType::Wpkh);
        }

        if spk.is_p2wsh() {
            return Ok(OutputType::Wsh);
        }

        if spk.is_p2sh() {
            if input
                .redeem_script
                .as_ref()
                .map(|s| s.is_p2wpkh())
                .unwrap_or(false)
            {
                return Ok(OutputType::ShWpkh);
            }
            if input
                .redeem_script
                .as_ref()
                .map(|x| x.is_p2wsh())
                .unwrap_or(false)
            {
                return Ok(OutputType::ShWsh);
            }
            return Ok(OutputType::Sh);
        }

        if spk.is_p2tr() {
            return Ok(OutputType::Tr);
        }

        // Something is wrong with the input scriptPubkey or we do not know how to sign
        // because there has been a new softfork that we do not yet support.
        Err(SignError::UnknownOutputType)
    }

    // like sign, but won't generate an error if some input can't be signed
    fn sign_partial<C, K>(
        &mut self,
        k: &K,
        secp: &bitcoin::secp256k1::Secp256k1<C>,
    ) -> SigningKeysMap
    where
        C: bitcoin::secp256k1::Signing,
        K: GetKey,
    {
        let tx = self.unsigned_tx.clone(); // clone because we need to mutably borrow when signing.
        let mut cache = SighashCache::new(&tx);

        let mut used = SigningKeysMap::new();

        for i in 0..self.inputs.len() {
            match self.signing_algorithm(i) {
                Ok(SigningAlgorithm::Ecdsa) => {
                    match self.bip32_sign_ecdsa(k, i, &mut cache, secp) {
                        Ok(v) if !v.is_empty() => {
                            debug!("Signed input {i}");
                            used.insert(i, SigningKeys::Ecdsa(v));
                        }
                        Ok(_) => {
                            debug!("Can't sign input {i}: no key found");
                        }
                        Err(e) => {
                            debug!("Can't sign input {i}: {e}");
                        }
                    }
                }
                Ok(SigningAlgorithm::Schnorr) => {
                    warn!("Can't sign input {i}: Schnorr signing is not supported yet");
                }
                Err(other) => {
                    warn!("Can't sign input {i}: {other}");
                }
            };
        }
        used
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::bip32::Xpriv;

    use super::*;
    use crate::{custom_logger, random_generation_utils::get_secp, slip132::FromSlip132};

    // A testnet P2WPKH spend with one input (sighash type ALL) and two outputs
    const TEST_PSBT_HEX: &str = "70736274ff010071020000000187ca9152f3540a73cfd51115277667e91a548fcf0544276f05fba9628c27fc5c0000000000fdffffff022a6203000000000016001487b78396f6f85213bce62e3374661bc578ae39d610560d00000000001600145c217d465b15f3c3041f9eac8ae88133485d4f6ae6340b00000100710200000001aa20bc793370fb83dba9a87753969fd3b9d7fd361be40a55d302f0d6fa1ddc410000000000feffffff02a8b81000000000001600149ef71340cba5b463069cfa4d781390cc9eefadb234de14d4010000001600140f4a26ef5174291b5c02b258a605d33944081b9f27cd240001011fa8b81000000000001600149ef71340cba5b463069cfa4d781390cc9eefadb2010304010000002206037a0f324d4c7baccc4da3bb2594cee6ee9f3b0771231fa7ce89b14ae191232bab0ccee87ee50000000001000000002202029402da79dd8b0d4f4d8eb625aaa79908088d0b1e10fbf70ab70fd5c84fbabbeb0ccee87ee501000000000000000000";
    // The key that signs the input of TEST_PSBT_HEX
    const TEST_SPRIV: &str = "vprv9Ks2HJ9nwsjejp3mbQnSKEEZfN9jNNAEvrBvZP6N3P473Q2u6Noskm5nSu7wyoyNZB6T4e9U5FWYPjcQFsFKFoATH6hWYkrr2GShCuAwfYs";

    fn test_xpriv() -> anyhow::Result<Secret<WExtendedPrivKey>> {
        Ok(Secret::from(Box::new(WExtendedPrivKey(
            Xpriv::from_slip132_str(TEST_SPRIV)?,
        ))))
    }

    #[test]
    fn test_sign() -> anyhow::Result<()> {
        custom_logger::init();
        let mut rng = rand::rng();
        let secp = get_secp(&mut rng);
        let tempdir = tempfile::tempdir()?;
        let psbt_path = tempdir.path().join("psbt.psbt");
        create_file(&hex::decode(TEST_PSBT_HEX)?, &psbt_path)?;
        let mut p = open_psbt_file(&psbt_path)?;
        let xpriv = test_xpriv()?;
        assert!(!p.inputs.is_empty());
        for i in &p.inputs {
            assert!(i.partial_sigs.is_empty())
        }
        let n = sign_psbt(&mut p, &[&xpriv], &secp)?;
        assert_eq!(n, 1);

        for i in &p.inputs {
            println!("{:?}", i);
            assert!(!i.partial_sigs.is_empty())
        }
        Ok(())
    }

    #[test]
    fn test_sign_without_sighash_type() -> anyhow::Result<()> {
        let mut rng = rand::rng();
        let secp = get_secp(&mut rng);
        let mut p = Psbt::deserialize(&hex::decode(TEST_PSBT_HEX)?)?;
        // An absent sighash type means SIGHASH_ALL
        p.inputs[0].sighash_type = None;
        let xpriv = test_xpriv()?;
        assert_eq!(sign_psbt(&mut p, &[&xpriv], &secp)?, 1);
        let sig = p.inputs[0]
            .partial_sigs
            .values()
            .next()
            .expect("a signature");
        assert_eq!(sig.sighash_type, EcdsaSighashType::All);
        Ok(())
    }

    #[test]
    fn test_sign_refuses_sighash_types_other_than_all() -> anyhow::Result<()> {
        let mut rng = rand::rng();
        let secp = get_secp(&mut rng);
        let xpriv = test_xpriv()?;
        for sighash_type in [
            PsbtSighashType::from(EcdsaSighashType::None),
            PsbtSighashType::from(EcdsaSighashType::Single),
            PsbtSighashType::from(EcdsaSighashType::AllPlusAnyoneCanPay),
            PsbtSighashType::from(EcdsaSighashType::NonePlusAnyoneCanPay),
            PsbtSighashType::from(EcdsaSighashType::SinglePlusAnyoneCanPay),
        ] {
            let mut p = Psbt::deserialize(&hex::decode(TEST_PSBT_HEX)?)?;
            p.inputs[0].sighash_type = Some(sighash_type);
            assert!(ensure_sighash_all(&p).is_err(), "{sighash_type} accepted");
            let error = sign_psbt(&mut p, &[&xpriv], &secp)
                .expect_err("signing must be refused")
                .to_string();
            assert!(
                error.contains(&sighash_type.to_string()),
                "unexpected error: {error}"
            );
            assert!(
                p.inputs.iter().all(|i| i.partial_sigs.is_empty()),
                "{sighash_type} produced a signature"
            );
        }
        Ok(())
    }
}
