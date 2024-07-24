use alkali::random;
use anyhow::Context;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use miniscript::{
    descriptor::{DerivPaths, Wildcard},
    Descriptor, DescriptorPublicKey,
};
use rand_core::CryptoRngCore;
use secp256k1::{All, Secp256k1};

use crate::{
    wallet_description::{KEY_SIZE, NONCE_SIZE, SALT_SIZE},
    OptOrigin, PaddingParams, MAX_BASE_PADDING_BYTES,
};

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

pub fn get_secp<Rng: CryptoRngCore>(rng: &mut Rng) -> Secp256k1<All> {
    let mut s = Secp256k1::new();
    s.randomize(rng);
    s
}

pub fn random_pkh_descriptor(
    secp: &Secp256k1<All>,
    rng: &mut impl CryptoRngCore,
) -> anyhow::Result<Descriptor<DescriptorPublicKey>> {
    let pk = random_descriptor_pk(secp, rng)?;
    Ok(Descriptor::Pkh(miniscript::descriptor::Pkh::new(pk)?))
}

pub fn random_wpkh_descriptor(
    secp: &Secp256k1<All>,
    rng: &mut impl CryptoRngCore,
) -> anyhow::Result<Descriptor<DescriptorPublicKey>> {
    let pk = random_descriptor_pk(secp, rng)?;
    Ok(Descriptor::Wpkh(miniscript::descriptor::Wpkh::new(pk)?))
}

pub fn random_sh_descriptors(
    n: usize,
    secp: &Secp256k1<All>,
    rng: &mut impl CryptoRngCore,
) -> anyhow::Result<Vec<Descriptor<DescriptorPublicKey>>> {
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(random_sh_descriptor(secp, rng)?)
    }
    Ok(v)
}

pub fn random_sh_descriptor(
    secp: &Secp256k1<All>,
    rng: &mut impl CryptoRngCore,
) -> anyhow::Result<Descriptor<DescriptorPublicKey>> {
    match random::random_u32_in_range(0, 2)? {
        0 => random_sh_sortedmulti_descriptor(secp, rng),
        1 => random_sh_wpkh_descriptor(secp, rng),
        // TODO: add others sh
        _others => unreachable!(),
    }
}

pub fn random_sh_sortedmulti_descriptor(
    secp: &Secp256k1<All>,
    rng: &mut impl CryptoRngCore,
) -> anyhow::Result<Descriptor<DescriptorPublicKey>> {
    let npks = random::random_u32_in_range(1, 16)?;
    let k: usize = random::random_u32_in_range(1, npks)?.try_into()?;

    let mut dpks = Vec::with_capacity(npks.try_into()?);
    for _ in 0..npks {
        let dpk = random_descriptor_pk(secp, rng)?;
        dpks.push(dpk);
    }

    Ok(Descriptor::Sh(miniscript::descriptor::Sh::new_sortedmulti(
        k, dpks,
    )?))
}

pub fn random_sh_wpkh_descriptor(
    secp: &Secp256k1<All>,
    rng: &mut impl CryptoRngCore,
) -> anyhow::Result<Descriptor<DescriptorPublicKey>> {
    Ok(Descriptor::Sh(miniscript::descriptor::Sh::new_with_wpkh(
        miniscript::descriptor::Wpkh::new(random_descriptor_pk(secp, rng)?)?,
    )))
}

pub fn random_wsh_descriptors(
    n: usize,
    secp: &Secp256k1<All>,
    rng: &mut impl CryptoRngCore,
) -> anyhow::Result<Vec<Descriptor<DescriptorPublicKey>>> {
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(random_wsh_descriptor(secp, rng)?)
    }
    Ok(v)
}

pub fn random_wsh_descriptor(
    secp: &Secp256k1<All>,
    rng: &mut impl CryptoRngCore,
) -> anyhow::Result<Descriptor<DescriptorPublicKey>> {
    let npks = random::random_u32_in_range(1, 16)?;
    let k: usize = random::random_u32_in_range(1, npks)?.try_into()?;

    let mut dpks = Vec::with_capacity(npks.try_into()?);
    for _ in 0..npks {
        let dpk = random_descriptor_pk(secp, rng)?;
        dpks.push(dpk);
    }

    // TODO: add others Wsh types
    Ok(Descriptor::Wsh(
        miniscript::descriptor::Wsh::new_sortedmulti(k, dpks)?,
    ))
}

pub fn random_single_full_pk(
    secp: &Secp256k1<All>,
    rng: &mut impl CryptoRngCore,
) -> miniscript::descriptor::SinglePubKey {
    let pk = random_pk(secp, rng);
    miniscript::descriptor::SinglePubKey::FullKey(pk.into())
}

pub fn _random_single_pk(
    secp: &Secp256k1<All>,
    rng: &mut impl CryptoRngCore,
) -> miniscript::descriptor::SinglePubKey {
    let pk = random_pk(secp, rng);
    let full: bool = rand::random();
    if full {
        miniscript::descriptor::SinglePubKey::FullKey(pk.into())
    } else {
        miniscript::descriptor::SinglePubKey::XOnly(pk.x_only_public_key().0)
    }
}

pub fn random_descriptor_pk(
    secp: &Secp256k1<All>,
    rng: &mut impl CryptoRngCore,
) -> anyhow::Result<DescriptorPublicKey> {
    match random::random_u32_in_range(0, 3)? {
        0 => {
            let key = random_single_full_pk(secp, rng);
            let k = miniscript::descriptor::SinglePub {
                origin: random_opt_origin()?,
                key,
            };
            Ok(DescriptorPublicKey::Single(k))
        }
        1 => {
            let d = miniscript::descriptor::DescriptorXKey {
                origin: random_opt_origin()?,
                xkey: random_xpub(secp, rng)?,
                derivation_path: random_derivation_path()?,
                wildcard: random_wildcard()?,
            };
            Ok(DescriptorPublicKey::XPub(d))
        }
        2 => {
            let d = miniscript::descriptor::DescriptorMultiXKey {
                origin: random_opt_origin()?,
                xkey: random_xpub(secp, rng)?,
                derivation_paths: random_deriv_paths()?,
                wildcard: random_wildcard()?,
            };
            Ok(DescriptorPublicKey::MultiXPub(d))
        }
        _other => unreachable!(),
    }
}

pub fn random_pk(secp: &Secp256k1<All>, rng: &mut impl CryptoRngCore) -> secp256k1::PublicKey {
    let kp = bitcoin::key::Keypair::new(secp, rng);
    kp.public_key()
}

pub fn random_xpub(secp: &Secp256k1<All>, rng: &mut impl CryptoRngCore) -> anyhow::Result<Xpub> {
    let chain_code: [u8; 32] = rand::random();
    let xkey = Xpub {
        network: bitcoin::NetworkKind::Test,
        depth: rand::random(),
        parent_fingerprint: random_fingerprint(),
        child_number: random_child_number()?,
        public_key: random_pk(secp, rng),
        chain_code: chain_code.into(),
    };
    Ok(xkey)
}

pub fn random_fingerprint() -> Fingerprint {
    let fingerprint: [u8; 4] = rand::random();
    fingerprint.into()
}

pub fn random_opt_origin() -> anyhow::Result<OptOrigin> {
    let none: bool = rand::random();
    if none {
        Ok(None)
    } else {
        let fingerprint = random_fingerprint();
        let derivation_path = random_derivation_path()?;
        Ok(Some((fingerprint, derivation_path)))
    }
}

pub fn random_wildcard() -> anyhow::Result<Wildcard> {
    Ok(match random::random_u32_in_range(0, 3)? {
        0 => Wildcard::None,
        1 => Wildcard::Unhardened,
        2 => Wildcard::Hardened,
        _other => unreachable!(),
    })
}

pub fn random_deriv_paths() -> anyhow::Result<DerivPaths> {
    let n: usize = random::random_u32_in_range(1, 9)?.try_into()?;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(random_derivation_path()?)
    }

    DerivPaths::new(v).context("empty paths")
}

pub fn random_derivation_path() -> anyhow::Result<DerivationPath> {
    let n: usize = random::random_u32_in_range(2, 9)?.try_into()?;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(random_child_number()?);
    }
    let derivation_path = DerivationPath::from(v);
    Ok(derivation_path)
}

pub fn random_normal_child_number() -> anyhow::Result<ChildNumber> {
    let index = random::random_u32_in_range(0, 1 << 31)?;
    Ok(ChildNumber::from_normal_idx(index)?)
}

pub fn random_child_number() -> anyhow::Result<ChildNumber> {
    let normal: bool = rand::random();
    let index = random::random_u32_in_range(0, 1 << 31)?;
    if normal {
        Ok(ChildNumber::from_normal_idx(index)?)
    } else {
        Ok(ChildNumber::from_hardened_idx(index)?)
    }
}
