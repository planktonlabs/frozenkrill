use std::io::{BufReader, BufWriter, Read, Write};

use anyhow::{bail, ensure, Context};
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use itertools::Itertools;
use miniscript::{
    descriptor::{DerivPaths, Wildcard},
    Descriptor, DescriptorPublicKey,
};
use secp256k1::XOnlyPublicKey;

use crate::OptOrigin;

use super::VarInt;

pub fn serialize_descriptor_pk(
    descriptor: &DescriptorPublicKey,
    w: &mut BufWriter<impl Write>,
) -> anyhow::Result<()> {
    match descriptor {
        DescriptorPublicKey::Single(miniscript::descriptor::SinglePub { origin, key }) => {
            // Single
            VarInt::ZERO.serialize(w)?;
            // Origin information (fingerprint and derivation path).
            serialize_opt_origin(origin, w)?;
            // The public key.
            match key {
                miniscript::descriptor::SinglePubKey::FullKey(k) => {
                    VarInt::ZERO.serialize(w)?;
                    // can be read with bitcoin::PublicKey::read_from()
                    k.write_into(w)?;
                }
                miniscript::descriptor::SinglePubKey::XOnly(k) => {
                    VarInt::ONE.serialize(w)?;
                    let vector: [u8; 32] = k.serialize();
                    super::serialize_byte_vector(&vector, w)?;
                }
            }
        }
        DescriptorPublicKey::XPub(miniscript::descriptor::DescriptorXKey::<
            bitcoin::bip32::Xpub,
        > {
            origin,
            xkey,
            derivation_path,
            wildcard,
        }) => {
            // XPub
            VarInt::ONE.serialize(w)?;
            // Origin information
            serialize_opt_origin(origin, w)?;
            // The extended key
            serialize_xpub(xkey, w)?;
            // The derivation path
            serialize_derivation_path(&derivation_path, w)?;
            // Whether the descriptor is wildcard
            serialize_wildcard(wildcard, w)?;
        }
        DescriptorPublicKey::MultiXPub(miniscript::descriptor::DescriptorMultiXKey::<
            bitcoin::bip32::Xpub,
        > {
            origin,
            xkey,
            derivation_paths,
            wildcard,
        }) => {
            // MultiXPub
            VarInt(2).serialize(w)?;
            // Origin information
            serialize_opt_origin(origin, w)?;
            // The extended key
            serialize_xpub(xkey, w)?;
            // The derivation paths. Never empty.
            serialize_derivation_paths(derivation_paths, w)?;
            // Whether the descriptor is wildcard
            serialize_wildcard(wildcard, w)?;
        }
    };
    Ok(())
}

fn serialize_wildcard(
    wildcard: &miniscript::descriptor::Wildcard,
    w: &mut BufWriter<impl Write>,
) -> anyhow::Result<()> {
    match wildcard {
        Wildcard::None => VarInt::ZERO.serialize(w)?,
        Wildcard::Unhardened => VarInt::ONE.serialize(w)?,
        Wildcard::Hardened => VarInt(2).serialize(w)?,
    };
    Ok(())
}

pub fn deserialize_wildcard(r: &mut BufReader<impl Read>) -> anyhow::Result<Wildcard> {
    Ok(match VarInt::deserialize(r)? {
        VarInt::ZERO => Wildcard::None,
        VarInt::ONE => Wildcard::Unhardened,
        VarInt(2) => Wildcard::Hardened,
        other => bail!("Found unexpected varint: {other:?} while deserializing Wildcard"),
    })
}

fn serialize_xpub(xkey: &Xpub, w: &mut BufWriter<impl Write>) -> anyhow::Result<()> {
    let buffer: [u8; 78] = xkey.encode();
    w.write_all(&buffer)?;
    Ok(())
}

pub fn deserialize_xpub(r: &mut BufReader<impl Read>) -> anyhow::Result<Xpub> {
    let mut buffer = [0u8; 78];
    r.read_exact(&mut buffer)?;
    Ok(Xpub::decode(&buffer)?)
}

pub fn deserialize_descriptor_pk(
    r: &mut BufReader<impl Read>,
) -> anyhow::Result<DescriptorPublicKey> {
    match VarInt::deserialize(r)? {
        VarInt::ZERO => {
            let origin = deserialize_opt_origin(r)?;
            match VarInt::deserialize(r)? {
                VarInt::ZERO => {
                    let key = bitcoin::PublicKey::read_from(r)?;
                    let key = miniscript::descriptor::SinglePubKey::FullKey(key);
                    Ok(DescriptorPublicKey::Single(miniscript::descriptor::SinglePub { origin, key }))
                }
                VarInt::ONE => {
                    let key = crate::encoding::deserialize_byte_vector(r)?;
                    let key = XOnlyPublicKey::from_slice(&key)?;
                    let key = miniscript::descriptor::SinglePubKey::XOnly(key);
                    Ok(DescriptorPublicKey::Single(miniscript::descriptor::SinglePub { origin, key }))
                }
                other => bail!("Found unexpected varint: {other:?} while deserializing Single DescriptorPublicKey"),
            }
        }
        VarInt::ONE => {
            let origin = deserialize_opt_origin(r)?;
            let xkey = deserialize_xpub(r)?;
            let derivation_path = deserialize_derivation_path(r)?;
            let wildcard = deserialize_wildcard(r)?;
            Ok(DescriptorPublicKey::XPub(
                miniscript::descriptor::DescriptorXKey::<bitcoin::bip32::Xpub> {
                    origin,
                    xkey,
                    derivation_path,
                    wildcard,
                },
            ))
        }
        VarInt(2) => {
            let origin = deserialize_opt_origin(r)?;
            let xkey = deserialize_xpub(r)?;
            let derivation_paths = deserialize_derivation_paths(r)?;
            let wildcard = deserialize_wildcard(r)?;
            Ok(DescriptorPublicKey::MultiXPub(
                miniscript::descriptor::DescriptorMultiXKey::<bitcoin::bip32::Xpub> {
                    origin,
                    xkey,
                    derivation_paths,
                    wildcard,
                },
            ))
        }
        other => {
            bail!("Found unexpected varint: {other:?} while deserializing DescriptorPublicKey")
        }
    }
}

pub fn serialize_opt_origin(
    origin: &OptOrigin,
    w: &mut BufWriter<impl Write>,
) -> anyhow::Result<()> {
    Ok(match origin {
        None => {
            VarInt::ZERO.serialize(w)?;
        }
        Some((fingerprint, derivation_path)) => {
            VarInt::ONE.serialize(w)?;
            serialize_fingerprint(fingerprint, w)?;
            serialize_derivation_path(derivation_path, w)?;
        }
    })
}

pub fn deserialize_opt_origin(r: &mut BufReader<impl Read>) -> anyhow::Result<OptOrigin> {
    match VarInt::deserialize(r)? {
        VarInt::ZERO => Ok(None),
        VarInt::ONE => {
            let fingerprint = deserialize_fingerprint(r)?;
            let derivation_path = deserialize_derivation_path(r)?;
            Ok(Some((fingerprint, derivation_path)))
        }
        other => bail!("Found unexpected varint: {other:?} while deserializing opt origin"),
    }
}

pub fn serialize_derivation_path(
    derivation_path: &DerivationPath,
    w: &mut BufWriter<impl Write>,
) -> anyhow::Result<()> {
    let children = derivation_path.to_u32_vec();
    // Sanity check if we can reverse this operation
    let c: Vec<ChildNumber> = children.iter().copied().map_into().collect_vec();
    let d = DerivationPath::from(c);
    ensure!(
        &d == derivation_path,
        "generated derivation path {d:?} is different from source {derivation_path:?}"
    );
    let varint_children = children.into_iter().map(VarInt::from).collect_vec();
    super::serialize_varint_vector(&varint_children, w)
}

pub fn deserialize_derivation_path(r: &mut BufReader<impl Read>) -> anyhow::Result<DerivationPath> {
    let children: Vec<VarInt> = super::deserialize_varint_vector(r)?;
    let children: Vec<u32> = children
        .into_iter()
        .map(|v| Ok(u32::try_from(v.0)?))
        .collect::<anyhow::Result<_>>()?;
    let children: Vec<ChildNumber> = children.into_iter().map_into().collect();
    Ok(children.into())
}

pub fn serialize_derivation_paths(
    derivation_paths: &DerivPaths,
    w: &mut BufWriter<impl Write>,
) -> anyhow::Result<()> {
    let derivation_paths = derivation_paths.paths();
    if derivation_paths.is_empty() {
        bail!("Tried to serialize empty derivation paths")
    }
    VarInt::try_from(derivation_paths.len())?.serialize(w)?;
    for p in derivation_paths {
        serialize_derivation_path(p, w)?;
    }
    Ok(())
}

pub fn deserialize_derivation_paths(r: &mut BufReader<impl Read>) -> anyhow::Result<DerivPaths> {
    let len: usize = VarInt::deserialize(r)?.0.try_into()?;
    let mut paths = Vec::with_capacity(len);
    for _ in 0..len {
        paths.push(deserialize_derivation_path(r)?);
    }
    DerivPaths::new(paths).context("expected non-empty list of derivation paths")
}

pub fn serialize_fingerprint(f: &Fingerprint, w: &mut BufWriter<impl Write>) -> anyhow::Result<()> {
    let f: &[u8; 4] = f.as_bytes();
    w.write_all(f)?;
    Ok(())
}

pub fn deserialize_fingerprint(r: &mut BufReader<impl Read>) -> anyhow::Result<Fingerprint> {
    let mut f = [0u8; 4];
    r.read_exact(&mut f)?;
    Ok(f.into())
}

pub fn serialize_descriptor_descriptor_pk(
    d: &Descriptor<DescriptorPublicKey>,
    w: &mut BufWriter<impl Write>,
) -> anyhow::Result<()> {
    match d {
        Descriptor::Bare(_d) => {
            VarInt::ZERO.serialize(w)?;
            todo!("Bare isn't supported")
        }
        Descriptor::Pkh(d) => {
            VarInt::ONE.serialize(w)?;
            serialize_descriptor_pk(d.as_inner(), w)?;
        }
        Descriptor::Wpkh(d) => {
            VarInt(2).serialize(w)?;
            serialize_descriptor_pk(d.as_inner(), w)?;
        }
        Descriptor::Sh(d) => {
            VarInt(3).serialize(w)?;
            match d.as_inner() {
                miniscript::descriptor::ShInner::Wsh(d) => {
                    VarInt::ZERO.serialize(w)?;
                    match d.as_inner() {
                        miniscript::descriptor::WshInner::SortedMulti(_d) => {
                            VarInt::ZERO.serialize(w)?;
                            todo!("Sh(Wsh sorted) isn't supported (yet)")
                        }
                        miniscript::descriptor::WshInner::Ms(_d) => {
                            VarInt::ONE.serialize(w)?;
                            todo!("Sh(Wsh) isn't supported (yet)")
                        }
                    }
                }
                miniscript::descriptor::ShInner::Wpkh(d) => {
                    VarInt::ONE.serialize(w)?;
                    serialize_descriptor_pk(d.as_inner(), w)?;
                }
                miniscript::descriptor::ShInner::SortedMulti(d) => {
                    VarInt(2).serialize(w)?;
                    VarInt::try_from(d.k())?.serialize(w)?;
                    let pks = d.pks();
                    VarInt::try_from(pks.len())?.serialize(w)?;
                    for pk in pks {
                        serialize_descriptor_pk(pk, w)?;
                    }
                }
                miniscript::descriptor::ShInner::Ms(_d) => {
                    VarInt(3).serialize(w)?;
                    todo!("Sh(Ms) isn't supported (yet)")
                }
            }
        }
        Descriptor::Wsh(d) => {
            VarInt(4).serialize(w)?;
            match d.as_inner() {
                miniscript::descriptor::WshInner::SortedMulti(d) => {
                    VarInt::ZERO.serialize(w)?;
                    VarInt::try_from(d.k())?.serialize(w)?;
                    let pks = d.pks();
                    VarInt::try_from(pks.len())?.serialize(w)?;
                    for pk in pks {
                        serialize_descriptor_pk(pk, w)?;
                    }
                }
                miniscript::descriptor::WshInner::Ms(_d) => {
                    VarInt::ONE.serialize(w)?;
                    todo!("Wsh(Ms) isn't supported (yet)")
                }
            }
        }
        Descriptor::Tr(_d) => {
            VarInt(5).serialize(w)?;
            todo!("Taproot isn't supported (yet)")
        }
    };
    Ok(())
}

pub fn deserialize_descriptor_descriptor_pk(
    r: &mut BufReader<impl Read>,
) -> anyhow::Result<Descriptor<DescriptorPublicKey>> {
    match VarInt::deserialize(r)? {
        VarInt::ZERO => todo!("Bare isn't supported"),
        VarInt::ONE => {
            let d = deserialize_descriptor_pk(r)?;
            Ok(Descriptor::Pkh(miniscript::descriptor::Pkh::new(d)?))
        }
        VarInt(2) => {
            let d = deserialize_descriptor_pk(r)?;
            Ok(Descriptor::Wpkh(miniscript::descriptor::Wpkh::new(d)?))
        }
        VarInt(3) => match VarInt::deserialize(r)? {
            VarInt::ZERO => {
                match VarInt::deserialize(r)? {
                    VarInt::ZERO => todo!("Sh(Wsh sorted) isn't supported (yet)"),
                    VarInt::ONE => todo!("Sh(Wsh) isn't supported (yet)"),
                    other => bail!("Found unexpected varint: {other:?} while deserializing Sh(Wsh) Descriptor<DescriptorPublicKey>"),
                };
            }
            VarInt::ONE => {
                let d = deserialize_descriptor_pk(r)?;
                Ok(Descriptor::Sh(miniscript::descriptor::Sh::new_wpkh(d)?))
            }
            VarInt(2) => {
                let k: usize = VarInt::deserialize(r)?.0.try_into()?;
                let len: usize = VarInt::deserialize(r)?.0.try_into()?;
                let mut pks = Vec::with_capacity(len);
                for _ in 0..len {
                    pks.push(deserialize_descriptor_pk(r)?);
                }
                Ok(Descriptor::Sh(miniscript::descriptor::Sh::new_sortedmulti(k, pks)?))
            }
            VarInt(3) => todo!("Sh(Ms) isn't supported (yet)"),
            other => bail!("Found unexpected varint: {other:?} while deserializing Sh Descriptor<DescriptorPublicKey>"),
        },
        VarInt(4) => match VarInt::deserialize(r)? {
            VarInt::ZERO => {
                let k: usize = VarInt::deserialize(r)?.0.try_into()?;
                let len: usize = VarInt::deserialize(r)?.0.try_into()?;
                let mut pks = Vec::with_capacity(len);
                for _ in 0..len {
                    pks.push(deserialize_descriptor_pk(r)?);
                }
                Ok(Descriptor::Wsh(miniscript::descriptor::Wsh::new_sortedmulti(k, pks)?))
            }
            VarInt::ONE => todo!("Wsh(Ms) isn't supported (yet)"),
            other => bail!("Found unexpected varint: {other:?} while deserializing Wsh Descriptor<DescriptorPublicKey>"),
        }
        VarInt(5) => todo!("Taproot isn't supported (yet)"),
        other => bail!("Found unexpected varint: {other:?} while deserializing Descriptor<DescriptorPublicKey>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random_generation_utils::*;

    #[test]
    fn test_serialization_deserialization() -> anyhow::Result<()> {
        use pretty_assertions::assert_eq;
        let mut rng = rand::thread_rng();
        let secp = get_secp(&mut rng);
        let mut ddpks = vec![
            random_wpkh_descriptor(&secp, &mut rng)?,
            random_pkh_descriptor(&secp, &mut rng)?,
        ];
        ddpks.extend(random_wsh_descriptors(10, &secp, &mut rng)?);
        ddpks.extend(random_sh_descriptors(10, &secp, &mut rng)?);
        for ddpk in ddpks {
            let mut w = BufWriter::new(Vec::new());
            serialize_descriptor_descriptor_pk(&ddpk, &mut w)?;
            let w = w.into_inner()?;
            let mut r = BufReader::new(w.as_slice());
            let deserialized_ddpk = deserialize_descriptor_descriptor_pk(&mut r)?;
            assert_eq!(ddpk, deserialized_ddpk);
        }
        Ok(())
    }
}
