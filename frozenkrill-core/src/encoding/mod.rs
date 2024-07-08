// Adapted from rust-bitcoin

use std::{
    io::{BufRead, BufReader, BufWriter, Read, Write},
    mem::size_of,
};

pub mod wallet;

/// A variable-length unsigned integer.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
pub struct VarInt(pub u64);

pub fn encode_u8(n: u8) -> [u8; size_of::<u8>()] {
    n.to_le_bytes()
}

pub fn decode_u8(bytes: [u8; size_of::<u8>()]) -> u8 {
    u8::from_le_bytes(bytes)
}

pub fn encode_u16(n: u16) -> [u8; size_of::<u16>()] {
    n.to_le_bytes()
}

pub fn decode_u16(bytes: [u8; size_of::<u16>()]) -> u16 {
    u16::from_le_bytes(bytes)
}

pub fn encode_u32(n: u32) -> [u8; size_of::<u32>()] {
    n.to_le_bytes()
}

pub fn decode_u32(bytes: [u8; size_of::<u32>()]) -> u32 {
    u32::from_le_bytes(bytes)
}

pub fn encode_u64(n: u64) -> [u8; size_of::<u64>()] {
    n.to_le_bytes()
}

pub fn decode_u64(bytes: [u8; size_of::<u64>()]) -> u64 {
    u64::from_le_bytes(bytes)
}

impl VarInt {
    pub const ZERO: VarInt = VarInt(0);
    pub const ONE: VarInt = VarInt(1);

    pub fn serialize<W: std::io::Write + ?Sized>(&self, w: &mut W) -> anyhow::Result<usize> {
        match self.0 {
            0..=0xFC => {
                w.write_all(&encode_u8(self.0.try_into()?))?;
                Ok(1)
            }
            0xFD..=0xFFFF => {
                w.write_all(&encode_u8(0xFD))?;
                w.write_all(&encode_u16(self.0.try_into()?))?;
                Ok(3)
            }
            0x10000..=0xFFFFFFFF => {
                w.write_all(&encode_u8(0xFE))?;
                w.write_all(&encode_u32(self.0.try_into()?))?;
                Ok(5)
            }
            _ => {
                w.write_all(&encode_u8(0xFF))?;
                w.write_all(&encode_u64(self.0))?;
                Ok(9)
            }
        }
    }

    pub fn deserialize<R: BufRead + ?Sized>(r: &mut R) -> anyhow::Result<Self> {
        let mut buffer = [0u8; 1];
        r.read_exact(&mut buffer)?;
        match buffer[0] {
            0xFF => {
                let mut buffer = [0u8; size_of::<u64>()];
                r.read_exact(&mut buffer)?;
                let x = decode_u64(buffer);
                if x < 0x100000000 {
                    Err(anyhow::anyhow!("NonMinimalVarInt"))
                } else {
                    Ok(VarInt::from(x))
                }
            }
            0xFE => {
                let mut buffer = [0u8; size_of::<u32>()];
                r.read_exact(&mut buffer)?;
                let x = decode_u32(buffer);
                if x < 0x10000 {
                    Err(anyhow::anyhow!("NonMinimalVarInt"))
                } else {
                    Ok(VarInt::from(x))
                }
            }
            0xFD => {
                let mut buffer = [0u8; size_of::<u16>()];
                r.read_exact(&mut buffer)?;
                let x = decode_u16(buffer);
                if x < 0xFD {
                    Err(anyhow::anyhow!("NonMinimalVarInt"))
                } else {
                    Ok(VarInt::from(x))
                }
            }
            n => Ok(VarInt::from(n)),
        }
    }
}

impl From<u8> for VarInt {
    fn from(value: u8) -> Self {
        Self(value.into())
    }
}

impl From<u16> for VarInt {
    fn from(value: u16) -> Self {
        Self(value.into())
    }
}

impl From<u32> for VarInt {
    fn from(value: u32) -> Self {
        Self(value.into())
    }
}

impl From<u64> for VarInt {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl TryFrom<usize> for VarInt {
    type Error = anyhow::Error;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

pub fn serialize_string(s: &str, w: &mut BufWriter<impl Write>) -> anyhow::Result<()> {
    VarInt::try_from(s.len())?.serialize(w)?;
    w.write_all(s.as_bytes())?;
    Ok(())
}

pub fn deserialize_string(r: &mut BufReader<impl Read>) -> anyhow::Result<String> {
    let len: usize = VarInt::deserialize(r)?.0.try_into()?;
    let mut buffer = vec![0u8; len];
    r.read_exact(&mut buffer)?;
    let s = String::from_utf8(buffer)?;
    Ok(s)
}

pub fn serialize_varint_vector(
    vector: &[VarInt],
    w: &mut BufWriter<impl Write>,
) -> anyhow::Result<()> {
    VarInt::try_from(vector.len())?.serialize(w)?;
    for v in vector {
        v.serialize(w)?;
    }
    Ok(())
}

pub fn deserialize_varint_vector(r: &mut BufReader<impl Read>) -> anyhow::Result<Vec<VarInt>> {
    let len: usize = VarInt::deserialize(r)?.0.try_into()?;
    let mut buffer: Vec<VarInt> = Vec::with_capacity(len);
    for _ in 0..len {
        buffer.push(VarInt::deserialize(r)?);
    }
    Ok(buffer)
}

pub fn serialize_byte_vector(vector: &[u8], w: &mut BufWriter<impl Write>) -> anyhow::Result<()> {
    VarInt::try_from(vector.len())?.serialize(w)?;
    w.write_all(vector)?;
    Ok(())
}

pub fn deserialize_byte_vector(r: &mut BufReader<impl Read>) -> anyhow::Result<Vec<u8>> {
    let len: usize = VarInt::deserialize(r)?.0.try_into()?;
    let mut buffer = vec![0u8; len];
    r.read_exact(&mut buffer)?;
    Ok(buffer)
}
