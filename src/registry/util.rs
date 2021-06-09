use std::io::{Cursor, Error as IoError, ErrorKind as IoErrorKind, Read, Seek, Write};

use bbs::{keys::SecretKey, SignatureMessage, FR_UNCOMPRESSED_SIZE, G1_COMPRESSED_SIZE};
use blake2::{
    digest::{generic_array::GenericArray, Input, VariableOutput},
    VarBlake2b,
};
use ff_zeroize::{Field, PrimeField};
use pairing_plus::{
    bls12_381::{Fr, FrRepr, G1},
    hash_to_field::BaseFromRO,
    serdes::SerDes,
    CurveProjective,
};

pub trait SeekWrite: Seek + Write {}

impl<W: Seek + Write> SeekWrite for W {}

pub fn sign_b(sk: &SecretKey, e: Fr, mut b: G1) -> [u8; G1_COMPRESSED_SIZE] {
    // unwrap secret key
    let skb = sk.to_bytes_compressed_form();
    let mut sk_e = Fr::deserialize(&mut Cursor::new(skb), false).unwrap();
    sk_e.add_assign(&e);
    b.mul_assign(sk_e.inverse().unwrap());
    let mut buf = [0u8; G1_COMPRESSED_SIZE];
    b.into_affine()
        .serialize(&mut Cursor::new(&mut buf[..]), true)
        .unwrap();
    buf
}

#[inline]
pub fn read_fixed<const B: usize>(reader: &mut impl Read) -> Result<[u8; B], IoError> {
    let mut buf = [0u8; B];
    reader.read_exact(&mut buf[..])?;
    Ok(buf)
}

pub fn read_str(reader: &mut impl Read) -> Result<String, IoError> {
    let len: [u8; 4] = read_fixed(reader)?;
    let len = u32::from_be_bytes(len);
    let mut s = vec![0u8; len as usize];
    reader.read_exact(&mut s[..])?;
    Ok(
        String::from_utf8(s)
            .map_err(|_| IoError::new(IoErrorKind::InvalidData, "Invalid UTF-8"))?,
    )
}

pub fn write_str(writer: &mut impl Write, s: &str) -> Result<(), IoError> {
    writer.write_all(&(s.len() as u32).to_be_bytes()[..])?;
    writer.write_all(s.as_bytes())?;
    Ok(())
}

#[inline]
pub fn fr_mul_repr(fr: FrRepr) -> [u64; 4] {
    let mut sc = [0; 4];
    sc.copy_from_slice(fr.as_ref());
    sc
}

pub fn hash_to_fr(data: &[u8]) -> Fr {
    let mut res = GenericArray::default();
    let mut hasher = VarBlake2b::new(FR_UNCOMPRESSED_SIZE).unwrap();
    hasher.input(data);
    hasher.variable_result(|out| {
        res.copy_from_slice(out);
    });
    Fr::from_okm(&res)
}

#[inline]
pub fn compute_index(index: u32, level: u16) -> SignatureMessage {
    // let mut data = [0u8; 8];
    // data[..4].copy_from_slice(&(height as u32).to_be_bytes()[..]);
    // data[4..].copy_from_slice(&index.to_be_bytes()[..]);
    // hash_to_fr(&data[..])
    SignatureMessage::from(Fr::from_repr(compute_index_repr(index, level)).unwrap())
}

#[inline]
pub fn compute_index_repr(index: u32, level: u16) -> FrRepr {
    FrRepr::from((index as u64) << 8 + level as u64)
}
