use std::{
    borrow::Cow,
    convert::TryInto,
    io::{Cursor, Error as IoError, ErrorKind as IoErrorKind, Read, Write},
};

use bbs::{
    keys::{DeterministicPublicKey, PublicKey, DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE},
    SignatureMessage, FR_COMPRESSED_SIZE,
};
use ff_zeroize::PrimeField;
use pairing_plus::{
    bls12_381::{Fr, FrRepr},
    serdes::SerDes,
};

use super::util::*;

pub const HEADER_MESSAGES: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryHeader<'h> {
    pub registry_type: Cow<'h, str>,
    pub registry_uri: Cow<'h, str>,
    pub timestamp: u64,
    pub interval: u32,
    pub block_size: u16,
    pub levels: u16,
    pub dpk: DeterministicPublicKey,
    pub e: Fr,
    pub s: Fr,
}

impl RegistryHeader<'static> {
    pub fn read(reader: &mut impl Read) -> Result<(Self, usize), IoError> {
        const FIXED_LEN: usize =
            16 + DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE + FR_COMPRESSED_SIZE + FR_COMPRESSED_SIZE;
        let typ = read_str(&mut *reader)?;
        let uri = read_str(&mut *reader)?;
        let flex_len = typ.as_bytes().len() + uri.as_bytes().len();
        let pad_len = 8 - (flex_len % 8);
        if pad_len < 8 {
            let mut pad = [0u8; 8];
            reader.read_exact(&mut pad[0..pad_len])?;
            if &pad[..] != &[0u8; 8][..] {
                return Err(IoError::new(IoErrorKind::InvalidData, "Invalid padding"));
            }
        }
        let h: [u8; FIXED_LEN] = read_fixed(reader)?;
        let timestamp = u64::from_be_bytes(h[..8].try_into().unwrap());
        let interval = u32::from_be_bytes(h[8..12].try_into().unwrap());
        let block_size = u16::from_be_bytes(h[12..14].try_into().unwrap());
        let levels = u16::from_be_bytes(h[14..16].try_into().unwrap());
        let mut c = Cursor::new(&h[16..]);
        let dpk: [u8; DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE] = read_fixed(&mut c)?;
        let dpk: DeterministicPublicKey = dpk
            .try_into()
            .map_err(|_| IoError::new(IoErrorKind::InvalidData, "Invalid public key"))?;
        let e = Fr::deserialize(&mut c, true)?;
        let s = Fr::deserialize(&mut c, true)?;
        Ok((
            Self {
                registry_type: Cow::Owned(typ),
                registry_uri: Cow::Owned(uri),
                timestamp,
                interval,
                block_size,
                levels,
                dpk,
                e,
                s,
            },
            8 + flex_len + pad_len + FIXED_LEN,
        ))
    }
}

impl RegistryHeader<'_> {
    pub fn public_key(&self) -> PublicKey {
        self.dpk
            .to_public_key(HEADER_MESSAGES + (self.block_size as usize))
            .unwrap()
    }

    pub fn signature_messages(&self) -> [SignatureMessage; HEADER_MESSAGES] {
        header_messages(
            &self.registry_type,
            &self.registry_uri,
            self.timestamp,
            self.interval,
        )
    }

    pub fn write(&self, writer: &mut impl Write) -> Result<(), IoError> {
        write_str(writer, &self.registry_type)?;
        write_str(writer, &self.registry_uri)?;
        let pad_len =
            (self.registry_type.as_bytes().len() + self.registry_uri.as_bytes().len()) % 8;
        let pad = [0u8; 8];
        if pad_len > 0 {
            writer.write_all(&pad[0..(8 - pad_len)])?;
        }
        let mut h = [0u8; 16
            + DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE
            + FR_COMPRESSED_SIZE
            + FR_COMPRESSED_SIZE];
        let mut c = Cursor::new(&mut h[..]);
        c.write(&self.timestamp.to_be_bytes()[..])?;
        c.write(&self.interval.to_be_bytes()[..])?;
        c.write(&self.block_size.to_be_bytes()[..])?;
        c.write(&self.levels.to_be_bytes()[..])?;
        c.write(&self.dpk.to_bytes_compressed_form())?;
        &self.e.serialize(&mut c, true);
        &self.s.serialize(&mut c, true);
        writer.write_all(&h[..])?;
        Ok(())
    }
}

#[inline]
pub(crate) fn header_messages(
    reg_type: &str,
    reg_uri: &str,
    timestamp: u64,
    interval: u32,
) -> [SignatureMessage; HEADER_MESSAGES] {
    [
        hash_to_fr(reg_type.as_bytes()).into(),
        hash_to_fr(reg_uri.as_bytes()).into(),
        Fr::from_repr(FrRepr::from(timestamp)).unwrap().into(),
        Fr::from_repr(FrRepr::from(interval as u64)).unwrap().into(),
    ]
}

#[test]
fn test_header_serde() {
    use ff_zeroize::Field;
    use rand::rngs::OsRng;

    let (dpk, _sk) = DeterministicPublicKey::new(None);
    let header = RegistryHeader {
        registry_type: Cow::Borrowed("registry/1"),
        registry_uri: Cow::Borrowed("test:uri"),
        timestamp: 1000,
        interval: 1001,
        block_size: 64,
        levels: 2,
        dpk,
        e: Fr::random(&mut OsRng),
        s: Fr::random(&mut OsRng),
    };
    let mut buf = Vec::new();
    header.write(&mut buf).unwrap();
    assert_eq!(buf.len(), 208);
    let (h2, h_len) = RegistryHeader::read(&mut Cursor::new(&buf[..])).unwrap();
    assert_eq!(header, h2);
    assert_eq!(h_len, 208);
}
