use std::{
    borrow::Cow,
    convert::TryInto,
    io::{Cursor, Error as IoError, ErrorKind as IoErrorKind, Read, Write},
};

use bbs::{
    keys::{DeterministicPublicKey, DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE},
    SignatureMessage, FR_COMPRESSED_SIZE,
};
use ff_zeroize::PrimeField;
use pairing_plus::{
    bls12_381::{Fr, FrRepr},
    serdes::SerDes,
};

use super::util::*;
use super::SIG_HEADER_MESSAGES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryHeader<'h> {
    pub type_: Cow<'h, str>,
    pub uri: Cow<'h, str>,
    pub timestamp: u64,
    pub interval: u32,
    pub block_size: u16,
    pub levels: u16,
    pub dpk: DeterministicPublicKey,
    pub e: Fr,
    pub s: Fr,
}

impl RegistryHeader<'static> {
    pub fn read(reader: &mut impl Read) -> Result<Self, IoError> {
        let typ = read_str(reader)?;
        let uri = read_str(reader)?;
        let pad_len = (typ.as_bytes().len() + uri.as_bytes().len()) % 8;
        let mut pad = [0u8; 8];
        if pad_len > 0 {
            reader.read_exact(&mut pad[0..(8 - pad_len)])?;
            if &pad[..] != &[0u8; 8][..] {
                return Err(IoError::new(IoErrorKind::InvalidData, "Invalid padding"));
            }
        }
        let h: [u8; 16
            + DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE
            + FR_COMPRESSED_SIZE
            + FR_COMPRESSED_SIZE] = read_fixed(reader)?;
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
        Ok(Self {
            type_: Cow::Owned(typ),
            uri: Cow::Owned(uri),
            timestamp,
            interval,
            block_size,
            levels,
            dpk,
            e,
            s,
        })
    }
}

impl RegistryHeader<'_> {
    pub fn signature_messages(&self) -> [SignatureMessage; SIG_HEADER_MESSAGES] {
        [
            hash_to_fr(self.type_.as_bytes()).into(),
            hash_to_fr(self.uri.as_bytes()).into(),
            Fr::from_repr(FrRepr::from(self.timestamp)).unwrap().into(),
            Fr::from_repr(FrRepr::from(self.interval as u64))
                .unwrap()
                .into(),
        ]
    }

    pub fn write(&self, writer: &mut impl Write) -> Result<(), IoError> {
        write_str(writer, &self.type_)?;
        write_str(writer, &self.uri)?;
        let pad_len = (self.type_.as_bytes().len() + self.uri.as_bytes().len()) % 8;
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

#[test]
fn test_header_serde() {
    use ff_zeroize::Field;
    use rand::rngs::OsRng;

    let (dpk, _sk) = DeterministicPublicKey::new(None);
    let header = RegistryHeader {
        type_: Cow::Borrowed("registry/1"),
        uri: Cow::Borrowed("test:uri"),
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
    let h2 = RegistryHeader::read(&mut Cursor::new(&buf[..])).unwrap();
    assert_eq!(header, h2);
}