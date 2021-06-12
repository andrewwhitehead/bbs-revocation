use std::io::{Error as IoError, Read};

use bbs::{keys::PublicKey, signature::Signature, SignatureMessage, G1_COMPRESSED_SIZE};
use pairing_plus::bls12_381::Fr;

use super::block::{Block, BlockCompute, BlockRepr, SignatureEntry};
use super::header::RegistryHeader;
use super::util::*;
use super::SIG_HEADER_MESSAGES;

pub struct RegistryReader<'r, R> {
    pub header: RegistryHeader<'r>,
    pub reader: &'r mut R,
}

impl<'r, R: Read> RegistryReader<'r, R> {
    pub fn new(reader: &'r mut R) -> Result<Self, IoError> {
        let header = RegistryHeader::read(reader)?;
        Ok(Self { header, reader })
    }

    pub fn header(&self) -> &RegistryHeader<'r> {
        &self.header
    }

    pub fn entries<const B: usize>(self) -> Result<SignatureIterator<'r, R, B>, IoError>
    where
        Block<B>: BlockRepr,
    {
        let len: [u8; 8] = read_fixed(&mut *self.reader)?;
        let len = u64::from_be_bytes(len);
        Ok(SignatureIterator::new(self.reader, len))
    }

    pub fn public_key(&self) -> Option<PublicKey> {
        if self.header.block_size == 8 {
            Some(<Block<8> as BlockRepr>::Compute::public_key(
                &self.header.dpk,
            ))
        } else if self.header.block_size == 64 {
            Some(<Block<64> as BlockRepr>::Compute::public_key(
                &self.header.dpk,
            ))
        } else {
            None
        }
    }

    pub fn signature_messages(&self) -> [SignatureMessage; SIG_HEADER_MESSAGES] {
        self.header.signature_messages()
    }

    pub fn find_signature(
        self,
        slot_index: u32,
    ) -> Result<Option<(Vec<u32>, u16, Signature)>, IoError> {
        if self.header.levels != 2 {
            return Ok(None);
        }
        let len: [u8; 8] = read_fixed(&mut *self.reader)?;
        let len = u64::from_be_bytes(len);
        if self.header.block_size == 8 {
            SignatureIterator::<R, 8>::new(self.reader, len).find_signature(
                slot_index,
                self.header.e,
                self.header.s,
            )
        } else if self.header.block_size == 64 {
            SignatureIterator::<R, 64>::new(self.reader, len).find_signature(
                slot_index,
                self.header.e,
                self.header.s,
            )
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug)]
pub struct SignatureIterator<'r, R, const B: usize> {
    reader: Option<&'r mut R>,
    offset: u32,
    level: u16,
    count: u16,
    len: u64,
}

impl<'r, R, const B: usize> SignatureIterator<'r, R, B>
where
    Block<B>: BlockRepr,
    R: Read,
{
    #[inline]
    pub fn new(reader: &'r mut R, len: u64) -> Self {
        Self {
            reader: Some(reader),
            offset: 0,
            level: 0,
            count: 0,
            len,
        }
    }

    pub fn find_signature(
        self,
        slot_index: u32,
        e: Fr,
        s: Fr,
    ) -> Result<Option<(Vec<u32>, u16, Signature)>, IoError> {
        if let Some(entry) = self.find_entry(slot_index)? {
            let indices = entry.indices().collect();
            let sig = entry.signature(e, s);
            Ok(Some((indices, entry.level, sig)))
        } else {
            Ok(None)
        }
    }

    pub fn find_entry(self, slot_index: u32) -> Result<Option<SignatureEntry<B>>, IoError> {
        let block_index = slot_index / (B as u32);
        for entry in self {
            let entry = entry?;
            if entry.level == 0 {
                if let Some(true) = entry.contains_index(slot_index) {
                    return Ok(Some(entry));
                }
            } else if entry.level == 1 {
                if let Some(true) = entry.contains_index(block_index) {
                    return Ok(Some(entry));
                }
            }
        }
        Ok(None)
    }

    #[inline]
    fn read_next(&mut self, reader: &mut R) -> Result<SignatureEntry<B>, IoError> {
        if self.count == 0 {
            let offs: [u8; 4] = read_fixed(reader)?;
            self.offset = u32::from_be_bytes(offs);
            let level: [u8; 2] = read_fixed(reader)?;
            self.level = u16::from_be_bytes(level);
            let count: [u8; 2] = read_fixed(reader)?;
            self.count = u16::from_be_bytes(count);
            self.len -= 8;
        }
        let mut nonrev = <Block<B> as BlockRepr>::Bytes::default();
        reader.read_exact(nonrev.as_mut())?;
        self.len -= nonrev.as_ref().len() as u64;
        let mut sig = [0u8; G1_COMPRESSED_SIZE];
        reader.read_exact(sig.as_mut())?;
        self.len -= G1_COMPRESSED_SIZE as u64;
        let entry = SignatureEntry {
            nonrev: Block::<B>::from_be_bytes(nonrev),
            offset: self.offset,
            level: self.level,
            sig,
        };
        self.count -= 1;
        self.offset += 1;
        Ok(entry)
    }
}

impl<'r, R, const B: usize> Iterator for SignatureIterator<'r, R, B>
where
    Block<B>: BlockRepr,
    R: Read,
{
    type Item = Result<SignatureEntry<B>, IoError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(reader) = self.reader.take() {
            if self.len == 0 {
                return None;
            }
            let result = self.read_next(reader);
            if result.is_ok() {
                self.reader.replace(reader);
            }
            Some(result)
        } else {
            None
        }
    }
}
