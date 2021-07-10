use std::io::{Error as IoError, Read, Seek, SeekFrom};

use bbs::prelude::PublicKey;
use bbs::{signature::Signature, G1_COMPRESSED_SIZE};
use pairing_plus::bls12_381::Fr;

use super::block::{Block, SignatureEntry};
use super::header::RegistryHeader;
use super::util::*;

pub struct RegistryReader<'r, R> {
    header: RegistryHeader<'r>,
    reader: TakeReset<R>,
}

impl<R: Read> RegistryReader<'static, R> {
    pub fn new(mut reader: R) -> Result<Self, IoError> {
        let (header, _) = RegistryHeader::read(&mut reader)?;
        let entries_len = u64::from_be_bytes(read_fixed(&mut reader)?);
        if header.levels != 2 {}
        Ok(Self {
            header,
            reader: TakeReset::new(reader, entries_len),
        })
    }
}

impl<'r, R: Read> RegistryReader<'r, R> {
    pub fn header(&self) -> &RegistryHeader<'r> {
        &self.header
    }

    #[inline]
    pub fn public_key(&self) -> PublicKey {
        self.header.public_key()
    }

    pub fn entry_count(self) -> Result<u32, IoError> {
        SignatureIterator::new(self.reader, self.header.block_size, self.header.levels)
            .entry_count()
    }

    pub fn entry_count_reset(&mut self) -> Result<u32, IoError>
    where
        R: Seek,
    {
        let result =
            SignatureIterator::new(&mut self.reader, self.header.block_size, self.header.levels)
                .entry_count()?;
        self.reader.reset()?;
        Ok(result)
    }

    pub fn find_signature(
        self,
        slot_index: u32,
    ) -> Result<Option<(Vec<u32>, u16, Signature)>, IoError> {
        SignatureIterator::new(self.reader, self.header.block_size, self.header.levels)
            .find_signature(slot_index, self.header.e, self.header.s)
    }

    pub fn find_signature_reset(
        &mut self,
        slot_index: u32,
    ) -> Result<Option<(Vec<u32>, u16, Signature)>, IoError>
    where
        R: Seek,
    {
        let result =
            SignatureIterator::new(&mut self.reader, self.header.block_size, self.header.levels)
                .find_signature(slot_index, self.header.e, self.header.s)?;
        self.reader.reset()?;
        Ok(result)
    }
}

impl<'r, R: Read> IntoIterator for RegistryReader<'r, R> {
    type Item = Result<SignatureEntry, IoError>;
    type IntoIter = SignatureIterator<TakeReset<R>>;

    fn into_iter(self) -> Self::IntoIter {
        SignatureIterator::new(self.reader, self.header.block_size, self.header.levels)
    }
}

pub struct TakeReset<R> {
    inner: R,
    pos: u64,
    limit: u64,
}

impl<R: Read> TakeReset<R> {
    pub fn new(reader: R, limit: u64) -> Self {
        Self {
            inner: reader,
            pos: 0,
            limit,
        }
    }
}

impl<R: Read> Read for TakeReset<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        let max = buf.len().min((self.limit - self.pos) as usize);
        let len = self.inner.read(&mut buf[..max])?;
        self.pos += len as u64;
        Ok(len)
    }
}

impl<R: Seek> TakeReset<R> {
    fn reset(&mut self) -> Result<(), IoError> {
        if self.pos != 0 {
            self.inner.seek(SeekFrom::Current(-(self.pos as i64)))?;
            self.pos = 0;
        }
        Ok(())
    }
}

pub trait DoneRead: Read {
    fn is_done(&self) -> bool;
}

impl<R: Read> DoneRead for TakeReset<R> {
    fn is_done(&self) -> bool {
        self.pos == self.limit
    }
}

impl<'r, R: DoneRead> DoneRead for &'r mut R {
    fn is_done(&self) -> bool {
        (&**self).is_done()
    }
}

#[derive(Debug)]
pub struct SignatureIterator<R: DoneRead> {
    reader: Option<R>,
    active_offset: u32,
    active_level: u16,
    active_count: u16,
    block_size: u16,
}

impl<R: DoneRead> SignatureIterator<R> {
    #[inline]
    pub(crate) fn new(reader: R, block_size: u16, levels: u16) -> Self {
        let reader = if levels == 2 && block_size <= 64 && block_size > 0 && block_size % 8 == 0 {
            Some(reader)
        } else {
            // not supported
            None
        };
        Self {
            reader,
            active_offset: 0,
            active_level: 0,
            active_count: 0,
            block_size,
        }
    }
}

impl<R: DoneRead> SignatureIterator<R> {
    pub fn entry_count(&mut self) -> Result<u32, IoError> {
        let mut count = 0;
        for entry in self {
            entry?;
            count += 1;
        }
        Ok(count)
    }

    pub(crate) fn find_signature(
        &mut self,
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

    pub(crate) fn find_entry(
        &mut self,
        slot_index: u32,
    ) -> Result<Option<SignatureEntry>, IoError> {
        let block_index = slot_index / (self.block_size as u32);
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
    fn read_next(&mut self, reader: &mut R) -> Result<SignatureEntry, IoError> {
        if self.active_count == 0 {
            let offs: [u8; 4] = read_fixed(&mut *reader)?;
            self.active_offset = u32::from_be_bytes(offs);
            let level: [u8; 2] = read_fixed(&mut *reader)?;
            self.active_level = u16::from_be_bytes(level);
            let count: [u8; 2] = read_fixed(&mut *reader)?;
            self.active_count = u16::from_be_bytes(count);
        }
        let nonrev = Block::read(&mut *reader, self.block_size)?;
        let mut sig = [0u8; G1_COMPRESSED_SIZE];
        reader.read_exact(sig.as_mut())?;
        let entry = SignatureEntry {
            nonrev,
            start: self.active_offset,
            count: self.block_size,
            level: self.active_level,
            sig,
        };
        self.active_count -= 1;
        self.active_offset += 1;
        Ok(entry)
    }
}

impl<R: DoneRead> Iterator for SignatureIterator<R> {
    type Item = Result<SignatureEntry, IoError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(mut reader) = self.reader.take() {
            let result = self.read_next(&mut reader);
            if result.is_ok() && !reader.is_done() {
                self.reader.replace(reader);
            }
            Some(result)
        } else {
            None
        }
    }
}

#[test]
fn test_take_reset() {
    use std::io::Cursor;

    let buf = [0u8, 1u8, 2u8, 3u8];
    let mut tr = TakeReset::new(Cursor::new(&buf[..]), 4);
    let mut cp = [0u8; 4];
    tr.read_exact(&mut cp[..]).unwrap();
    assert_eq!(cp, buf);
    assert!(tr.is_done());
    tr.reset().unwrap();
    assert!(!tr.is_done());
    tr.read_exact(&mut cp[..]).unwrap();
    assert_eq!(cp, buf);
    assert!(tr.is_done());
}
