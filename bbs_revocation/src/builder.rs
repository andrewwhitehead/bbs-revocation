use std::borrow::Cow;
use std::fmt::Debug;
use std::io::{Cursor, Error as IoError, Seek, SeekFrom, Write};
use std::time::SystemTime;

use bbs::{
    keys::{DeterministicPublicKey, PublicKey, SecretKey},
    SignatureMessage,
};
use ff_zeroize::Field;
use pairing_plus::bls12_381::Fr;
use rand::rngs::OsRng;

use super::block::{Block, SignatureEntry};
use super::header::{RegistryHeader, HEADER_MESSAGES};

#[derive(Clone, Debug)]
pub struct RegistryBuilder<'b> {
    header: RegistryHeader<'b>,
    entry_count: u32,
    sk: &'b SecretKey,
}

impl<'b> RegistryBuilder<'b> {
    pub fn new(
        uri: &'b str,
        block_size: u16,
        entry_count: u32,
        dpk: &DeterministicPublicKey,
        sk: &'b SecretKey,
    ) -> Self {
        assert!(block_size > 0 && block_size <= 64 && block_size % 8 == 0);
        Self {
            header: RegistryHeader {
                registry_type: Cow::Borrowed("bbs-registry;v=1"),
                registry_uri: Cow::Borrowed(uri),
                timestamp: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                interval: 0,
                block_size,
                levels: 2,
                dpk: dpk.clone(),
                e: Fr::random(&mut OsRng),
                s: Fr::random(&mut OsRng),
            },
            entry_count,
            sk,
        }
    }

    pub fn interval(mut self, value: u32) -> Self {
        self.header.interval = value;
        self
    }

    pub fn timestamp(mut self, value: u64) -> Self {
        self.header.timestamp = value;
        self
    }

    pub fn header(&self) -> &RegistryHeader<'_> {
        &self.header
    }

    pub fn write<W: Seek + Write>(
        &self,
        mut writer: W,
        revoked: impl IntoIterator<Item = u32>,
    ) -> Result<usize, IoError> {
        self.header.write(&mut writer)?;
        let mut regw = RegistryWriter::new(&mut writer);
        regw.write_signatures(SignatureProducer::from_revoked(
            &self.header,
            self.entry_count,
            revoked,
            &self.sk,
        ))
    }
}

#[derive(Debug)]
pub struct RegistryWriter<W> {
    writer: W,
}

impl<W: Seek + Write> RegistryWriter<W> {
    pub(crate) fn new(writer: W) -> Self {
        Self { writer }
    }

    pub fn write_signatures(
        &mut self,
        entries: impl IntoIterator<Item = SignatureEntry>,
    ) -> Result<usize, IoError> {
        let writer = &mut self.writer;
        let start = writer.stream_position()?;
        writer.write_all(&0u64.to_be_bytes()[..])?; // length placeholder
        let mut span = 0;
        let mut offset = 0;
        let mut entry_start = 0;
        let update_count = |writer: &mut W, start, c: u32| {
            writer.seek(SeekFrom::Start(start + 4))?;
            writer.write_all(&c.to_be_bytes()[..])?;
            Result::<_, IoError>::Ok(())
        };
        let mut count = 0;
        for entry in entries.into_iter() {
            if span == 0 || entry.start != offset + 1 {
                span = 0;
                offset = entry.start;
                entry_start = writer.stream_position()?;
                let mut offs_count = [0u8; 8];
                let mut c = Cursor::new(&mut offs_count[..]);
                c.write(&offset.to_be_bytes()[..])?;
                c.write(&entry.level.to_be_bytes()[..])?;
                c.write(&1u16.to_be_bytes()[..])?;
                writer.write_all(&offs_count[..])?;
            } else if span > 1 {
                update_count(writer, entry_start, span)?;
                span = 0;
            }
            writer.write_all(&entry.nonrev.to_le_bytes()[..(entry.count as usize / 8)])?;
            writer.write_all(&entry.sig_a[..])?;
            span += 1;
            count += 1;
        }
        if span > 1 {
            update_count(writer, entry_start, span)?;
        }
        // update length
        let len: u64 = writer.stream_position()? - start - 8;
        writer.seek(SeekFrom::Start(start))?;
        writer.write_all(&len.to_be_bytes()[..])?;
        writer.seek(SeekFrom::End(0))?;
        Ok(count)
    }
}

pub struct SignatureProducer<'p> {
    buffer: Vec<u8>,
    offset: usize,
    block_size: u16,
    level: u16,
    pk: PublicKey,
    sk: &'p SecretKey,
    header_messages: [SignatureMessage; HEADER_MESSAGES],
    e: Fr,
    s: Fr,
}

impl<'p> SignatureProducer<'p> {
    pub fn from_revoked(
        header: &RegistryHeader<'_>,
        entry_count: u32,
        revoked: impl IntoIterator<Item = u32>,
        sk: &'p SecretKey,
    ) -> Self {
        let bsize = (entry_count as usize + 7) / 8;
        let mut buffer = vec![u8::MAX; bsize];
        let tail_c = (bsize * 8) - (entry_count as usize);
        if tail_c > 0 {
            // clear non-issued indices
            buffer[bsize - 1] = (1u8 << (8 - tail_c)) - 1;
        }
        for idx in revoked.into_iter() {
            let bidx = (idx as usize) / 8;
            if bidx < buffer.len() {
                buffer[bidx] &= !(1 << (idx % 8));
            }
        }
        Self::from_registry_buffer(header, buffer, sk)
    }

    pub fn from_registry_buffer(
        header: &RegistryHeader<'_>,
        buffer: Vec<u8>,
        sk: &'p SecretKey,
    ) -> Self {
        let pk = header.public_key();
        Self {
            buffer,
            offset: 0,
            block_size: header.block_size,
            level: 1,
            pk,
            sk,
            header_messages: header.messages(),
            e: header.e,
            s: header.s,
        }
    }
}

impl Iterator for SignatureProducer<'_> {
    type Item = SignatureEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let block_size = self.block_size as usize;
        loop {
            if self.level == 1 {
                let start = (self.offset * 8 / block_size) as u32;
                if let Some(nonrev) = Block::build(block_size, || {
                    let offset = self.offset;
                    let end = self.buffer.len().min(offset + (block_size / 8));
                    if end > offset {
                        self.offset = end;
                        let nonrev = Block::from_slice(&self.buffer[offset..end]);
                        if nonrev.count() == self.block_size {
                            // subtract block
                            for idx in offset..end {
                                self.buffer[idx] = 0;
                            }
                            Some(true)
                        } else {
                            Some(false)
                        }
                    } else {
                        self.level = 0;
                        self.offset = 0;
                        None
                    }
                }) {
                    return Some(SignatureEntry::create(
                        nonrev,
                        self.header_messages,
                        start,
                        self.block_size,
                        1,
                        &self.pk,
                        &self.sk,
                        self.e,
                        self.s,
                    ));
                }
            } else {
                let end = self.buffer.len().min(self.offset + (block_size / 8));
                if end > self.offset {
                    let nonrev = Block::from_slice(&self.buffer[self.offset..end]);
                    let start = (self.offset * 8) as u32;
                    self.offset = end;
                    if nonrev.count() > 0 {
                        return Some(SignatureEntry::create(
                            nonrev,
                            self.header_messages,
                            start,
                            self.block_size,
                            0,
                            &self.pk,
                            &self.sk,
                            self.e,
                            self.s,
                        ));
                    }
                } else {
                    return None;
                }
            }
        }
    }
}

#[test]
fn test_sig_producer_level_1() {
    let entry_count = 10;
    let revoked = &[0, 1, 2, 3, 8];
    let (dpk, sk) = DeterministicPublicKey::new(None);
    let e = Fr::random(&mut OsRng);
    let s = Fr::random(&mut OsRng);
    let header = RegistryHeader {
        registry_type: Cow::Borrowed("reg-type"),
        registry_uri: Cow::Borrowed("reg-uri"),
        timestamp: 1,
        interval: 0,
        block_size: 8,
        levels: 2,
        dpk,
        e,
        s,
    };
    let header_messages = header.messages();
    let producer =
        SignatureProducer::from_revoked(&header, entry_count, revoked.iter().copied(), &sk);
    let entries = producer.collect::<Vec<_>>();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].level, 0);
    assert_eq!(
        entries[0].indices().collect::<Vec<_>>(),
        vec![4, 5, 6, 7, 7, 7, 7, 7]
    );
    assert_eq!(entries[1].level, 0);
    assert_eq!(
        entries[1].indices().collect::<Vec<_>>(),
        vec![9, 9, 9, 9, 9, 9, 9, 9]
    );
    let sig0 = entries[0].signature(e, s);
    let pk = header.public_key();
    let verified = sig0
        .verify(&entries[0].messages(header_messages)[..], &pk)
        .unwrap();
    assert_eq!(verified, true);

    let sig1 = entries[1].signature(e, s);
    let verified = sig1
        .verify(&entries[1].messages(header_messages)[..], &pk)
        .unwrap();
    assert_eq!(verified, true);

    // check wrong signature
    let verified = sig0
        .verify(&entries[1].messages(header_messages)[..], &pk)
        .unwrap();
    assert_eq!(verified, false);
}

#[test]
fn test_sig_producer_level_2() {
    let entry_count = 16;
    let revoked = &[4];
    let (dpk, sk) = DeterministicPublicKey::new(None);
    let e = Fr::random(&mut OsRng);
    let s = Fr::random(&mut OsRng);
    let header = RegistryHeader {
        registry_type: Cow::Borrowed("reg-type"),
        registry_uri: Cow::Borrowed("reg-uri"),
        timestamp: 1,
        interval: 0,
        block_size: 8,
        levels: 2,
        dpk,
        e,
        s,
    };
    let header_messages = header.messages();
    let producer =
        SignatureProducer::from_revoked(&header, entry_count, revoked.iter().copied(), &sk);
    let entries = producer.collect::<Vec<_>>();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].level, 1);
    assert_eq!(entries[0].start, 0);
    assert_eq!(entries[0].count, 8);
    assert_eq!(entries[0].nonrev, Block::from(1 << 1));
    assert_eq!(
        entries[0].indices().collect::<Vec<_>>(),
        vec![1, 1, 1, 1, 1, 1, 1, 1]
    );
    assert_eq!(entries[1].level, 0);
    assert_eq!(entries[1].start, 0);
    assert_eq!(entries[1].count, 8);
    assert_eq!(
        entries[1].indices().collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 5, 6, 7, 7]
    );
    let sig0 = entries[0].signature(e, s);
    let pk = header.public_key();
    let verified = sig0
        .verify(&entries[0].messages(header_messages)[..], &pk)
        .unwrap();

    assert_eq!(verified, true);

    let sig1 = entries[1].signature(e, s);
    let verified = sig1
        .verify(&entries[1].messages(header_messages)[..], &pk)
        .unwrap();
    assert_eq!(verified, true);

    // check wrong signature
    let verified = sig0
        .verify(&entries[1].messages(header_messages)[..], &pk)
        .unwrap();
    assert_eq!(verified, false);
}
