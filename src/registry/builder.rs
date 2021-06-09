use std::borrow::Cow;
use std::fmt::Debug;
use std::io::{Cursor, Error as IoError, SeekFrom, Write};
use std::time::SystemTime;

use bbs::{
    keys::{DeterministicPublicKey, PublicKey, SecretKey},
    SignatureMessage,
};
use ff_zeroize::Field;
use pairing_plus::bls12_381::Fr;
use rand::rngs::OsRng;

use super::block::{Block, BlockCompute, BlockRepr, SignatureEntry};
use super::header::RegistryHeader;
use super::util::*;
use super::SIG_HEADER_MESSAGES;

#[derive(Clone, Debug)]
pub struct RegistryBuilder<'b, const B: usize> {
    header: RegistryHeader<'b>,
    size: u32,
    dpk: &'b DeterministicPublicKey,
    sk: &'b SecretKey,
}

impl<'b, const B: usize> RegistryBuilder<'b, B> {
    pub fn new(
        uri: &'b str,
        size: u32,
        dpk: &'b DeterministicPublicKey,
        sk: &'b SecretKey,
    ) -> Self {
        Self {
            header: RegistryHeader {
                type_: Cow::Borrowed("bbs-registry;v=1"),
                uri: Cow::Borrowed(uri),
                timestamp: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                interval: 0,
                block_size: B as u16,
                levels: 2,
                dpk: dpk.clone(),
                e: Fr::random(&mut OsRng),
                s: Fr::random(&mut OsRng),
            },
            size,
            dpk,
            sk,
            // pk: dpk.to_public_key(B + SIG_HEADER_MESSAGES).unwrap(),
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

    pub fn write(
        &self,
        writer: &mut impl SeekWrite,
        revoked: impl IntoIterator<Item = u32>,
    ) -> Result<(), IoError>
    where
        Block<B>: BlockRepr,
    {
        self.header.write(writer)?;
        let mut regw = RegistryWriter::new(writer);
        regw.write_signatures(SignatureProducer::<B>::new(
            self.size,
            revoked,
            &self.dpk,
            &self.sk,
            self.header.signature_messages(),
            self.header.e,
            self.header.s,
        ))
    }
}

#[derive(Debug)]
pub struct RegistryWriter<'w, W, const B: usize> {
    writer: &'w mut W,
}

impl<'w, W: SeekWrite, const B: usize> RegistryWriter<'w, W, B> {
    pub(crate) fn new(writer: &'w mut W) -> Self {
        Self { writer }
    }

    pub fn write_signatures(
        &mut self,
        entries: impl IntoIterator<Item = SignatureEntry<B>>,
    ) -> Result<(), IoError>
    where
        Block<B>: BlockRepr,
    {
        let writer = &mut *self.writer;
        let start = writer.stream_position()?;
        writer.write_all(&0u64.to_be_bytes()[..])?; // length
        let mut span = 0;
        let mut offset = 0;
        let mut entry_start = 0;
        let update_count = |writer: &mut W, start, c: u32| {
            writer.seek(SeekFrom::Start(start + 4))?;
            writer.write_all(&c.to_be_bytes()[..])?;
            Result::<_, IoError>::Ok(())
        };
        for entry in entries.into_iter() {
            if span == 0 || entry.offset != offset + 1 {
                span = 0;
                offset = entry.offset;
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
            writer.write_all(Block::<B>::to_be_bytes(&entry.nonrev).as_ref())?;
            writer.write_all(&entry.sig[..])?;
            span += 1;
        }
        if span > 1 {
            update_count(writer, entry_start, span)?;
        }
        let len: u64 = writer.stream_position()? - start - 8;
        writer.seek(SeekFrom::Start(start))?;
        writer.write_all(&len.to_be_bytes()[..])?;
        writer.seek(SeekFrom::End(0))?;
        Ok(())
    }
}

pub struct SignatureProducer<'p, const B: usize> {
    buffer: Vec<u8>,
    offset: usize,
    level: u16,
    pk: PublicKey,
    sk: &'p SecretKey,
    header_messages: [SignatureMessage; SIG_HEADER_MESSAGES],
    e: Fr,
    s: Fr,
}

impl<'p, const B: usize> SignatureProducer<'p, B>
where
    Block<B>: BlockRepr,
{
    pub fn new(
        size: u32,
        revoked: impl IntoIterator<Item = u32>,
        dpk: &DeterministicPublicKey,
        sk: &'p SecretKey,
        header_messages: [SignatureMessage; SIG_HEADER_MESSAGES],
        e: Fr,
        s: Fr,
    ) -> Self {
        let pk = <Block<B> as BlockRepr>::Compute::public_key(dpk);
        let bsize = (size as usize + 7) / 8;
        let mut buffer = vec![0u8; bsize];
        let mut tail = 0u8;
        for _ in 0..(8 - (size % 8)) {
            tail = (tail >> 1) | (1 << 7);
        }
        buffer[bsize - 1] = tail;
        for idx in revoked.into_iter() {
            let bidx = (idx as usize) / 8;
            buffer[bidx] |= 1 << (idx % 8);
        }
        Self {
            buffer,
            offset: 0,
            level: 0,
            pk,
            sk,
            e,
            s,
            header_messages,
        }
    }
}

impl<const B: usize> Iterator for SignatureProducer<'_, B>
where
    Block<B>: BlockRepr,
{
    type Item = SignatureEntry<B>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.level == 1 {
                return None;
            } else if self.offset < self.buffer.len() {
                let (nonrev, len) = Block::<B>::read_le_bytes(&self.buffer[self.offset..]);
                let offset = (self.offset * 8) as u32;
                self.offset += len;
                if Block::<B>::count_non_revoked(nonrev) > 0 {
                    let indices = Block::<B>::block_iter(nonrev, offset);
                    let b = <Block<B> as BlockRepr>::Compute::compute_b(
                        self.header_messages,
                        indices,
                        self.level,
                        &self.pk,
                        self.s,
                    );
                    let sig = sign_b(&self.sk, self.e, b);
                    return Some(SignatureEntry {
                        nonrev,
                        offset,
                        level: 0,
                        sig,
                    });
                }
            } else {
                return None;
            }
        }
    }
}

#[test]
fn test_sig_producer() {
    use bbs::RandomElem;

    // represents the registry type, URI, timestamp, interval
    let header_messages = [
        SignatureMessage::random(),
        SignatureMessage::random(),
        SignatureMessage::random(),
        SignatureMessage::random(),
    ];
    let reg_size = 10;
    let revoked = &[0, 1, 2, 3, 8];
    let (dpk, sk) = DeterministicPublicKey::new(None);
    let e = Fr::random(&mut OsRng);
    let s = Fr::random(&mut OsRng);
    let producer = SignatureProducer::<8>::new(
        reg_size,
        revoked.iter().copied(),
        &dpk,
        &sk,
        header_messages,
        e,
        s,
    );
    let entries = producer.collect::<Vec<_>>();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries[0].indices().collect::<Vec<_>>(),
        vec![4, 5, 6, 7, 7, 7, 7, 7]
    );
    assert_eq!(
        entries[1].indices().collect::<Vec<_>>(),
        vec![9, 9, 9, 9, 9, 9, 9, 9]
    );
    let sig0 = entries[0].signature(e, s);
    let pk = entries[0].public_key(&dpk);
    let verified = entries[0]
        .with_messages(header_messages, |msgs| sig0.verify(msgs, &pk))
        .unwrap();
    assert_eq!(verified, true);

    let sig1 = entries[1].signature(e, s);
    let verified = entries[1]
        .with_messages(header_messages, |msgs| sig1.verify(msgs, &pk))
        .unwrap();
    assert_eq!(verified, true);

    // check wrong signature
    let verified = entries[1]
        .with_messages(header_messages, |msgs| sig0.verify(msgs, &pk))
        .unwrap();
    assert_eq!(verified, false);
}
