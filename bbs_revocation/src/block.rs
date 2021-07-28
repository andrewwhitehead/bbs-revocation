use std::{
    fmt::{self, Debug, Formatter},
    io::{Cursor, Error as IoError, Read, Write},
};

use bbs::{
    keys::{PublicKey, SecretKey},
    signature::{Signature, SIGNATURE_COMPRESSED_SIZE},
    SignatureMessage, G1_COMPRESSED_SIZE,
};
use ff_zeroize::PrimeField;
use pairing_plus::{
    bls12_381::{Fr, G1Affine, G1},
    serdes::SerDes,
    CurveAffine, CurveProjective,
};

use super::header::HEADER_MESSAGES;
use super::util::*;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Block(u64);

impl Block {
    const SIZE: usize = 8;

    pub(crate) const fn debug_print(&self, count: u16) -> BlockDebug {
        BlockDebug {
            nonrev: self.0,
            count: count as usize,
        }
    }

    pub const fn is_revoked_at(&self, offset: u32) -> bool {
        self.0 & (1 << offset) == 0
    }

    pub const fn is_revoked(&self) -> bool {
        self.0 == 0
    }

    pub const fn count(&self) -> u16 {
        self.0.count_ones() as u16
    }

    #[inline]
    pub fn from_slice(buffer: &[u8]) -> Self {
        let mut val = [0u8; Self::SIZE];
        let len = buffer.len().min(Self::SIZE);
        val[..len].copy_from_slice(&buffer[..len]);
        Self(u64::from_le_bytes(val))
    }

    #[inline]
    pub fn read<R: Read>(mut reader: R, block_size: u16) -> Result<Self, IoError> {
        let mut val = [0u8; Self::SIZE];
        let len = (block_size as usize / 8).min(Self::SIZE);
        reader.read_exact(&mut val[..len])?;
        Ok(Self(u64::from_le_bytes(val)))
    }

    pub fn build(count: usize, mut f: impl FnMut() -> Option<bool>) -> Option<Self> {
        let mut count = count.min(64);
        let mut flag = 1u64;
        let mut repr = 0u64;
        while count > 0 {
            if let Some(nonrev) = f() {
                if nonrev {
                    repr |= flag;
                }
                flag <<= 1;
                count -= 1;
            } else {
                break;
            }
        }
        if repr != 0 {
            Some(Self(repr))
        } else {
            None
        }
    }

    #[inline]
    pub fn indices(&self, start: u32, count: usize, pad: bool) -> OffsetIter {
        OffsetIter::new(self.0, start, count, pad)
    }

    pub fn compute_b(
        &self,
        head: [SignatureMessage; HEADER_MESSAGES],
        start: u32,
        count: u16,
        level: u16,
        pk: &PublicKey,
        s: Fr,
    ) -> G1 {
        assert!(count <= 64);
        const FC: usize = 2 + HEADER_MESSAGES + 64;
        // up to 2 + 66 messages
        let mut bases = heapless::Vec::<_, FC>::new();
        let mut scalars = heapless::Vec::<[u64; 4], FC>::new();

        // P
        bases.push(G1Affine::one()).unwrap();
        // [1, 0, 0, 0] = fr_mul_repr(&FrRepr::from(1)).unwrap())
        scalars.push([1, 0, 0, 0]).unwrap();
        // h0 * s
        bases.push(pk.h0.as_ref().into_affine()).unwrap();
        scalars.push(fr_mul_repr(s.into_repr())).unwrap();

        // hi * mi
        for h in &pk.h {
            bases.push(h.as_ref().into_affine()).unwrap();
        }
        for msg in head.iter() {
            scalars.push(fr_mul_repr(msg.as_ref().into_repr())).unwrap();
        }
        for index in self.indices(start, count as usize, true) {
            scalars
                .push(fr_mul_repr(compute_index_repr(index, level)))
                .unwrap();
        }

        let s = scalars.iter().collect::<heapless::Vec<_, FC>>();
        G1Affine::sum_of_products(&bases[..], &s[..])
    }

    #[inline]
    pub fn to_le_bytes(&self) -> [u8; Self::SIZE] {
        self.0.to_le_bytes()
    }

    #[inline]
    pub fn with_messages<R>(
        &self,
        head: [SignatureMessage; HEADER_MESSAGES],
        start: u32,
        count: u16,
        level: u16,
        f: impl FnOnce(&[SignatureMessage]) -> R,
    ) -> R {
        const FC: usize = HEADER_MESSAGES + 64;
        let mut msgs = heapless::Vec::<SignatureMessage, FC>::new();
        msgs.extend(head.iter().copied());
        msgs.extend(
            OffsetIter::new(self.0, start, count as usize, true)
                .map(|index| compute_index_message(index, level)),
        );
        f(&msgs[..])
    }
}

impl Debug for Block {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("Block({:?})", self.debug_print(64)))
    }
}

impl From<u64> for Block {
    fn from(val: u64) -> Self {
        Block(val)
    }
}

pub(crate) struct BlockDebug {
    nonrev: u64,
    count: usize,
}

impl Debug for BlockDebug {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut n = self.nonrev;
        for _ in 0..self.count {
            f.write_str(if n & 1 == 0 { "0" } else { "1" })?;
            n >>= 1;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct OffsetIter {
    nonrev: u64,
    offset: u32,
    last: u32,
    end: u32,
    remain: usize,
    pad: bool,
}

impl OffsetIter {
    #[inline]
    pub fn new(nonrev: u64, offset: u32, remain: usize, pad: bool) -> Self {
        Self {
            nonrev,
            offset,
            last: offset,
            end: offset + (remain as u32),
            remain,
            pad,
        }
    }
}

impl Iterator for OffsetIter {
    type Item = u32;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while self.offset < self.end {
            let cmp = self.nonrev & 1;
            let offs = self.offset;
            self.nonrev >>= 1;
            self.offset += 1;
            if cmp == 1 {
                self.remain -= 1;
                self.last = offs;
                return Some(offs);
            }
        }
        if self.remain > 0 && self.pad {
            self.remain -= 1;
            Some(self.last)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy)]
pub struct SignatureEntry {
    pub nonrev: Block,
    pub start: u32,
    pub level: u16,
    pub count: u16,
    pub sig_a: [u8; G1_COMPRESSED_SIZE],
}

impl SignatureEntry {
    pub(crate) fn create(
        nonrev: Block,
        head: [SignatureMessage; HEADER_MESSAGES],
        start: u32,
        count: u16,
        level: u16,
        pk: &PublicKey,
        sk: &SecretKey,
        sig_e: Fr,
        sig_s: Fr,
    ) -> SignatureEntry {
        let b = nonrev.compute_b(head, start, count, level, pk, sig_s);
        let sig_a = sign_b(sk, sig_e, b);
        SignatureEntry {
            nonrev,
            start,
            count,
            level,
            sig_a,
        }
    }

    pub fn contains_index(&self, index: u32) -> Option<bool> {
        if self.start <= index && self.start + (self.count as u32) > index {
            Some(!self.nonrev.is_revoked_at(index - self.start))
        } else {
            None
        }
    }

    pub fn index_position(&self, mut index: u32) -> Option<usize> {
        if self.level == 1 {
            index /= self.count as u32;
        }
        self.nonrev
            .indices(self.start, self.count as usize, false)
            .enumerate()
            .find_map(|(pos, i)| if i == index { Some(pos) } else { None })
    }

    #[inline]
    pub fn indices(&self) -> OffsetIter {
        self.nonrev.indices(self.start, self.count as usize, true)
    }

    #[inline]
    pub fn unique_indices(&self) -> OffsetIter {
        self.nonrev.indices(self.start, self.count as usize, false)
    }

    pub(crate) fn signature(&self, sig_e: Fr, sig_s: Fr) -> Signature {
        let mut sig = [0u8; SIGNATURE_COMPRESSED_SIZE];
        let mut c = Cursor::new(&mut sig[..]);
        c.write(&self.sig_a[..]).unwrap();
        sig_e.serialize(&mut c, true).unwrap();
        sig_s.serialize(&mut c, true).unwrap();
        Signature::from(sig)
    }

    #[cfg(test)]
    pub fn with_messages<R>(
        &self,
        head: [SignatureMessage; HEADER_MESSAGES],
        f: impl FnOnce(&[SignatureMessage]) -> R,
    ) -> R {
        self.nonrev
            .with_messages(head, self.start, self.count, self.level, f)
    }
}

impl Debug for SignatureEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureEntry")
            .field("nonrev", &self.nonrev.debug_print(self.count))
            .field("start", &self.start)
            .field("level", &self.level)
            .field("count", &self.count)
            .field("sig_a", &"<sig>")
            .finish()
    }
}

#[test]
fn test_offset_iter() {
    let iter = OffsetIter::new(
        11u64, // ..00001011
        10, 8, true,
    );
    assert_eq!(
        iter.collect::<Vec<u32>>(),
        vec![10u32, 11u32, 13u32, 13u32, 13u32, 13u32, 13u32, 13u32]
    );
}

#[test]
fn test_entry_indices() {
    let entry = SignatureEntry {
        nonrev: Block::from(u8::MAX as u64), // ..00011111111
        start: 4,
        count: 8,
        level: 0,
        sig_a: [0u8; 48],
    };
    assert_eq!(
        entry.indices().collect::<Vec<_>>(),
        vec![4, 5, 6, 7, 8, 9, 10, 11]
    );
}

#[test]
fn test_build_block() {
    let mut idx = 0;
    let repr = Block::build(64, || {
        idx += 1;
        Some(idx == 3 || idx == 5)
    })
    .unwrap();
    assert_eq!(repr, Block::from((1u64 << 2) + (1 << 4)));
    assert_eq!(
        repr.to_le_bytes(),
        [(1u8 << 2) + (1 << 4), 0, 0, 0, 0, 0, 0, 0]
    );
}
