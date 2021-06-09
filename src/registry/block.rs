use std::{
    fmt::Debug,
    io::{Cursor, Write},
    ops::{BitAnd, ShrAssign},
};

use bbs::{
    keys::{DeterministicPublicKey, PublicKey},
    signature::{Signature, SIGNATURE_COMPRESSED_SIZE},
    SignatureMessage, G1_COMPRESSED_SIZE,
};
use ff_zeroize::PrimeField;
use pairing_plus::{
    bls12_381::{Fr, G1Affine, G1},
    serdes::SerDes,
    CurveAffine, CurveProjective,
};

use super::util::*;
use super::SIG_HEADER_MESSAGES;

#[derive(Debug)]
pub struct Block<const B: usize>;

pub trait BlockRepr {
    type Repr: Clone + Copy + Debug;
    type Bytes: AsRef<[u8]> + AsMut<[u8]> + Default;
    type Iter: Iterator<Item = u32>;
    type Compute: BlockCompute;

    fn to_be_bytes(repr: &Self::Repr) -> Self::Bytes;
    fn from_be_bytes(bytes: Self::Bytes) -> Self::Repr;
    fn read_le_bytes(bs: &[u8]) -> (Self::Repr, usize);
    fn count_non_revoked(repr: Self::Repr) -> usize;
    fn block_iter(repr: Self::Repr, offset: u32) -> Self::Iter;
    fn check_index(repr: Self::Repr, pos: u32) -> bool;
}

impl BlockRepr for Block<8> {
    type Repr = u8;
    type Bytes = [u8; 1];
    type Iter = OffsetIter<u8>;
    type Compute = ComputeBlock<12, 14>;

    #[inline]
    fn to_be_bytes(repr: &Self::Repr) -> Self::Bytes {
        repr.to_be_bytes()
    }

    #[inline]
    fn from_be_bytes(bytes: Self::Bytes) -> Self::Repr {
        bytes[0]
    }

    #[inline]
    fn read_le_bytes(bs: &[u8]) -> (Self::Repr, usize) {
        if bs.len() > 0 {
            (bs[0], 1)
        } else {
            (u8::MAX, 0)
        }
    }

    #[inline]
    fn count_non_revoked(repr: Self::Repr) -> usize {
        repr.count_zeros() as usize
    }

    fn block_iter(repr: Self::Repr, offset: u32) -> Self::Iter {
        OffsetIter::new(repr, offset, 8)
    }

    #[inline]
    fn check_index(repr: Self::Repr, pos: u32) -> bool {
        (repr >> pos) & 1 == 0
    }
}

impl BlockRepr for Block<64> {
    type Repr = u64;
    type Bytes = [u8; 8];
    type Iter = OffsetIter<u64>;
    type Compute = ComputeBlock<68, 70>;

    #[inline]
    fn to_be_bytes(repr: &Self::Repr) -> Self::Bytes {
        repr.to_be_bytes()
    }

    #[inline]
    fn from_be_bytes(bytes: Self::Bytes) -> Self::Repr {
        u64::from_be_bytes(bytes)
    }

    #[inline]
    fn read_le_bytes(bs: &[u8]) -> (Self::Repr, usize) {
        let mut buf = [u8::MAX; 8];
        let len = bs.len().min(8);
        buf[..len].copy_from_slice(&bs[..len]);
        (u64::from_le_bytes(buf), len)
    }

    #[inline]
    fn count_non_revoked(repr: Self::Repr) -> usize {
        repr.count_zeros() as usize
    }

    fn block_iter(repr: Self::Repr, offset: u32) -> Self::Iter {
        OffsetIter::new(repr, offset, 64)
    }

    #[inline]
    fn check_index(repr: Self::Repr, pos: u32) -> bool {
        println!("{:b} {}", repr, pos);
        (repr >> pos) & 1 == 0
    }
}

#[derive(Debug)]
pub struct OffsetIter<R> {
    repr: R,
    offset: u32,
    last: u32,
    end: u32,
    remain: usize,
}

impl<R> OffsetIter<R> {
    #[inline]
    pub fn new(repr: R, offset: u32, remain: usize) -> Self {
        Self {
            repr,
            offset,
            last: offset,
            end: offset + (remain as u32),
            remain,
        }
    }
}

impl<R> Iterator for OffsetIter<R>
where
    R: BitAnd<Output = R> + Copy + From<u8> + PartialEq + ShrAssign,
{
    type Item = u32;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let one = R::from(1u8);
        let zero = R::from(0u8);
        while self.offset < self.end {
            let cmp = self.repr & one;
            let offs = self.offset;
            self.repr >>= one;
            self.offset += 1;
            if cmp == zero {
                self.remain -= 1;
                self.last = offs;
                return Some(offs);
            }
        }
        if self.remain > 0 {
            self.remain -= 1;
            Some(self.last)
        } else {
            None
        }
    }
}

pub trait BlockCompute {
    fn compute_b<I>(
        head: [SignatureMessage; SIG_HEADER_MESSAGES],
        indices: I,
        level: u16,
        pk: &PublicKey,
        s: Fr,
    ) -> G1
    where
        I: IntoIterator<Item = u32>;

    fn public_key(dpk: &DeterministicPublicKey) -> PublicKey;

    fn with_messages<I, F, R>(
        head: [SignatureMessage; SIG_HEADER_MESSAGES],
        indices: I,
        level: u16,
        f: F,
    ) -> R
    where
        I: IntoIterator<Item = u32>,
        F: FnOnce(&[SignatureMessage]) -> R;
}

pub struct ComputeBlock<const MC: usize, const FC: usize>;

impl<const MC: usize, const FC: usize> BlockCompute for ComputeBlock<MC, FC> {
    fn compute_b<I>(
        head: [SignatureMessage; SIG_HEADER_MESSAGES],
        indices: I,
        level: u16,
        pk: &PublicKey,
        s: Fr,
    ) -> G1
    where
        I: IntoIterator<Item = u32>,
    {
        // 2 + 66 messages
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
        for index in indices {
            scalars
                .push(fr_mul_repr(compute_index_repr(index, level)))
                .unwrap();
        }

        let s = scalars.iter().collect::<heapless::Vec<_, FC>>();
        G1Affine::sum_of_products(&bases[..], &s[..])
    }

    fn public_key(dpk: &DeterministicPublicKey) -> PublicKey {
        dpk.to_public_key(MC).unwrap()
    }

    fn with_messages<I, F, R>(
        head: [SignatureMessage; SIG_HEADER_MESSAGES],
        indices: I,
        level: u16,
        f: F,
    ) -> R
    where
        I: IntoIterator<Item = u32>,
        F: FnOnce(&[SignatureMessage]) -> R,
    {
        let mut msgs = heapless::Vec::<_, MC>::new();
        msgs.extend(head.iter().copied());
        for idx in indices {
            msgs.push(compute_index(idx, level)).unwrap();
        }
        f(msgs.as_slice())
    }
}

#[derive(Clone, Debug)]
pub struct SignatureEntry<const B: usize>
where
    Block<B>: BlockRepr,
{
    pub nonrev: <Block<B> as BlockRepr>::Repr,
    pub offset: u32,
    pub level: u16,
    pub sig: [u8; G1_COMPRESSED_SIZE],
}

impl<const B: usize> SignatureEntry<B>
where
    Block<B>: BlockRepr,
{
    pub fn contains_index(&self, index: u32) -> Option<bool> {
        if self.offset <= index && self.offset + (B as u32) > index {
            Some(Block::<B>::check_index(self.nonrev, index - self.offset))
        } else {
            None
        }
    }

    pub fn indices(&self) -> impl Iterator<Item = u32> {
        Block::<B>::block_iter(self.nonrev, self.offset)
    }

    pub fn public_key(&self, dpk: &DeterministicPublicKey) -> PublicKey {
        <Block<B> as BlockRepr>::Compute::public_key(dpk)
    }

    pub fn signature(&self, e: Fr, s: Fr) -> Signature {
        let mut sig = [0u8; SIGNATURE_COMPRESSED_SIZE];
        let mut c = Cursor::new(&mut sig[..]);
        c.write(&self.sig[..]).unwrap();
        e.serialize(&mut c, true).unwrap();
        s.serialize(&mut c, true).unwrap();
        Signature::from(sig)
    }

    pub fn with_messages<R>(
        &self,
        head: [SignatureMessage; SIG_HEADER_MESSAGES],
        f: impl FnOnce(&[SignatureMessage]) -> R,
    ) -> R {
        <Block<B> as BlockRepr>::Compute::with_messages(head, self.indices(), self.level, f)
    }
}

#[test]
fn test_offset_iter() {
    let iter = OffsetIter::<u8>::new(
        !11u8, // 11110100
        10, 8,
    );
    assert_eq!(
        iter.collect::<Vec<u32>>(),
        vec![10u32, 11u32, 13u32, 13u32, 13u32, 13u32, 13u32, 13u32]
    );
}
