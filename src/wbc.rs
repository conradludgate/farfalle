//! Wide block cipher

use std::marker::PhantomData;

use cipher::{Array, InOutBuf, typenum::Unsigned};
use crypto_common::BlockSizes;
use digest::core_api::{Buffer, ExtendableOutputCore, UpdateCore};
use hybrid_array::ArraySize;
use subtle::ConstantTimeEq;

use crate::{deck::DeckCore, sanse::apply_padded};

pub trait WideBlockCipherCore {
    type BlockSize: BlockSizes;
    type G: DeckCore + Clone;
    type H: DeckCore + Clone;
    type Alignnemt: ArraySize;
}

pub struct WideBlockCipher<Core: WideBlockCipherCore> {
    g: Core::G,
    h: Core::H,
}

impl<Core: WideBlockCipherCore> Clone for WideBlockCipher<Core> {
    fn clone(&self) -> Self {
        Self {
            g: self.g.clone(),
            h: self.h.clone(),
        }
    }
}

impl<Core: WideBlockCipherCore> WideBlockCipher<Core> {
    pub fn init(key: &[u8]) -> Self {
        let g = <Core::G as DeckCore>::init(key);
        let h = <Core::H as DeckCore>::init(key);
        Self { g, h }
    }
}

fn split<Core: WideBlockCipherCore>(n: usize) -> usize {
    let l = <Core::Alignnemt as Unsigned>::USIZE;
    let b = <Core::BlockSize as Unsigned>::USIZE;
    assert!(b % l == 0);
    assert!(l >= 2);

    if n <= 2 * b - (l + 2) {
        ((n + l) / (2 * l)) * l
    } else {
        let q = (n + l + 1).div_ceil(b);
        let x = (q - 1).ilog2();
        (q - 1 << x) * b - l
    }
}

impl<Core: WideBlockCipherCore> WideBlockCipher<Core> {
    pub fn encrypt_inout(self, tweak: &[u8], buffer: InOutBuf<'_, '_, u8>) {
        let Self { mut g, mut h } = self;

        let mut tweak_buffer = Buffer::<Core::G>::new(&[]);
        tweak_buffer.digest_blocks(tweak, |t| g.update_blocks(t));
        g.finalize_xof_core(&mut tweak_buffer);

        let n = buffer.len();
        let s = split::<Core>(n);
        let (left, right) = buffer.into_out_with_copied_in().split_at_mut(s);

        let b = <Core::BlockSize as Unsigned>::USIZE;

        let (right0, _) = right.split_at_mut(core::cmp::min(b, n - s));
        apply_padded(&mut h.clone(), left, 0x00).xor_in2out(InOutBuf::from(right0));

        apply_padded(&mut g.clone(), right, 0x80).xor_in2out(InOutBuf::from(&mut *left));
        apply_padded(&mut g, left, 0x00).xor_in2out(InOutBuf::from(&mut *right));

        let (left0, _) = left.split_at_mut(core::cmp::min(b, s));
        apply_padded(&mut h, right, 0x80).xor_in2out(InOutBuf::from(left0));
    }

    pub fn decrypt_inout(self, tweak: &[u8], buffer: InOutBuf<'_, '_, u8>) {
        let Self { mut g, mut h } = self;

        let mut tweak_buffer = Buffer::<Core::G>::new(&[]);
        tweak_buffer.digest_blocks(tweak, |t| g.update_blocks(t));
        g.finalize_xof_core(&mut tweak_buffer);

        let n = buffer.len();
        let s = split::<Core>(n);
        let (left, right) = buffer.into_out_with_copied_in().split_at_mut(s);

        let b = <Core::BlockSize as Unsigned>::USIZE;

        let (left0, _) = left.split_at_mut(core::cmp::min(b, s));
        apply_padded(&mut h.clone(), right, 0x80).xor_in2out(InOutBuf::from(left0));

        apply_padded(&mut g.clone(), left, 0x00).xor_in2out(InOutBuf::from(&mut *right));
        apply_padded(&mut g, right, 0x80).xor_in2out(InOutBuf::from(&mut *left));

        let (right0, _) = right.split_at_mut(core::cmp::min(b, n - s));
        apply_padded(&mut h, left, 0x00).xor_in2out(InOutBuf::from(right0));
    }
}

pub struct WideBlockCipherAuthenticated<Core: WideBlockCipherCore, T: ArraySize> {
    inner: WideBlockCipher<Core>,
    _tag: PhantomData<T>,
}

impl<Core: WideBlockCipherCore, T: ArraySize> WideBlockCipherAuthenticated<Core, T> {
    pub fn init(key: &[u8]) -> Self {
        Self {
            inner: WideBlockCipher::init(key),
            _tag: PhantomData,
        }
    }
}

impl<Core: WideBlockCipherCore, T: ArraySize> WideBlockCipherAuthenticated<Core, T> {
    pub fn encrypt_in_place(self, tweak: &[u8], buffer: &mut impl aead::Buffer) -> aead::Result<()> {
        buffer.extend_from_slice(&Array::<u8, T>::default())?;
        self.inner
            .encrypt_inout(tweak, InOutBuf::from(buffer.as_mut()));
        Ok(())
    }

    pub fn decrypt_in_place<'out>(
        self,
        tweak: &[u8],
        buffer: &'out mut impl aead::Buffer,
    ) -> aead::Result<&'out mut [u8]> {
        if buffer.len() < T::USIZE {
            return Err(aead::Error);
        }

        let n = buffer.len() - T::USIZE;

        self.inner
            .clone()
            .decrypt_inout(tweak, InOutBuf::from(buffer.as_mut()));

        let tag = Array::<u8, T>::default();
        let actual_tag = &buffer.as_ref()[n..];
        if tag.ct_ne(actual_tag).into() {
            self.inner
                .encrypt_inout(tweak, InOutBuf::from(buffer.as_mut()));
            return Err(aead::Error);
        }

        buffer.truncate(n);
        Ok(buffer.as_mut())
    }
}
