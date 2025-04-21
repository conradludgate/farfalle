//! Deck-SANE construction.

use aead::Error;
use crypto_common::BlockSizeUser;
use digest::XofReader;
use digest::core_api::{Buffer, ExtendableOutputCore, UpdateCore};
use digest::typenum::Unsigned;
use hybrid_array::{Array, ArraySize};
use inout::InOutBuf;
use subtle::ConstantTimeEq;

use crate::SessionAead;
use crate::core_api::{self, XofReaderCoreWrapper};
use crate::deck::DeckCore;

/// Core parameters used by [`DeckSane`]
pub trait DeckSaneCore {
    /// The [`DeckCore`] implementation to use
    type Core: DeckCore;
    /// The size of the tags the SAE impl produces
    type TagSize: ArraySize;
    /// The alignment of the key stream after the tag.
    type Alignnemt: ArraySize;
}

type XofReaderW<D> =
    XofReaderCoreWrapper<<<D as DeckSaneCore>::Core as ExtendableOutputCore>::ReaderCore>;

/// Deck-SANE is a session-aware authenticated encryption ([`SessionAEAD`]) construction based on [`Deck`](DeckCore) functions.
pub struct DeckSane<D: DeckSaneCore> {
    /// the history
    d: D::Core,
    /// the state of the next keystream
    k: XofReaderW<D>,
    /// u1 that is stored in bit 7 (0x40)
    e: u8,
}

impl<D: DeckSaneCore> DeckSane<D> {
    pub fn init(key: &[u8], iv: &[u8]) -> Self {
        let mut d = <D::Core as DeckCore>::init(key);

        // apply IV to history.
        let mut buffer = Buffer::<D::Core>::new(&[]);
        buffer.digest_blocks(iv, |b| d.update_blocks(b));
        let mut k = XofReaderCoreWrapper::from_core(d.finalize_xof_core(&mut buffer));
        Self::consume_tag_and_offset(&mut k);

        Self { d, k, e: 0 }
    }

    fn consume_tag_and_offset(k: &mut XofReaderW<D>) -> Array<u8, D::TagSize> {
        let mut tag = Array::<u8, D::TagSize>::default();
        let mut offset =
            <D::Alignnemt as Unsigned>::USIZE.next_multiple_of(<D::TagSize as Unsigned>::USIZE);

        k.read(&mut tag[..]);
        offset = offset - <D::TagSize as Unsigned>::USIZE;

        let mut spare = Array::<u8, <D::Core as BlockSizeUser>::BlockSize>::default();
        while offset > <<D::Core as BlockSizeUser>::BlockSize as Unsigned>::USIZE {
            k.read(&mut tag[..]);
            offset = offset - <<D::Core as BlockSizeUser>::BlockSize as Unsigned>::USIZE;
        }
        if offset > 0 {
            k.read(&mut spare[..offset]);
        }

        tag
    }
}

impl<D: DeckSaneCore> SessionAead for DeckSane<D> {
    type Tag = D::TagSize;

    fn encrypt_inout_detached(
        &mut self,
        ad: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
    ) -> Array<u8, Self::Tag> {
        // apply keystream to plaintext
        core_api::xor(&mut self.k, buffer.reborrow());
        let ciphertext = buffer.into_out();

        let mut k = apply_ad_ct(&mut self.d, self.e, ad, ciphertext);
        self.e ^= 0x40;

        let tag = Self::consume_tag_and_offset(&mut k);

        self.k = k;

        tag
    }

    fn decrypt_inout_detached(
        &mut self,
        ad: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Array<u8, Self::Tag>,
    ) -> Result<(), Error> {
        // apply associated data to history
        let ciphertext = buffer.get_in();

        let mut k = apply_ad_ct(&mut self.d, self.e, ad, ciphertext);
        self.e ^= 0x40;

        let actual_tag = Self::consume_tag_and_offset(&mut k);
        if tag.ct_ne(&actual_tag).into() {
            return Err(Error);
        }

        // apply keystream to ciphertext
        core_api::xor(&mut self.k, buffer);
        self.k = k;

        Ok(())
    }
}

fn apply_ad_ct<D: DeckCore>(
    d: &mut D,
    e: u8,
    ad: &[u8],
    ct: &[u8],
) -> XofReaderCoreWrapper<D::ReaderCore> {
    if ct.is_empty() {
        // apply associated data to history
        apply_padded(ad, e | 0x20, d)
    } else {
        if !ad.is_empty() {
            // apply associated data to history
            apply_padded(ad, e | 0x20, d);
        }
        // apply ciphertext to history
        apply_padded(ct, e | 0xa0, d)
    }
}

pub(crate) fn apply_padded<D: DeckCore>(
    m: &[u8],
    sep: u8,
    d: &mut D,
) -> XofReaderCoreWrapper<D::ReaderCore> {
    let mut buffer = Buffer::<D>::new(&[]);
    buffer.digest_blocks(m, |b| d.update_blocks(b));
    buffer.digest_blocks(&[sep], |b| d.update_blocks(b));
    XofReaderCoreWrapper::from_core(d.finalize_xof_core(&mut buffer))
}
