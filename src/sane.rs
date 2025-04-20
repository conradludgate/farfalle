//! Deck-SANE construction.

use crypto_common::{BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser};
use digest::KeyInit;
use digest::core_api::{Buffer, ExtendableOutputCore, UpdateCore};
use digest::typenum::Unsigned;
use hybrid_array::{Array, ArraySize};
use inout::InOutBuf;
use subtle::ConstantTimeEq;

use crate::deck::DeckCore;
use crate::xorbuffer::XofReaderCoreWrapperXor;

pub trait DeckSaneCore {
    type Core: DeckCore;
    type Nonce: ArraySize;
    type TagSize: ArraySize;
    type Alignnemt: ArraySize;
}

type XorReader<D> =
    XofReaderCoreWrapperXor<<<D as DeckSaneCore>::Core as ExtendableOutputCore>::ReaderCore>;

pub struct DeckSane<D: DeckSaneCore> {
    /// the history
    d: D::Core,
    /// the state of the next keystream
    k: XorReader<D>,
    /// u1 that is stored in bit 7 (0x40)
    e: u8,
}

#[derive(Debug)]
pub struct Error;

/// Session-supporting authenticated encryption scheme
pub trait SessionAead: KeyIvInit {
    type Tag: ArraySize;

    /// Encrypt the data in the provided [`InOutBuf`], returning the authentication tag.
    fn encrypt_inout_detached(
        &mut self,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Array<u8, Self::Tag>;

    /// Decrypt the data in the provided [`InOutBuf`], returning an error in the event the
    /// provided authentication tag is invalid for the given ciphertext (i.e. ciphertext
    /// is modified/unauthentic)
    fn decrypt_inout_detached(
        &mut self,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Array<u8, Self::Tag>,
    ) -> Result<(), Error>;
}

impl<D: DeckSaneCore> KeySizeUser for DeckSane<D> {
    type KeySize = <D::Core as KeySizeUser>::KeySize;
}

impl<D: DeckSaneCore> IvSizeUser for DeckSane<D> {
    type IvSize = D::Nonce;
}

impl<D: DeckSaneCore> KeyIvInit for DeckSane<D> {
    fn new(key: &digest::Key<Self>, iv: &crypto_common::Iv<Self>) -> Self {
        let mut d = <D::Core as KeyInit>::new(key);

        let mut buffer = Buffer::<D::Core>::new(&[]);
        buffer.digest_blocks(iv, |b| d.update_blocks(b));
        let mut k = XofReaderCoreWrapperXor::from_core(d.finalize_xof_core(&mut buffer));
        consume_tag::<D>(&mut k);

        Self { d, k, e: 0 }
    }
}

fn consume_tag<D: DeckSaneCore>(k: &mut XorReader<D>) -> Array<u8, D::TagSize> {
    let mut tag = Array::<u8, D::TagSize>::default();
    let mut offset =
        <D::Alignnemt as Unsigned>::USIZE.next_multiple_of(<D::TagSize as Unsigned>::USIZE);

    k.xor(InOutBuf::from(&mut tag[..]));
    offset = offset - <D::TagSize as Unsigned>::USIZE;

    let mut spare = Array::<u8, <D::Core as BlockSizeUser>::BlockSize>::default();
    while offset > <<D::Core as BlockSizeUser>::BlockSize as Unsigned>::USIZE {
        k.xor(InOutBuf::from(&mut tag[..]));
        offset = offset - <<D::Core as BlockSizeUser>::BlockSize as Unsigned>::USIZE;
    }
    if offset > 0 {
        k.xor(InOutBuf::from(&mut spare[..offset]));
    }

    tag
}

impl<D: DeckSaneCore> SessionAead for DeckSane<D> {
    type Tag = D::TagSize;

    fn encrypt_inout_detached(
        &mut self,
        ad: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
    ) -> Array<u8, Self::Tag> {
        // assume offset = D::TagSize;

        // apply keystream to plaintext
        self.k.xor(buffer.reborrow());
        let ciphertext = buffer.into_out();

        let mut k = apply_ad_ct(&mut self.d, self.e, ad, ciphertext);
        self.e ^= 0x40;

        let mut tag = Array::<u8, Self::Tag>::default();
        k.xor(InOutBuf::from(&mut tag[..]));

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

        let mut actual_tag = Array::<u8, Self::Tag>::default();
        k.xor(InOutBuf::from(&mut actual_tag[..]));
        if tag.ct_ne(&actual_tag).into() {
            return Err(Error);
        }

        // apply keystream to ciphertext
        self.k.xor(buffer);
        self.k = k;

        Ok(())
    }
}

fn apply_ad_ct<D: DeckCore>(
    d: &mut D,
    e: u8,
    ad: &[u8],
    ct: &[u8],
) -> XofReaderCoreWrapperXor<D::ReaderCore> {
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

fn apply_padded<D: DeckCore>(
    m: &[u8],
    sep: u8,
    d: &mut D,
) -> XofReaderCoreWrapperXor<D::ReaderCore> {
    let mut buffer = Buffer::<D>::new(&[]);
    buffer.digest_blocks(m, |b| d.update_blocks(b));
    buffer.digest_blocks(&[sep], |b| d.update_blocks(b));
    XofReaderCoreWrapperXor::from_core(d.finalize_xof_core(&mut buffer))
}
