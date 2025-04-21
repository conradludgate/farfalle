//! Deck-SANSE construction.

use aead::Error;
use cipher::Block;
use digest::core_api::{Buffer, ExtendableOutputCore, XofReaderCore};
use hybrid_array::{Array, ArraySize};
use inout::InOutBuf;
use subtle::{Choice, ConstantTimeEq};

use crate::SessionAead;
use crate::deck::DeckCore;

/// Core parameters used by [`DeckSanse`]
pub trait DeckSanseCore {
    type Core: DeckCore + Clone;
    type TagSize: ArraySize;
}

/// Deck-SANSE is a strong-initialized-value (SIV) session-aware authenticated encryption ([`SessionAEAD`])
/// construction based on [`Deck`](DeckCore) functions
pub struct DeckSanse<D: DeckSanseCore> {
    /// the history
    d: D::Core,
    /// u1 that is stored in bit 6 (0x20)
    e: u8,
}

impl<D: DeckSanseCore> DeckSanse<D> {
    pub fn init(key: &[u8]) -> Self {
        let d = <D::Core as DeckCore>::init(key);

        Self { d, e: 0 }
    }
}

impl<D: DeckSanseCore> SessionAead for DeckSanse<D>
where
    <D::Core as ExtendableOutputCore>::ReaderCore: Clone,
{
    type Tag = D::TagSize;

    fn encrypt_inout_detached(
        &mut self,
        ad: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Array<u8, Self::Tag> {
        let e = self.e;
        self.e ^= 0x20;

        if buffer.is_empty() {
            // apply associated data to history
            apply_padded(&mut self.d, ad, e).read_tag()
        } else {
            if !ad.is_empty() {
                // apply associated data to history
                apply_padded(&mut self.d, ad, e);
            }

            let mut d_copy = self.d.clone();

            // apply plaintext to history
            let tag = apply_padded(&mut self.d, buffer.get_in(), e | 0x40).read_tag();

            // apply tag to history for a SIV keystream and apply keystream to buffer
            apply_padded(&mut d_copy, &tag, e | 0xc0).xor_in2out(buffer);

            tag
        }
    }

    fn decrypt_inout_detached(
        &mut self,
        ad: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Array<u8, Self::Tag>,
    ) -> Result<(), Error> {
        let e = self.e;
        self.e ^= 0x20;

        if buffer.is_empty() {
            // apply associated data to history
            let actual_tag = apply_padded(&mut self.d, ad, e).read_tag();
            if ct_ne(tag, &actual_tag).into() {
                return Err(Error);
            }
        } else {
            if !ad.is_empty() {
                // apply associated data to history
                apply_padded(&mut self.d, ad, e);
            }

            let mut d_copy = self.d.clone();

            // apply tag to history for a SIV keystream and apply keystream to buffer
            let k = apply_padded(&mut d_copy, &tag, e | 0xc0);
            let pt = k.clone().xor_in2out(buffer);

            // apply plaintext to history
            let actual_tag = apply_padded(&mut self.d, &pt, e | 0x40).read_tag();

            if ct_ne(tag, &actual_tag).into() {
                // reapply keystream.
                let _ct = k.xor_in2out(InOutBuf::from(pt));
                return Err(Error);
            }
        }

        Ok(())
    }
}

fn ct_ne<T: ArraySize>(a: &Array<u8, T>, b: &Array<u8, T>) -> Choice {
    a.ct_ne(b)
}

pub(crate) fn apply_padded<D: DeckCore>(d: &mut D, m: &[u8], sep: u8) -> KeyStream<D::ReaderCore> {
    let mut buffer = Buffer::<D>::new(&[]);
    buffer.digest_blocks(m, |b| d.update_blocks(b));
    buffer.digest_blocks(&[sep], |b| d.update_blocks(b));
    KeyStream(d.finalize_xof_core(&mut buffer))
}

#[derive(Clone, Default)]
pub(crate) struct KeyStream<T: XofReaderCore>(T);

impl<X: XofReaderCore> KeyStream<X> {
    pub(crate) fn read_tag<T: ArraySize>(self) -> Array<u8, T> {
        let mut buf = Array::<u8, T>::default();
        self.read(&mut buf);
        buf
    }

    fn read(mut self, buf: &mut [u8]) {
        let (blocks, last) = Block::<X>::slice_as_chunks_mut(buf);
        for block in blocks {
            *block = self.0.read_block();
        }
        let n = last.len();
        if n > 0 {
            last.copy_from_slice(&self.0.read_block()[..n]);
        }
    }

    pub(crate) fn xor_in2out<'out>(mut self, mut buf: InOutBuf<'_, 'out, u8>) -> &'out mut [u8] {
        let (blocks, mut last) = buf.reborrow().into_chunks();
        for mut block in blocks {
            block.xor_in2out(&self.0.read_block());
        }
        let n = last.len();
        if n > 0 {
            last.xor_in2out(&self.0.read_block()[..n]);
        }
        buf.into_out()
    }
}
