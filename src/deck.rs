use aead::consts::B1;
use cipher::{
    Array,
    typenum::{Bit, UTerm},
};
use crypto_common::BlockSizes;
use digest::{
    block_buffer::{BlockBuffer, BufferKind, Eager}, core_api::{Buffer, ExtendableOutputCore, UpdateCore}, Update, XofReader
};

pub trait Padding {
    type BufferKind: BufferKind;
    fn apply<B: BlockSizes>(self, buffer: &mut BlockBuffer<B, Self::BufferKind>) -> Array<u8, B>;
}

pub trait Delim {
    const N: u8;
}

impl Delim for UTerm {
    const N: u8 = 0;
}

#[derive(Default)]
pub struct D<B, U>(B, U);

impl<B: Bit, U: Delim> Delim for D<B, U> {
    const N: u8 = B::U8 << 7 | U::N >> 1;
}

#[derive(Default)]
pub struct WithTrailingZeros<N: Delim>(N);

impl<N: Delim> Padding for WithTrailingZeros<N> {
    type BufferKind = Eager;
    fn apply<B: BlockSizes>(self, buffer: &mut BlockBuffer<B, Self::BufferKind>) -> Array<u8, B> {
        let mut out = Array::default();
        buffer.digest_pad(N::N, &[], |b| out = b.clone());
        buffer.reset();
        out
    }
}

impl<N: Delim> WithTrailingZeros<N> {
    pub fn prefix<B: Bit>(self) -> WithTrailingZeros<D<B, N>> {
        WithTrailingZeros(D(B::default(), self.0))
    }
}

pub type OnlyZeros = WithTrailingZeros<UTerm>;

/// pad10* as defined by the farfalle paper
pub type Pad1X = WithTrailingZeros<D<B1, UTerm>>;

/// Block-based core impl for Doubly-Extendable Cryptographic Keyed ([`Deck`]) functions.
pub trait DeckCore: ExtendableOutputCore + UpdateCore {
    /// Retrieve XOF reader using remaining data stored in the block buffer and the lower `B` bits in delim
    fn finalize_deck_prepadded<const B: u8>(&mut self, buffer: &mut Buffer<Self>, delim: u8) -> Self::ReaderCore;

    fn init(key: &[u8]) -> Self;
}

/// Trait for Doubly-Extendable Cryptographic Keyed (deck) functions.
///
/// These are a keyed extendable output ([`XOF`](digest::ExtendableOutput)) function,
/// except they are explicitly designed to support further updates of the state after finalization.
pub trait Deck: Update {
    /// Reader
    type Reader: XofReader;

    /// Finalize the updates, retrieve XOF reader, and update the deck state.
    fn finalize_deck(&mut self) -> Self::Reader;

    /// Initialise the deck function
    fn init(key: &[u8]) -> Self;
}
