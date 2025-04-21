use aead::consts::B1;
use cipher::{
    Array,
    typenum::{Bit, UTerm},
};
use crypto_common::BlockSizes;
use digest::{
    Update, XofReader,
    block_buffer::{BlockBuffer, BufferKind, Eager},
    core_api::{ExtendableOutputCore, UpdateCore},
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
pub struct D<U, B>(U, B);

impl<U: Delim, B: Bit> Delim for D<U, B> {
    const N: u8 = B::U8 << 7 | U::N >> 1;
}

#[derive(Default)]
pub struct WithTrailingZeros<N: Delim>(N);

impl<N: Delim> Padding for WithTrailingZeros<N> {
    type BufferKind = Eager;
    fn apply<B: BlockSizes>(self, buffer: &mut BlockBuffer<B, Self::BufferKind>) -> Array<u8, B> {
        let mut out = Array::default();
        buffer.digest_pad(N::N, &[], |b| out = b.clone());
        out
    }
}

impl<N: Delim> WithTrailingZeros<N> {
    pub fn push<B: Bit>(self) -> WithTrailingZeros<D<N, B>> {
        WithTrailingZeros(D(self.0, B::default()))
    }
}

pub type OnlyZeros = WithTrailingZeros<UTerm>;

/// pad10* as defined by the farfalle paper
pub type Pad1X = WithTrailingZeros<D<UTerm, B1>>;

/// Block-based core impl for Doubly-Extendable Cryptographic Keyed ([`Deck`]) functions.
pub trait DeckCore: ExtendableOutputCore + UpdateCore {
    type Padding: Padding<BufferKind = Self::BufferKind> + Default;

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
