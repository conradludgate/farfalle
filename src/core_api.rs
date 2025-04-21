use core::fmt;

use cipher::{AlgorithmName, Array, consts::U64};
use digest::{
    Update, XofReader,
    block_buffer::{BlockBuffer, ReadBuffer},
    core_api::{BufferKindUser, UpdateCore, XofReaderCore},
};
use inout::InOutBuf;

use crate::{
    dec::{Dec, DecCore},
    deck::{Deck, DeckCore},
};

#[inline]
pub(crate) fn xor<'out, R: XofReader>(reader: &mut R, mut buffer: InOutBuf<'_, 'out, u8>) -> &'out mut [u8] {
    let mut block = Array::<u8, U64>::default();
    let (chunks, mut last) = buffer.reborrow().into_chunks::<U64>();
    for mut chunk in chunks {
        reader.read(&mut block);
        chunk.xor_in2out(&block);
    }
    let n = last.len();
    if n > 0 {
        reader.read(&mut block[..n]);
        last.xor_in2out(&block[..n]);
    }
    buffer.into_out()
}

/// Wrapper around [`XofReaderCore`] implementations.
///
/// It handles data buffering and implements the mid-level traits.
///
/// This is a direct copy of [`digest::core_api::XofReaderCoreWrapper`] due to the constructor being private.
#[derive(Clone, Default)]
pub struct XofReaderCoreWrapper<T>
where
    T: XofReaderCore,
{
    pub(super) core: T,
    pub(super) buffer: ReadBuffer<T::BlockSize>,
}

impl<T: XofReaderCore> XofReaderCoreWrapper<T> {
    pub(crate) fn from_core(core: T) -> Self {
        Self {
            core,
            buffer: ReadBuffer::default(),
        }
    }
}

impl<T> fmt::Debug for XofReaderCoreWrapper<T>
where
    T: XofReaderCore + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        T::write_alg_name(f)?;
        f.write_str(" { .. }")
    }
}

impl<T> XofReader for XofReaderCoreWrapper<T>
where
    T: XofReaderCore,
{
    #[inline]
    fn read(&mut self, buffer: &mut [u8]) {
        let Self { core, buffer: buf } = self;
        buf.read(buffer, |block| *block = core.read_block());
    }
}

/// Wrapper around [`BufferKindUser`].
///
/// It handles data buffering and implements the slice-based traits.
///
/// This is a direct copy of [`digest::core_api::CoreWrapper`] due to the core being private.
#[derive(Clone, Default)]
pub struct CoreWrapper<T: BufferKindUser> {
    core: T,
    buffer: BlockBuffer<T::BlockSize, T::BufferKind>,
}

impl<D: UpdateCore + BufferKindUser> Update for CoreWrapper<D> {
    fn update(&mut self, input: &[u8]) {
        let Self { core, buffer } = self;
        buffer.digest_blocks(input, |blocks| core.update_blocks(blocks));
    }
}

impl<D: DeckCore + BufferKindUser> Deck for CoreWrapper<D> {
    type Reader = XofReaderCoreWrapper<D::ReaderCore>;

    fn finalize_deck(&mut self) -> Self::Reader {
        let Self { core, buffer } = self;
        XofReaderCoreWrapper::from_core(core.finalize_xof_core(buffer))
    }

    fn init(key: &[u8]) -> Self {
        Self {
            core: D::init(key),
            buffer: BlockBuffer::new(&[]),
        }
    }
}

impl<D: DecCore + BufferKindUser> Dec for CoreWrapper<D> {
    type Reader = XofReaderCoreWrapper<D::ReaderCore>;

    fn finalize_dec(&mut self) -> Self::Reader {
        let Self { core, buffer } = self;
        XofReaderCoreWrapper::from_core(core.finalize_xof_core(buffer))
    }
}
