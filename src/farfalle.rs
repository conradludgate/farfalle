use digest::block_buffer::Eager;
use digest::core_api::{BufferKindUser, ExtendableOutputCore, UpdateCore, XofReaderCore};
use digest::crypto_common::{BlockSizeUser, BlockSizes};
use digest::typenum::Unsigned;
use hybrid_array::Array;
use inout::InOut;

use crate::Permutation;
use crate::deck::{DeckCore, Pad1X};

/// Definition of a farfalle construction.
///
/// It consists of 4 cryptographic permutations, and 2 rolling functions,
/// both with the same block size state.
///
/// The 4 permutation functions are security sensitive, although they can all be
/// identical.
///
/// The roll functions are also permutations, but are generally a lot
/// more lightweight than the other 4 cryptographic permutations.
///
/// See the paper on Farfalle for security details, specifically section 5.
/// <https://tosc.iacr.org/index.php/ToSC/article/view/855>
pub trait FarfalleCore {
    type StateSize: BlockSizes;

    /// Permutation function used for deriving the initial mask from the key
    type Pb: Permutation<Size = Self::StateSize>;
    /// Permutation function used in the compression layer
    type Pc: Permutation<Size = Self::StateSize>;
    /// Permutation function used between compression and expansion
    type Pd: Permutation<Size = Self::StateSize>;
    /// Permutation function used in the expansion layer
    type Pe: Permutation<Size = Self::StateSize>;

    /// Rolling function used for generating masks that are added to the input blocks in the compression layer
    type Rc: Permutation<Size = Self::StateSize>;
    /// Rolling function used to update the internal state during expansion
    type Re: Permutation<Size = Self::StateSize>;
}

pub struct Farfalle<Core: FarfalleCore> {
    /// input keymask
    k: Array<u8, Core::StateSize>,
    /// input state
    x: Array<u8, Core::StateSize>,
}

impl<Core: FarfalleCore> Clone for Farfalle<Core> {
    fn clone(&self) -> Self {
        Self {
            k: self.k.clone(),
            x: self.x.clone(),
        }
    }
}

impl<Core: FarfalleCore> BlockSizeUser for Farfalle<Core> {
    type BlockSize = Core::StateSize;
}

impl<Core: FarfalleCore> BufferKindUser for Farfalle<Core> {
    type BufferKind = Eager;
}

impl<Core: FarfalleCore> Farfalle<Core> {
    fn update_block(&mut self, mut m: crypto_common::Block<Self>) {
        InOut::from(&mut m).xor_in2out(&self.k);
        Core::Rc::permute(&mut self.k);

        Core::Pc::permute(&mut m);
        InOut::from(&mut self.x).xor_in2out(&m);
    }
}

impl<Core: FarfalleCore> UpdateCore for Farfalle<Core> {
    fn update_blocks(&mut self, blocks: &[crypto_common::Block<Self>]) {
        for m in blocks {
            self.update_block(m.clone());
        }
    }
}

impl<Core: FarfalleCore> ExtendableOutputCore for Farfalle<Core> {
    type ReaderCore = FarfalleXofCore<Core>;

    fn finalize_xof_core(
        &mut self,
        buffer: &mut digest::core_api::Buffer<Self>,
    ) -> Self::ReaderCore {
        let n = buffer.get_data().len();
        if n > 0 {
            let mut m = Array::<u8, Core::StateSize>::default();
            m[..n].copy_from_slice(buffer.get_data());
            buffer.reset();
            m[n] = 0x80;
            self.update_block(m);
        }

        Core::Rc::permute(&mut self.k);

        let k = self.k.clone();
        let mut y = self.x.clone();
        Core::Pd::permute(&mut y);

        FarfalleXofCore {
            k,
            y,
        }
    }
}

pub struct FarfalleXofCore<Core: FarfalleCore> {
    k: Array<u8, Core::StateSize>,
    y: Array<u8, Core::StateSize>,
}

impl<Core: FarfalleCore> Clone for FarfalleXofCore<Core> {
    fn clone(&self) -> Self {
        Self {
            k: self.k.clone(),
            y: self.y.clone(),
        }
    }
}

impl<Core: FarfalleCore> BlockSizeUser for FarfalleXofCore<Core> {
    type BlockSize = Core::StateSize;
}

impl<Core: FarfalleCore> XofReaderCore for FarfalleXofCore<Core> {
    fn read_block(&mut self) -> crypto_common::Block<Self> {
        let mut b = self.y.clone();
        Core::Pe::permute(&mut b);
        InOut::from(&mut b).xor_in2out(&self.k);
        Core::Re::permute(&mut self.y);
        b
    }
}

impl<Core: FarfalleCore> DeckCore for Farfalle<Core> {
    type Padding = Pad1X;

    fn init(key: &[u8]) -> Self {
        assert!(key.len() < <Core::StateSize as Unsigned>::USIZE);

        let mut k = Array::<u8, Core::StateSize>::default();
        k[..key.len()].copy_from_slice(key);
        k[key.len()] = 0x80;
        Core::Pb::permute(&mut k);

        let x = Array::default();

        Self {
            k,
            x,
        }
    }
}
