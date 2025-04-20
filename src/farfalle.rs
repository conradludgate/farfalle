use std::marker::PhantomData;

use digest::block_buffer::Eager;
use digest::core_api::{BufferKindUser, ExtendableOutputCore, UpdateCore, XofReaderCore};
use digest::crypto_common::{BlockSizeUser, BlockSizes, KeyInit, KeySizeUser};
use hybrid_array::{Array, ArraySize};
use inout::InOut;

use crate::Permutation;

pub struct Farfalle<Pb, Pc, Pd, Pe, Rc, Re, B, K>
where
    Pb: Permutation<Size = B>,
    Pc: Permutation<Size = B>,
    Pd: Permutation<Size = B>,
    Pe: Permutation<Size = B>,
    Rc: Permutation<Size = B>,
    Re: Permutation<Size = B>,
    B: ArraySize,
    K: ArraySize,
{
    /// permutation for deriving the initial mask from the key K.
    _pb: PhantomData<(Pb, K)>,
    /// permutation for the compression layer
    pc: Pc,
    /// permutation between the compression layer and the expansion layer
    pd: Pd,
    /// permutation for the expansion layer
    pe: Pe,

    /// rolling function for generating masks for the compression layer
    rollc: Rc,
    /// rolling function to update state for the expansion layer
    rolle: Re,

    /// keymask
    k: Array<u8, B>,
    // k_: Array<u8, B>,
    /// input state
    x: Array<u8, B>,
    // /// output state
    // y: Array<u8, B>,
}

impl<Pb, Pc, Pd, Pe, Rc, Re, B, K> KeySizeUser for Farfalle<Pb, Pc, Pd, Pe, Rc, Re, B, K>
where
    Pb: Permutation<Size = B> + Default,
    Pc: Permutation<Size = B> + Default,
    Pd: Permutation<Size = B> + Default,
    Pe: Permutation<Size = B> + Default + Clone,
    Rc: Permutation<Size = B> + Default,
    Re: Permutation<Size = B> + Default + Clone,
    B: BlockSizes,
    K: ArraySize,
{
    type KeySize = K;
}

impl<Pb, Pc, Pd, Pe, Rc, Re, B, K> KeyInit for Farfalle<Pb, Pc, Pd, Pe, Rc, Re, B, K>
where
    Pb: Permutation<Size = B> + Default,
    Pc: Permutation<Size = B> + Default,
    Pd: Permutation<Size = B> + Default,
    Pe: Permutation<Size = B> + Default + Clone,
    Rc: Permutation<Size = B> + Default,
    Re: Permutation<Size = B> + Default + Clone,
    B: BlockSizes,
    K: ArraySize,
{
    fn new(key: &digest::Key<Self>) -> Self {
        assert!(K::USIZE < B::USIZE);

        let pb = Pb::default();
        let mut k = Array::<u8, B>::default();
        k[..key.len()].copy_from_slice(key);
        k[key.len()] = 0x80;
        pb.permute(&mut k);

        let x = Array::default();

        let pd = Pd::default();
        let mut y = x.clone();
        pd.permute(&mut y);

        Self {
            _pb: PhantomData,
            pc: Default::default(),
            pd,
            pe: Default::default(),
            rollc: Default::default(),
            rolle: Default::default(),
            k,
            x,
        }
    }
}

impl<Pb, Pc, Pd, Pe, Rc, Re, B, K> BlockSizeUser for Farfalle<Pb, Pc, Pd, Pe, Rc, Re, B, K>
where
    Pb: Permutation<Size = B> + Default,
    Pc: Permutation<Size = B> + Default,
    Pd: Permutation<Size = B> + Default,
    Pe: Permutation<Size = B> + Default + Clone,
    Rc: Permutation<Size = B> + Default,
    Re: Permutation<Size = B> + Default + Clone,
    B: BlockSizes,
    K: ArraySize,
{
    type BlockSize = B;
}

impl<Pb, Pc, Pd, Pe, Rc, Re, B, K> BufferKindUser for Farfalle<Pb, Pc, Pd, Pe, Rc, Re, B, K>
where
    Pb: Permutation<Size = B> + Default,
    Pc: Permutation<Size = B> + Default,
    Pd: Permutation<Size = B> + Default,
    Pe: Permutation<Size = B> + Default + Clone,
    Rc: Permutation<Size = B> + Default,
    Re: Permutation<Size = B> + Default + Clone,
    B: BlockSizes,
    K: ArraySize,
{
    type BufferKind = Eager;
}

impl<Pb, Pc, Pd, Pe, Rc, Re, B, K> Farfalle<Pb, Pc, Pd, Pe, Rc, Re, B, K>
where
    Pb: Permutation<Size = B> + Default,
    Pc: Permutation<Size = B> + Default,
    Pd: Permutation<Size = B> + Default,
    Pe: Permutation<Size = B> + Default + Clone,
    Rc: Permutation<Size = B> + Default,
    Re: Permutation<Size = B> + Default + Clone,
    B: BlockSizes,
    K: ArraySize,
{
    fn update_block(&mut self, mut m: crypto_common::Block<Self>) {
        InOut::from(&mut m).xor_in2out(&self.k);
        self.rollc.permute(&mut self.k);

        self.pc.permute(&mut m);
        InOut::from(&mut self.x).xor_in2out(&m);
    }
}

impl<Pb, Pc, Pd, Pe, Rc, Re, B, K> UpdateCore for Farfalle<Pb, Pc, Pd, Pe, Rc, Re, B, K>
where
    Pb: Permutation<Size = B> + Default,
    Pc: Permutation<Size = B> + Default,
    Pd: Permutation<Size = B> + Default,
    Pe: Permutation<Size = B> + Default + Clone,
    Rc: Permutation<Size = B> + Default,
    Re: Permutation<Size = B> + Default + Clone,
    B: BlockSizes,
    K: ArraySize,
{
    fn update_blocks(&mut self, blocks: &[crypto_common::Block<Self>]) {
        for m in blocks {
            self.update_block(m.clone());
        }
    }
}

impl<Pb, Pc, Pd, Pe, Rc, Re, B, K> ExtendableOutputCore for Farfalle<Pb, Pc, Pd, Pe, Rc, Re, B, K>
where
    Pb: Permutation<Size = B> + Default,
    Pc: Permutation<Size = B> + Default,
    Pd: Permutation<Size = B> + Default,
    Pe: Permutation<Size = B> + Default + Clone,
    Rc: Permutation<Size = B> + Default,
    Re: Permutation<Size = B> + Default + Clone,
    B: BlockSizes,
    K: ArraySize,
{
    type ReaderCore = FarfalleXofCore<Pe, Re, B>;

    fn finalize_xof_core(
        &mut self,
        buffer: &mut digest::core_api::Buffer<Self>,
    ) -> Self::ReaderCore {
        let n = buffer.get_data().len();
        if n > 0 {
            let mut m = Array::<u8, B>::default();
            m[..n].copy_from_slice(buffer.get_data());
            buffer.reset();
            m[n] = 0x80;
            self.update_block(m);
        }

        self.rollc.permute(&mut self.k);

        let k = self.k.clone();
        let mut y = self.x.clone();
        self.pd.permute(&mut y);

        FarfalleXofCore {
            pe: self.pe.clone(),
            rolle: self.rolle.clone(),
            k,
            y,
        }
    }
}

pub struct FarfalleXofCore<Pe, Re, B>
where
    Pe: Permutation<Size = B>,
    Re: Permutation<Size = B>,
    B: ArraySize,
{
    pe: Pe,
    rolle: Re,
    k: Array<u8, B>,
    y: Array<u8, B>,
}

impl<Pe, Re, B> BlockSizeUser for FarfalleXofCore<Pe, Re, B>
where
    Pe: Permutation<Size = B>,
    Re: Permutation<Size = B>,
    B: BlockSizes,
{
    type BlockSize = B;
}

impl<Pe, Re, B> XofReaderCore for FarfalleXofCore<Pe, Re, B>
where
    Pe: Permutation<Size = B>,
    Re: Permutation<Size = B>,
    B: BlockSizes,
{
    fn read_block(&mut self) -> crypto_common::Block<Self> {
        let mut b = self.y.clone();
        self.pe.permute(&mut b);
        InOut::from(&mut b).xor_in2out(&self.k);
        self.rolle.permute(&mut self.y);
        b
    }
}
