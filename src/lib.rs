use hybrid_array::{Array, ArraySize};
use inout::InOutBuf;

pub mod core_api;
pub mod dec;
pub mod deck;
pub mod farfalle;
pub mod sane;
pub mod sanse;
pub mod wbc;

pub trait Permutation {
    type Size: ArraySize;
    fn permute(block: &mut Array<u8, Self::Size>);
}

/// Session-supporting authenticated encryption scheme
pub trait SessionAead {
    type Tag: ArraySize;

    /// Encrypt the data in the provided [`InOutBuf`], returning the authentication tag.
    /// This also moves the session state forward.
    fn encrypt_inout_detached(
        &mut self,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Array<u8, Self::Tag>;

    /// Decrypt the data in the provided [`InOutBuf`], returning an error in the event the
    /// provided authentication tag is invalid for the given ciphertext (i.e. ciphertext
    /// is modified/unauthentic)
    ///
    /// This also moves the session state forward, but must be discarded if there is a tag error.
    fn decrypt_inout_detached(
        &mut self,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Array<u8, Self::Tag>,
    ) -> aead::Result<()>;
}

#[cfg(test)]
mod tests {
    use digest::consts::{U16, U32, U48};
    use inout::InOutBuf;

    use crate::{
        Permutation, SessionAead,
        farfalle::{Farfalle, FarfalleCore},
        sane::{DeckSane, DeckSaneCore},
    };

    struct XoofffCore;
    impl FarfalleCore for XoofffCore {
        type StateSize = U48;
        type Pb = Xoodoo<6>;
        type Pc = Xoodoo<6>;
        type Pd = Xoodoo<6>;
        type Pe = Xoodoo<6>;
        type Rc = RollXC;
        type Re = RollXE;
    }
    type XoofffDeckCore = Farfalle<XoofffCore>;
    // type XoofffDeck = crate::deck::CoreWrapper<XoofffDeckCore>;

    struct XoofffSaneCore;
    impl DeckSaneCore for XoofffSaneCore {
        type Core = XoofffDeckCore;
        type TagSize = U16;
        type Alignnemt = U32;
    }

    type XoofffSane = DeckSane<XoofffSaneCore>;

    #[test]
    fn check() {
        let key = [0; 32];
        let iv = [0; 16];
        let mut enc = XoofffSane::init(&key, &iv);
        let mut dec = XoofffSane::init(&key, &iv);

        let ad1 = *b"foo";
        let mut msg1 = *b"abcd";
        let tag = enc.encrypt_inout_detached(&ad1, InOutBuf::from(&mut msg1[..]));
        dec.decrypt_inout_detached(&ad1, InOutBuf::from(&mut msg1[..]), &tag)
            .unwrap();
        assert_eq!(msg1, *b"abcd");

        let ad2 = *b"bar";
        let mut msg2 = *b"xyzw";
        let tag = enc.encrypt_inout_detached(&ad2, InOutBuf::from(&mut msg2[..]));
        dec.decrypt_inout_detached(&ad2, InOutBuf::from(&mut msg2[..]), &tag)
            .unwrap();
        assert_eq!(msg2, *b"xyzw");
    }

    #[derive(Default, Clone, Copy)]
    struct Xoodoo<const R: usize> {}

    impl<const R: usize> Permutation for Xoodoo<R> {
        type Size = U48;

        fn permute(block: &mut hybrid_array::Array<u8, Self::Size>) {
            let mut b: [u32; 12] = unsafe { core::mem::transmute(block.clone()) };
            xoodoo::<R>(&mut b);
            *block = unsafe { core::mem::transmute(b) };
        }
    }

    #[derive(Default, Clone, Copy)]
    struct RollXC {}
    impl Permutation for RollXC {
        type Size = U48;

        fn permute(block: &mut hybrid_array::Array<u8, Self::Size>) {
            let mut b: [u32; 12] = unsafe { core::mem::transmute(block.clone()) };
            rollxc(&mut b);
            *block = unsafe { core::mem::transmute(b) };
        }
    }

    #[derive(Default, Clone, Copy)]
    struct RollXE {}
    impl Permutation for RollXE {
        type Size = U48;

        fn permute(block: &mut hybrid_array::Array<u8, Self::Size>) {
            let mut b: [u32; 12] = unsafe { core::mem::transmute(block.clone()) };
            rollxe(&mut b);
            *block = unsafe { core::mem::transmute(b) };
        }
    }

    /// <https://docs.rs/xoodoo-p/0.1.0/src/xoodoo_p/lib.rs.html>
    const MAX_ROUNDS: usize = 12;
    fn xoodoo<const R: usize>(st: &mut [u32; 12]) {
        debug_assert!(R <= MAX_ROUNDS, "R must be <= {} (was {}", R, MAX_ROUNDS);

        // Load lanes into registers.
        let mut a00 = st[0];
        let mut a01 = st[1];
        let mut a02 = st[2];
        let mut a03 = st[3];
        let mut a10 = st[4];
        let mut a11 = st[5];
        let mut a12 = st[6];
        let mut a13 = st[7];
        let mut a20 = st[8];
        let mut a21 = st[9];
        let mut a22 = st[10];
        let mut a23 = st[11];

        // Perform last R rounds.
        for &round_key in &ROUND_KEYS[MAX_ROUNDS - R..MAX_ROUNDS] {
            let p0 = a00 ^ a10 ^ a20;
            let p1 = a01 ^ a11 ^ a21;
            let p2 = a02 ^ a12 ^ a22;
            let p3 = a03 ^ a13 ^ a23;

            let e0 = p3.rotate_left(5) ^ p3.rotate_left(14);
            let e1 = p0.rotate_left(5) ^ p0.rotate_left(14);
            let e2 = p1.rotate_left(5) ^ p1.rotate_left(14);
            let e3 = p2.rotate_left(5) ^ p2.rotate_left(14);

            let tmp0 = e0 ^ a00 ^ round_key;
            let tmp1 = e1 ^ a01;
            let tmp2 = e2 ^ a02;
            let tmp3 = e3 ^ a03;
            let tmp4 = e3 ^ a13;
            let tmp5 = e0 ^ a10;
            let tmp6 = e1 ^ a11;
            let tmp7 = e2 ^ a12;
            let tmp8 = (e0 ^ a20).rotate_left(11);
            let tmp9 = (e1 ^ a21).rotate_left(11);
            let tmp10 = (e2 ^ a22).rotate_left(11);
            let tmp11 = (e3 ^ a23).rotate_left(11);

            a00 = (!tmp4 & tmp8) ^ tmp0;
            a01 = (!tmp5 & tmp9) ^ tmp1;
            a02 = (!tmp6 & tmp10) ^ tmp2;
            a03 = (!tmp7 & tmp11) ^ tmp3;

            a10 = ((!tmp8 & tmp0) ^ tmp4).rotate_left(1);
            a11 = ((!tmp9 & tmp1) ^ tmp5).rotate_left(1);
            a12 = ((!tmp10 & tmp2) ^ tmp6).rotate_left(1);
            a13 = ((!tmp11 & tmp3) ^ tmp7).rotate_left(1);

            a20 = ((!tmp2 & tmp6) ^ tmp10).rotate_left(8);
            a21 = ((!tmp3 & tmp7) ^ tmp11).rotate_left(8);
            a22 = ((!tmp0 & tmp4) ^ tmp8).rotate_left(8);
            a23 = ((!tmp1 & tmp5) ^ tmp9).rotate_left(8);
        }

        // Load registers into lanes.
        st[0] = a00;
        st[1] = a01;
        st[2] = a02;
        st[3] = a03;
        st[4] = a10;
        st[5] = a11;
        st[6] = a12;
        st[7] = a13;
        st[8] = a20;
        st[9] = a21;
        st[10] = a22;
        st[11] = a23;
    }

    const ROUND_KEYS: [u32; MAX_ROUNDS] = [
        0x00000058, 0x00000038, 0x000003C0, 0x000000D0, 0x00000120, 0x00000014, 0x00000060,
        0x0000002C, 0x00000380, 0x000000F0, 0x000001A0, 0x00000012,
    ];

    fn rollxc(st: &mut [u32; 12]) {
        // Load lanes into registers.
        let mut a00 = st[0];
        let mut a01 = st[1];
        let mut a02 = st[2];
        let mut a03 = st[3];
        let mut a10 = st[4];
        let mut a11 = st[5];
        let mut a12 = st[6];
        let mut a13 = st[7];
        let mut a20 = st[8];
        let mut a21 = st[9];
        let mut a22 = st[10];
        let mut a23 = st[11];

        // A00 <- A00 + (A00 << 13) + (A10 <<< 3)
        a00 = a00 ^ (a00 << 13) ^ a10.rotate_left(3);

        // B <- A0 <<< (3, 0)
        let b0 = a03;
        let b1 = a00;
        let b2 = a01;
        let b3 = a02;

        // A0 <- A1
        a00 = a10;
        a01 = a11;
        a02 = a12;
        a03 = a13;

        // A1 <- A2
        a10 = a20;
        a11 = a21;
        a12 = a22;
        a13 = a23;

        // A2 <- B
        a20 = b0;
        a21 = b1;
        a22 = b2;
        a23 = b3;

        // Load registers into lanes.
        st[0] = a00;
        st[1] = a01;
        st[2] = a02;
        st[3] = a03;
        st[4] = a10;
        st[5] = a11;
        st[6] = a12;
        st[7] = a13;
        st[8] = a20;
        st[9] = a21;
        st[10] = a22;
        st[11] = a23;
    }

    fn rollxe(st: &mut [u32; 12]) {
        // Load lanes into registers.
        let mut a00 = st[0];
        let mut a01 = st[1];
        let mut a02 = st[2];
        let mut a03 = st[3];
        let mut a10 = st[4];
        let mut a11 = st[5];
        let mut a12 = st[6];
        let mut a13 = st[7];
        let mut a20 = st[8];
        let mut a21 = st[9];
        let mut a22 = st[10];
        let mut a23 = st[11];

        // A00 <- A10 . A20 + (A00 <<< 5) + (A10 <<< 13) + 0x00000007
        a00 = a10 & a20 ^ (a00.rotate_left(5)) ^ a10.rotate_left(13) ^ 0x00000007;

        // B <- A0 <<< (3, 0)
        let b0 = a03;
        let b1 = a00;
        let b2 = a01;
        let b3 = a02;

        // A0 <- A1
        a00 = a10;
        a01 = a11;
        a02 = a12;
        a03 = a13;

        // A1 <- A2
        a10 = a20;
        a11 = a21;
        a12 = a22;
        a13 = a23;

        // A2 <- B
        a20 = b0;
        a21 = b1;
        a22 = b2;
        a23 = b3;

        // Load registers into lanes.
        st[0] = a00;
        st[1] = a01;
        st[2] = a02;
        st[3] = a03;
        st[4] = a10;
        st[5] = a11;
        st[6] = a12;
        st[7] = a13;
        st[8] = a20;
        st[9] = a21;
        st[10] = a22;
        st[11] = a23;
    }
}
