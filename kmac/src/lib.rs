use core::{fmt, slice};
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore, ExtendableOutputCore,
        OutputSizeUser, UpdateCore,
    },
    crypto_common::{Key, KeySizeUser},
    HashMarker, InvalidLength, KeyInit, MacMarker, Output,
    consts::{U136, U168, U32, U64},
};

use sha3::{CShake128, CShake128Core, CShake256Core};

#[macro_use]
mod macros;

const FUNCTION_NAME: &[u8] = b"KMAC";

impl_kmac!(Kmac128Core, Kmac128, CShake128Core, "KMAC128", 32);
impl_kmac!(Kmac256Core, Kmac256, CShake256Core, "KMAC256", 64);


#[inline(always)]
pub(crate) fn right_encode(val: u64, buf: &mut [u8; 9]) -> &[u8] {
    buf[..8].copy_from_slice(&val.to_be_bytes());
    let off = buf[..7].iter().take_while(|&&a| a == 0).count();
    buf[8] = (8 - off) as u8;
    &buf[off..]
}

#[inline(always)]
pub(crate) fn left_encode(val: u64, buf: &mut [u8; 9]) -> &[u8] {
    buf[1..].copy_from_slice(&val.to_be_bytes());
    let off = buf[1..8].iter().take_while(|&&a| a == 0).count();
    buf[off] = (8 - off) as u8;
    &buf[off..]
}

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
