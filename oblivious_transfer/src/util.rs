use ark_ec::Group;
use ark_std::{cfg_into_iter, vec, vec::Vec};
use core::ops::{BitAnd, Shl, Shr};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[inline]
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    cfg_into_iter!(a)
        .zip(cfg_into_iter!(b))
        .map(|(a, b)| a ^ b)
        .collect()
}

#[inline]
pub fn and(a: &[u8], b: &[u8]) -> Vec<u8> {
    cfg_into_iter!(a)
        .zip(cfg_into_iter!(b))
        .map(|(a, b)| a & b)
        .collect()
}

#[inline]
pub fn xor_in_place(a: &mut [u8], b: &[u8]) {
    cfg_into_iter!(a)
        .zip(cfg_into_iter!(b))
        .for_each(|(a, b)| *a = *a ^ *b)
}

/// Returns `[g, 2*g, 3*g, ..., n*g]`
pub fn multiples_of_g<G: Group>(g: G, n: usize) -> Vec<G> {
    assert!(n > 0);
    let mut v = Vec::with_capacity(n);
    v.push(g);
    for i in 1..n {
        v.push(v[i - 1] + v[0]);
    }
    v
}

#[inline]
pub fn divide_by_8<T: Shr<Output = T> + From<u8>>(n: T) -> T {
    n >> 3.into()
}

#[inline]
pub fn multiply_by_8<T: Shl<Output = T> + From<u8>>(n: T) -> T {
    n << 3.into()
}

#[inline]
pub fn modulo_8<T: BitAnd<Output = T> + From<u8>>(n: T) -> T {
    n & 7u8.into()
}

#[inline]
pub fn is_multiple_of_8<T: BitAnd<Output = T> + From<u8> + Eq>(n: T) -> bool {
    modulo_8(n) == 0u8.into()
}

/// Transpose an 8x8 bit matrix given as a u64. The code is taken from the book Hacker's Delight's figure 7.6 after
/// slight modification. In the book's code, the matrix is passed as an array of 8 bytes which converts it to a
/// 64-bit number but here that number is passed directly.
fn transpose8(w: u64) -> u64 {
    let mut x = w;
    // Swapping 2x2 bit-matrices
    // x & 0xAA55AA55AA55AA55 will select those bits that wont change during 2x2 transpose and set others to 0
    // x & 0x00AA00AA00AA00AA will select those bits of the bottom rows (odd-numbered) that are to be moved to the above row and the left shift of 7 will move them at the required position
    // x >> 7 will move those bits of the top row that are to moved to the required position in the bottom row and the & 0x00AA00AA00AA00AA will select those bits of the top rows that are moved at their required position
    x = (x & 0xAA55AA55AA55AA55)
        | ((x & 0x00AA00AA00AA00AA) << 7)
        | ((x >> 7) & 0x00AA00AA00AA00AA);

    // Swapping 2x2 matrices where each element is a 2×2-bit matrix
    // x & 0xCCCC3333CCCC3333 will select those bits that wont change during the transpose and set others to 0
    // x & 0x0000CCCC0000CCCC will select those bits of the bottom rows (odd-numbered) that are to be moved to the above row and the left shift of 14 will move them at the required position
    x = (x & 0xCCCC3333CCCC3333)
        | ((x & 0x0000CCCC0000CCCC) << 14)
        | ((x >> 14) & 0x0000CCCC0000CCCC);

    // Swapping 2x2 matrices where each element is a 4×4-bit matrix
    // x & 0xF0F0F0F00F0F0F0F will select those bits that wont change during the transpose and set others to 0
    // Rest is similar to above 2 transposes
    x = (x & 0xF0F0F0F00F0F0F0F)
        | ((x & 0x00000000F0F0F0F0) << 28)
        | ((x >> 28) & 0x00000000F0F0F0F0);
    x
}

/// Transpose a bit-matrix by dividing into submatrices, each of 8x8 bits, transposing the submatrix and
/// placing the submatrices into their appropriate position
fn transpose_portable(input: &[u8], nrows: usize, ncols: usize) -> Vec<u8> {
    assert_eq!(modulo_8(nrows), 0);
    let total_bits = multiply_by_8(input.len());
    assert_eq!(nrows * ncols, total_bits);
    let ncols_by_8 = ncols / 8;
    let nrows_by_8 = (input.len() / ncols_by_8) / 8;
    let mut result = vec![0u8; input.len()];

    for row in 0..nrows_by_8 {
        let row8 = row << 3;
        for col in 0..ncols_by_8 {
            let col8 = col << 3;
            // Construct an 8x8 bit matrix by reading the `col`th column upto 8 rows into a 64-bit number
            // in little-endian format (lowest index byte of `input` is the LSB of the number)
            let submatrix = (input[(row8 + 0) * ncols_by_8 + col] as u64)
                | ((input[(row8 + 1) * ncols_by_8 + col] as u64) << 8)
                | ((input[(row8 + 2) * ncols_by_8 + col] as u64) << 16)
                | ((input[(row8 + 3) * ncols_by_8 + col] as u64) << 24)
                | ((input[(row8 + 4) * ncols_by_8 + col] as u64) << 32)
                | ((input[(row8 + 5) * ncols_by_8 + col] as u64) << 40)
                | ((input[(row8 + 6) * ncols_by_8 + col] as u64) << 48)
                | ((input[(row8 + 7) * ncols_by_8 + col] as u64) << 56);

            // Transpose the 8x8 bit matrix
            let transposed = transpose8(submatrix);

            // Place the transposed 8x8 bit matrix into the appropriate position
            result[(col8 + 0) * nrows_by_8 + row] = (transposed & 0xFF) as u8;
            result[(col8 + 1) * nrows_by_8 + row] = ((transposed >> 8) & 0xFF) as u8;
            result[(col8 + 2) * nrows_by_8 + row] = ((transposed >> 16) & 0xFF) as u8;
            result[(col8 + 3) * nrows_by_8 + row] = ((transposed >> 24) & 0xFF) as u8;
            result[(col8 + 4) * nrows_by_8 + row] = ((transposed >> 32) & 0xFF) as u8;
            result[(col8 + 5) * nrows_by_8 + row] = ((transposed >> 40) & 0xFF) as u8;
            result[(col8 + 6) * nrows_by_8 + row] = ((transposed >> 48) & 0xFF) as u8;
            result[(col8 + 7) * nrows_by_8 + row] = ((transposed >> 56) & 0xFF) as u8;
        }
    }

    result
}

// Following copied from https://github.com/GaloisInc/swanky/blob/master/ocelot/src/utils.rs

/// Transpose given matrix of `nrows` rows and `ncols` columns in row-major order
#[cfg(test)]
#[inline]
pub fn transpose_naive(input: &[u8], nrows: usize, ncols: usize) -> Vec<u8> {
    assert_eq!(modulo_8(nrows), 0);
    let total_bits = multiply_by_8(input.len());
    assert_eq!(nrows * ncols, total_bits);
    let mut output = vec![0u8; input.len()];

    transpose_inplace(&mut output, input, total_bits, nrows, ncols);
    output
}

#[cfg(test)]
#[inline]
fn transpose_inplace(dst: &mut [u8], src: &[u8], total_bits: usize, nrows: usize, ncols: usize) {
    let it = cfg_into_iter!(0..total_bits)
        .map(|i| {
            let bit = get_bit(src, i);
            let (row, col) = (i / ncols, i % ncols);
            (bit, col * nrows + row)
        })
        .collect::<Vec<_>>();
    for (bit, pos) in it {
        set_bit(dst, pos, bit);
    }
}

#[cfg(test)]
// BITMASKS_i = 1 << i
const BITMASKS: [u8; 8] = [1, 2, 4, 8, 16, 32, 64, 128];
#[cfg(test)]
// BITMASKS_NOT_i = !(1 << i)
const BITMASKS_NOT: [u8; 8] = [
    !BITMASKS[0],
    !BITMASKS[1],
    !BITMASKS[2],
    !BITMASKS[3],
    !BITMASKS[4],
    !BITMASKS[5],
    !BITMASKS[6],
    !BITMASKS[7],
];

#[cfg(test)]
#[inline]
fn get_bit(src: &[u8], i: usize) -> u8 {
    let byte = src[divide_by_8(i)];
    let bit_pos = modulo_8(i);
    (byte & BITMASKS[bit_pos] != 0) as u8
}

#[cfg(test)]
#[inline]
fn set_bit(dst: &mut [u8], i: usize, b: u8) {
    let bit_pos = modulo_8(i);
    if b == 1 {
        dst[divide_by_8(i)] |= BITMASKS[bit_pos];
    } else {
        dst[divide_by_8(i)] &= BITMASKS_NOT[bit_pos];
    }
}

#[inline(always)]
#[cfg(target_arch = "x86_64")]
fn transpose_using_sse(m: &[u8], nrows: usize, ncols: usize) -> Vec<u8> {
    assert!(nrows >= 16);
    assert_eq!(nrows % 8, 0);
    assert_eq!(ncols % 8, 0);
    let mut transposed = vec![0u8; nrows * ncols / 8];
    unsafe {
        sse_trans(
            transposed.as_mut_ptr() as *mut u8,
            m.as_ptr(),
            nrows as u64,
            ncols as u64,
        )
    }
    transposed
}

#[link(name = "transpose")]
#[cfg(target_arch = "x86_64")]
extern "C" {
    fn sse_trans(out: *mut u8, inp: *const u8, nrows: u64, ncols: u64);
}

pub fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
    let offset = if is_multiple_of_8(bv.len()) { 0 } else { 1 };
    let mut v = vec![0u8; divide_by_8(bv.len()) + offset];
    for (i, b) in bv.iter().enumerate() {
        v[divide_by_8(i)] |= (*b as u8) << modulo_8(i);
    }
    v
}

pub fn u8vec_to_boolvec(v: &[u8]) -> Vec<bool> {
    let mut bv = Vec::with_capacity(multiply_by_8(v.len()));
    for byte in v.iter() {
        for i in 0..8 {
            bv.push((1 << i) & byte != 0);
        }
    }
    bv
}

#[inline]
pub fn transpose(input: &[u8], nrows: usize, ncols: usize) -> Vec<u8> {
    #[cfg(target_arch = "x86_64")]
    return transpose_using_sse(input, nrows, ncols);

    #[cfg(not(target_arch = "x86_64"))]
    return transpose_portable(input, nrows, ncols);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{
        rand::{prelude::StdRng, SeedableRng},
        UniformRand,
    };
    use std::time::Instant;

    fn _transpose(nrows: usize, ncols: usize) {
        let mut rng = StdRng::seed_from_u64(0u64);

        let m = (0..nrows * ncols / 8)
            .map(|_| u8::rand(&mut rng))
            .collect::<Vec<u8>>();

        let start = Instant::now();
        let m1 = transpose_naive(&m, nrows, ncols);
        let m2 = transpose_naive(&m1, ncols, nrows);
        let end = start.elapsed();
        assert_eq!(m, m2);
        assert_ne!(m, m1);
        println!(
            "Naively, time for twice transposing {}x{} matrix {:?}",
            nrows, ncols, end
        );

        let start = Instant::now();
        let m3 = transpose(&m, nrows, ncols);
        let m4 = transpose(&m3, ncols, nrows);
        let end = start.elapsed();
        assert_eq!(m, m4);
        assert_ne!(m, m3);
        assert_eq!(m1, m3);
        println!(
            "Using SSE, time for twice transposing {}x{} matrix {:?}",
            nrows, ncols, end
        );

        let start = Instant::now();
        let m5 = transpose_portable(&m, nrows, ncols);
        let m6 = transpose_portable(&m5, ncols, nrows);
        let end = start.elapsed();
        assert_eq!(m, m6);
        assert_ne!(m, m5);
        assert_eq!(m3, m5);
        println!(
            "For portable, time for twice transposing {}x{} matrix {:?}",
            nrows, ncols, end
        );
    }

    #[test]
    fn test_xor() {
        let a = [0, 1, 2, 3, 4];
        let b = [5, 6, 7, 8, 9];
        let c = xor(&a, &b);
        let mut d = a.clone();
        xor_in_place(&mut d, &b);
        assert_eq!(c, d)
    }

    #[test]
    fn test_transpose() {
        _transpose(16, 16);
        _transpose(24, 16);
        _transpose(32, 16);
        _transpose(40, 16);
        _transpose(128, 16);
        _transpose(128, 24);
        _transpose(128, 128);
        _transpose(128, 1 << 16);
        _transpose(128, 1 << 18);
        _transpose(32, 32);
        _transpose(64, 32);
    }
}
