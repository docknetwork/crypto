use ark_ec::Group;
use ark_std::{cfg_into_iter, vec, vec::Vec};

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
pub fn divide_by_8(n: usize) -> usize {
    n >> 3
}

#[inline]
pub fn modulo_8(n: usize) -> usize {
    n & 7
}

#[inline]
pub fn is_multiple_of_8(n: usize) -> bool {
    modulo_8(n) == 0
}

// TODO: Optimize matrix transpose

// Following copied from https://github.com/GaloisInc/swanky/blob/master/ocelot/src/utils.rs

/// Transpose given matrix of `nrows` rows and `ncols` columns
#[inline]
pub fn transpose(input: &[u8], nrows: usize, ncols: usize) -> Vec<u8> {
    assert_eq!(modulo_8(nrows), 0);
    assert_eq!(modulo_8(ncols), 0);
    assert_eq!(nrows * ncols, input.len() << 3); // x << 3 = x * 8
    let mut output = vec![0u8; input.len()];

    transpose_inplace(&mut output, input, ncols);
    output
}

#[inline]
fn transpose_inplace(dst: &mut [u8], src: &[u8], m: usize) {
    assert!(src.len() % m == 0);
    let l = src.len() * 8;
    let n = l / m;
    let it = cfg_into_iter!(0..l)
        .map(|i| {
            let bit = get_bit(src, i);
            let (row, col) = (i / m, i % m);
            (bit, col * n + row)
        })
        .collect::<Vec<_>>();
    for (bit, pos) in it {
        set_bit(dst, pos, bit);
    }
}

// BITMASKS_i = 1 << i
const BITMASKS: [u8; 8] = [1, 2, 4, 8, 16, 32, 64, 128];

#[inline]
fn get_bit(src: &[u8], i: usize) -> u8 {
    let byte = src[divide_by_8(i)];
    let bit_pos = modulo_8(i);
    (byte & BITMASKS[bit_pos] != 0) as u8
}

#[inline]
fn set_bit(dst: &mut [u8], i: usize, b: u8) {
    let bit_pos = modulo_8(i);
    if b == 1 {
        dst[divide_by_8(i)] |= BITMASKS[bit_pos];
    } else {
        dst[divide_by_8(i)] &= !BITMASKS[bit_pos];
    }
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
    let mut bv = Vec::with_capacity(v.len() * 8);
    for byte in v.iter() {
        for i in 0..8 {
            bv.push((1 << i) & byte != 0);
        }
    }
    bv
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
        let m_ = m.clone();
        let start = Instant::now();
        let m = transpose(&m, nrows, ncols);
        let m = transpose(&m, ncols, nrows);
        let end = start.elapsed();
        assert_eq!(m, m_);
        println!("Time for transposing {}x{} matrix {:?}", nrows, ncols, end);
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
