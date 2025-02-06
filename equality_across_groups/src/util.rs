use ark_ff::BigInt;

pub fn bitwise_and<const LIMBS: usize>(a: &BigInt<LIMBS>, b: &BigInt<LIMBS>) -> BigInt<LIMBS> {
    let mut res = BigInt::zero();
    for i in 0..LIMBS {
        res.0[i] = a.0[i] & &b.0[i];
    }
    res
}

pub fn from_bytes_le<const LIMBS: usize>(bytes: &[u8]) -> BigInt<LIMBS> {
    let mut res = BigInt::zero();
    for (i, bytes_8) in bytes.chunks(8).enumerate() {
        let mut b_8 = [0; 8];
        for j in 0..bytes_8.len() {
            b_8[j] = bytes_8[j];
        }
        res.0[i] = u64::from_le_bytes(b_8);
    }
    res
}
