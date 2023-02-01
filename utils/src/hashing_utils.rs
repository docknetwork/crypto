#![allow(non_snake_case)]

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{to_bytes, PrimeField};
use ark_std::vec;
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use hkdf::Hkdf;

const ZERO_AS_OCTET: [u8; 1] = [0u8];

// [trait_alias](https://doc.rust-lang.org/beta/unstable-book/language-features/trait-alias.html) are in unstable Rust.
// Uncomment following when they become stable and use ExpandableDigest
// trait ExpandableDigest = Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone;

/// Deterministically generate a field element from given seed similar to the procedure defined
/// here <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.3>
/// This process can be used to create secret keys from limited entropy source (the seed) without
/// using any other source of randomness.
/// `ikm` is the seed, `salt` is for domain separation. The above spec mentions `key_info` but is
/// omitted here as only one element is created.
/// Note that it can be variable time but it's less likely
pub fn field_elem_from_seed<F, D>(ikm: &[u8], salt: &[u8]) -> F
where
    F: PrimeField,
    D: Digest + Update + BlockInput + FixedOutput + Reset + Default + Clone,
{
    // IKM || I2OSP(0, 1), append 1 byte as 0 to `ikm`
    let mut ikm_appended = ikm.to_vec();
    ikm_appended.extend_from_slice(&ZERO_AS_OCTET);

    // log_2(r), byte size of the field order
    let field_size_in_bytes = (F::size_in_bits() + 7) / 8;

    // I2OSP(L, 2), convert `L` to a 2 byte array
    // L = ceil(3 * log_2(r) / 16)
    let L: u16 = (3 * field_size_in_bytes as u16 + 15) / 16;
    let L_as_bytes = L.to_be_bytes();

    loop {
        let salt_hash = D::digest(salt);
        let (_, hkdf) = Hkdf::<D>::extract(Some(&salt_hash), &ikm_appended);
        let mut okm = vec![0u8; field_size_in_bytes];

        // This cannot fail
        hkdf.expand(&L_as_bytes, &mut okm).unwrap();
        let f = F::from_be_bytes_mod_order(&okm);
        if !f.is_zero() {
            return f;
        }
    }
}

/// Hash bytes to a point on the curve. Returns as Projective coordinates. This is vulnerable to timing attack and is only used when input
/// is public anyway like when generating setup parameters.
pub fn projective_group_elem_from_try_and_incr<G: AffineCurve, D: Digest>(
    bytes: &[u8],
) -> G::Projective {
    let mut hash = D::digest(bytes);
    let mut g = G::from_random_bytes(&hash);
    let mut j = 1u64;
    while g.is_none() {
        hash = D::digest(&to_bytes![bytes, "-attempt-".as_bytes(), j].unwrap());
        g = G::from_random_bytes(&hash);
        j += 1;
    }
    g.unwrap().mul_by_cofactor_to_projective()
}

/// Hash bytes to a point on the curve. Returns as Affine coordinates. This is vulnerable to timing attack and is only used when input
/// is public anyway like when generating setup parameters.
pub fn affine_group_elem_from_try_and_incr<G: AffineCurve, D: Digest>(bytes: &[u8]) -> G {
    projective_group_elem_from_try_and_incr::<G, D>(bytes).into_affine()
}

/// Hash bytes to a field element. This is vulnerable to timing attack and is only used when input
/// is public anyway like when generating setup parameters or challenge
pub fn field_elem_from_try_and_incr<F: PrimeField, D: Digest>(bytes: &[u8]) -> F {
    let mut hash = D::digest(bytes);
    let mut f = F::from_random_bytes(&hash);
    let mut j = 1u64;
    while f.is_none() {
        hash = D::digest(&to_bytes![bytes, "-attempt-".as_bytes(), j].unwrap());
        f = F::from_random_bytes(&hash);
        j += 1;
    }
    f.unwrap()
}
