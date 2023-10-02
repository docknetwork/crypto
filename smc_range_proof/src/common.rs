use ark_ec::AffineRepr;

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, vec::Vec};
use digest::Digest;
use dock_crypto_utils::{
    concat_slices,
    ff::{inner_product, powers},
    hashing_utils::affine_group_elem_from_try_and_incr,
    misc::rand,
};

/// Commitment key to commit the set member
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct MemberCommitmentKey<G: AffineRepr> {
    pub g: G,
    pub h: G,
}

impl<G: AffineRepr> MemberCommitmentKey<G> {
    pub fn new<D: Digest>(label: &[u8]) -> Self {
        let g = affine_group_elem_from_try_and_incr::<G, D>(&concat_slices![label, b" : G"]);
        let h = affine_group_elem_from_try_and_incr::<G, D>(&concat_slices![label, b" : H"]);
        Self { g, h }
    }

    pub fn generate_using_rng<R: RngCore>(rng: &mut R) -> Self {
        Self {
            g: rand(rng),
            h: rand(rng),
        }
    }

    /// Pedersen commitment to the set member
    pub fn commit(&self, member: &G::ScalarField, randomness: &G::ScalarField) -> G {
        (self.g * member + self.h * randomness).into()
    }

    pub fn commit_decomposed(
        &self,
        base: u16,
        digits: &[G::ScalarField],
        randomness: &G::ScalarField,
    ) -> G {
        let base_powers = powers(&G::ScalarField::from(base), digits.len() as u32);
        self.commit_decomposed_given_base_powers(&base_powers, digits, randomness)
    }

    pub fn commit_decomposed_given_base_powers(
        &self,
        base_powers: &[G::ScalarField],
        digits: &[G::ScalarField],
        randomness: &G::ScalarField,
    ) -> G {
        (self.g * inner_product(base_powers, digits) + self.h * randomness).into()
    }
}

/// Representation of `value` in base `base`-representation. Returns the base `base` digits in little-endian form
pub fn base_n_digits(mut value: u64, base: u16) -> Vec<u16> {
    let mut digits = Vec::<u16>::new();
    while value != 0 {
        // Note: Can use bitwise ops if base is power of 2
        digits.push((value % base as u64) as u16);
        value = value / base as u64;
    }
    digits
}

/// Same as `base_n_digits` but pads representation with 0s to the until to make the output vector length as `size`
pub fn padded_base_n_digits_as_field_elements<F: PrimeField>(
    value: u64,
    base: u16,
    size: usize,
) -> Vec<F> {
    let mut digits = base_n_digits(value, base)
        .into_iter()
        .map(|d| F::from(d))
        .collect::<Vec<_>>();
    while digits.len() < size {
        digits.push(F::zero());
    }
    digits
}

#[macro_export]
macro_rules! randomize_sigs {
    ($members: expr, $randomizers: expr, $params: expr) => {{
        let mut A = Vec::with_capacity($members.len());
        for m in $members {
            A.push($params.get_sig_for_member(m)?)
        }
        cfg_into_iter!(A)
            .enumerate()
            .map(|(i, A_i)| A_i.0 * $randomizers[i])
            .collect::<Vec<_>>()
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };

    #[test]
    fn base_digits() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let comm_key = MemberCommitmentKey::<G1Affine>::generate_using_rng(&mut rng);

        let value = u64::rand(&mut rng);
        let randomness = Fr::rand(&mut rng);
        let base = 4;
        let digits = base_n_digits(value, base);
        let mut expected_value = 0u64;
        let mut power = 1u64;
        for (i, digit) in digits.iter().enumerate() {
            let d = *digit as u64;
            expected_value += d * power;
            if i != digits.len() - 1 {
                power = base as u64 * power;
            }
        }
        assert_eq!(expected_value, value);

        let digits = digits.into_iter().map(|d| Fr::from(d)).collect::<Vec<_>>();
        let comm = comm_key.commit(&Fr::from(value), &randomness);
        let comm_d = comm_key.commit_decomposed(base, &digits, &randomness);
        assert_eq!(comm, comm_d)
    }
}
