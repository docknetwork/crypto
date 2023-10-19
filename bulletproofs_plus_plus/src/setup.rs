use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, rand::RngCore, vec::Vec, UniformRand};
use digest::Digest;
use dock_crypto_utils::{concat_slices, hashing_utils::affine_group_elem_from_try_and_incr};

use crate::util::base_bits;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SetupParams<Gr: AffineRepr> {
    pub G: Gr,
    pub G_vec: Vec<Gr>,
    pub H_vec: Vec<Gr>,
}

impl<Gr: AffineRepr> SetupParams<Gr> {
    pub fn new<D: Digest>(label: &[u8], g_count: u32, h_count: u32) -> Self {
        let g = affine_group_elem_from_try_and_incr::<Gr, D>(&concat_slices![label, b" : G"]);
        let g_vec = cfg_into_iter!((0..g_count))
            .map(|i| {
                affine_group_elem_from_try_and_incr::<Gr, D>(&concat_slices![
                    label,
                    b" : g_",
                    i.to_le_bytes()
                ])
            })
            .collect::<Vec<Gr>>();
        let h_vec = cfg_into_iter!((0..h_count))
            .map(|i| {
                affine_group_elem_from_try_and_incr::<Gr, D>(&concat_slices![
                    label,
                    b" : h_",
                    i.to_le_bytes()
                ])
            })
            .collect::<Vec<Gr>>();
        Self {
            G: g,
            G_vec: g_vec,
            H_vec: h_vec,
        }
    }

    /// Create setup params for perfect range, i.e a range of form `[0, base^l)`
    pub fn new_for_perfect_range_proof<D: Digest>(
        label: &[u8],
        base: u16,
        num_value_bits: u16,
        num_proofs: u32,
    ) -> Self {
        Self::new::<D>(
            label,
            Self::get_no_of_G(base, num_value_bits, num_proofs),
            8,
        )
    }

    /// Create setup params for an arbitrary range, i.e a range of form `[a, b)`
    pub fn new_for_arbitrary_range_proof<D: Digest>(
        label: &[u8],
        base: u16,
        num_value_bits: u16,
        num_proofs: u32,
    ) -> Self {
        Self::new_for_perfect_range_proof::<D>(label, base, num_value_bits, num_proofs * 2)
    }

    /// Create Pedersen commitment as `C = v*G + gamma*H_vec[0]`
    pub fn compute_pedersen_commitment(&self, v: u64, gamma: &Gr::ScalarField) -> Gr {
        ((self.G * Gr::ScalarField::from(v)) + self.H_vec[0] * gamma).into_affine()
    }

    /// Returns `v*g + <g_vec, n> + <h_vec, l>`
    pub fn compute_commitment(
        &self,
        v: &Gr::ScalarField,
        l: &[Gr::ScalarField],
        n: &[Gr::ScalarField],
    ) -> Gr {
        Self::compute_commitment_given_bases(v, l, n, &self.G, &self.G_vec, &self.H_vec)
    }

    /// Returns `v*g + <g_vec, n> + <h_vec, l>`
    pub fn compute_commitment_given_bases(
        v: &Gr::ScalarField,
        l: &[Gr::ScalarField],
        n: &[Gr::ScalarField],
        g: &Gr,
        g_vec: &[Gr],
        h_vec: &[Gr],
    ) -> Gr {
        (g.mul(v) + Gr::Group::msm_unchecked(g_vec, n) + Gr::Group::msm_unchecked(h_vec, l))
            .into_affine()
    }

    /// Generates random `v` and returns pair `(v, v*g + <g_vec, n> + <h_vec, l>)`
    pub fn gen_randomness_and_compute_commitment<R: RngCore>(
        &self,
        rng: &mut R,
        l: &[Gr::ScalarField],
        n: &[Gr::ScalarField],
    ) -> (Gr::ScalarField, Gr) {
        let v = Gr::ScalarField::rand(rng);
        (v, self.compute_commitment(&v, l, n))
    }

    pub fn get_pedersen_commitment_key(&self) -> (Gr, Gr) {
        (self.G, self.H_vec[0])
    }

    /// Get number of generators `G_i` required for creating proofs
    pub fn get_no_of_G(base: u16, num_value_bits: u16, num_proofs: u32) -> u32 {
        core::cmp::max(num_value_bits as u32 / base_bits(base) as u32, base as u32) * num_proofs
    }
}
