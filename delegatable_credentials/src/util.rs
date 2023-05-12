use ark_ec::{pairing::Pairing};
use ark_std::{rand::RngCore, UniformRand};
use digest::Digest;
use dock_crypto_utils::{concat_slices, hashing_utils::projective_group_elem_from_try_and_incr};

pub type GeneratorPair<E> = (<E as Pairing>::G1Affine, <E as Pairing>::G2Affine);

pub fn generator_pair<E: Pairing, R: RngCore>(rng: &mut R) -> GeneratorPair<E> {
    (E::G1Affine::rand(rng), E::G2Affine::rand(rng))
}

pub fn generator_pair_deterministic<E: Pairing, D: Digest>(label: &[u8]) -> GeneratorPair<E> {
    let g1 =
        projective_group_elem_from_try_and_incr::<E::G1Affine, D>(&concat_slices![label, b" : G1"])
            .into();
    let g2 =
        projective_group_elem_from_try_and_incr::<E::G2Affine, D>(&concat_slices![label, b" : G2"])
            .into();
    (g1, g2)
}
