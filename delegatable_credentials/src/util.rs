use ark_ec::pairing::Pairing;
use ark_std::{rand::RngCore, UniformRand};
use digest::Digest;
use dock_crypto_utils::{affine_group_element_from_byte_slices, join};

pub type GeneratorPair<E> = (<E as Pairing>::G1Affine, <E as Pairing>::G2Affine);

pub fn generator_pair<E: Pairing, R: RngCore>(rng: &mut R) -> GeneratorPair<E> {
    (E::G1Affine::rand(rng), E::G2Affine::rand(rng))
}

pub fn generator_pair_deterministic<E: Pairing, D: Digest>(label: &[u8]) -> GeneratorPair<E> {
    join!(
        affine_group_element_from_byte_slices!(label, b" : G1"),
        affine_group_element_from_byte_slices!(label, b" : G2")
    )
}
