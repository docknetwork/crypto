use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::to_bytes;
use ark_std::rand::RngCore;
use ark_std::UniformRand;
use digest::Digest;
use dock_crypto_utils::hashing_utils::projective_group_elem_from_try_and_incr;

pub type GeneratorPair<E> = (
    <E as PairingEngine>::G1Affine,
    <E as PairingEngine>::G2Affine,
);

pub fn generator_pair<E: PairingEngine, R: RngCore>(rng: &mut R) -> GeneratorPair<E> {
    (
        E::G1Projective::rand(rng).into_affine(),
        E::G2Projective::rand(rng).into_affine(),
    )
}

pub fn generator_pair_deterministic<E: PairingEngine, D: Digest>(label: &[u8]) -> GeneratorPair<E> {
    let g1 = projective_group_elem_from_try_and_incr::<E::G1Affine, D>(
        &to_bytes![label, " : G1".as_bytes()].unwrap(),
    )
    .into();
    let g2 = projective_group_elem_from_try_and_incr::<E::G2Affine, D>(
        &to_bytes![label, " : G2".as_bytes()].unwrap(),
    )
    .into();
    (g1, g2)
}
