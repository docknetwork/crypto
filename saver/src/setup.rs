use crate::circuit::BitsizeCheckCircuit;
use crate::keygen::{keygen, DecryptionKey, EncryptionKey, SecretKey};
use crate::saver_groth16;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::to_bytes;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    io::{Read, Write},
    rand::RngCore,
    UniformRand,
};
use digest::Digest;
use dock_crypto_utils::hashing_utils::affine_group_elem_from_try_and_incr;

/// Create "G" and "H" from the paper.
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct EncryptionGens<E: PairingEngine> {
    pub G: E::G1Affine,
    pub H: E::G2Affine,
}

impl<E: PairingEngine> EncryptionGens<E> {
    pub fn new<D: Digest>(label: &[u8]) -> Self {
        let G = affine_group_elem_from_try_and_incr::<E::G1Affine, D>(
            &to_bytes![label, " : G".as_bytes()].unwrap(),
        );
        let H = affine_group_elem_from_try_and_incr::<E::G2Affine, D>(
            &to_bytes![label, " : H".as_bytes()].unwrap(),
        );
        Self { G, H }
    }

    pub fn new_using_rng<R: RngCore>(rng: &mut R) -> Self {
        let G = E::G1Projective::rand(rng).into_affine();
        let H = E::G2Projective::rand(rng).into_affine();
        Self { G, H }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ChunkedCommitmentGens<G: AffineCurve> {
    pub G: G,
    pub H: G,
}

impl<G: AffineCurve> ChunkedCommitmentGens<G> {
    pub fn new<D: Digest>(label: &[u8]) -> Self {
        let G = affine_group_elem_from_try_and_incr::<G, D>(
            &to_bytes![label, " : G".as_bytes()].unwrap(),
        );
        let H = affine_group_elem_from_try_and_incr::<G, D>(
            &to_bytes![label, " : H".as_bytes()].unwrap(),
        );
        Self { G, H }
    }

    pub fn new_using_rng<R: RngCore>(rng: &mut R) -> Self {
        let G = G::Projective::rand(rng).into_affine();
        let H = G::Projective::rand(rng).into_affine();
        Self { G, H }
    }
}

pub fn setup_for_groth16<E: PairingEngine, R: RngCore>(
    rng: &mut R,
    chunk_bit_size: u8,
    enc_gens: &EncryptionGens<E>,
) -> crate::Result<(
    saver_groth16::ProvingKey<E>,
    SecretKey<E::Fr>,
    EncryptionKey<E>,
    DecryptionKey<E>,
)> {
    // Create SNARK SRS
    let circuit = BitsizeCheckCircuit::new(chunk_bit_size, None, None, true);
    let proving_key = saver_groth16::generate_srs::<E, R, _>(circuit, enc_gens, rng)?;
    let g_i = saver_groth16::get_gs_for_encryption(&proving_key.pk.vk);

    // Create secret key, encryption key, decryption key
    let (sk, ek, dk) = keygen(
        rng,
        chunk_bit_size,
        enc_gens,
        g_i,
        &proving_key.pk.delta_g1,
        &proving_key.gamma_g1,
    )?;
    Ok((proving_key, sk, ek, dk))
}
