use crate::{
    circuit::BitsizeCheckCircuit,
    keygen::{keygen, DecryptionKey, EncryptionKey, SecretKey},
    saver_groth16,
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, vec::Vec, UniformRand};
use digest::Digest;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use dock_crypto_utils::{affine_group_element_from_byte_slices, serde_utils::*};

/// Create "G" and "H" from the paper.
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct EncryptionGens<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub G: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub H: E::G2Affine,
}

/// Create "G" and "H" from the paper.
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PreparedEncryptionGens<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub G: E::G1Prepared,
    #[serde_as(as = "ArkObjectBytes")]
    pub H: E::G2Prepared,
}

impl<E: Pairing> EncryptionGens<E> {
    pub fn new<D: Digest>(label: &[u8]) -> Self {
        let G = affine_group_element_from_byte_slices!(label, b" : G");
        let H = affine_group_element_from_byte_slices!(label, b" : H");
        Self { G, H }
    }

    pub fn new_using_rng<R: RngCore>(rng: &mut R) -> Self {
        let G = E::G1Affine::rand(rng);
        let H = E::G2Affine::rand(rng);
        Self { G, H }
    }
}

impl<E: Pairing> From<EncryptionGens<E>> for PreparedEncryptionGens<E> {
    fn from(ek: EncryptionGens<E>) -> Self {
        Self {
            G: E::G1Prepared::from(ek.G),
            H: E::G2Prepared::from(ek.H),
        }
    }
}

/// Generators used to create commitment key of the chunked commitment
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct ChunkedCommitmentGens<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub G: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub H: G,
}

impl<G: AffineRepr> ChunkedCommitmentGens<G> {
    pub fn new<D: Digest>(label: &[u8]) -> Self {
        let G = affine_group_element_from_byte_slices!(label, b" : G");
        let H = affine_group_element_from_byte_slices!(label, b" : H");
        Self { G, H }
    }

    pub fn new_using_rng<R: RngCore>(rng: &mut R) -> Self {
        let G = G::Group::rand(rng).into_affine();
        let H = G::Group::rand(rng).into_affine();
        Self { G, H }
    }
}

/// Generate secret key, encryption key, decryption key and generate SNARK proving and verifying key
pub fn setup_for_groth16<E: Pairing, R: RngCore>(
    rng: &mut R,
    chunk_bit_size: u8,
    enc_gens: &EncryptionGens<E>,
) -> crate::Result<(
    saver_groth16::ProvingKey<E>,
    SecretKey<E::ScalarField>,
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{saver_groth16::ProvingKey, test_serialization};
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::{prelude::StdRng, SeedableRng};
    use blake2::Blake2b512;

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn gens() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let label = [1, 2, 3];
        let enc_gens_1 = EncryptionGens::<Bls12_381>::new::<Blake2b512>(&label);
        let enc_gens_2 = EncryptionGens::<Bls12_381>::new::<Blake2b512>(&label);
        let enc_gens_3 = EncryptionGens::<Bls12_381>::new::<Blake2b512>(&[1, 2]);
        assert_eq!(enc_gens_1, enc_gens_2);
        assert_ne!(enc_gens_2, enc_gens_3);
        assert_ne!(
            EncryptionGens::<Bls12_381>::new_using_rng(&mut rng),
            EncryptionGens::<Bls12_381>::new_using_rng(&mut rng)
        );

        let comm_gens_1 =
            ChunkedCommitmentGens::<<Bls12_381 as Pairing>::G1Affine>::new::<Blake2b512>(&label);
        let comm_gens_2 =
            ChunkedCommitmentGens::<<Bls12_381 as Pairing>::G1Affine>::new::<Blake2b512>(&label);
        let comm_gens_3 =
            ChunkedCommitmentGens::<<Bls12_381 as Pairing>::G1Affine>::new::<Blake2b512>(&[1, 0]);
        assert_eq!(comm_gens_1, comm_gens_2);
        assert_ne!(comm_gens_2, comm_gens_3);
        assert_ne!(
            ChunkedCommitmentGens::<<Bls12_381 as Pairing>::G1Affine>::new_using_rng(&mut rng),
            ChunkedCommitmentGens::<<Bls12_381 as Pairing>::G1Affine>::new_using_rng(&mut rng)
        )
    }

    #[test]
    fn setup_for_groth16_works() {
        fn check(chunk_bit_size: u8) {
            let chunk_count = crate::utils::chunks_count::<Fr>(chunk_bit_size) as usize;
            let mut rng = StdRng::seed_from_u64(0u64);
            let enc_gens = EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);
            let comm_gens =
                ChunkedCommitmentGens::<<Bls12_381 as Pairing>::G1Affine>::new_using_rng(&mut rng);
            test_serialization!(EncryptionGens<Bls12_381>, enc_gens);
            test_serialization!(
                ChunkedCommitmentGens::<<Bls12_381 as Pairing>::G1Affine>,
                comm_gens
            );

            let (snark_pk, sk, ek, dk) =
                setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens).unwrap();
            assert_eq!(snark_pk.pk.vk.gamma_abc_g1.len(), chunk_count + 1);
            ek.validate().unwrap();
            dk.validate().unwrap();
            assert_eq!(ek.supported_chunks_count().unwrap(), chunk_count as u8);
            assert_eq!(dk.supported_chunks_count().unwrap(), chunk_count as u8);

            test_serialization!(ProvingKey<Bls12_381>, snark_pk);
            test_serialization!(EncryptionKey<Bls12_381>, ek);
            test_serialization!(DecryptionKey<Bls12_381>, dk);
            test_serialization!(SecretKey<Fr>, sk);
        }

        check(4);
        check(8);
        check(16);
    }
}
