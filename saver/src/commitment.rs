//! Getting a commitment to the message as a single field element from commitment to its b-ary decomposition.
//!
//! Commitment created during encryption
//! `
//! psi = m_1*Y_1 + m_2*Y_2 + ... + m_n*Y_n + r*P_2
//! `
//!
//! To get a commitment to the message `m`, `m*G + r'*H` from `psi`, create a commitment `J` as:
//!
//! ` J = m_1*G_1 + m_2*G_2 + ... + m_n*G_n + r'*H `
//!
//! where `G_i = {b^{n-i}}*G` so `G_1 = {b^{n-1}}*G`, and so on.
//!
//! Now prove the equality of openings of the commitments `psi` and `J`. Note that `J` is same as `m*G + r'*H` because
//! `
//! m_1*G_1 + m_2*G_2 + ... + m_n*G_n + r'*H
//!   = m_1*{b^{n-1}}*G + m_2*{b^{n-2}}*G + ... + m_n*G + r'*H
//!   = ( m_1*{b^{n-1}} + m_2*{b^{n-2}} + ... + m_n ) * G + r'*H
//!   = m*G + r'*H
//! `
//!
//! Since `b`, `n` and `G` are public, it can be ensured that `G_i`s are correctly created.

use crate::setup::ChunkedCommitmentGens;
use crate::utils::{chunks_count, decompose};
use ark_ec::msm::{FixedBaseMSM, VariableBaseMSM};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    io::{Read, Write},
    vec,
    vec::Vec,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use dock_crypto_utils::msm::multiply_field_elems_with_same_group_elem;
use dock_crypto_utils::serde_utils::*;

#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct ChunkedCommitment<G: AffineCurve>(
    #[serde_as(as = "AffineGroupBytes")] pub G,
    #[serde_as(as = "Vec<AffineGroupBytes>")] pub Vec<G>,
);

impl<G: AffineCurve> ChunkedCommitment<G> {
    /// Decompose a given field element `message` to `chunks_count` chunks each of size `chunk_bit_size` and
    /// create a Pedersen commitment to those chunks. say `m` is decomposed as `m_1`, `m_2`, .. `m_n`.
    /// Create multiples of `g` as `g_n, g_{n-1}, ..., g_2, g_1` using `create_gs`. Now commit as `m_1 * g_1 + m_2 * g_2 + ... + m_n * g_n + r * h`
    pub fn new(
        message: &G::ScalarField,
        blinding: &G::ScalarField,
        chunk_bit_size: u8,
        gens: &ChunkedCommitmentGens<G>,
    ) -> crate::Result<Self> {
        let mut decomposed = decompose(message, chunk_bit_size)?
            .into_iter()
            .map(|m| <G::ScalarField as PrimeField>::BigInt::from(m as u64))
            .collect::<Vec<_>>();
        decomposed.push(blinding.into_repr());
        let gs = Self::commitment_key(gens, chunk_bit_size);
        Ok(Self(
            VariableBaseMSM::multi_scalar_mul(&gs, &decomposed).into_affine(),
            gs,
        ))
    }

    /// Given a group element `g`, create `chunks_count` multiples of `g` as `g_n, g_{n-1}, ..., g_2, g_1` where each `g_i = {radix^i} * g` and `radix = 2^chunk_bit_ize`
    pub fn commitment_key(gens: &ChunkedCommitmentGens<G>, chunk_bit_size: u8) -> Vec<G> {
        let radix = (1 << chunk_bit_size) as u16;
        let chunks = chunks_count::<G::ScalarField>(chunk_bit_size);
        let mut gs = if radix.is_power_of_two() {
            Self::commitment_key_for_radix_power_of_2(gens.G.into_projective(), chunks, radix)
        } else {
            Self::commitment_key_for_radix_non_power_of_2(gens.G.into_projective(), chunks, radix)
        };
        G::Projective::batch_normalization(&mut gs);
        let mut ck = gs.into_iter().map(|v| v.into()).collect::<Vec<_>>();
        ck.push(gens.H);
        ck
    }

    fn commitment_key_for_radix_power_of_2(
        g: G::Projective,
        chunks_count: u8,
        radix: u16,
    ) -> Vec<G::Projective> {
        let mut gs = vec![g];
        // log2 doublings are equivalent to multiplication by radix
        let log2 = radix.trailing_zeros();
        for i in 1..chunks_count {
            // Multiply the last element of `gs` by `radix` by repeated doublings
            let mut curr = gs[i as usize - 1].clone();
            for _ in 0..log2 {
                curr.double_in_place();
            }
            gs.push(curr);
        }
        gs.reverse();
        gs
    }

    fn commitment_key_for_radix_non_power_of_2(
        g: G::Projective,
        chunks_count: u8,
        radix: u16,
    ) -> Vec<G::Projective> {
        let radix = G::ScalarField::from(radix as u64);
        // factors = [radix^{chunks_count - 1}, radix^{chunks_count - 2}, ..., 1]
        let mut factors = vec![];
        for i in 1..chunks_count {
            factors.push(radix.pow(&[(chunks_count - i) as u64]));
        }
        factors.push(G::ScalarField::one());
        multiply_field_elems_with_same_group_elem(g, &factors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::tests::enc_setup;
    use crate::encryption::Encryption;
    use ark_bls12_381::{Bls12_381, G1Affine};
    use ark_ec::PairingEngine;
    use ark_std::collections::BTreeSet;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::SeedableRng;
    use ark_std::UniformRand;
    use blake2::Blake2b;
    use std::ops::Add;
    use std::time::{Duration, Instant};

    use proof_system::prelude::{
        EqualWitnesses, MetaStatement, MetaStatements, Proof, ProofSpec, Statement, Statements,
        Witness, WitnessRef, Witnesses,
    };
    use proof_system::statement::PedersenCommitment as PedersenCommitmentStmt;

    type Fr = <Bls12_381 as PairingEngine>::Fr;
    type ProofG1 = Proof<Bls12_381, G1Affine, Fr, Blake2b>;

    #[test]
    fn commitment_key_creation() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let g = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng);
        let chunks_count = 32;
        let chunk_bit_size = 8u8;

        let start = Instant::now();
        let gs_1 = ChunkedCommitment::<<Bls12_381 as PairingEngine>::G1Affine>::commitment_key_for_radix_power_of_2(g, chunks_count, 1 << chunk_bit_size);
        println!(
            "commitment_key_for_radix_power_of_2 time {:?}",
            start.elapsed()
        );

        let start = Instant::now();
        let gs_2 = ChunkedCommitment::<<Bls12_381 as PairingEngine>::G1Affine>::commitment_key_for_radix_non_power_of_2(g, chunks_count, 1 << chunk_bit_size);
        println!(
            "commitment_key_for_radix_non_power_of_2 time {:?}",
            start.elapsed()
        );

        assert_eq!(gs_1, gs_2);
    }

    #[test]
    fn commitment_transform_works() {
        fn check(chunk_bit_size: u8) {
            let mut rng = StdRng::seed_from_u64(0u64);
            let n = chunks_count::<Fr>(chunk_bit_size) as usize;
            let (_, g_i, _, ek, _) = enc_setup(chunk_bit_size, &mut rng);

            let gens =
                ChunkedCommitmentGens::<<Bls12_381 as PairingEngine>::G1Affine>::new_using_rng(
                    &mut rng,
                );

            let count = 10;
            let mut total_prove = Duration::default();
            let mut total_verify = Duration::default();

            for _ in 0..count {
                let m = Fr::rand(&mut rng);
                let blinding = Fr::rand(&mut rng);

                let comm_1 = gens
                    .G
                    .mul(m.into_repr())
                    .add(&(gens.H.mul(blinding.into_repr())));
                let comm_2 = ChunkedCommitment::<<Bls12_381 as PairingEngine>::G1Affine>::new(
                    &m,
                    &blinding,
                    chunk_bit_size,
                    &gens,
                )
                .unwrap()
                .0;

                assert_eq!(comm_1, comm_2);

                let (ct, r) = Encryption::encrypt(&mut rng, &m, &ek, &g_i, chunk_bit_size).unwrap();
                let comm_ct = ct.commitment;

                let mut decomposed = decompose(&m, chunk_bit_size)
                    .unwrap()
                    .into_iter()
                    .map(|m| Fr::from(m as u64))
                    .collect::<Vec<_>>();
                let gs =
                    ChunkedCommitment::<<Bls12_381 as PairingEngine>::G1Affine>::commitment_key(
                        &gens,
                        chunk_bit_size,
                    );
                decomposed.push(blinding);

                assert_eq!(gs.len(), decomposed.len());

                let bases = ek.commitment_key();

                let mut wit2 = decomposed.clone();
                wit2[n as usize] = r;

                let start = Instant::now();
                let mut statements = Statements::new();
                statements.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
                    bases: gs.clone(),
                    commitment: comm_2.clone(),
                }));
                statements.add(Statement::PedersenCommitment(PedersenCommitmentStmt {
                    bases: bases.clone(),
                    commitment: comm_ct.clone(),
                }));

                let mut meta_statements = MetaStatements::new();
                for i in 0..n as usize {
                    meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
                        vec![(0, i), (1, i)]
                            .into_iter()
                            .collect::<BTreeSet<WitnessRef>>(),
                    )));
                }

                let proof_spec = ProofSpec {
                    statements: statements.clone(),
                    meta_statements: meta_statements.clone(),
                    context: None,
                };

                let mut witnesses = Witnesses::new();
                witnesses.add(Witness::PedersenCommitment(decomposed));
                witnesses.add(Witness::PedersenCommitment(wit2));

                let proof =
                    ProofG1::new(&mut rng, proof_spec.clone(), witnesses.clone(), None).unwrap();
                total_prove += start.elapsed();

                let start = Instant::now();
                proof.verify(proof_spec, None).unwrap();
                total_verify += start.elapsed();
            }

            println!(
                "Time taken for {} iterations and {} chunk size:",
                count, chunk_bit_size
            );
            println!("Proving {:?}", total_prove);
            println!("Verifying {:?}", total_verify);
        }
        check(4);
        check(8);
    }
}
