use crate::utils::decompose;
use ark_ec::msm::{FixedBaseMSM, VariableBaseMSM};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, PrimeField};
use ark_std::{rand::RngCore, vec, vec::Vec, UniformRand};

/// Given a group element `g`, create `chunks_count` group elements `g_1, g_2, ..., g_n` where each `g_i = {radix^{chunks_count-1}} * g`.
pub fn create_gs<G: AffineCurve>(g: &G, chunks_count: u8, radix: u16) -> Vec<G> {
    // TODO: This can be done more efficiently using just doublings if radix is always a power of 2
    // which is quite likely true in practice.
    let mut factors = vec![];
    let radix = G::ScalarField::from(radix as u64);
    for i in 1..=chunks_count {
        factors.push(radix.pow(&[(chunks_count - i) as u64]));
    }
    let scalar_size = G::ScalarField::size_in_bits();
    let window_size = FixedBaseMSM::get_mul_window_size(factors.len());
    let table = FixedBaseMSM::get_window_table(scalar_size, window_size, g.into_projective());
    let mut gs = FixedBaseMSM::multi_scalar_mul(scalar_size, window_size, &table, &factors);
    G::Projective::batch_normalization(&mut gs);
    gs.into_iter().map(|v| v.into()).collect()
}

/// Decompose a given field element `message` to `chunks_count` chunks each of size `chunk_bit_size` and
/// create a Pedersen commitment to those chunks. say `m` is decomposed as `m_1`, `m_2`, .. `m_n`.
/// Create multiples of `g` as `g_1, g_2, .. g_n` using `create_gs`. Now commit as `m_1 * g_1 + m_2 * g_2 + ... + m_n * g_n + r * h`
pub fn commitment_to_chunks<G: AffineCurve>(
    message: &G::ScalarField,
    chunks_count: u8,
    g: &G,
    chunk_bit_size: u8,
    h: &G,
    r: &G::ScalarField,
) -> G {
    let mut decomposed = decompose(message, chunk_bit_size)
        .into_iter()
        .map(|m| G::ScalarField::from(m as u64).into_repr())
        .collect::<Vec<_>>();
    let mut gs = create_gs(g, chunks_count, 1 << chunk_bit_size);
    assert_eq!(gs.len(), decomposed.len());
    gs.push(h.clone());
    decomposed.push(r.into_repr());
    VariableBaseMSM::multi_scalar_mul(&gs, &decomposed).into_affine()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::encrypt;
    use crate::encryption::tests::enc_setup;
    use ark_bls12_381::{Bls12_381, G1Affine};
    use ark_ec::PairingEngine;
    use ark_std::collections::BTreeSet;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::SeedableRng;
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
    fn commitment_transform_works() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let chunk_bit_size = 8u8;
        let n = 32;
        let (gens, g_i, sk, ek, dk) = enc_setup(n, &mut rng);

        let G = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();
        let H = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();

        let count = 10;
        let mut total_prove = Duration::default();
        let mut total_verify = Duration::default();

        for _ in 0..count {
            let m = Fr::rand(&mut rng);
            let blinding = Fr::rand(&mut rng);

            let comm_1 = G.mul(m.into_repr()).add(&(H.mul(blinding.into_repr())));
            let comm_2 = commitment_to_chunks(&m, n, &G, chunk_bit_size, &H, &blinding);

            assert_eq!(comm_1, comm_2);

            let (ct, r) = encrypt(&mut rng, &m, &ek, &g_i, chunk_bit_size);
            let comm_ct = ct.last().unwrap();

            let mut decomposed = decompose(&m, chunk_bit_size)
                .into_iter()
                .map(|m| Fr::from(m as u64))
                .collect::<Vec<_>>();
            let mut gs = create_gs(&G, n, 1 << chunk_bit_size);
            assert_eq!(gs.len(), decomposed.len());
            gs.push(H.clone());
            decomposed.push(blinding);

            let mut bases = ek.Y.clone();
            bases.push(ek.P_1.clone());

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
}
