use ark_bls12_381::Bls12_381;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use schnorr_pok::{discrete_log::PokDiscreteLogProtocol, SchnorrCommitment};

type Fr = <Bls12_381 as Pairing>::ScalarField;

macro_rules! bench_single {
    ($group_affine:ident, $group_projective:ident, $c: ident) => {
        let mut rng = StdRng::seed_from_u64(0u64);
        let base = <Bls12_381 as Pairing>::$group_projective::rand(&mut rng).into_affine();
        let witness = Fr::rand(&mut rng);

        $c.bench_function("Generate proof", |b| {
            b.iter(|| {
                let blinding = Fr::rand(&mut rng);
                let protocol =
                    PokDiscreteLogProtocol::<<Bls12_381 as Pairing>::$group_affine>::init(
                        black_box(witness),
                        blinding,
                        black_box(&base),
                    );
                let challenge = Fr::rand(&mut rng);
                protocol.gen_proof(&challenge);
            })
        });

        let y = base.mul_bigint(witness.into_bigint()).into_affine();
        let blinding = Fr::rand(&mut rng);
        let protocol = PokDiscreteLogProtocol::<<Bls12_381 as Pairing>::$group_affine>::init(
            witness, blinding, &base,
        );
        // Not benchmarking challenge contribution as that is just serialization
        let challenge = Fr::rand(&mut rng);
        let proof = protocol.gen_proof(&challenge);

        $c.bench_function("Verify proof", |b| {
            b.iter(|| proof.verify(black_box(&y), black_box(&base), black_box(&challenge)))
        });
    };
}

macro_rules! bench_vector {
    ($group_projective:ident, $c: ident) => {
        let mut rng = StdRng::seed_from_u64(0u64);
        let counts = [2, 4, 8, 15, 20, 30, 40, 60];

        let mut bases_vec = vec![];
        let mut witnesses_vec = vec![];
        let mut y_vec = vec![];

        for count in counts {
            let bases = (0..count)
                .into_iter()
                .map(|_| <Bls12_381 as Pairing>::$group_projective::rand(&mut rng).into_affine())
                .collect::<Vec<_>>();
            let witnesses = (0..count)
                .into_iter()
                .map(|_| Fr::rand(&mut rng))
                .collect::<Vec<_>>();
            let y = <Bls12_381 as Pairing>::$group_projective::msm_unchecked(&bases, &witnesses)
                .into_affine();
            bases_vec.push(bases);
            witnesses_vec.push(witnesses);
            y_vec.push(y);
        }

        let mut proof_group = $c.benchmark_group("Proof generation");
        for (i, count) in counts.iter().enumerate() {
            proof_group.bench_with_input(
                BenchmarkId::from_parameter(format!("{} elements", count)),
                count,
                |b, &count| {
                    b.iter(|| {
                        let blindings = (0..count)
                            .into_iter()
                            .map(|_| Fr::rand(&mut rng))
                            .collect::<Vec<_>>();
                        let comm = SchnorrCommitment::new(black_box(&bases_vec[i]), blindings);

                        let challenge = Fr::rand(&mut rng);

                        comm.response(black_box(&witnesses_vec[i]), &challenge)
                            .unwrap();
                    });
                },
            );
        }
        proof_group.finish();

        let mut t_vec = vec![];
        let mut chal_vec = vec![];
        let mut resp_vec = vec![];
        for (i, count) in counts.iter().enumerate() {
            let blindings = (0..*count)
                .into_iter()
                .map(|_| Fr::rand(&mut rng))
                .collect::<Vec<_>>();

            let comm = SchnorrCommitment::new(&bases_vec[i], blindings);
            let challenge = Fr::rand(&mut rng);
            let resp = comm.response(&witnesses_vec[i], &challenge).unwrap();

            t_vec.push(comm.t.clone());
            chal_vec.push(challenge);
            resp_vec.push(resp);
        }

        let mut verif_group = $c.benchmark_group("Proof verification");
        for (i, count) in counts.iter().enumerate() {
            verif_group.bench_with_input(
                BenchmarkId::from_parameter(format!("{} elements", count)),
                count,
                |b, &_count| {
                    b.iter(|| {
                        resp_vec[i].is_valid(
                            black_box(&bases_vec[i]),
                            black_box(&y_vec[i]),
                            black_box(&t_vec[i]),
                            black_box(&chal_vec[i]),
                        )
                    });
                },
            );
        }
        verif_group.finish();
    };
}

fn schnorr_single_g1(c: &mut Criterion) {
    bench_single!(G1Affine, G1, c);
}

fn schnorr_single_g2(c: &mut Criterion) {
    bench_single!(G2Affine, G2, c);
}

fn schnorr_vector_g1(c: &mut Criterion) {
    bench_vector!(G1, c);
}

fn schnorr_vector_g2(c: &mut Criterion) {
    bench_vector!(G2, c);
}

criterion_group!(
    benches,
    schnorr_single_g1,
    schnorr_single_g2,
    schnorr_vector_g1,
    schnorr_vector_g2
);
criterion_main!(benches);
