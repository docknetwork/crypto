use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::{prelude::StdRng, SeedableRng},
};
use bbs_plus::{prelude::KeypairG2, setup::SignatureParamsG1, signature::SignatureG1};
use blake2::Blake2b512;
use bulletproofs_plus_plus::prelude::SetupParams;
use std::time::Instant;

use proof_system::{
    prelude::{EqualWitnesses, MetaStatements, ProofSpec, Witness, WitnessRef, Witnesses},
    proof::Proof,
    statement::{
        bbs_plus::{
            PoKBBSSignatureG1Prover as PoKSignatureBBSG1ProverStmt,
            PoKBBSSignatureG1Verifier as PoKSignatureBBSG1VerifierStmt,
        },
        bound_check_bpp::BoundCheckBpp as BoundCheckStmt,
        Statements,
    },
    witness::PoKBBSSignatureG1 as PoKSignatureBBSG1Wit,
};

use test_utils::{bbs::*, test_serialization};

#[test]
fn pok_of_bbs_plus_sig_and_bounded_message_using_bulletproofs_plus_plus() {
    // Prove knowledge of BBS+ signature and a specific message satisfies some bounds i.e. min <= message <= max.
    // Here message set as min and them max
    let mut rng = StdRng::seed_from_u64(0u64);

    let min = 100;
    let max = 200;
    let msg_count = 5;
    let msgs = (0..msg_count)
        .map(|i| Fr::from(min + 1 + i as u64))
        .collect::<Vec<_>>();

    let (sig_params, sig_keypair, sig) = bbs_plus_sig_setup_given_messages(&mut rng, &msgs);

    let bpp_setup_params =
        SetupParams::<G1Affine>::new_for_arbitrary_range_proof::<Blake2b512>(b"test", 2, 64, 1);

    fn check(
        rng: &mut StdRng,
        min: u64,
        max: u64,
        msg_idx: usize,
        msg: Fr,
        msgs: Vec<Fr>,
        sig_params: SignatureParamsG1<Bls12_381>,
        sig_keypair: KeypairG2<Bls12_381>,
        sig: SignatureG1<Bls12_381>,
        bpp_setup_params: SetupParams<G1Affine>,
        valid_proof: bool,
    ) {
        let mut prover_statements = Statements::new();
        prover_statements.add(PoKSignatureBBSG1ProverStmt::new_statement_from_params(
            sig_params.clone(),
            BTreeMap::new(),
        ));
        prover_statements.add(
            BoundCheckStmt::new_statement_from_params(min, max, bpp_setup_params.clone()).unwrap(),
        );

        let mut meta_statements = MetaStatements::new();
        meta_statements.add_witness_equality(EqualWitnesses(
            vec![(0, msg_idx), (1, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        ));

        if valid_proof {
            test_serialization!(Statements<Bls12_381>, prover_statements);
            test_serialization!(MetaStatements, meta_statements);
        }

        let proof_spec_prover = ProofSpec::new(
            prover_statements.clone(),
            meta_statements.clone(),
            vec![],
            None,
        );
        proof_spec_prover.validate().unwrap();

        if valid_proof {
            test_serialization!(ProofSpec<Bls12_381>, proof_spec_prover);
        }

        let mut witnesses = Witnesses::new();
        witnesses.add(PoKSignatureBBSG1Wit::new_as_witness(
            sig.clone(),
            msgs.clone().into_iter().enumerate().collect(),
        ));
        witnesses.add(Witness::BoundCheckBpp(msg));

        if valid_proof {
            test_serialization!(Witnesses<Bls12_381>, witnesses);
        }

        let start = Instant::now();
        let proof = Proof::new::<StdRng, Blake2b512>(
            rng,
            proof_spec_prover,
            witnesses.clone(),
            None,
            Default::default(),
        )
        .unwrap()
        .0;
        println!(
            "Time taken to create proof of Bulletproofs++ bound check of 1 message in signature over {} messages {:?}",
            msgs.len(),
            start.elapsed()
        );

        if valid_proof {
            test_serialization!(Proof<Bls12_381>, proof);
        }

        let mut verifier_statements = Statements::new();
        verifier_statements.add(PoKSignatureBBSG1VerifierStmt::new_statement_from_params(
            sig_params.clone(),
            sig_keypair.public_key.clone(),
            BTreeMap::new(),
        ));
        verifier_statements.add(
            BoundCheckStmt::new_statement_from_params(min, max, bpp_setup_params.clone()).unwrap(),
        );

        let proof_spec_verifier = ProofSpec::new(
            verifier_statements.clone(),
            meta_statements.clone(),
            vec![],
            None,
        );
        proof_spec_verifier.validate().unwrap();

        let start = Instant::now();
        let res =
            proof.verify::<StdRng, Blake2b512>(rng, proof_spec_verifier, None, Default::default());
        assert_eq!(res.is_ok(), valid_proof);
        println!(
            "Time taken to verify proof of Bulletproofs++ bound check of 1 message in signature over {} messages {:?}",
            msgs.len(),
            start.elapsed()
        );
    }

    // Following message's bounds will be checked

    // Check for message that is signed and satisfies the bounds
    check(
        &mut rng,
        min,
        max,
        1,
        msgs[1],
        msgs.clone(),
        sig_params.clone(),
        sig_keypair.clone(),
        sig.clone(),
        bpp_setup_params.clone(),
        true,
    );

    // Check for message that satisfies the bounds but is not signed
    check(
        &mut rng,
        min,
        max,
        0,
        Fr::from(min + 10),
        msgs,
        sig_params,
        sig_keypair,
        sig,
        bpp_setup_params,
        false,
    );
}
