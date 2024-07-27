use crate::{
    persistence::test::InMemoryState,
    positive::{Accumulator, PositiveAccumulator},
    proofs_keyed_verification::{MembershipProofProtocol, MembershipWitnessValidityProof},
    setup::SecretKey as AccumSecretKey,
    setup_keyed_verification::{PublicKey as AccumPublicKey, SetupParams},
};
use ark_secp256r1::{Affine, Fr};
use ark_std::{
    collections::BTreeMap,
    rand::{prelude::StdRng, SeedableRng},
    UniformRand,
};
use dock_crypto_utils::{
    schnorr_signature::Signature as SchnorrSignature, signature::MessageOrBlinding,
};
use kvac::bbs_sharp::{
    mac::{ProofOfValidityOfMAC, MAC},
    proof::{HardwareSignatureType, PoKOfMACProtocol},
    setup::{MACParams, SecretKey, SignerPublicKey, UserPublicKey},
};
use schnorr_pok::compute_random_oracle_challenge;
use sha2::Sha256;
use std::collections::BTreeSet;

#[test]
fn bbs_sharp_with_keyed_accumulator() {
    let mut rng = StdRng::seed_from_u64(0u64);
    let message_count = 10;
    let rev_index = 2;
    let messages = (0..message_count)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();
    let params = MACParams::<Affine>::new::<Sha256>(b"test", message_count);
    let signer_sk = SecretKey::new(&mut rng);
    let signer_pk = SignerPublicKey::new_from_params(&signer_sk, &params);

    let accum_params = SetupParams::<Affine>::new::<Sha256>(b"test");
    let seed = [0, 1, 2, 10, 11];
    let accum_sk = AccumSecretKey::generate_using_seed::<Sha256>(&seed);
    let accum_pk = AccumPublicKey::new_from_secret_key(&accum_sk, &accum_params);
    let mut accumulator = PositiveAccumulator::initialize(&accum_params);
    let mut state = InMemoryState::new();

    // Ad some random elements
    for _ in 0..5 {
        let elem = Fr::rand(&mut rng);
        accumulator = accumulator.add(elem, &accum_sk, &mut state).unwrap();
    }
    // Add user's revocation id
    accumulator = accumulator
        .add(messages[rev_index], &accum_sk, &mut state)
        .unwrap();
    // Generate witness and witness validity proof to be sent to the user
    let rev_wit = accumulator
        .get_membership_witness(&messages[rev_index], &accum_sk, &state)
        .unwrap();
    let rev_wit_validity_proof = MembershipWitnessValidityProof::new::<StdRng, Sha256>(
        &mut rng,
        accumulator.value(),
        &rev_wit,
        &messages[rev_index],
        accum_sk.clone(),
        &accum_pk,
        &accum_params,
    );

    let user_sk = SecretKey::new(&mut rng);
    let user_pk = UserPublicKey::new_from_params(&user_sk, &params);

    // Signer sends the following 2 items to the user
    let mac = MAC::new(&mut rng, &messages, &user_pk, &signer_sk, &params).unwrap();
    let proof = ProofOfValidityOfMAC::new::<_, Sha256>(
        &mut rng, &mac, &signer_sk, &signer_pk, &params, None,
    );

    // User verifies both
    mac.verify(&messages, &user_pk, &signer_sk, &params)
        .unwrap();
    proof
        .verify::<Sha256>(&mac, &messages, &user_pk, &signer_pk, params.clone())
        .unwrap();

    // User verifies accumulator witness validity proof
    rev_wit_validity_proof
        .verify::<Sha256>(
            accumulator.value(),
            &rev_wit,
            &messages[rev_index],
            &accum_pk,
            &accum_params,
        )
        .unwrap();

    // User starts generating proof for the verifier
    let user_auth_message = [1, 2, 3, 4, 5];
    let schnorr_signature =
        SchnorrSignature::new::<_, Sha256>(&mut rng, &user_auth_message, &user_sk.0, &params.g);
    assert!(schnorr_signature.verify::<Sha256>(&user_auth_message, &user_pk.0, &params.g));

    let mut revealed_indices = BTreeSet::new();
    revealed_indices.insert(5);
    revealed_indices.insert(7);

    let mut revealed_msgs = BTreeMap::new();
    for i in revealed_indices.iter() {
        revealed_msgs.insert(*i, messages[*i]);
    }

    // Use same blinding in proof of knowledge of signature and proof of accumulator membership protocol
    // so that responses can be compared for equality
    let blinding_for_rev = Fr::rand(&mut rng);

    let pok_sig = PoKOfMACProtocol::init(
        &mut rng,
        &mac,
        &params,
        messages.iter().enumerate().map(|(idx, msg)| {
            if idx == rev_index {
                MessageOrBlinding::BlindMessageWithConcreteBlinding {
                    message: msg,
                    blinding: blinding_for_rev,
                }
            } else if revealed_indices.contains(&idx) {
                MessageOrBlinding::RevealMessage(msg)
            } else {
                MessageOrBlinding::BlindMessageRandomly(msg)
            }
        }),
        &user_pk,
        HardwareSignatureType::Schnorr,
        None,
    )
    .unwrap();

    let pok_accum = MembershipProofProtocol::init(
        &mut rng,
        messages[rev_index].clone(),
        Some(blinding_for_rev),
        &rev_wit,
        accumulator.value(),
    );

    let mut chal_bytes_prover = vec![];
    pok_sig
        .challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_prover)
        .unwrap();
    pok_accum
        .challenge_contribution(accumulator.value(), &mut chal_bytes_prover)
        .unwrap();

    // The proves can include the verifier's given nonce if exists
    let challenge_prover = compute_random_oracle_challenge::<Fr, Sha256>(&chal_bytes_prover);
    let transformed_schnorr_sig = pok_sig.transform_schnorr_sig(schnorr_signature).unwrap();
    let proof_sig = pok_sig.gen_proof(&challenge_prover).unwrap();

    let proof_accum = pok_accum.gen_proof(&challenge_prover).unwrap();

    let mut chal_bytes_verifier = vec![];
    proof_sig
        .challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_verifier)
        .unwrap();
    proof_accum
        .challenge_contribution(accumulator.value(), &mut chal_bytes_verifier)
        .unwrap();
    let challenge_verifier = compute_random_oracle_challenge::<Fr, Sha256>(&chal_bytes_verifier);

    assert_eq!(challenge_prover, challenge_verifier);

    // The verifier needs to check that the Schnorr signature is valid
    assert!(transformed_schnorr_sig.verify::<Sha256>(
        &user_auth_message,
        &proof_sig.blinded_pk,
        &params.g
    ));

    // This is an example where the verifier has the secret key
    proof_sig
        .verify(
            &revealed_msgs,
            &challenge_verifier,
            &signer_sk,
            &params,
            None,
        )
        .unwrap();
    proof_accum
        .verify(accumulator.value(), &accum_sk, &challenge_verifier)
        .unwrap();

    // Check response for Schnorr protocol equal. In production, `proof_system` integration will be
    // done and that will do this check
    assert_eq!(
        proof_sig
            .get_resp_for_message(rev_index, &revealed_indices)
            .unwrap(),
        proof_accum.get_schnorr_response_for_element().unwrap()
    );

    // This is an example where the verifier does not have the secret key but creates the keyed proof
    // which will be verified by the signer and the verifier checks the part of proof that contains the
    // revealed messages
    let keyed_proof_sig = proof_sig.to_keyed_proof();
    keyed_proof_sig.verify(signer_sk.as_ref()).unwrap();
    proof_sig
        .verify_common(&revealed_msgs, &challenge_verifier, &params, None)
        .unwrap();

    let keyed_proof_accum = proof_accum.to_keyed_proof();
    keyed_proof_accum.verify(&accum_sk).unwrap();
    proof_accum
        .verify_schnorr_proof(accumulator.value(), &challenge_verifier)
        .unwrap();
}
