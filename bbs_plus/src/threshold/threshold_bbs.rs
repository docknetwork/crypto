use ark_ec::{AffineRepr, CurveGroup};

use super::{multiplication_phase::Phase2Output, utils::compute_R_and_u};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::RngCore,
    vec::Vec,
};
use digest::DynDigest;
use dock_crypto_utils::expect_equality;

use crate::{
    error::BBSPlusError, setup::SignatureParams23G1, signature_23::Signature23G1,
    threshold::randomness_generation_phase::Phase1,
};
use dock_crypto_utils::signature::MultiMessageSignatureParams;
use oblivious_transfer_protocols::{cointoss, zero_sharing, ParticipantId};

/// The length of vectors `r`, `e`, `masked_signing_key_shares`, `masked_rs` should
/// be `batch_size` as each item of the vector corresponds to 1 signature
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase1Output<F: PrimeField> {
    pub id: ParticipantId,
    pub batch_size: u32,
    /// Shares of the random `r`, one share for each item in the batch
    pub r: Vec<F>,
    pub e: Vec<F>,
    /// Additive shares of the signing key masked by a random `alpha`
    pub masked_signing_key_shares: Vec<F>,
    /// Additive shares of `r` masked by a random `beta`
    pub masked_rs: Vec<F>,
    pub others: Vec<ParticipantId>,
}

/// A share of the BBS signature created by one signer. A client will aggregate many such shares to
/// create the final signature.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct BBSSignatureShare<E: Pairing> {
    pub id: ParticipantId,
    pub e: E::ScalarField,
    pub u: E::ScalarField,
    pub R: E::G1Affine,
}

impl<F: PrimeField, const SALT_SIZE: usize> Phase1<F, SALT_SIZE> {
    pub fn init_for_bbs<R: RngCore>(
        rng: &mut R,
        batch_size: u32,
        id: ParticipantId,
        others: BTreeSet<ParticipantId>,
        protocol_id: Vec<u8>,
    ) -> Result<
        (
            Self,
            cointoss::Commitments,
            BTreeMap<ParticipantId, cointoss::Commitments>,
        ),
        BBSPlusError,
    > {
        if others.contains(&id) {
            return Err(BBSPlusError::ParticipantCannotBePresentInOthers(id));
        }
        let r = (0..batch_size).map(|_| F::rand(rng)).collect();
        // 1 random value `e` need to be generated per signature
        let (commitment_protocol, comm) =
            cointoss::Party::commit(rng, id, batch_size, protocol_id.clone());
        // Each signature will have its own zero-sharing of `alpha` and `beta`
        let (zero_sharing_protocol, comm_zero_share) =
            zero_sharing::Party::init(rng, id, 2 * batch_size, others, protocol_id);
        Ok((
            Self {
                id,
                batch_size,
                r,
                commitment_protocol,
                zero_sharing_protocol,
            },
            comm,
            comm_zero_share,
        ))
    }

    /// End phase 1 and return the output of this phase
    pub fn finish_for_bbs<D: Default + DynDigest + Clone>(
        self,
        signing_key: &F,
    ) -> Result<Phase1Output<F>, BBSPlusError> {
        // TODO: Ensure every one has participated in both protocols
        let id = self.id;
        let batch_size = self.batch_size;
        let r = self.r.clone();
        let (others, randomness, masked_signing_key_share, masked_r) =
            self.compute_randomness_and_arguments_for_multiplication::<D>(signing_key)?;
        debug_assert_eq!(randomness.len() as u32, batch_size);
        let e = randomness;
        Ok(Phase1Output {
            id,
            batch_size,
            r,
            e,
            masked_signing_key_shares: masked_signing_key_share,
            masked_rs: masked_r,
            others,
        })
    }
}

impl<E: Pairing> BBSSignatureShare<E> {
    /// `sig_index_in_batch` is the index of this signature in batch and also in the Phase1 and Phase2 outputs
    pub fn new(
        messages: &[E::ScalarField],
        sig_index_in_batch: usize,
        phase1: &Phase1Output<E::ScalarField>,
        phase2: &Phase2Output<E::ScalarField>,
        sig_params: &SignatureParams23G1<E>,
    ) -> Result<Self, BBSPlusError> {
        if messages.is_empty() {
            return Err(BBSPlusError::NoMessageToSign);
        }
        expect_equality!(
            messages.len(),
            sig_params.supported_message_count(),
            BBSPlusError::MessageCountIncompatibleWithSigParams
        );
        // Create map of msg index (0-based) -> message
        let msg_map: BTreeMap<usize, &E::ScalarField> =
            messages.iter().enumerate().map(|(i, e)| (i, e)).collect();
        Self::new_with_committed_messages(
            &E::G1Affine::zero(),
            msg_map,
            sig_index_in_batch,
            phase1,
            phase2,
            sig_params,
        )
    }

    /// `sig_index_in_batch` is the index of this signature in batch and also in the Phase1 and Phase2 outputs
    pub fn new_with_committed_messages(
        commitment: &E::G1Affine,
        uncommitted_messages: BTreeMap<usize, &E::ScalarField>,
        sig_index_in_batch: usize,
        phase1: &Phase1Output<E::ScalarField>,
        phase2: &Phase2Output<E::ScalarField>,
        sig_params: &SignatureParams23G1<E>,
    ) -> Result<Self, BBSPlusError> {
        let b = sig_params.b(uncommitted_messages)?;
        let commitment_plus_b = b + commitment;
        let (R, u) = compute_R_and_u(
            commitment_plus_b,
            &phase1.r[sig_index_in_batch],
            &phase1.e[sig_index_in_batch],
            &phase1.masked_rs[sig_index_in_batch],
            &phase1.masked_signing_key_shares[sig_index_in_batch],
            sig_index_in_batch as u32,
            phase2,
        );
        Ok(Self {
            id: phase1.id,
            e: phase1.e[sig_index_in_batch],
            u,
            R,
        })
    }

    pub fn aggregate(sig_shares: Vec<Self>) -> Result<Signature23G1<E>, BBSPlusError> {
        // TODO: Ensure correct threshold. Share should contain threshold and share id
        let mut sum_R = E::G1::zero();
        let mut sum_u = E::ScalarField::zero();
        let mut expected_e = E::ScalarField::zero();
        for (i, share) in sig_shares.into_iter().enumerate() {
            if i == 0 {
                expected_e = share.e;
            } else {
                if expected_e != share.e {
                    return Err(BBSPlusError::IncorrectEByParticipant(share.id));
                }
            }
            sum_u += share.u;
            sum_R += share.R;
        }
        let A = sum_R * sum_u.inverse().unwrap();
        Ok(Signature23G1 {
            A: A.into_affine(),
            e: expected_e,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::Zero;
    use std::time::{Duration, Instant};

    use crate::{
        setup::{PublicKeyG2, SecretKey},
        threshold::{
            multiplication_phase::Phase2, threshold_bbs_plus::tests::trusted_party_keygen,
        },
    };
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use oblivious_transfer_protocols::ot_based_multiplication::{
        dkls18_mul_2p::MultiplicationOTEParams, dkls19_batch_mul_2p::GadgetVector,
    };
    use test_utils::ot::do_pairwise_base_ot;

    #[test]
    fn signing() {
        let mut rng = StdRng::seed_from_u64(0u64);
        const BASE_OT_KEY_SIZE: u16 = 128;
        const KAPPA: u16 = 256;
        const STATISTICAL_SECURITY_PARAMETER: u16 = 80;
        let ote_params = MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};
        let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<
            Blake2b512,
        >(ote_params, b"test-gadget-vector");

        let protocol_id = b"test".to_vec();

        let sig_batch_size = 3;
        let threshold_signers = 5;
        let total_signers = 8;
        let all_party_set = (1..=total_signers).into_iter().collect::<BTreeSet<_>>();
        let threshold_party_set = (1..=threshold_signers).into_iter().collect::<BTreeSet<_>>();

        // The signers do a keygen. This is a one time setup.
        let (sk, sk_shares) =
            trusted_party_keygen::<_, Fr>(&mut rng, threshold_signers, total_signers);

        // The signers run OT protocol instances. This is also a one time setup.
        let base_ot_outputs = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
            &mut rng,
            ote_params.num_base_ot(),
            total_signers,
            all_party_set.clone(),
        );

        let message_count = 5;
        let params = SignatureParams23G1::<Bls12_381>::generate_using_rng(&mut rng, message_count);
        let public_key =
            PublicKeyG2::generate_using_secret_key_and_bbs23_params(&SecretKey(sk), &params);

        println!(
            "For a batch size of {} BBS signatures and {} signers",
            sig_batch_size, threshold_signers
        );

        // Following have to happen for each new batch of signatures. Batch size can be 1 when creating one signature at a time

        let mut round1s = vec![];
        let mut commitments = vec![];
        let mut commitments_zero_share = vec![];
        let mut round1outs = vec![];

        // Signers initiate round-1 and each signer sends commitments to others
        let start = Instant::now();
        for i in 1..=threshold_signers {
            let mut others = threshold_party_set.clone();
            others.remove(&i);
            let (round1, comm, comm_zero) = Phase1::<Fr, 256>::init_for_bbs(
                &mut rng,
                sig_batch_size,
                i,
                others,
                protocol_id.clone(),
            )
            .unwrap();
            round1s.push(round1);
            commitments.push(comm);
            commitments_zero_share.push(comm_zero);
        }

        // Signers process round-1 commitments received from others
        for i in 1..=threshold_signers {
            for j in 1..=threshold_signers {
                if i != j {
                    round1s[i as usize - 1]
                        .receive_commitment(
                            j,
                            commitments[j as usize - 1].clone(),
                            commitments_zero_share[j as usize - 1]
                                .get(&i)
                                .unwrap()
                                .clone(),
                        )
                        .unwrap();
                }
            }
        }

        // Signers create round-1 shares once they have the required commitments from others
        for i in 1..=threshold_signers {
            for j in 1..=threshold_signers {
                if i != j {
                    let share = round1s[j as usize - 1].get_comm_shares_and_salts();
                    let zero_share = round1s[j as usize - 1]
                        .get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&i);
                    round1s[i as usize - 1]
                        .receive_shares(j, share, zero_share)
                        .unwrap();
                }
            }
        }

        // Signers finish round-1 to generate the output
        let mut expected_sk = Fr::zero();
        for (i, round1) in round1s.into_iter().enumerate() {
            let out = round1.finish_for_bbs::<Blake2b512>(&sk_shares[i]).unwrap();
            expected_sk += out.masked_signing_key_shares.iter().sum::<Fr>();
            round1outs.push(out);
        }
        println!("Phase 1 took {:?}", start.elapsed());

        assert_eq!(expected_sk, sk * Fr::from(sig_batch_size));
        for i in 1..threshold_signers {
            assert_eq!(round1outs[0].e, round1outs[i as usize].e);
        }

        let mut round2s = vec![];
        let mut all_msg_1s = vec![];

        // Signers initiate round-2 and each signer sends messages to others
        let start = Instant::now();
        for i in 1..=threshold_signers {
            let mut others = threshold_party_set.clone();
            others.remove(&i);
            let (phase, U) = Phase2::init(
                &mut rng,
                i,
                round1outs[i as usize - 1].masked_signing_key_shares.clone(),
                round1outs[i as usize - 1].masked_rs.clone(),
                base_ot_outputs[i as usize - 1].clone(),
                others,
                ote_params,
                &gadget_vector,
            )
            .unwrap();
            round2s.push(phase);
            all_msg_1s.push((i, U));
        }

        // Signers process round-2 messages received from others
        let mut all_msg_2s = vec![];
        for (sender_id, msg_1s) in all_msg_1s {
            for (receiver_id, m) in msg_1s {
                let m2 = round2s[receiver_id as usize - 1]
                    .receive_message1::<Blake2b512>(sender_id, m, &gadget_vector)
                    .unwrap();
                all_msg_2s.push((receiver_id, sender_id, m2));
            }
        }

        for (sender_id, receiver_id, m2) in all_msg_2s {
            round2s[receiver_id as usize - 1]
                .receive_message2::<Blake2b512>(sender_id, m2, &gadget_vector)
                .unwrap();
        }

        let round2_outputs = round2s.into_iter().map(|p| p.finish()).collect::<Vec<_>>();
        println!("Phase 2 took {:?}", start.elapsed());

        // Check that multiplication phase ran successfully, i.e. each signer has an additive share of
        // a multiplication with every other signer
        for i in 1..=threshold_signers {
            for (j, z_A) in &round2_outputs[i as usize - 1].0.z_A {
                let z_B = round2_outputs[*j as usize - 1].0.z_B.get(&i).unwrap();
                for k in 0..sig_batch_size as usize {
                    assert_eq!(
                        z_A.0[k] + z_B.0[k],
                        round1outs[i as usize - 1].masked_signing_key_shares[k]
                            * round1outs[*j as usize - 1].masked_rs[k]
                    );
                    assert_eq!(
                        z_A.1[k] + z_B.1[k],
                        round1outs[i as usize - 1].masked_rs[k]
                            * round1outs[*j as usize - 1].masked_signing_key_shares[k]
                    );
                }
            }
        }

        // This is the final step where each signer generates his share of the signature without interaction
        // with any other signer and sends this share to the client
        let mut sig_shares_time = Duration::default();
        let mut sig_aggr_time = Duration::default();
        for k in 0..sig_batch_size as usize {
            let messages = (0..message_count)
                .into_iter()
                .map(|_| Fr::rand(&mut rng))
                .collect::<Vec<_>>();

            // Get shares from a threshold number of signers
            let mut shares = vec![];
            let start = Instant::now();
            for i in 0..threshold_signers as usize {
                let share = BBSSignatureShare::new(
                    &messages,
                    k,
                    &round1outs[i],
                    &round2_outputs[i],
                    &params,
                )
                .unwrap();
                shares.push(share);
            }
            sig_shares_time += start.elapsed();

            // Client aggregate the shares to get the final signature
            let start = Instant::now();
            let sig = BBSSignatureShare::aggregate(shares).unwrap();
            sig_aggr_time += start.elapsed();
            sig.verify(&messages, public_key.clone(), params.clone())
                .unwrap();
        }

        println!("Generating signature shares took {:?}", sig_shares_time);
        println!("Aggregating signature shares took {:?}", sig_aggr_time);
    }
}
