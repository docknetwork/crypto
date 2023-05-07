use crate::threshold::commitment::{Commitments, SALT_SIZE};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, Zero};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::RngCore,
    vec::Vec,
};
use digest::DynDigest;
use oblivious_transfer::ParticipantId;

use crate::{
    error::BBSPlusError,
    setup::{MultiMessageSignatureParams, SignatureParamsG1},
    signature::SignatureG1,
};

use super::{
    multiplication_phase::Phase2Output,
    utils::{compute_R_and_u, compute_masked_arguments_to_multiply},
};

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase1<F: PrimeField> {
    pub id: ParticipantId,
    pub r: F,
    pub commitment_protocol: super::commitment::Party<F>,
    pub zero_sharing_protocol: super::zero_sharing::Party<F>,
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase1Output<F: PrimeField> {
    pub id: ParticipantId,
    pub r: F,
    pub e: F,
    pub s: F,
    /// Additive share of the signing key masked by a random `alpha`
    pub masked_signing_key_share: F,
    /// Additive share of `r` masked by a random `beta`
    pub masked_r: F,
    pub others: Vec<ParticipantId>,
}

impl<F: PrimeField> Phase1<F> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        id: ParticipantId,
        others: BTreeSet<ParticipantId>,
        protocol_id: Vec<u8>,
    ) -> (Self, Commitments, BTreeMap<ParticipantId, Commitments>) {
        let r = F::rand(rng);
        let (commitment_protocol, comm) =
            super::commitment::Party::commit(rng, id, 2, protocol_id.clone());
        let (zero_sharing_protocol, comm_zero_share) =
            super::zero_sharing::Party::init(rng, id, 2, others, protocol_id);
        (
            Self {
                id,
                r,
                commitment_protocol,
                zero_sharing_protocol,
            },
            comm,
            comm_zero_share,
        )
    }

    pub fn get_comm_shares_and_salts(&self) -> Vec<(F, [u8; SALT_SIZE])> {
        self.commitment_protocol.own_shares_and_salts.clone()
    }

    pub fn get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(
        &self,
        other_id: &ParticipantId,
    ) -> Vec<(F, [u8; SALT_SIZE])> {
        // TODO: Remove unwrap
        self.zero_sharing_protocol
            .cointoss_protocols
            .get(other_id)
            .unwrap()
            .own_shares_and_salts
            .clone()
    }

    pub fn receive_commitment(
        &mut self,
        sender_id: ParticipantId,
        comm: Commitments,
        comm_zero_share: Commitments,
    ) -> Result<(), BBSPlusError> {
        self.commitment_protocol
            .receive_commitment(sender_id, comm)?;
        self.zero_sharing_protocol
            .receive_commitment(sender_id, comm_zero_share)?;
        Ok(())
    }

    pub fn receive_shares(
        &mut self,
        sender_id: ParticipantId,
        shares: Vec<(F, [u8; SALT_SIZE])>,
        comm_zero_shares: Vec<(F, [u8; SALT_SIZE])>,
    ) -> Result<(), BBSPlusError> {
        self.commitment_protocol.receive_shares(sender_id, shares)?;
        self.zero_sharing_protocol
            .receive_shares(sender_id, comm_zero_shares)?;
        Ok(())
    }

    pub fn finish<D: Default + DynDigest + Clone>(
        self,
        signing_key: &F,
    ) -> Result<Phase1Output<F>, BBSPlusError> {
        // TODO: Ensure every one has participated in both protocols
        let others = self
            .commitment_protocol
            .other_shares
            .keys()
            .map(|p| *p)
            .collect::<Vec<_>>();
        let mut es = self.commitment_protocol.compute_joint_randomness();
        let zero_shares = self.zero_sharing_protocol.compute_zero_shares::<D>()?;
        debug_assert_eq!(es.len(), 2);
        let e = es.pop().unwrap();
        let s = es.pop().unwrap();
        let (masked_signing_key_share, masked_r) = compute_masked_arguments_to_multiply(
            signing_key,
            &self.r,
            zero_shares,
            self.id,
            &others,
        );
        Ok(Phase1Output {
            id: self.id,
            r: self.r,
            e,
            s,
            masked_signing_key_share,
            masked_r,
            others,
        })
    }
}

pub struct BBSPlusSignatureShare<E: Pairing> {
    pub id: ParticipantId,
    pub e: E::ScalarField,
    pub s: E::ScalarField,
    pub u: E::ScalarField,
    pub R: E::G1Affine,
}

impl<E: Pairing> BBSPlusSignatureShare<E> {
    pub fn new(
        messages: &[E::ScalarField],
        phase1: Phase1Output<E::ScalarField>,
        phase1_ote: Phase2Output<E::ScalarField>,
        sig_params: &SignatureParamsG1<E>,
    ) -> Result<Self, BBSPlusError> {
        if messages.is_empty() {
            return Err(BBSPlusError::NoMessageToSign);
        }
        if messages.len() != sig_params.supported_message_count() {
            return Err(BBSPlusError::MessageCountIncompatibleWithSigParams(
                messages.len(),
                sig_params.supported_message_count(),
            ));
        }
        // Create map of msg index (0-based) -> message
        let msg_map: BTreeMap<usize, &E::ScalarField> =
            messages.iter().enumerate().map(|(i, e)| (i, e)).collect();
        Self::new_with_committed_messages(
            &E::G1Affine::zero(),
            msg_map,
            phase1,
            phase1_ote,
            sig_params,
        )
    }

    pub fn new_with_committed_messages(
        commitment: &E::G1Affine,
        uncommitted_messages: BTreeMap<usize, &E::ScalarField>,
        phase1: Phase1Output<E::ScalarField>,
        phase2: Phase2Output<E::ScalarField>,
        sig_params: &SignatureParamsG1<E>,
    ) -> Result<Self, BBSPlusError> {
        let b = sig_params.b(uncommitted_messages, &phase1.s)?;
        let commitment_plus_b = b + commitment;
        let (R, u) = compute_R_and_u(
            commitment_plus_b,
            phase1.r,
            phase1.e,
            phase1.masked_r,
            phase1.masked_signing_key_share,
            phase2,
        );
        Ok(Self {
            id: phase1.id,
            e: phase1.e,
            s: phase1.s,
            u,
            R,
        })
    }

    pub fn aggregate(sig_shares: Vec<Self>) -> Result<SignatureG1<E>, BBSPlusError> {
        // TODO: Ensure correct threshold. Share should contain threshold and share id
        let mut sum_R = E::G1::zero();
        let mut sum_u = E::ScalarField::zero();
        let mut expected_e = E::ScalarField::zero();
        let mut expected_s = E::ScalarField::zero();
        for (i, share) in sig_shares.into_iter().enumerate() {
            if i == 0 {
                expected_e = share.e;
                expected_s = share.s;
            } else {
                if expected_e != share.e {
                    return Err(BBSPlusError::IncorrectEByParticipant(share.id));
                }
                if expected_s != share.s {
                    return Err(BBSPlusError::IncorrectSByParticipant(share.id));
                }
            }
            sum_u += share.u;
            sum_R += share.R;
        }
        let A = sum_R * sum_u.inverse().unwrap();
        Ok(SignatureG1 {
            A: A.into_affine(),
            e: expected_e,
            s: expected_s,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_ff::Zero;
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};

    use crate::{
        setup::{PublicKeyG2, SecretKey},
        threshold::{
            base_ot_phase::tests::do_base_ot_for_threshold_sig, multiplication_phase::Phase2,
        },
    };
    use oblivious_transfer::ot_based_multiplication::{
        dkls18_mul_2p::MultiplicationOTEParams, dkls19_batch_mul_2p::GadgetVector,
    };

    use ark_std::{
        cfg_into_iter,
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;

    use rayon::prelude::*;

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    // TODO: Remove and use from other crate
    pub fn deal_random_secret<R: RngCore, F: PrimeField>(
        rng: &mut R,
        threshold: ParticipantId,
        total: ParticipantId,
    ) -> (F, Vec<F>, DensePolynomial<F>) {
        let secret = F::rand(rng);
        let (shares, poly) = deal_secret(rng, secret.clone(), threshold, total);
        (secret, shares, poly)
    }
    pub fn deal_secret<R: RngCore, F: PrimeField>(
        rng: &mut R,
        secret: F,
        threshold: ParticipantId,
        total: ParticipantId,
    ) -> (Vec<F>, DensePolynomial<F>) {
        let mut coeffs = Vec::with_capacity(threshold as usize);
        coeffs.append(&mut (0..threshold - 1).map(|_| F::rand(rng)).collect());
        coeffs.insert(0, secret);
        let poly = DensePolynomial::from_coefficients_vec(coeffs);
        let shares = cfg_into_iter!((1..=total))
            .map(|i| poly.evaluate(&F::from(i as u64)))
            .collect::<Vec<_>>();
        (shares, poly)
    }

    #[test]
    fn signing() {
        let mut rng = StdRng::seed_from_u64(0u64);
        const BASE_OT_KEY_SIZE: u16 = 128;
        const KAPPA: u16 = 256;
        const STATISTICAL_SECURITY_PARAMETER: u16 = 80;
        let ote_params = MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};
        let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<
            Blake2b512,
        >(ote_params, b"test");

        let protocol_id = b"test".to_vec();

        let num_parties = 5;
        let all_party_set = (1..=num_parties).into_iter().collect::<BTreeSet<_>>();
        let (sk, sk_shares, _poly) =
            deal_random_secret::<_, Fr>(&mut rng, num_parties, num_parties);

        let base_ot_outputs = do_base_ot_for_threshold_sig::<BASE_OT_KEY_SIZE>(
            &mut rng,
            ote_params.num_base_ot(),
            num_parties,
            all_party_set.clone(),
        );

        let mut round1s = vec![];
        let mut commitments = vec![];
        let mut commitments_zero_share = vec![];
        let mut round1outs = vec![];

        for i in 1..=num_parties {
            let mut others = all_party_set.clone();
            others.remove(&i);
            let (round1, comm, comm_zero) =
                Phase1::<Fr>::init(&mut rng, i, others, protocol_id.clone());
            round1s.push(round1);
            commitments.push(comm);
            commitments_zero_share.push(comm_zero);
        }

        for i in 1..=num_parties {
            for j in 1..=num_parties {
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

        for i in 1..=num_parties {
            for j in 1..=num_parties {
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

        let mut expected_sk = Fr::zero();
        for (i, round1) in round1s.into_iter().enumerate() {
            let out = round1.finish::<Blake2b512>(&sk_shares[i]).unwrap();
            expected_sk += out.masked_signing_key_share;
            round1outs.push(out);
        }
        assert_eq!(expected_sk, sk);

        for i in 1..num_parties {
            assert_eq!(round1outs[0].e, round1outs[i as usize].e);
            assert_eq!(round1outs[0].s, round1outs[i as usize].s);
        }

        let mut round2s = vec![];
        let mut all_u = vec![];

        for i in 1..=num_parties {
            let mut others = all_party_set.clone();
            others.remove(&i);
            let (phase, U) = Phase2::init(
                &mut rng,
                i,
                round1outs[i as usize - 1].masked_signing_key_share,
                round1outs[i as usize - 1].masked_r,
                base_ot_outputs[i as usize - 1].clone(),
                others,
                ote_params,
                &gadget_vector,
            )
            .unwrap();
            round2s.push(phase);
            all_u.push((i, U));
        }

        let mut all_tau = vec![];
        for (sender_id, U) in all_u {
            for (receiver_id, (U_i, rlc, gamma)) in U {
                let (tau, r, gamma) = round2s[receiver_id as usize - 1]
                    .receive_u::<Blake2b512>(sender_id, U_i, rlc, gamma, &gadget_vector)
                    .unwrap();
                all_tau.push((receiver_id, sender_id, (tau, r, gamma)));
            }
        }

        for (sender_id, receiver_id, (tau, r, gamma)) in all_tau {
            round2s[receiver_id as usize - 1]
                .receive_tau::<Blake2b512>(sender_id, tau, r, gamma, &gadget_vector)
                .unwrap();
        }

        let round2_outputs = round2s.into_iter().map(|p| p.finish()).collect::<Vec<_>>();

        for i in 1..=num_parties {
            for (j, z_A) in &round2_outputs[i as usize - 1].z_A {
                let z_B = round2_outputs[*j as usize - 1].z_B.get(&i).unwrap();
                assert_eq!(
                    z_A.0 + z_B.0,
                    round1outs[i as usize - 1].masked_signing_key_share
                        * round1outs[*j as usize - 1].masked_r
                );
                assert_eq!(
                    z_A.1 + z_B.1,
                    round1outs[i as usize - 1].masked_r
                        * round1outs[*j as usize - 1].masked_signing_key_share
                );
            }
        }

        let message_count = 10;
        let messages = (0..message_count)
            .into_iter()
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let _message_map = messages
            .iter()
            .enumerate()
            .map(|m| m)
            .collect::<BTreeMap<_, _>>();
        let params = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng, message_count);
        let public_key = PublicKeyG2::generate_using_secret_key(&SecretKey(sk), &params);

        let mut shares = vec![];
        for i in 0..num_parties as usize {
            let share = BBSPlusSignatureShare::new(
                &messages,
                round1outs[i].clone(),
                round2_outputs[i].clone(),
                &params,
            )
            .unwrap();
            shares.push(share);
        }

        let sig = BBSPlusSignatureShare::aggregate(shares).unwrap();
        sig.verify(&messages, public_key, params).unwrap();
    }
}
