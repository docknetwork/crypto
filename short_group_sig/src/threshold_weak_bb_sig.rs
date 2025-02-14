//! Threshold weak-BB signature generation
//!
//! A weak-BB signature is of the form `g*1/(sk+m)` where `sk` is the signer's secret key and `m` is the message.
//! This is based on the multiplication technique described in the paper on [threshold BBS+](https://eprint.iacr.org/2023/602)
//!
//! This describes 2 variations of getting a threshold weak-BB signature:
//!
//! 1. Each signer has a secret key share `sk_i` and the full message `m`
//! 2. Each signer has a secret key share `sk_i` and a share of the message as `m_i`
//!
//! Both `sk` and `m` (in case of second variation) are assumed to be shared using Shamir secret sharing (or a DKG based on that)
//!
//! The high level idea is:
//! - Each signer samples a random value `r_i`. The sum of these random values is called `r` as `r = \sum{r_i}`
//! - The signers jointly compute a product of `u = r*(sk+m)` such that each signer `i` has a share of it as `u_i` such that `u = \sum{u_i}`
//! - Each signer sends to the user `R_i, u_i` to the user where `R_i = g*r_i`.
//! - User combines these to form `R = \sum{R_i} = g*\sum{r_i} = g*r` and `u = \sum{u_i} = r*(sk+m)`. Now `R * 1/u = g*1/(sk+m)`
//!
//! The protocol proceeds in 2 phases:
//!
//! 1. **Phase 1**: This is a 2 round protocol, independent of the message `m` and generates randomness, like `r_i` (and other
//!    blindings to be used in MPC multiplication protocol).
//! 2. **Phase 2**
//!    - for variation 1: Here the parties run a 2 round MPC multiplication protocol where each party's input is `(r_i, (sk_i + m))` and output is `(g*r_i, u_i)`
//!    where `u_i` is a share of `r*(sk+m)` such that `\sum{u_i} = r*(sk+m)`. `(g*r_i, u_i)` is called the `SigShare` and user can combine
//!    these shares from all signers to get `g*1/(sk+m)` as described above.
//!    - for variation 2: Here the parties run a 2 round MPC multiplication protocol where each party's input is `(r_i, (sk_i + m_i))` and output is `(g*r_i, u_i)`
//!    where `u_i` is a share of `r*(sk+m)` such that `\sum{u_i} = r*(sk+m)`. `(g*r_i, u_i)` is called the `SigShare` and user can combine
//!    these shares from all signers to get `g*1/(sk+m)` as described above.

use crate::error::ShortGroupSigError;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::RngCore,
    vec,
    vec::Vec,
};
use core::fmt::Debug;
use digest::{Digest, DynDigest, ExtendableOutput, Update};
pub use oblivious_transfer_protocols::{
    cointoss::Commitments,
    error::OTError,
    ot_based_multiplication::{
        base_ot_multi_party_pairwise::BaseOTOutput,
        batch_mul_multi_party::{Message1, Message2, Participant as MultPart},
        dkls18_mul_2p::MultiplicationOTEParams,
        dkls19_batch_mul_2p::GadgetVector,
    },
    zero_sharing, ParticipantId,
};

/// This is the first phase of signing where signers generate randomness.
/// This phase is independent of the message to be signed and thus can be treated as precomputation.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase1<F: PrimeField, const SALT_SIZE: usize> {
    pub id: ParticipantId,
    /// Blinding of `(m_i + sk_i)`. Used in multiplication as `r*(m_i + sk_i)`
    pub r: F,
    /// Protocols to generate shares of 0s. These will be used to blind the inputs to the multiplication
    pub zero_sharing_protocol: zero_sharing::Party<F, SALT_SIZE>,
}

/// Output of a signer when Phase 1 finishes
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase1Output<F: PrimeField> {
    pub id: ParticipantId,
    pub r: F,
    pub others: BTreeSet<ParticipantId>,
    /// Blinding for signing key term to be added before multiplication
    pub blinding_sk_term: F,
    /// Blinding for randomness to be added before multiplication
    pub blinding_r: F,
}

/// This is the second and last phase of signing where signers use the output of phase 1 to generate
/// a signature share to be sent to the user.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase2<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16> {
    inner: MultPart<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    pub id: ParticipantId,
    /// Set to None when the full message is not known to the signers but only a share is
    pub message: Option<F>,
    pub r: F,
    /// Each signer's share of `r` but masked with a random pad `alpha`, i.e. `masked_r_share = r_share + alpha`
    pub masked_r_share: F,
    /// In case the message is fully known to the signers, it's the share of signer's secret key masked with a
    /// random pad `beta`, i.e. `masked_sk_term_share = sk_share + beta`
    /// In case only a share of the message is known to the signers, it's the share of signer's secret key and message
    /// share masked with a random pad `beta`, i.e. `masked_sk_term_share = sk_share + message_share + beta`
    pub masked_sk_term_share: F,
}

/// Share of the signature created by a signer at the end of phase 2. The user collects these shares
/// and aggregates to form a complete signature that can be verified using the threshold public key
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SigShare<G: AffineRepr> {
    pub signer_id: ParticipantId,
    pub u: G::ScalarField,
    pub R: G,
}

impl<F: PrimeField, const SALT_SIZE: usize> Phase1<F, SALT_SIZE> {
    pub fn init<R: RngCore, D: Digest>(
        rng: &mut R,
        id: ParticipantId,
        others: BTreeSet<ParticipantId>,
        protocol_id: Vec<u8>,
    ) -> Result<(Self, BTreeMap<ParticipantId, Commitments>), ShortGroupSigError> {
        if others.contains(&id) {
            let e = OTError::ParticipantCannotBePresentInOthers(id);
            return Err(ShortGroupSigError::OTError(e));
        }
        let r = F::rand(rng);
        let (zero_sharing_protocol, comm_zero_share) =
            zero_sharing::Party::init::<R, D>(rng, id, 2, others, protocol_id);
        Ok((
            Self {
                id,
                r,
                zero_sharing_protocol,
            },
            comm_zero_share,
        ))
    }

    pub fn finish<D: Default + DynDigest + Clone>(
        self,
    ) -> Result<Phase1Output<F>, ShortGroupSigError> {
        // TODO: Ensure every one has participated in both protocols
        let id = self.id;
        let r = self.r.clone();

        let others = self
            .zero_sharing_protocol
            .cointoss_protocols
            .keys()
            .map(|p| *p)
            .collect();
        let mut zero_shares = self.zero_sharing_protocol.compute_zero_shares::<D>()?;
        let blinding_r = zero_shares.pop().unwrap();
        let blinding_sk_term = zero_shares.pop().unwrap();

        Ok(Phase1Output {
            id,
            r,
            others,
            blinding_r,
            blinding_sk_term,
        })
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
        comm_zero_share: Commitments,
    ) -> Result<(), ShortGroupSigError> {
        self.zero_sharing_protocol
            .receive_commitment(sender_id, comm_zero_share)?;
        Ok(())
    }

    pub fn receive_shares<D: Digest>(
        &mut self,
        sender_id: ParticipantId,
        zero_shares: Vec<(F, [u8; SALT_SIZE])>,
    ) -> Result<(), ShortGroupSigError> {
        self.zero_sharing_protocol
            .receive_shares::<D>(sender_id, zero_shares)?;
        Ok(())
    }

    pub fn ready_to_compute_randomness_and_arguments_for_multiplication(&self) -> bool {
        self.zero_sharing_protocol
            .has_shares_from_all_who_committed()
    }
}

impl<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16>
    Phase2<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>
{
    /// The returned map contains the messages that need to be sent to the parties with corresponding
    /// key in the map
    pub fn init_for_known_message<R: RngCore, X: Default + Update + ExtendableOutput>(
        rng: &mut R,
        id: ParticipantId,
        signing_key: F,
        message: F,
        phase_1_output: Phase1Output<F>,
        base_ot_output: BaseOTOutput,
        ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        label: &'static [u8],
    ) -> Result<(Self, BTreeMap<ParticipantId, Message1<F>>), ShortGroupSigError> {
        let lambda = Self::lagrange_coeff(&phase_1_output)?;
        Self::init::<R, X>(
            rng,
            id,
            signing_key * lambda,
            Some(message),
            phase_1_output,
            base_ot_output,
            ote_params,
            gadget_vector,
            label,
        )
    }

    /// Assumes that the message share provided was created using Shamir secret sharing.
    /// The returned map contains the messages that need to be sent to the parties with corresponding
    /// key in the map
    pub fn init_for_shared_message<R: RngCore, X: Default + Update + ExtendableOutput>(
        rng: &mut R,
        id: ParticipantId,
        signing_key: F,
        message_share: F,
        phase_1_output: Phase1Output<F>,
        base_ot_output: BaseOTOutput,
        ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        label: &'static [u8],
    ) -> Result<(Self, BTreeMap<ParticipantId, Message1<F>>), ShortGroupSigError> {
        let lambda = Self::lagrange_coeff(&phase_1_output)?;
        Self::init::<R, X>(
            rng,
            id,
            (signing_key + message_share) * lambda,
            None,
            phase_1_output,
            base_ot_output,
            ote_params,
            gadget_vector,
            label,
        )
    }

    /// Process received `Message1` from signer with id `sender_id`
    pub fn receive_message1<
        D: Default + DynDigest + Clone,
        X: Default + Update + ExtendableOutput,
    >(
        &mut self,
        sender_id: ParticipantId,
        message: Message1<F>,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<Message2<F>, ShortGroupSigError> {
        self.inner
            .receive_message1::<D, X>(sender_id, message, gadget_vector)
            .map_err(|e| e.into())
    }

    /// Process received `Message2` from signer with id `sender_id`
    pub fn receive_message2<D: Default + DynDigest + Clone>(
        &mut self,
        sender_id: ParticipantId,
        message: Message2<F>,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<(), ShortGroupSigError> {
        self.inner
            .receive_message2::<D>(sender_id, message, gadget_vector)
            .map_err(|e| e.into())
    }

    pub fn finish<G: AffineRepr<ScalarField = F>>(self, pk_gen: &G) -> SigShare<G> {
        let inner = self.inner.finish();
        let R = pk_gen.mul(self.r).into_affine();
        let u = if let Some(message) = self.message {
            // Message was fully known to the signer
            self.masked_r_share * (message + self.masked_sk_term_share) + inner.compute_u(0)
        } else {
            // Only a share of the message was known to the signer. Not adding the message since its share is already part of `masked_sk_term_share`
            self.masked_r_share * self.masked_sk_term_share + inner.compute_u(0)
        };
        SigShare {
            signer_id: self.id,
            u,
            R,
        }
    }

    fn init<R: RngCore, X: Default + Update + ExtendableOutput>(
        rng: &mut R,
        id: ParticipantId,
        signing_key_term: F,
        message: Option<F>,
        phase_1_output: Phase1Output<F>,
        base_ot_output: BaseOTOutput,
        ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        label: &'static [u8],
    ) -> Result<(Self, BTreeMap<ParticipantId, Message1<F>>), ShortGroupSigError> {
        let masked_r_share = phase_1_output.blinding_r + phase_1_output.r;
        let masked_sk_term_share = phase_1_output.blinding_sk_term + signing_key_term;
        let (inner, msgs) = MultPart::<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>::init::<R, X>(
            rng,
            id,
            vec![masked_sk_term_share],
            vec![masked_r_share],
            base_ot_output,
            phase_1_output.others,
            ote_params,
            gadget_vector,
            label,
        )?;
        Ok((
            Self {
                inner,
                id: phase_1_output.id,
                message,
                r: phase_1_output.r,
                masked_r_share,
                masked_sk_term_share,
            },
            msgs,
        ))
    }

    fn lagrange_coeff(phase_1_output: &Phase1Output<F>) -> Result<F, ShortGroupSigError> {
        secret_sharing_and_dkg::common::lagrange_basis_at_0::<F>(
            &phase_1_output.others.iter().map(|x| *x).collect::<Vec<_>>(),
            phase_1_output.id,
        )
        .map_err(|e| e.into())
    }
}

impl<G: AffineRepr> SigShare<G> {
    pub fn aggregate(shares: Vec<Self>) -> G {
        let mut sum_R = G::Group::zero();
        let mut sum_u = G::ScalarField::zero();
        for share in shares {
            sum_u += share.u;
            sum_R += share.R;
        }
        (sum_R * sum_u.inverse().unwrap()).into_affine()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        common::SignatureParams,
        weak_bb_sig::{PublicKeyG2, SecretKey, SignatureG1},
    };
    use ark_bls12_381::{Bls12_381, Fr, G1Affine};
    use ark_ff::Zero;
    use ark_std::{
        rand::{prelude::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use oblivious_transfer_protocols::ot_based_multiplication::{
        base_ot_multi_party_pairwise::BaseOTOutput, dkls18_mul_2p::MultiplicationOTEParams,
        dkls19_batch_mul_2p::GadgetVector,
    };
    use secret_sharing_and_dkg::shamir_ss::{deal_random_secret, deal_secret};
    use sha3::Shake256;
    use std::time::Instant;
    use test_utils::ot::do_pairwise_base_ot;

    const BASE_OT_KEY_SIZE: u16 = 128;
    const KAPPA: u16 = 256;
    const STATISTICAL_SECURITY_PARAMETER: u16 = 80;
    const OTE_PARAMS: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER> =
        MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};

    /// Just for testing, let a trusted party do the keygen and give each signer its keushare
    pub fn trusted_party_keygen(
        rng: &mut StdRng,
        threshold: ParticipantId,
        total: ParticipantId,
    ) -> (Fr, Vec<Fr>) {
        let (secret, shares, _) = deal_random_secret(rng, threshold, total).unwrap();
        (secret, shares.0.into_iter().map(|s| s.share).collect())
    }

    fn do_phase1(
        rng: &mut StdRng,
        threshold_signers: ParticipantId,
        protocol_id: Vec<u8>,
    ) -> Vec<Phase1Output<Fr>> {
        let threshold_party_set = (1..=threshold_signers).into_iter().collect::<BTreeSet<_>>();

        let mut phase1s = vec![];
        let mut commitments_zero_share = vec![];

        // Signers initiate round-1 and each signer sends commitments to others
        let start = Instant::now();
        for i in 1..=threshold_signers {
            let mut others = threshold_party_set.clone();
            others.remove(&i);
            let (round1, comm_zero) =
                Phase1::<Fr, 256>::init::<_, Blake2b512>(rng, i, others, protocol_id.clone())
                    .unwrap();
            phase1s.push(round1);
            commitments_zero_share.push(comm_zero);
        }

        // Signers process round-1 commitments received from others
        for i in 1..=threshold_signers {
            for j in 1..=threshold_signers {
                if i != j {
                    phase1s[i as usize - 1]
                        .receive_commitment(
                            j,
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
                    let zero_share = phase1s[j as usize - 1]
                        .get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&i);
                    phase1s[i as usize - 1]
                        .receive_shares::<Blake2b512>(j, zero_share)
                        .unwrap();
                }
            }
        }

        // Signers finish round-1 to generate the output
        let phase1_outputs = phase1s
            .into_iter()
            .map(|p| p.finish::<Blake2b512>().unwrap())
            .collect::<Vec<_>>();
        println!("Phase 1 took {:?}", start.elapsed());
        phase1_outputs
    }

    /// Pass `full_message` if all signers know the full message. Pass `message_shares` if each signer knows
    /// only a share of the original message.
    fn do_phase2(
        rng: &mut StdRng,
        threshold_signers: ParticipantId,
        gadget_vector: &GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        pk_gen: &G1Affine,
        base_ot_outputs: &[BaseOTOutput],
        phase1_outs: &[Phase1Output<Fr>],
        expected_sk_term: Fr,
        secret_key_shares: &[Fr],
        full_message: Option<Fr>,
        message_shares: Option<Vec<Fr>>,
    ) -> Vec<SigShare<G1Affine>> {
        let mut phase2s = vec![];
        let mut all_msg_1s = vec![];

        let label = b"test";

        // Only one of them should be set
        assert!(full_message.is_some() ^ message_shares.is_some());
        let known_message = full_message.is_some();
        let full_message = full_message.unwrap_or_default();
        let message_shares = message_shares.unwrap_or_default();

        // Signers initiate round-2 and each signer sends messages to others
        let start = Instant::now();
        for i in 1..=threshold_signers {
            let (phase, msgs) = if known_message {
                Phase2::init_for_known_message::<_, Shake256>(
                    rng,
                    i,
                    secret_key_shares[i as usize - 1],
                    full_message,
                    phase1_outs[i as usize - 1].clone(),
                    base_ot_outputs[i as usize - 1].clone(),
                    OTE_PARAMS,
                    &gadget_vector,
                    label,
                )
                .unwrap()
            } else {
                Phase2::init_for_shared_message::<_, Shake256>(
                    rng,
                    i,
                    secret_key_shares[i as usize - 1],
                    message_shares[i as usize - 1],
                    phase1_outs[i as usize - 1].clone(),
                    base_ot_outputs[i as usize - 1].clone(),
                    OTE_PARAMS,
                    &gadget_vector,
                    label,
                )
                .unwrap()
            };
            phase2s.push(phase);
            all_msg_1s.push((i, msgs));
        }

        let mut sk_term = Fr::zero();
        for p in &phase2s {
            sk_term += p.masked_sk_term_share
        }
        assert_eq!(expected_sk_term, sk_term);

        // Signers process round-2 messages received from others
        let mut all_msg_2s = vec![];
        for (sender_id, msg_1s) in all_msg_1s {
            for (receiver_id, m) in msg_1s {
                let m2 = phase2s[receiver_id as usize - 1]
                    .receive_message1::<Blake2b512, Shake256>(sender_id, m, &gadget_vector)
                    .unwrap();
                all_msg_2s.push((receiver_id, sender_id, m2));
            }
        }

        for (sender_id, receiver_id, m2) in all_msg_2s {
            phase2s[receiver_id as usize - 1]
                .receive_message2::<Blake2b512>(sender_id, m2, &gadget_vector)
                .unwrap();
        }

        let sig_shares = phase2s
            .into_iter()
            .map(|p| p.finish(pk_gen))
            .collect::<Vec<_>>();
        println!("Phase 2 took {:?}", start.elapsed());
        sig_shares
    }

    #[test]
    fn known_message() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let sig_params = SignatureParams::<Bls12_381>::generate_using_rng(&mut rng);
        let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<
            Blake2b512,
        >(OTE_PARAMS, b"test-gadget-vector");

        for (threshold_signers, total_signers) in [(5, 8), (15, 25), (20, 30)] {
            println!("\n\nFor {}-of-{}", threshold_signers, total_signers);
            let all_party_set = (1..=total_signers).into_iter().collect::<BTreeSet<_>>();

            // The signers do a keygen. This is a one time setup.
            let (sk, sk_shares) = trusted_party_keygen(&mut rng, threshold_signers, total_signers);
            // Public key created by the trusted party using the secret key directly. In practice, this will be a result of a DKG
            let pk = PublicKeyG2::generate_using_secret_key(&SecretKey(sk), &sig_params);

            // The signers run OT protocol instances. This is also a one time setup.
            let base_ot_outputs = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
                &mut rng,
                OTE_PARAMS.num_base_ot(),
                total_signers,
                all_party_set.clone(),
            );

            let protocol_id = b"test".to_vec();

            let phase1_outs = do_phase1(&mut rng, threshold_signers, protocol_id.clone());

            let message = Fr::rand(&mut rng);
            let sig_shares = do_phase2(
                &mut rng,
                threshold_signers,
                &gadget_vector,
                &sig_params.g1,
                &base_ot_outputs,
                &phase1_outs,
                sk,
                &sk_shares,
                Some(message),
                None,
            );

            let start = Instant::now();
            let aggregated_sig = SigShare::aggregate(sig_shares);
            println!(
                "Aggregating {} shares took {:?}",
                threshold_signers,
                start.elapsed()
            );
            SignatureG1(aggregated_sig)
                .verify(&message, &pk, &sig_params)
                .unwrap();
        }
    }

    #[test]
    fn shared_message() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let sig_params = SignatureParams::<Bls12_381>::generate_using_rng(&mut rng);
        let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<
            Blake2b512,
        >(OTE_PARAMS, b"test-gadget-vector");

        for (threshold_signers, total_signers) in [(5, 8), (15, 25), (20, 30)] {
            println!("\n\nFor {}-of-{}", threshold_signers, total_signers);
            let all_party_set = (1..=total_signers).into_iter().collect::<BTreeSet<_>>();

            // The signers do a keygen. This is a one time setup.
            let (sk, sk_shares) = trusted_party_keygen(&mut rng, threshold_signers, total_signers);
            // Public key created by the trusted party using the secret key directly. In practice, this will be a result of a DKG
            let pk = PublicKeyG2::generate_using_secret_key(&SecretKey(sk), &sig_params);

            // The signers run OT protocol instances. This is also a one time setup.
            let base_ot_outputs = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
                &mut rng,
                OTE_PARAMS.num_base_ot(),
                total_signers,
                all_party_set.clone(),
            );

            let protocol_id = b"test".to_vec();

            let phase1_outs = do_phase1(&mut rng, threshold_signers, protocol_id.clone());

            let message = Fr::rand(&mut rng);
            let (message_shares, _) =
                deal_secret::<StdRng, Fr>(&mut rng, message, threshold_signers, total_signers)
                    .unwrap();

            let sig_shares = do_phase2(
                &mut rng,
                threshold_signers,
                &gadget_vector,
                &sig_params.g1,
                &base_ot_outputs,
                &phase1_outs,
                sk + message,
                &sk_shares,
                None,
                Some(
                    message_shares
                        .0
                        .into_iter()
                        .map(|share| share.share)
                        .collect(),
                ),
            );

            let start = Instant::now();
            let aggregated_sig = SigShare::aggregate(sig_shares);
            println!(
                "Aggregating {} shares took {:?}",
                threshold_signers,
                start.elapsed()
            );
            SignatureG1(aggregated_sig)
                .verify(&message, &pk, &sig_params)
                .unwrap();
        }
    }
}
