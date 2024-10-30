//! Threshold issuance in SyRA. The secret key is shared among signers using Shamir secret sharing and they jointly generate
//! SyRA VRF.
//!
//! Note: Multiplicative notation is used
//!
//! SyRA VRF described in Fig. 4 of the paper is of the form `(g^1/(sk+s), g_hat^1/(sk+s))` where `sk` is the signer's secret key
//! and `s` is the user-id and `g, g_hat` are public parameters. This is similar to a weak-BB signature which has the form
//! `g^1/(sk+s)`. So SyRA VRF is essentially 2 weak-BB signatures. So I use the protocol for threshold weak-BB signature from
//! the corresponding package.
//!
//! The high level idea is:
//! - The signers jointly compute a random value `r` such that each signer `i` has a share of it as `r_i` such that `r = \sum{r_i}`
//! - The signers jointly compute a product of `u = r*(sk+s)` such that each signer `i` has a share of it as `u_i` such that `u = \sum{u_i}`
//! - Each signer sends to the user `R_i, R_hat_i, S_i, u_i` to the user where `R_i = g^r_i, R_hat_i = g_hat^r_i, S_i = e(g, g_hat)^r_i`.
//! - User combines these to form `R = \prod{R_i} = g^\prod{r_i} = g^r`, `R_hat = \prod{R_hat_i} = g_hat^\prod{r_i} = g_hat^r`,
//!   `S = \prod{S_i} = e(g, g_hat)^\sum{r_i} = e(g, g_hat)^r` and `u = \sum{u_i} = r*(sk+s)`. Now `R^1/u = g^1/(sk+s)`,
//!   `R_hat^1/u = g_hat^1/(sk+s)` and `S^1/u = e(g, g_hat)^1/(sk+s)`
//! - User uses `R, R_hat, S` to verify its secret key as per Fig.4
//!
//! The protocol proceeds in 2 phases:
//!
//! 1. **Phase 1**: This is a 2 round protocol, independent of the message `m` and generates randomness, like `r_i` (and other
//!    blindings to be used in MPC multiplication protocol).
//! 2. **Phase 2**: Here the parties run a 2 round MPC multiplication protocol where each party's input is `(r_i, (sk_i + m))` and output
//!    is `(g^r_i, g_hat^r_i, e(g, g_hat)^r_i, u_i)` where `u_i` is a share of `r*(sk+m)` such that `\sum{u_i} = r*(sk+m)`.
//!    `(g^r_i, g_hat^r_i, e(g, g_hat)^r_i, u_i)` is called the `UserSecretKeyShare` and user can combine
//!    these shares from all signers to get `g^1/(sk+m), g_hat^1/(sk+s), e(g, g_hat)^1/(sk+s)` as described above.

use crate::{
    error::SyraError,
    setup::{IssuerSecretKey, PreparedSetupParams, UserSecretKey},
    vrf::{Output, Proof},
};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    CurveGroup,
};
use ark_ff::{Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{collections::BTreeMap, ops::Mul, rand::RngCore, vec::Vec};
use digest::DynDigest;
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use short_group_sig::threshold_weak_bb_sig::{
    BaseOTOutput, GadgetVector, Message1, Message2, MultiplicationOTEParams, ParticipantId,
    Phase1Output, SigShare,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

// NOTE: Phase 1 is exactly identical to the Phase1 of weak-BB signature so that can be used as it is.

/// This is the second and last phase of signing where signers use the output of phase 1 to generate
/// a signature share to be sent to the user.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase2<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16>(
    pub short_group_sig::threshold_weak_bb_sig::Phase2<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
);

/// Share of the user secret key given by a single signer at the end of phase 2. The user collects these shares
/// and aggregates to form a complete user secret key that can be verified using the threshold public key
#[serde_as]
#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
    Zeroize,
    ZeroizeOnDrop,
)]
pub struct UserSecretKeyShare<E: Pairing> {
    pub signer_id: ParticipantId,
    /// `g^r_i`
    #[serde_as(as = "ArkObjectBytes")]
    pub R: E::G1Affine,
    /// `g_hat^r_i`
    #[serde_as(as = "ArkObjectBytes")]
    pub R_hat: E::G2Affine,
    /// `e(g, g_hat)^r_i`
    #[serde_as(as = "ArkObjectBytes")]
    pub S: PairingOutput<E>,
    /// Share of `r*(sk+s)` where `s` is user-id
    #[serde_as(as = "ArkObjectBytes")]
    pub u: E::ScalarField,
}

impl<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16>
    Phase2<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>
{
    /// This internally uses `init_for_known_message` of threshold weak-BB signature as the signers must
    /// know the full message which here is the user id. This is important to prevent the user from
    /// getting multiple signatures over the arbitrary user ids. A way to achieve signing with user-id
    /// shares could be for the user to prove that the shares belong to "certain user-id" (likely in a commitment)
    pub fn init<R: RngCore>(
        rng: &mut R,
        id: ParticipantId,
        issuer_sk: &IssuerSecretKey<F>,
        user_id: F,
        phase_1_output: Phase1Output<F>,
        base_ot_output: BaseOTOutput,
        ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        label: &'static [u8],
    ) -> Result<(Self, BTreeMap<ParticipantId, Message1<F>>), SyraError> {
        let (inner, m) = short_group_sig::threshold_weak_bb_sig::Phase2::<
            F,
            KAPPA,
            STATISTICAL_SECURITY_PARAMETER,
        >::init_for_known_message(
            rng,
            id,
            issuer_sk.0,
            user_id,
            phase_1_output,
            base_ot_output,
            ote_params,
            gadget_vector,
            label,
        )?;
        Ok((Self(inner), m))
    }

    /// Process received `Message1` from signer with id `sender_id`
    pub fn receive_message1<D: Default + DynDigest + Clone>(
        &mut self,
        sender_id: ParticipantId,
        message: Message1<F>,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<Message2<F>, SyraError> {
        self.0
            .receive_message1::<D>(sender_id, message, gadget_vector)
            .map_err(|e| e.into())
    }

    /// Process received `Message2` from signer with id `sender_id`
    pub fn receive_message2<D: Default + DynDigest + Clone>(
        &mut self,
        sender_id: ParticipantId,
        message: Message2<F>,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<(), SyraError> {
        self.0
            .receive_message2::<D>(sender_id, message, gadget_vector)
            .map_err(|e| e.into())
    }

    /// Finish phase 2 to get the user secret key share to be sent to the user.
    pub fn finish<E: Pairing<ScalarField = F>>(
        self,
        params: impl Into<PreparedSetupParams<E>>,
    ) -> UserSecretKeyShare<E> {
        let params = params.into();
        let r = self.0.r;
        let R_hat = params.g_hat.mul(r).into_affine();
        let SigShare { signer_id, R, u } = self.0.finish::<E::G1Affine>(&params.g);
        let S = params.pairing * r;
        UserSecretKeyShare {
            signer_id,
            R,
            R_hat,
            S,
            u,
        }
    }
}

impl<E: Pairing> UserSecretKeyShare<E> {
    /// Aggregate the shares to form the final user secret key
    pub fn aggregate(shares: Vec<Self>) -> UserSecretKey<E> {
        let mut sum_R = E::G1::zero();
        let mut sum_R_hat = E::G2::zero();
        let mut sum_S = PairingOutput::<E>::zero();
        let mut sum_u = E::ScalarField::zero();
        // u = \sum_i{share_i.u} = r*(sk + s)
        // R = \prod_i{share_i.R} / u = g^1/(sk + s)
        // R_hat = \prod_i{share_i.R_hat} / u = g_hat^1/(sk + s)
        // S = \prod_i{share_i.S} / u = e(g, h_hat)^1/(sk + s)
        for share in shares {
            sum_R += share.R;
            sum_R_hat += share.R_hat;
            sum_S += share.S;
            sum_u += share.u;
        }
        let u_inv = sum_u.inverse().unwrap();
        let R = (sum_R * u_inv).into_affine();
        let R_hat = (sum_R_hat * u_inv).into_affine();
        let S = sum_S * u_inv;
        UserSecretKey(Output(S), Proof(R, R_hat))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, time::Instant};

    use super::*;

    use crate::setup::{IssuerPublicKey, IssuerSecretKey, SetupParams};
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use blake2::Blake2b512;
    use schnorr_pok::compute_random_oracle_challenge;
    use secret_sharing_and_dkg::shamir_ss::deal_random_secret;
    use short_group_sig::threshold_weak_bb_sig::Phase1;
    use test_utils::ot::do_pairwise_base_ot;

    const BASE_OT_KEY_SIZE: u16 = 128;
    const KAPPA: u16 = 256;
    const STATISTICAL_SECURITY_PARAMETER: u16 = 80;
    const OTE_PARAMS: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER> =
        MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};

    /// Just for testing, let a trusted party do the keygen and give each signer its keyshare
    pub fn trusted_party_keygen<R: RngCore, F: PrimeField>(
        rng: &mut R,
        threshold: ParticipantId,
        total: ParticipantId,
    ) -> (F, Vec<F>) {
        let (secret, shares, _) = deal_random_secret(rng, threshold, total).unwrap();
        (secret, shares.0.into_iter().map(|s| s.share).collect())
    }

    /// First phase of signing where signers generate randomness
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
                Phase1::<Fr, 256>::init(rng, i, others, protocol_id.clone()).unwrap();
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
                        .receive_shares(j, zero_share)
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

    /// Second phase of signing where signers operate on the message and phase 1 output
    fn do_phase2(
        rng: &mut StdRng,
        threshold_signers: ParticipantId,
        gadget_vector: &GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        params: impl Into<PreparedSetupParams<Bls12_381>>,
        base_ot_outputs: &[BaseOTOutput],
        phase1_outs: &[Phase1Output<Fr>],
        expected_sk_term: Fr,
        secret_key_shares: &[IssuerSecretKey<Fr>],
        user_id: Fr,
    ) -> Vec<UserSecretKeyShare<Bls12_381>> {
        let mut phase2s = vec![];
        let mut all_msg_1s = vec![];

        let label = b"test";
        // Signers initiate round-2 and each signer sends messages to others
        let start = Instant::now();
        for i in 1..=threshold_signers {
            let (phase, msgs) = Phase2::init(
                rng,
                i,
                &secret_key_shares[i as usize - 1],
                user_id,
                phase1_outs[i as usize - 1].clone(),
                base_ot_outputs[i as usize - 1].clone(),
                OTE_PARAMS,
                &gadget_vector,
                label,
            )
            .unwrap();
            phase2s.push(phase);
            all_msg_1s.push((i, msgs));
        }
        let mut sk_term = Fr::zero();
        for p in &phase2s {
            sk_term += p.0.masked_sk_term_share
        }
        assert_eq!(expected_sk_term, sk_term);
        // Signers process round-2 messages received from others
        let mut all_msg_2s = vec![];
        for (sender_id, msg_1s) in all_msg_1s {
            for (receiver_id, m) in msg_1s {
                let m2 = phase2s[receiver_id as usize - 1]
                    .receive_message1::<Blake2b512>(sender_id, m, &gadget_vector)
                    .unwrap();
                all_msg_2s.push((receiver_id, sender_id, m2));
            }
        }

        for (sender_id, receiver_id, m2) in all_msg_2s {
            phase2s[receiver_id as usize - 1]
                .receive_message2::<Blake2b512>(sender_id, m2, &gadget_vector)
                .unwrap();
        }

        let params = params.into();
        let usk_shares = phase2s
            .into_iter()
            .map(|p| p.finish::<Bls12_381>(params.clone()))
            .collect::<Vec<_>>();
        println!("Phase 2 took {:?}", start.elapsed());
        usk_shares
    }

    #[test]
    fn issue() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<
            Blake2b512,
        >(OTE_PARAMS, b"test-gadget-vector");

        let threshold_signers = 5;
        let total_signers = 8;
        let all_party_set = (1..=total_signers).into_iter().collect::<BTreeSet<_>>();

        let params = SetupParams::<Bls12_381>::new::<Blake2b512>(b"test");

        // The signers do a keygen. This is a one time setup.
        let (sk, sk_shares) =
            trusted_party_keygen::<_, Fr>(&mut rng, threshold_signers, total_signers);
        let isk_shares = sk_shares
            .into_iter()
            .map(|s| IssuerSecretKey(s))
            .collect::<Vec<_>>();
        // Public key created by the trusted party using the secret key directly. In practice, this will be a result of a DKG
        let threshold_ipk = IssuerPublicKey::new(&mut rng, &IssuerSecretKey(sk), &params);

        // The signers run OT protocol instances. This is also a one time setup.
        let base_ot_outputs = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
            &mut rng,
            OTE_PARAMS.num_base_ot(),
            total_signers,
            all_party_set.clone(),
        );

        // Signing starts
        let protocol_id = b"test".to_vec();

        let phase1_outs = do_phase1(&mut rng, threshold_signers, protocol_id.clone());

        // Signer creates user secret key
        let user_id = compute_random_oracle_challenge::<Fr, Blake2b512>(b"low entropy user-id");

        let usk_shares = do_phase2(
            &mut rng,
            threshold_signers,
            &gadget_vector,
            params.clone(),
            &base_ot_outputs,
            &phase1_outs,
            sk,
            &isk_shares,
            user_id,
        );

        let start = Instant::now();
        let usk = UserSecretKeyShare::aggregate(usk_shares);
        println!(
            "Aggregating {} shares took {:?}",
            threshold_signers,
            start.elapsed()
        );

        usk.verify(user_id, &threshold_ipk, params.clone()).unwrap();
    }
}
