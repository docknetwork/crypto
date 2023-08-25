//! Two party multiplication where each party has 1 input. Based on the protocol 5 of the
//! paper [Secure Two-party Threshold ECDSA from ECDSA Assumptions](https://eprint.iacr.org/2018/499)
//! Multiplication participants are called Party1 and Party2 where Party1 acts as the OT sender and Party2 as the
//! receiver

use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, rand::RngCore, vec, vec::Vec, UniformRand};
use digest::{Digest, DynDigest};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{Bit, BitMatrix};
use dock_crypto_utils::{
    concat_slices, hashing_utils::field_elem_from_try_and_incr, serde_utils::ArkObjectBytes,
};

use crate::{
    base_ot::simplest_ot::{OneOfTwoROTSenderKeys, ROTReceiverKeys},
    configs::OTEConfig,
    error::OTError,
    ot_extensions::kos_ote::{
        CorrelationTag, OTExtensionReceiverSetup, OTExtensionSenderSetup, RLC as KOSRLC,
    },
};
use dock_crypto_utils::transcript::Transcript;

use crate::util::is_multiple_of_8;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(
    Clone, Debug, PartialEq, Copy, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct MultiplicationOTEParams<const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16> {}

/// A public vector of random values used by both multiplication participants. Its important that the
/// values are random and not influenced by any participant
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct GadgetVector<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16>(
    pub MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    #[serde_as(as = "Vec<ArkObjectBytes>")] pub Vec<F>,
);

/// Random Linear Combination used for error checking
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct RLC<F: PrimeField> {
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub r: Vec<F>,
    #[serde_as(as = "ArkObjectBytes")]
    pub u: F,
}

impl<const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16>
    MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>
{
    pub const fn num_base_ot(&self) -> u16 {
        KAPPA
    }

    pub const fn num_extensions(&self) -> u32 {
        2 * (KAPPA as u32 + STATISTICAL_SECURITY_PARAMETER as u32)
    }

    pub const fn overhead(&self) -> u32 {
        KAPPA as u32 + 2 * STATISTICAL_SECURITY_PARAMETER as u32
    }
}

impl<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16>
    GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>
{
    /// Use random oracle to create the random values
    pub fn new<D: Digest>(
        ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        label: &[u8],
    ) -> Self {
        let mut g = Vec::with_capacity(ote_params.num_extensions() as usize);
        g.push(F::one());
        for i in 1..ote_params.num_base_ot() {
            g.push(g[i as usize - 1].double())
        }
        let prefix = concat_slices!(label, b"-");
        for i in 0..ote_params.overhead() {
            g.push(field_elem_from_try_and_incr::<F, D>(&concat_slices!(
                prefix,
                &i.to_be_bytes()
            )))
        }
        Self(ote_params, g)
    }
}

/// Acts as sender in OT extension
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct Party1<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16> {
    pub ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    #[serde_as(as = "ArkObjectBytes")]
    pub alpha: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub alpha_hat: F,
    pub base_ot_choices: Vec<Bit>,
    pub base_ot_keys: ROTReceiverKeys,
}

/// Acts as receiver in OT extension
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct Party2<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16> {
    pub ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    #[serde_as(as = "ArkObjectBytes")]
    pub beta: F,
    pub encoded_beta: Vec<Bit>,
    pub ote_setup: OTExtensionReceiverSetup,
}

impl<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16>
    Party1<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>
{
    /// Assumes that the base OT is already done and this party for the receiver in that.
    pub fn new<R: RngCore>(
        rng: &mut R,
        alpha: F,
        base_ot_choices: Vec<Bit>,
        base_ot_keys: ROTReceiverKeys,
        ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<Self, OTError> {
        if !is_multiple_of_8(KAPPA as usize) {
            return Err(OTError::SecurityParameterShouldBeMultipleOf8(KAPPA));
        }
        if !is_multiple_of_8(STATISTICAL_SECURITY_PARAMETER as usize) {
            return Err(OTError::SecurityParameterShouldBeMultipleOf8(
                STATISTICAL_SECURITY_PARAMETER,
            ));
        }
        let alpha_hat = F::rand(rng);
        Ok(Self {
            alpha,
            alpha_hat,
            ote_params,
            base_ot_choices,
            base_ot_keys,
        })
    }

    pub fn receive<D: Default + DynDigest + Clone>(
        self,
        U: BitMatrix,
        rlc: KOSRLC,
        transcript: &mut impl Transcript,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<(F, CorrelationTag<F>, RLC<F>), OTError> {
        add_to_transcript(transcript, &U, &rlc);
        let ote_config = OTEConfig::new(
            self.ote_params.num_base_ot(),
            self.ote_params.num_extensions(),
        )?;
        let correlations = self.get_ote_correlation();
        let ext_sender_setup = OTExtensionSenderSetup::new::<STATISTICAL_SECURITY_PARAMETER>(
            ote_config,
            U,
            rlc,
            self.base_ot_choices,
            self.base_ot_keys,
        )?;
        let (t_A, tau) = ext_sender_setup.transfer::<F, D>(correlations.clone())?;
        add_tau_to_transcript(transcript, &tau);
        let chi = transcript.challenge_scalar::<F>(b"chi");
        let chi_hat = transcript.challenge_scalar::<F>(b"chi_hat");
        let r = cfg_iter!(t_A.0)
            .map(|(t_A_i, t_A_hat_i)| chi * t_A_i + chi_hat * t_A_hat_i)
            .collect::<Vec<_>>();
        let u = chi * self.alpha + chi_hat * self.alpha_hat;
        let share = cfg_into_iter!(t_A.0)
            .enumerate()
            .map(|(i, (t_A_i, _))| t_A_i * gadget_vector.1[i])
            .sum::<F>();
        Ok((share, tau, RLC { r, u }))
    }

    fn get_ote_correlation(&self) -> Vec<(F, F)> {
        cfg_into_iter!(0..self.ote_params.num_extensions())
            .map(|_| (self.alpha.clone(), self.alpha_hat.clone()))
            .collect()
    }
}

impl<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16>
    Party2<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>
{
    /// Assumes that the base OT is already done and this party for the sender in that.
    pub fn new<R: RngCore>(
        rng: &mut R,
        beta: F,
        base_ot_keys: OneOfTwoROTSenderKeys,
        transcript: &mut impl Transcript,
        ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<(Self, BitMatrix, KOSRLC), OTError> {
        if !is_multiple_of_8(KAPPA as usize) {
            return Err(OTError::SecurityParameterShouldBeMultipleOf8(KAPPA));
        }
        if !is_multiple_of_8(STATISTICAL_SECURITY_PARAMETER as usize) {
            return Err(OTError::SecurityParameterShouldBeMultipleOf8(
                STATISTICAL_SECURITY_PARAMETER,
            ));
        }
        assert_eq!(ote_params, gadget_vector.0);
        let encoded_beta = Self::encode(rng, beta, gadget_vector);
        let ote_config = OTEConfig::new(ote_params.num_base_ot(), ote_params.num_extensions())?;
        let (ext_receiver_setup, U, rlc) = OTExtensionReceiverSetup::new::<
            _,
            STATISTICAL_SECURITY_PARAMETER,
        >(
            rng, ote_config, encoded_beta.clone(), base_ot_keys
        )?;
        add_to_transcript(transcript, &U, &rlc);
        Ok((
            Self {
                ote_params,
                beta,
                encoded_beta,
                ote_setup: ext_receiver_setup,
            },
            U,
            rlc,
        ))
    }

    pub fn receive<D: Default + DynDigest + Clone>(
        self,
        tau: CorrelationTag<F>,
        rlc: RLC<F>,
        transcript: &mut impl Transcript,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<F, OTError> {
        add_tau_to_transcript(transcript, &tau);
        let t_B = self.ote_setup.receive::<F, D>(tau)?;
        let chi = transcript.challenge_scalar::<F>(b"chi");
        let chi_hat = transcript.challenge_scalar::<F>(b"chi_hat");
        let RLC { r, u } = rlc;
        let res = cfg_iter!(t_B.0)
            .zip(cfg_into_iter!(r))
            .enumerate()
            .try_for_each(|(i, ((t_B_i, t_B_hat_i), r_i))| {
                let u_j = if self.encoded_beta[i] {
                    F::one() * u
                } else {
                    F::zero() * u
                };
                let rhs = u_j - r_i;
                if ((chi * t_B_i) + (chi_hat * t_B_hat_i)) == rhs {
                    Ok(())
                } else {
                    Err(())
                }
            });
        res.map_err(|_| OTError::RandomLinearCombinationCheckFailed)?;
        Ok(cfg_into_iter!(t_B.0)
            .enumerate()
            .map(|(i, (t_B_i, _))| t_B_i * gadget_vector.1[i])
            .sum::<F>())
    }

    /// Assumes gadget vector has correct OTE params.
    fn encode<R: RngCore>(
        rng: &mut R,
        element: F,
        gadget: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Vec<Bit> {
        let mut gamma = (0..gadget.0.overhead())
            .map(|_| bool::rand(rng))
            .collect::<Vec<_>>();
        let inner_product = cfg_iter!(gamma)
            .enumerate()
            .map(|(i, gm)| {
                gadget.1[gadget.0.num_base_ot() as usize + i] * {
                    if *gm {
                        F::one()
                    } else {
                        F::zero()
                    }
                }
            })
            .sum::<F>();
        let mut encoded = (element - inner_product).into_bigint().to_bits_le();
        encoded.append(&mut gamma);
        encoded
    }
}

pub(crate) fn add_to_transcript(transcript: &mut impl Transcript, U: &BitMatrix, rlc: &KOSRLC) {
    transcript.append_message(b"U", &U.0);
    transcript.append_message(b"KOSRLC.x", &rlc.x);
    transcript.append_message(b"KOSRLC.t", &rlc.t);
}

pub(crate) fn add_tau_to_transcript<F: PrimeField>(
    transcript: &mut impl Transcript,
    tau: &CorrelationTag<F>,
) {
    let mut tau_bytes = vec![];
    for (t0, t1) in &tau.0 {
        t0.serialize_compressed(&mut tau_bytes).unwrap();
        t1.serialize_compressed(&mut tau_bytes).unwrap();
    }
    transcript.append_message(b"tau", &tau_bytes);
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::base_ot::simplest_ot::tests::do_1_of_2_base_ot;

    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_ff::Field;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use dock_crypto_utils::transcript::new_merlin_transcript;
    use test_utils::test_serialization;

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn two_party_multiplication() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let B = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);

        fn check<const KEY_SIZE: u16, const KAPPA: u16, const SSP: u16>(
            rng: &mut StdRng,
            alpha: Fr,
            beta: Fr,
            ote_params: MultiplicationOTEParams<KAPPA, SSP>,
            gadget_vector: &GadgetVector<Fr, KAPPA, SSP>,
            B: &<Bls12_381 as Pairing>::G1Affine,
        ) {
            // Perform base OT with roles reversed
            // In practice do VSOT
            let (base_ot_choices, base_ot_sender_keys, base_ot_receiver_keys) =
                do_1_of_2_base_ot::<KEY_SIZE>(rng, ote_params.num_base_ot(), B);

            let base_ot_choices = base_ot_choices
                .into_iter()
                .map(|b| b % 2 != 0)
                .collect::<Vec<_>>();

            let mut party1_transcript = new_merlin_transcript(b"test-multiplication");
            let mut party2_transcript = new_merlin_transcript(b"test-multiplication");

            // party1 will act as sender and party2 as receiver in the OT extension
            let party1 = Party1::new::<StdRng>(
                rng,
                alpha,
                base_ot_choices,
                base_ot_receiver_keys,
                ote_params,
            )
            .unwrap();
            let (party2, U, kos_rlc) = Party2::new(
                rng,
                beta,
                base_ot_sender_keys,
                &mut party2_transcript,
                ote_params,
                &gadget_vector,
            )
            .unwrap();

            let (share_1, tau, rlc) = party1
                .clone()
                .receive::<Blake2b512>(U, kos_rlc, &mut party1_transcript, &gadget_vector)
                .unwrap();
            let share_2 = party2
                .clone()
                .receive::<Blake2b512>(
                    tau.clone(),
                    rlc.clone(),
                    &mut party2_transcript,
                    &gadget_vector,
                )
                .unwrap();

            assert_eq!(share_1 + share_2, alpha * beta);

            test_serialization!(Party1<Fr, KAPPA, SSP>, party1);
            test_serialization!(Party2<Fr, KAPPA, SSP>, party2);
            test_serialization!(CorrelationTag<Fr>, tau);
            test_serialization!(RLC<Fr>, rlc);
        }

        const KAPPA: u16 = 256;
        const SSP: u16 = 80;
        let ote_params = MultiplicationOTEParams::<KAPPA, SSP> {};
        let gadget_vector =
            GadgetVector::<Fr, KAPPA, SSP>::new::<Blake2b512>(ote_params, b"test-gadget-vector");
        assert_eq!(gadget_vector.1.len() as u32, ote_params.num_extensions());
        for i in 0..ote_params.num_base_ot() as usize {
            assert_eq!(gadget_vector.1[i], Fr::from(2u64).pow(&[i as u64]));
        }
        test_serialization!(GadgetVector<Fr, KAPPA, SSP>, gadget_vector);

        let alpha = Fr::rand(&mut rng);
        let beta = Fr::rand(&mut rng);
        check::<128, KAPPA, SSP>(&mut rng, alpha, beta, ote_params, &gadget_vector, &B);
    }
}
