//! Two party multiplication where each party where each party has multiple inputs. based on protocol 1 of
//! the paper [Threshold ECDSA from ECDSA Assumptions: The Multiparty Case](https://eprint.iacr.org/2019/523)
//! Multiplication participants are called Party1 and Party2 where Party1 acts as the OT sender and Party2 as the
//! receiver

use crate::{
    ot_based_multiplication::dkls18_mul_2p::{
        add_tau_to_transcript, add_to_transcript, MultiplicationOTEParams,
    },
    Bit, BitMatrix,
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, rand::RngCore, vec::Vec, UniformRand};
use digest::{Digest, DynDigest};
use dock_crypto_utils::{
    concat_slices, hashing_utils::field_elem_from_try_and_incr, join, serde_utils::ArkObjectBytes,
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    base_ot::simplest_ot::{OneOfTwoROTSenderKeys, ROTReceiverKeys},
    configs::OTEConfig,
    error::OTError,
    ot_extensions::kos_ote::{
        CorrelationTag, OTExtensionReceiverSetup, OTExtensionSenderSetup, RLC as KOSRLC,
    },
    util::is_multiple_of_8,
};
use dock_crypto_utils::transcript::Transcript;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

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

impl<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16>
    GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>
{
    /// Use random oracle to create the random values
    pub fn new<D: Digest>(
        ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        label: &[u8],
    ) -> Self {
        let overhead = ote_params.overhead();
        let mut g = Vec::with_capacity(overhead as usize);
        let prefix = concat_slices!(label, b"-");
        for i in 0..overhead {
            g.push(field_elem_from_try_and_incr::<F, D>(&concat_slices!(
                prefix,
                &i.to_be_bytes()
            )))
        }
        Self(ote_params, g)
    }
}

/// Random Linear Combination used for error checking
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct RLC<F: PrimeField> {
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub r: Vec<F>,
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub u: Vec<F>,
}

/// Inputs to the multiplier masked by a random pad
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct MaskedInputs<F: PrimeField>(#[serde_as(as = "Vec<ArkObjectBytes>")] pub Vec<F>);

/// Acts as sender in OT extension
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct Party1<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16> {
    pub batch_size: u32,
    pub ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    /// Vector of values to multiply
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub a: Vec<F>,
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub a_hat: Vec<F>,
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub a_tilde: Vec<F>,
    pub base_ot_choices: Vec<Bit>,
    pub base_ot_keys: ROTReceiverKeys,
}

/// Acts as receiver in OT extension
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct Party2<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16> {
    pub batch_size: u32,
    pub ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    /// Vector of values to multiply
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub b: Vec<F>,
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub b_tilde: Vec<F>,
    /// Choices for OT extension
    pub beta: Vec<Bit>,
    pub ote_setup: OTExtensionReceiverSetup,
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct Party1Shares<F: PrimeField>(#[serde_as(as = "Vec<ArkObjectBytes>")] pub Vec<F>);

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct Party2Shares<F: PrimeField>(#[serde_as(as = "Vec<ArkObjectBytes>")] pub Vec<F>);

impl<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16>
    Party1<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>
{
    /// Assumes that the base OT is already done and this party for the receiver in that.
    pub fn new<R: RngCore>(
        rng: &mut R,
        a: Vec<F>,
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
        let batch_size = a.len() as u32;
        let a_hat = (0..batch_size).map(|_| F::rand(rng)).collect::<Vec<_>>();
        let a_tilde = (0..batch_size).map(|_| F::rand(rng)).collect::<Vec<_>>();
        Ok(Self {
            batch_size,
            a,
            a_hat,
            a_tilde,
            base_ot_choices,
            base_ot_keys,
            ote_params,
        })
    }

    pub fn receive<D: Default + DynDigest + Clone>(
        self,
        U: BitMatrix,
        rlc: KOSRLC,
        gamma_b: MaskedInputs<F>,
        transcript: &mut impl Transcript,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<(Party1Shares<F>, CorrelationTag<F>, RLC<F>, MaskedInputs<F>), OTError> {
        let batch_size = self.batch_size() as u32;
        let overhead = self.ote_params.overhead();
        if gamma_b.len() as u32 != batch_size {
            return Err(OTError::IncorrectBatchSize(
                batch_size as usize,
                gamma_b.len(),
            ));
        }
        add_to_transcript(transcript, &U, &rlc);
        let ote_config = OTEConfig::new(self.ote_params.num_base_ot(), batch_size * overhead)?;

        let correlations = self.get_ote_correlation();
        let ext_sender_setup = OTExtensionSenderSetup::new::<STATISTICAL_SECURITY_PARAMETER>(
            ote_config,
            U,
            rlc,
            self.base_ot_choices,
            self.base_ot_keys,
        )?;

        let (t_A, tau) = ext_sender_setup.transfer::<F, D>(correlations)?;
        add_tau_to_transcript(transcript, &tau);
        let chi = transcript.challenge_scalars::<F>(b"chi", batch_size as usize);
        let chi_hat = transcript.challenge_scalars::<F>(b"chi_hat", batch_size as usize);
        let (r, ua) = join!(
            cfg_into_iter!(0..overhead as usize)
                .map(|i| {
                    cfg_into_iter!(0..batch_size as usize)
                        .map(|j| {
                            chi[j] * t_A.0[j * overhead as usize + i].0
                                + chi_hat[j] * t_A.0[j * overhead as usize + i].1
                        })
                        .sum::<F>()
                })
                .collect::<Vec<_>>(),
            cfg_into_iter!(0..batch_size as usize)
                .map(|i| {
                    let u_i = chi[i] * self.a_tilde[i] + chi_hat[i] * self.a_hat[i];
                    let gamma_a_i = self.a[i] - self.a_tilde[i];
                    (u_i, gamma_a_i)
                })
                .collect::<Vec<_>>()
                .into_iter()
                .multiunzip::<(Vec<_>, Vec<_>)>()
        );
        let (u, gamma_a) = ua;

        // Party 1 generates their multiplication share
        let shares = cfg_into_iter!(0..batch_size as usize)
            .map(|i| {
                (self.a[i] * gamma_b.0[i])
                    + cfg_into_iter!(0..overhead as usize)
                        .map(|j| gadget_vector.1[j] * t_A.0[i * overhead as usize + j].0)
                        .sum::<F>()
            })
            .collect::<Vec<_>>();
        Ok((
            Party1Shares(shares),
            tau,
            RLC { r, u },
            MaskedInputs(gamma_a),
        ))
    }

    fn get_ote_correlation(&self) -> Vec<(F, F)> {
        let overhead = self.ote_params.overhead();
        cfg_into_iter!(0..self.batch_size as usize)
            .flat_map(|i| {
                cfg_into_iter!(0..overhead)
                    .map(|_| (self.a_tilde[i].clone(), self.a_hat[i].clone()))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    pub fn batch_size(&self) -> usize {
        self.a.len()
    }
}

impl<F: PrimeField, const KAPPA: u16, const STATISTICAL_SECURITY_PARAMETER: u16>
    Party2<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>
{
    /// Assumes that the base OT is already done and this party for the sender in that.
    pub fn new<R: RngCore>(
        rng: &mut R,
        b: Vec<F>,
        base_ot_keys: OneOfTwoROTSenderKeys,
        transcript: &mut impl Transcript,
        ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<(Self, BitMatrix, KOSRLC, MaskedInputs<F>), OTError> {
        let batch_size = b.len();
        let overhead = ote_params.overhead();
        let beta = (0..batch_size * overhead as usize)
            .map(|_| bool::rand(rng))
            .collect::<Vec<_>>();
        Self::new_with_given_ote_choices(
            rng,
            b,
            beta,
            base_ot_keys,
            transcript,
            ote_params,
            gadget_vector,
        )
    }

    /// Same as `Self::new` except the choices used in OT extension are provided by the caller and
    /// not generated internally
    pub fn new_with_given_ote_choices<R: RngCore>(
        rng: &mut R,
        b: Vec<F>,
        beta: Vec<Bit>,
        base_ot_keys: OneOfTwoROTSenderKeys,
        transcript: &mut impl Transcript,
        ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<(Self, BitMatrix, KOSRLC, MaskedInputs<F>), OTError> {
        if !is_multiple_of_8(KAPPA as usize) {
            return Err(OTError::SecurityParameterShouldBeMultipleOf8(KAPPA));
        }
        if !is_multiple_of_8(STATISTICAL_SECURITY_PARAMETER as usize) {
            return Err(OTError::SecurityParameterShouldBeMultipleOf8(
                STATISTICAL_SECURITY_PARAMETER,
            ));
        }
        assert_eq!(ote_params, gadget_vector.0);
        let batch_size = b.len() as u32;
        let overhead = ote_params.overhead() as usize;
        let extended_ot_count = batch_size * ote_params.overhead();
        let ote_config = OTEConfig::new(ote_params.num_base_ot(), extended_ot_count)?;
        let b_tilde = cfg_into_iter!(0..batch_size as usize)
            .map(|i| {
                cfg_iter!(beta[i * overhead..((i + 1) * overhead)])
                    .enumerate()
                    .map(|(j, gm)| {
                        gadget_vector.1[j] * {
                            if *gm {
                                F::one()
                            } else {
                                F::zero()
                            }
                        }
                    })
                    .sum::<F>()
            })
            .collect::<Vec<F>>();
        let (ext_receiver_setup, U, rlc) = OTExtensionReceiverSetup::new::<
            _,
            STATISTICAL_SECURITY_PARAMETER,
        >(rng, ote_config, beta.clone(), base_ot_keys)?;
        let gamma_b = cfg_into_iter!(0..batch_size as usize)
            .map(|i| b[i] - b_tilde[i])
            .collect::<Vec<_>>();

        add_to_transcript(transcript, &U, &rlc);
        Ok((
            Self {
                batch_size,
                ote_params,
                b,
                b_tilde,
                beta,
                ote_setup: ext_receiver_setup,
            },
            U,
            rlc,
            MaskedInputs(gamma_b),
        ))
    }

    pub fn receive<D: Default + DynDigest + Clone>(
        self,
        tau: CorrelationTag<F>,
        rlc: RLC<F>,
        gamma_a: MaskedInputs<F>,
        transcript: &mut impl Transcript,
        gadget_vector: &GadgetVector<F, KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    ) -> Result<Party2Shares<F>, OTError> {
        let batch_size = self.batch_size();
        let overhead = self.ote_params.overhead() as usize;
        if gamma_a.len() != batch_size {
            return Err(OTError::IncorrectBatchSize(batch_size, gamma_a.len()));
        }
        if tau.len() != batch_size * overhead {
            return Err(OTError::IncorrectCorrelationTagSize(
                batch_size * overhead,
                tau.len(),
            ));
        }
        let RLC { r, u } = rlc;
        if r.len() != overhead {
            return Err(OTError::IncorrectRLCSize(overhead, r.len()));
        }
        if u.len() != batch_size {
            return Err(OTError::IncorrectRLCSize(batch_size, u.len()));
        }

        add_tau_to_transcript(transcript, &tau);
        let chi = transcript.challenge_scalars::<F>(b"chi", batch_size);
        let chi_hat = transcript.challenge_scalars::<F>(b"chi_hat", batch_size);
        let t_B = self.ote_setup.receive::<F, D>(tau)?;
        let res = cfg_into_iter!(0..overhead).try_for_each(|i| {
            let mut lhs = cfg_into_iter!(0..batch_size)
                .map(|j| {
                    chi[j] * t_B.0[j * overhead + i].0 + chi_hat[j] * t_B.0[j * overhead + i].1
                })
                .sum::<F>();
            lhs += r[i];
            let rhs = cfg_into_iter!(0..batch_size)
                .map(|j| {
                    if self.beta[j * overhead + i] {
                        F::one() * u[j]
                    } else {
                        F::zero() * u[j]
                    }
                })
                .sum::<F>();
            if lhs == rhs {
                Ok(())
            } else {
                Err(())
            }
        });
        res.map_err(|_| OTError::RandomLinearCombinationCheckFailed)?;
        Ok(Party2Shares(
            cfg_into_iter!(0..batch_size)
                .map(|i| {
                    (self.b_tilde[i] * gamma_a.0[i])
                        + cfg_into_iter!(0..overhead)
                            .map(|j| gadget_vector.1[j] * t_B.0[i * overhead + j].0)
                            .sum::<F>()
                })
                .collect::<Vec<_>>(),
        ))
    }

    pub fn batch_size(&self) -> usize {
        self.b.len()
    }
}

impl<F: PrimeField> MaskedInputs<F> {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl<F: PrimeField> Party1Shares<F> {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl<F: PrimeField> Party2Shares<F> {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::base_ot::simplest_ot::tests::do_1_of_2_base_ot;
    use std::time::{Duration, Instant};

    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;

    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use dock_crypto_utils::transcript::new_merlin_transcript;
    use test_utils::{test_serialization, G1};

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn two_party_batch_multiplication() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let B = G1::rand(&mut rng);

        fn check<const KEY_SIZE: u16, const KAPPA: u16, const SSP: u16>(
            rng: &mut StdRng,
            a: Vec<Fr>,
            b: Vec<Fr>,
            ote_params: MultiplicationOTEParams<KAPPA, SSP>,
            gadget_vector: &GadgetVector<Fr, KAPPA, SSP>,
            B: &G1,
            check_serialization: bool,
        ) {
            // Perform base OT with roles reversed
            // In practice do VSOT
            let (base_ot_choices, base_ot_sender_keys, base_ot_receiver_keys) =
                do_1_of_2_base_ot::<KEY_SIZE>(rng, ote_params.num_base_ot(), B);

            let batch_size = a.len();

            let base_ot_choices = base_ot_choices
                .into_iter()
                .map(|b| b % 2 != 0)
                .collect::<Vec<_>>();

            let mut party1_transcript = new_merlin_transcript(b"test-multiplication");
            let mut party2_transcript = new_merlin_transcript(b"test-multiplication");

            let mut party1_time = Duration::default();
            let mut party2_time = Duration::default();

            // party1 will act as sender and party2 as receiver in the OT extension

            let start = Instant::now();
            let party1 = Party1::new::<StdRng>(
                rng,
                a.clone(),
                base_ot_choices,
                base_ot_receiver_keys,
                ote_params,
            )
            .unwrap();
            party1_time += start.elapsed();

            let start = Instant::now();
            let (party2, U, kos_rlc, gamma_b) = Party2::new(
                rng,
                b.clone(),
                base_ot_sender_keys,
                &mut party2_transcript,
                ote_params,
                &gadget_vector,
            )
            .unwrap();
            party2_time += start.elapsed();

            let start = Instant::now();
            let (shares_1, tau, rlc, gamma_a) = party1
                .clone()
                .receive::<Blake2b512>(
                    U,
                    kos_rlc,
                    gamma_b.clone(),
                    &mut party1_transcript,
                    &gadget_vector,
                )
                .unwrap();
            party1_time += start.elapsed();

            let start = Instant::now();
            let shares_2 = party2
                .clone()
                .receive::<Blake2b512>(
                    tau,
                    rlc,
                    gamma_a.clone(),
                    &mut party2_transcript,
                    &gadget_vector,
                )
                .unwrap();
            party2_time += start.elapsed();

            // Check if shares are correct
            for i in 0..batch_size {
                assert_eq!(shares_1.0[i] + shares_2.0[i], a[i] * b[i]);
            }

            println!(
                "For batch size {}, party1 takes {:?} and party2 takes {:?}",
                batch_size, party1_time, party2_time
            );

            if check_serialization {
                test_serialization!(Party1<Fr, KAPPA, SSP>, party1);
                test_serialization!(Party2<Fr, KAPPA, SSP>, party2);
                test_serialization!(MaskedInputs<Fr>, gamma_a);
                test_serialization!(MaskedInputs<Fr>, gamma_b);
                test_serialization!(Party1Shares<Fr>, shares_1);
                test_serialization!(Party2Shares<Fr>, shares_2);
            }
        }

        const KAPPA: u16 = 256;
        const SSP: u16 = 80;
        let ote_params = MultiplicationOTEParams::<KAPPA, SSP> {};
        let gadget_vector =
            GadgetVector::<Fr, KAPPA, SSP>::new::<Blake2b512>(ote_params, b"test-gadget-vector");
        test_serialization!(GadgetVector<Fr, KAPPA, SSP>, gadget_vector);

        let mut checked_serialization = false;
        for batch_size in [2, 4, 8, 20, 40, 80] {
            let a = (0..batch_size)
                .map(|_| Fr::rand(&mut rng))
                .collect::<Vec<_>>();
            let b = (0..batch_size)
                .map(|_| Fr::rand(&mut rng))
                .collect::<Vec<_>>();
            check::<128, KAPPA, SSP>(
                &mut rng,
                a,
                b,
                ote_params,
                &gadget_vector,
                &B,
                !checked_serialization,
            );
            checked_serialization = true;
        }
    }
}
