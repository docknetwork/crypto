//! Two party multiplication. Implements 2 variants, single where each party has 1 input and
//! batch multiplication where each party has multiple inputs.
//! The single multiplication is based on the protocol 5 of the paper [Secure Two-party Threshold ECDSA from ECDSA Assumptions](https://eprint.iacr.org/2018/499)
//! The batch multiplication is based on protocol 1 of the paper [Threshold ECDSA from ECDSA Assumptions: The Multiparty Case](https://eprint.iacr.org/2019/523)
//! Multiplication participants are called Party1 and Party2 where Party1 acts as the OT sender and Party2 as the
//! receiver

use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, rand::RngCore, vec::Vec, UniformRand};

use digest::Digest;
use itertools::Itertools;

use crate::Bit;
use dock_crypto_utils::concat_slices;
use dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr;

#[cfg(feature = "parallel")]
use rayon::prelude::*;
use crate::configs::OTEConfig;
use crate::kos_ote::{OTExtensionReceiverSetup, OTExtensionSenderSetup};
use crate::simplest_ot::OneOfTwoROTSenderKeys;

#[derive(Clone, Debug, PartialEq, Copy, CanonicalSerialize, CanonicalDeserialize)]
pub struct MultiplicationOTEParams<const kappa: u16, const s: u16> {}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct GadgetVector<F: PrimeField, const kappa: u16, const s: u16>(
    pub MultiplicationOTEParams<kappa, s>,
    pub Vec<F>,
);

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct GadgetVectorForBatchMultiplication<F: PrimeField, const kappa: u16, const s: u16>(
    pub MultiplicationOTEParams<kappa, s>,
    pub Vec<F>,
);

impl<const kappa: u16, const s: u16> MultiplicationOTEParams<kappa, s> {
    pub const fn num_base_ot(&self) -> u16 {
        kappa
    }

    pub const fn num_extensions(&self) -> usize {
        2 * (kappa as usize + s as usize)
    }

    pub const fn overhead(&self) -> usize {
        kappa as usize + 2 * s as usize
    }
}

impl<F: PrimeField, const kappa: u16, const s: u16> GadgetVector<F, kappa, s> {
    pub fn new<D: Digest>(ote_params: MultiplicationOTEParams<kappa, s>, label: &[u8]) -> Self {
        let mut g = Vec::with_capacity(ote_params.num_extensions());
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

impl<F: PrimeField, const kappa: u16, const s: u16>
    GadgetVectorForBatchMultiplication<F, kappa, s>
{
    pub fn new<D: Digest>(ote_params: MultiplicationOTEParams<kappa, s>, label: &[u8]) -> Self {
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

/// Acts as sender in OT extension
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Party1<F: PrimeField, const kappa: u16, const s: u16> {
    pub ote_params: MultiplicationOTEParams<kappa, s>,
    pub alpha: F,
    pub alpha_hat: F,
    pub ot_ext_sender_setup: OTExtensionSenderSetup
}

/// Acts as receiver in OT extension
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Party2<F: PrimeField, const kappa: u16, const s: u16> {
    pub ote_params: MultiplicationOTEParams<kappa, s>,
    pub beta: F,
    pub encoded_beta: Vec<Bit>,
    pub ot_ext_receiver_setup: OTExtensionReceiverSetup
}

/// Acts as sender in OT extension
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Party1ForBatchMultiplication<F: PrimeField, const kappa: u16, const s: u16> {
    pub batch_size: usize,
    pub ote_params: MultiplicationOTEParams<kappa, s>,
    pub a: Vec<F>,
    pub a_hat: Vec<F>,
    pub a_tilde: Vec<F>,
}

/// Acts as receiver in OT extension
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Party2ForBatchMultiplication<F: PrimeField, const kappa: u16, const s: u16> {
    pub batch_size: usize,
    pub ote_params: MultiplicationOTEParams<kappa, s>,
    pub b: Vec<F>,
    pub b_tilde: Vec<F>,
    pub beta: Vec<Bit>,
}

impl<F: PrimeField, const kappa: u16, const s: u16> Party1<F, kappa, s> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        alpha: F,
        ote_params: MultiplicationOTEParams<kappa, s>,
    ) -> Self {
        let alpha_hat = F::rand(rng);
        Self {
            alpha,
            alpha_hat,
            ote_params,
        }
    }

    pub fn get_ote_correlation(&self) -> Vec<(F, F)> {
        cfg_into_iter!(0..self.ote_params.num_extensions())
            .map(|_| (self.alpha.clone(), self.alpha_hat.clone()))
            .collect()
    }
}

impl<F: PrimeField, const kappa: u16, const s: u16> Party2<F, kappa, s> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        beta: F,
        base_ot_keys: OneOfTwoROTSenderKeys,
        ote_params: MultiplicationOTEParams<kappa, s>,
        gadget_vector: &GadgetVector<F, kappa, s>,
    ) -> Self {
        assert_eq!(ote_params, gadget_vector.0);
        let extended_ot_count = ote_params.num_extensions();
        let ote_config = OTEConfig::new(ote_params.num_base_ot(), extended_ot_count).unwrap();
        let encoded_beta = Self::encode(rng, beta, gadget_vector);
        // TODO: Remove unwrap
        let (ext_receiver_setup, U, rlc) = OTExtensionReceiverSetup::new::<R, s>(
            rng,
            ote_config,
            encoded_beta.clone(),
            base_ot_keys,
        )
            .unwrap();
        Self {
            ote_params,
            beta,
            encoded_beta,
        }
    }

    /// Assumes gadget vector has correct OTE params.
    pub fn encode<R: RngCore>(
        rng: &mut R,
        element: F,
        gadget: &GadgetVector<F, kappa, s>,
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

impl<F: PrimeField, const kappa: u16, const s: u16> Party1ForBatchMultiplication<F, kappa, s> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        a: Vec<F>,
        ote_params: MultiplicationOTEParams<kappa, s>,
    ) -> Self {
        let batch_size = a.len();
        let a_hat = (0..batch_size).map(|_| F::rand(rng)).collect::<Vec<_>>();
        let a_tilde = (0..batch_size).map(|_| F::rand(rng)).collect::<Vec<_>>();
        Self {
            batch_size,
            a,
            a_hat,
            a_tilde,
            ote_params,
        }
    }

    pub fn get_ote_correlation(&self) -> Vec<(F, F)> {
        let overhead = self.ote_params.overhead();
        cfg_into_iter!(0..self.batch_size)
            .flat_map(|i| {
                cfg_into_iter!(0..overhead)
                    .map(|_| (self.a_tilde[i].clone(), self.a_hat[i].clone()))
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

impl<F: PrimeField, const kappa: u16, const s: u16> Party2ForBatchMultiplication<F, kappa, s> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        b: Vec<F>,
        ote_params: MultiplicationOTEParams<kappa, s>,
        gadget_vector: &GadgetVectorForBatchMultiplication<F, kappa, s>,
    ) -> Self {
        let batch_size = b.len();
        let overhead = ote_params.overhead();
        let beta = (0..batch_size * overhead as usize)
            .map(|_| bool::rand(rng))
            .collect::<Vec<_>>();
        Self::new_with_given_ote_choices(b, beta, ote_params, gadget_vector)
    }

    /// Same as `Self::new` except the choices used in OT extension are provided by the caller and
    /// not generated internally
    pub fn new_with_given_ote_choices(
        b: Vec<F>,
        beta: Vec<Bit>,
        ote_params: MultiplicationOTEParams<kappa, s>,
        gadget_vector: &GadgetVectorForBatchMultiplication<F, kappa, s>,
    ) -> Self {
        assert_eq!(ote_params, gadget_vector.0);
        let batch_size = b.len();
        let overhead = ote_params.overhead() as usize;
        let b_tilde = cfg_into_iter!(0..batch_size)
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
            .collect();
        Self {
            batch_size,
            ote_params,
            b,
            b_tilde,
            beta,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::alsz_ote::tests::do_1_of_2_base_ot;
    use crate::kos_ote::{OTExtensionReceiverSetup, OTExtensionSenderSetup};

    use crate::configs::OTEConfig;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_ff::Field;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_std::UniformRand;
    use blake2::Blake2b512;

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn two_party_multiplication() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let B = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);

        fn check<const KEY_SIZE: usize, const KAPPA: u16, const SSP: u16>(
            rng: &mut StdRng,
            alpha: Fr,
            beta: Fr,
            ote_params: MultiplicationOTEParams<KAPPA, SSP>,
            gadget_vector: &GadgetVector<Fr, KAPPA, SSP>,
            B: &<Bls12_381 as Pairing>::G1Affine,
        ) {
            // Perform base OT with roles reversed
            // TODO: Do VSOT
            let (base_ot_choices, base_ot_sender_keys, base_ot_receiver_keys) =
                do_1_of_2_base_ot::<KEY_SIZE>(rng, ote_params.num_base_ot(), B);

            // party1 will act as sender and party2 as receiver in the OT extension
            let party1 = Party1::new::<StdRng>(rng, alpha, ote_params);
            let party2 = Party2::new(rng, beta, base_ot_sender_keys, ote_params, &gadget_vector);

            // Perform OT extension
            let extended_ot_count = ote_params.num_extensions();
            let ote_config = OTEConfig::new(ote_params.num_base_ot(), extended_ot_count).unwrap();
            let (ext_receiver_setup, U, rlc) = OTExtensionReceiverSetup::new::<_, SSP>(
                rng,
                ote_config,
                party2.encoded_beta.clone(),
                base_ot_sender_keys,
            )
            .unwrap();

            let base_ot_choices = base_ot_choices
                .into_iter()
                .map(|b| b % 2 != 0)
                .collect::<Vec<_>>();
            let ext_sender_setup = OTExtensionSenderSetup::new::<SSP>(
                ote_config,
                U,
                rlc,
                base_ot_choices,
                base_ot_receiver_keys,
            )
            .unwrap();

            // TODO: Gen by hashing
            let chi = Fr::rand(rng);
            let chi_hat = Fr::rand(rng);

            // Do actions by party1
            let correlations = party1.get_ote_correlation();
            let (t_A, tau) = ext_sender_setup.transfer::<Fr, Blake2b512>(correlations.clone());
            let r = cfg_iter!(t_A)
                .map(|(t_A_i, t_A_hat_i)| chi * t_A_i + chi_hat * t_A_hat_i)
                .collect::<Vec<_>>();
            let u = chi * party1.alpha + chi_hat * party1.alpha_hat;
            let share_A = cfg_iter!(t_A)
                .enumerate()
                .map(|(i, (t_A_i, _))| t_A_i * &gadget_vector.1[i])
                .sum::<Fr>();

            // Do actions by party2
            let t_B = ext_receiver_setup.receive::<Fr, Blake2b512>(tau);
            let res = cfg_iter!(t_B)
                .zip(cfg_into_iter!(r))
                .enumerate()
                .try_for_each(|(i, ((t_B_i, t_B_hat_i), r_i))| {
                    let u_j = if party2.encoded_beta[i] {
                        Fr::one() * u
                    } else {
                        Fr::zero() * u
                    };
                    let rhs = u_j - r_i;
                    if ((chi * t_B_i) + (chi_hat * t_B_hat_i)) == rhs {
                        Ok(())
                    } else {
                        Err(())
                    }
                });
            assert!(res.is_ok());

            for (i, b) in party2.encoded_beta.iter().enumerate() {
                if *b {
                    assert_eq!(correlations[i].0 - t_A[i].0, t_B[i].0);
                    assert_eq!(correlations[i].1 - t_A[i].1, t_B[i].1);
                } else {
                    assert_eq!(t_A[i].0, -t_B[i].0);
                    assert_eq!(t_A[i].1, -t_B[i].1);
                }
            }

            let share_B = cfg_iter!(t_B)
                .enumerate()
                .map(|(i, (t_B_i, _))| t_B_i * &gadget_vector.1[i])
                .sum::<Fr>();
            assert_eq!(share_A + share_B, alpha * beta);
        }

        const kappa: u16 = 256;
        const s: u16 = 80;
        let ote_params = MultiplicationOTEParams::<kappa, s> {};
        let gadget_vector = GadgetVector::<Fr, kappa, s>::new::<Blake2b512>(ote_params, b"test");
        assert_eq!(gadget_vector.1.len(), ote_params.num_extensions());
        for i in 0..ote_params.num_base_ot() as usize {
            assert_eq!(gadget_vector.1[i], Fr::from(2u64).pow(&[i as u64]));
        }
        let alpha = Fr::rand(&mut rng);
        let beta = Fr::rand(&mut rng);
        check::<16, kappa, s>(
            &mut rng,
            alpha,
            beta,
            ote_params,
            &gadget_vector,
            &B,
        );
    }

    #[test]
    fn two_party_batch_multiplication() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let B = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);

        fn check<const KEY_SIZE: usize, const KAPPA: u16, const SSP: u16>(
            rng: &mut StdRng,
            a: Vec<Fr>,
            b: Vec<Fr>,
            ote_params: MultiplicationOTEParams<KAPPA, SSP>,
            gadget_vector: &GadgetVectorForBatchMultiplication<Fr, KAPPA, SSP>,
            B: &<Bls12_381 as Pairing>::G1Affine,
        ) {
            // Perform base OT with roles reversed
            // TODO: Do VSOT
            let (base_ot_choices, base_ot_sender_keys, base_ot_receiver_keys) =
                do_1_of_2_base_ot::<KEY_SIZE>(rng, ote_params.num_base_ot(), B);

            let batch_size = a.len();

            // party1 will act as sender and party2 as receiver in the OT extension
            let party1 = Party1ForBatchMultiplication::new(rng, a, ote_params);
            let party2 = Party2ForBatchMultiplication::new(rng, b, ote_params, &gadget_vector);

            // Perform OT extension
            let extended_ot_count = batch_size * ote_params.overhead();
            let ote_config = OTEConfig::new(ote_params.num_base_ot(), extended_ot_count).unwrap();

            let (ext_receiver_setup, U, rlc) = OTExtensionReceiverSetup::new::<_, SSP>(
                rng,
                ote_config,
                party2.beta.clone(),
                base_ot_sender_keys,
            )
            .unwrap();

            let base_ot_choices = base_ot_choices
                .into_iter()
                .map(|b| b % 2 != 0)
                .collect::<Vec<_>>();
            let ext_sender_setup = OTExtensionSenderSetup::new::<SSP>(
                ote_config,
                U,
                rlc,
                base_ot_choices,
                base_ot_receiver_keys,
            )
            .unwrap();

            // TODO: Gen by hashing
            let chi = vec![Fr::rand(rng); batch_size];
            let chi_hat = vec![Fr::rand(rng); batch_size];

            // Do actions by party1
            let correlations = party1.get_ote_correlation();
            let (t_A, tau) = ext_sender_setup.transfer::<Fr, Blake2b512>(correlations.clone());
            let overhead = ote_params.overhead();
            assert_eq!(correlations.len(), overhead * batch_size);
            assert_eq!(t_A.len(), tau.len());
            assert_eq!(t_A.len(), overhead * batch_size);

            let r = cfg_into_iter!(0..overhead)
                .map(|i| {
                    cfg_into_iter!(0..batch_size)
                        .map(|j| {
                            chi[j] * t_A[j * overhead + i].0 + chi_hat[j] * t_A[j * overhead + i].1
                        })
                        .sum::<Fr>()
                })
                .collect::<Vec<_>>();
            let (u, gamma_a) = cfg_into_iter!(0..batch_size)
                .map(|i| {
                    let u_i = chi[i] * party1.a_tilde[i] + chi_hat[i] * party1.a_hat[i];
                    let gamma_a_i = party1.a[i] - party1.a_tilde[i];
                    (u_i, gamma_a_i)
                })
                .collect::<Vec<_>>()
                .into_iter()
                .multiunzip::<(Vec<_>, Vec<_>)>();

            // Do actions by party2
            let t_B = ext_receiver_setup.receive::<Fr, Blake2b512>(tau);
            assert_eq!(t_B.len(), overhead * batch_size);
            let res = cfg_into_iter!(0..overhead).try_for_each(|i| {
                let mut lhs = cfg_into_iter!(0..batch_size)
                    .map(|j| {
                        chi[j] * t_B[j * overhead + i].0 + chi_hat[j] * t_B[j * overhead + i].1
                    })
                    .sum::<Fr>();
                lhs += r[i];
                let rhs = cfg_into_iter!(0..batch_size)
                    .map(|j| {
                        if party2.beta[j * overhead + i] {
                            Fr::one() * u[j]
                        } else {
                            Fr::zero() * u[j]
                        }
                    })
                    .sum::<Fr>();
                if lhs == rhs {
                    Ok(())
                } else {
                    Err(())
                }
            });
            assert!(res.is_ok());

            for (i, b) in party2.beta.iter().enumerate() {
                if *b {
                    assert_eq!(correlations[i].0 - t_A[i].0, t_B[i].0);
                    assert_eq!(correlations[i].1 - t_A[i].1, t_B[i].1);
                } else {
                    assert_eq!(t_A[i].0, -t_B[i].0);
                    assert_eq!(t_A[i].1, -t_B[i].1);
                }
            }
            // Party 2 generates their multiplication share
            let shares_B = cfg_into_iter!(0..batch_size)
                .map(|i| {
                    (party2.b_tilde[i] * gamma_a[i])
                        + cfg_into_iter!(0..overhead)
                            .map(|j| gadget_vector.1[j] * t_B[i * overhead + j].0)
                            .sum::<Fr>()
                })
                .collect::<Vec<_>>();
            let gamma_b = cfg_into_iter!(0..batch_size)
                .map(|i| party2.b[i] - party2.b_tilde[i])
                .collect::<Vec<_>>();

            // Party 1 generates their multiplication share
            let shares_A = cfg_into_iter!(0..batch_size)
                .map(|i| {
                    (party1.a[i] * gamma_b[i])
                        + cfg_into_iter!(0..overhead)
                            .map(|j| gadget_vector.1[j] * t_A[i * overhead + j].0)
                            .sum::<Fr>()
                })
                .collect::<Vec<_>>();

            // Check if shares are correct
            for i in 0..batch_size {
                assert_eq!(shares_A[i] + shares_B[i], party1.a[i] * party2.b[i]);
            }
        }

        let batch_size = 8;
        const kappa: u16 = 256;
        const s: u16 = 80;
        let ote_params = MultiplicationOTEParams::<kappa, s> {};
        let gadget_vector = GadgetVectorForBatchMultiplication::<Fr, kappa, s>::new::<Blake2b512>(
            ote_params, b"test",
        );
        let a = (0..batch_size)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let b = (0..batch_size)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        check::<16, kappa, s>(&mut rng, a, b, ote_params, &gadget_vector, &B);
    }
}
