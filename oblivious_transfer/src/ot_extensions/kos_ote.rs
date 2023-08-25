//! OT extension based on the paper [Actively Secure OT Extension with Optimal Overhead](https://eprint.iacr.org/2015/546)
//! Implements protocol in Fig. 7.
//! The `transfer` and `receive` are taken from the protocol 9 of the paper [Secure Two-party Threshold ECDSA from ECDSA Assumptions](https://eprint.iacr.org/2018/499)

use ark_ff::{
    field_hashers::{DefaultFieldHasher, HashToField},
    PrimeField,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, rand::RngCore, vec, vec::Vec, UniformRand};
use digest::{DynDigest, ExtendableOutput, Update};
use dock_crypto_utils::{join, serde_utils::ArkObjectBytes};
use itertools::MultiUnzip;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sha3::Shake256;

use crate::{
    base_ot::simplest_ot::{OneOfTwoROTSenderKeys, ROTReceiverKeys},
    ot_extensions::alsz_ote,
    util::{and, is_multiple_of_8, xor, xor_in_place},
    Bit, BitMatrix, Message,
};

use crate::{configs::OTEConfig, error::OTError};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Random Linear Combination used for error checking
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct RLC {
    pub x: Vec<u8>,
    pub t: Vec<u8>,
}

#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct OTExtensionReceiverSetup {
    pub ote_config: OTEConfig,
    /// Choices used in OT extension
    pub ot_extension_choices: Vec<Bit>,
    /// `extended_ot_count x base_ot_count` bit-matrix
    pub T: BitMatrix,
}

#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct OTExtensionSenderSetup {
    pub ote_config: OTEConfig,
    /// Choices used in base OT, packed
    pub base_ot_choices: Vec<u8>,
    /// `extended_ot_count x base_ot_count` bit-matrix
    pub Q: BitMatrix,
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct CorrelationTag<F: PrimeField>(
    #[serde_as(as = "Vec<(ArkObjectBytes, ArkObjectBytes)>")] pub Vec<(F, F)>,
);

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct SenderOutput<F: PrimeField>(
    #[serde_as(as = "Vec<(ArkObjectBytes, ArkObjectBytes)>")] pub Vec<(F, F)>,
);

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct ReceiverOutput<F: PrimeField>(
    #[serde_as(as = "Vec<(ArkObjectBytes, ArkObjectBytes)>")] pub Vec<(F, F)>,
);

impl OTExtensionReceiverSetup {
    pub fn new<R: RngCore, const STATISTICAL_SECURITY_PARAMETER: u16>(
        rng: &mut R,
        ote_config: OTEConfig,
        mut choices: Vec<Bit>,
        base_ot_keys: OneOfTwoROTSenderKeys,
    ) -> Result<(Self, BitMatrix, RLC), OTError> {
        if !is_multiple_of_8(STATISTICAL_SECURITY_PARAMETER) {
            return Err(OTError::SecurityParameterShouldBeMultipleOf8(
                STATISTICAL_SECURITY_PARAMETER,
            ));
        }
        choices.extend(
            (0..ote_config.num_base_ot + STATISTICAL_SECURITY_PARAMETER).map(|_| bool::rand(rng)),
        );
        let l_prime = choices
            .len()
            .try_into()
            .map_err(|_| OTError::TooManyChoices(choices.len()))?;
        let new_ote_config = OTEConfig::new(ote_config.num_base_ot, l_prime)?;
        let (setup, U) =
            alsz_ote::OTExtensionReceiverSetup::new(new_ote_config, choices, base_ot_keys)?;
        let row_byte_size = ote_config.row_byte_size();
        debug_assert_eq!(U.0.len(), l_prime as usize * row_byte_size);
        let chi = gen_randomness(
            setup.ote_config.num_base_ot as u32,
            setup.ote_config.num_ot_extensions,
            &U,
            row_byte_size as u32 * l_prime,
        );
        let mut x = vec![0; row_byte_size];
        let mut t = vec![0; row_byte_size];
        // `ones` is equivalent to a bit vector with all 1s
        let ones = vec![255; row_byte_size];
        let zeroes = vec![0; row_byte_size];
        for i in 0..l_prime as usize {
            let chi_i = &chi[i * row_byte_size..(i + 1) * row_byte_size];
            join!(
                xor_in_place(
                    &mut x,
                    &and(
                        if setup.ot_extension_choices[i] {
                            &ones
                        } else {
                            &zeroes
                        },
                        chi_i,
                    ),
                ),
                xor_in_place(
                    &mut t,
                    &and(
                        &setup.T.0[i * row_byte_size..(i + 1) * row_byte_size],
                        chi_i,
                    ),
                )
            );
        }
        Ok((
            Self {
                ote_config,
                ot_extension_choices: setup.ot_extension_choices,
                T: setup.T,
            },
            U,
            RLC { x, t },
        ))
    }

    pub fn decrypt(
        &self,
        encryptions: Vec<(Message, Message)>,
        message_size: u32,
    ) -> Result<Vec<Message>, OTError> {
        alsz_ote::OTExtensionReceiverSetup::decrypt_(
            self.ote_config,
            &self.T,
            &self.ot_extension_choices,
            encryptions,
            message_size,
        )
    }

    pub fn decrypt_correlated(
        &self,
        encryptions: Vec<Message>,
        message_size: u32,
    ) -> Result<Vec<Message>, OTError> {
        alsz_ote::OTExtensionReceiverSetup::decrypt_correlated_(
            self.ote_config,
            &self.T,
            &self.ot_extension_choices,
            encryptions,
            message_size,
        )
    }

    /// Receiver takes the correlation tag and creates its correlated output
    /// Step 7 of Protocol 9 in paper Secure Two-party Threshold ECDSA
    pub fn receive<F: PrimeField, D: Default + DynDigest + Clone>(
        &self,
        tau: CorrelationTag<F>,
    ) -> Result<ReceiverOutput<F>, OTError> {
        if tau.len() != self.ote_config.num_ot_extensions as usize {
            return Err(OTError::IncorrectNoOfCorrelations(
                self.ote_config.num_ot_extensions as usize,
                tau.len(),
            ));
        }
        let row_byte_size = self.ote_config.row_byte_size();
        Ok(ReceiverOutput(
            cfg_into_iter!(tau.0)
                .enumerate()
                .map(|(i, tau_i)| {
                    let hasher = <DefaultFieldHasher<D> as HashToField<F>>::new(b"KOS-OTE");
                    let t = &self.T.0[i * row_byte_size..(i + 1) * row_byte_size];
                    let m = if self.ot_extension_choices[i] {
                        F::one()
                    } else {
                        F::zero()
                    };
                    let tau_i = (tau_i.0 * m, tau_i.1 * m);
                    let mut t_B_i = hash_to_field(i as u32, &t, &hasher);
                    t_B_i = (tau_i.0 - t_B_i.0, tau_i.1 - t_B_i.1);
                    t_B_i
                })
                .collect(),
        ))
    }
}

impl OTExtensionSenderSetup {
    pub fn new<const STATISTICAL_SECURITY_PARAMETER: u16>(
        ote_config: OTEConfig,
        U: BitMatrix,
        rlc: RLC,
        base_ot_choices: Vec<Bit>,
        base_ot_keys: ROTReceiverKeys,
    ) -> Result<Self, OTError> {
        if !is_multiple_of_8(STATISTICAL_SECURITY_PARAMETER as usize) {
            return Err(OTError::SecurityParameterShouldBeMultipleOf8(
                STATISTICAL_SECURITY_PARAMETER,
            ));
        }
        let row_byte_size = ote_config.row_byte_size();
        if rlc.t.len() != row_byte_size {
            return Err(OTError::RandomLinearCombinationCheckSizeIncorrect(
                row_byte_size as u16,
                rlc.t.len() as u16,
            ));
        }
        if rlc.x.len() != row_byte_size {
            return Err(OTError::RandomLinearCombinationCheckSizeIncorrect(
                row_byte_size as u16,
                rlc.x.len() as u16,
            ));
        }
        let l_prime = ote_config.num_ot_extensions
            + ote_config.num_base_ot as u32
            + STATISTICAL_SECURITY_PARAMETER as u32;
        let new_ote_config = OTEConfig::new(ote_config.num_base_ot, l_prime)?;

        let chi = gen_randomness(
            ote_config.num_base_ot as u32,
            l_prime,
            &U,
            row_byte_size as u32 * l_prime as u32,
        );
        let setup = alsz_ote::OTExtensionSenderSetup::new(
            new_ote_config,
            U,
            base_ot_choices,
            base_ot_keys,
        )?;
        debug_assert_eq!(setup.Q.0.len(), l_prime as usize * row_byte_size);
        debug_assert_eq!(setup.base_ot_choices.len(), row_byte_size);
        let mut q = vec![0; row_byte_size];
        for i in 0..l_prime as usize {
            let chi_i = &chi[i * row_byte_size..(i + 1) * row_byte_size];
            xor_in_place(
                &mut q,
                &and(
                    &setup.Q.0[i * row_byte_size..(i + 1) * row_byte_size],
                    chi_i,
                ),
            );
        }
        if rlc.t != xor(&q, &and(&rlc.x, &setup.base_ot_choices)) {
            return Err(OTError::RandomLinearCombinationCheckFailed);
        }
        Ok(Self {
            ote_config,
            base_ot_choices: setup.base_ot_choices,
            Q: setup.Q,
        })
    }

    pub fn encrypt(
        &self,
        messages: Vec<(Message, Message)>,
        message_size: u32,
    ) -> Result<Vec<(Message, Message)>, OTError> {
        alsz_ote::OTExtensionSenderSetup::encrypt_(
            self.ote_config,
            &self.Q,
            &self.base_ot_choices,
            messages,
            message_size,
        )
    }

    pub fn encrypt_correlated<F: Sync + Sized + Fn(&Message) -> Message>(
        &self,
        deltas: Vec<F>,
        message_size: u32,
    ) -> Result<(Vec<(Message, Message)>, Vec<Message>), OTError> {
        alsz_ote::OTExtensionSenderSetup::encrypt_correlated_(
            self.ote_config,
            &self.Q,
            &self.base_ot_choices,
            deltas,
            message_size,
        )
    }

    /// Sender takes the correlation and transfers the correlated output and correlation tag.
    /// Step 6 of Protocol 9 in paper Secure Two-party Threshold ECDSA
    pub fn transfer<F: PrimeField, D: Default + DynDigest + Clone>(
        &self,
        alpha: Vec<(F, F)>,
    ) -> Result<(SenderOutput<F>, CorrelationTag<F>), OTError> {
        if alpha.len() != self.ote_config.num_ot_extensions as usize {
            return Err(OTError::IncorrectNoOfCorrelations(
                self.ote_config.num_ot_extensions as usize,
                alpha.len(),
            ));
        }
        let row_byte_size = self.ote_config.row_byte_size();
        let (t_A, tau) = cfg_into_iter!(alpha)
            .enumerate()
            .map(|(i, alpha_i)| {
                let hasher = <DefaultFieldHasher<D> as HashToField<F>>::new(b"KOS-OTE");
                let q = &self.Q.0[i * row_byte_size..(i + 1) * row_byte_size];
                let t_A_i = hash_to_field(i as u32, &q, &hasher);
                let mut tau_i = hash_to_field(i as u32, &xor(&q, &self.base_ot_choices), &hasher);
                tau_i = (tau_i.0 - t_A_i.0 + alpha_i.0, tau_i.1 - t_A_i.1 + alpha_i.1);
                (t_A_i, tau_i)
            })
            .collect::<Vec<_>>()
            .into_iter()
            .multiunzip();
        Ok((SenderOutput(t_A), CorrelationTag(tau)))
    }
}

impl<F: PrimeField> SenderOutput<F> {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl<F: PrimeField> ReceiverOutput<F> {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl<F: PrimeField> CorrelationTag<F> {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

fn gen_randomness(a: u32, b: u32, U: &BitMatrix, output_size: u32) -> Vec<u8> {
    let mut bytes = a.to_be_bytes().to_vec();
    bytes.extend(&b.to_be_bytes());
    bytes.extend_from_slice(&U.0);
    let mut randomness = vec![0; output_size as usize];
    let mut hasher = Shake256::default();
    hasher.update(&bytes);
    hasher.finalize_xof_into(&mut randomness);
    randomness
}

pub fn hash_to_field<F: PrimeField, D: Default + DynDigest + Clone>(
    index: u32,
    q: &[u8],
    hasher: &DefaultFieldHasher<D>,
) -> (F, F) {
    let mut seed = index.to_be_bytes().to_vec();
    seed.extend_from_slice(q);
    let mut out = hasher.hash_to_field(&seed, 2);
    let out_0 = out.pop().unwrap();
    let out_1 = out.pop().unwrap();
    (out_0, out_1)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::base_ot::simplest_ot::tests::do_1_of_2_base_ot;
    use std::time::Instant;

    use ark_bls12_381::Fr;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use test_utils::{test_serialization, G1};

    #[test]
    fn kos() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let B = G1::rand(&mut rng);

        fn check<const KEY_SIZE: u16, const SSP: u16>(
            rng: &mut StdRng,
            base_ot_count: u16,
            extended_ot_count: usize,
            ot_ext_choices: Vec<bool>,
            message_size: u32,
            B: &G1,
            check_serialization: bool,
        ) {
            let message_size = message_size as usize;
            // Perform base OT with roles reversed
            // In practice, do VSOT
            let (base_ot_choices, base_ot_sender_keys, base_ot_receiver_keys) =
                do_1_of_2_base_ot::<KEY_SIZE>(rng, base_ot_count, B);

            let ote_config = OTEConfig::new(base_ot_count, extended_ot_count as u32).unwrap();

            let start = Instant::now();
            // Perform OT extension
            let (ext_receiver_setup, U, rlc) = OTExtensionReceiverSetup::new::<_, SSP>(
                rng,
                ote_config,
                ot_ext_choices.clone(),
                base_ot_sender_keys,
            )
            .unwrap();
            let receiver_setup_time = start.elapsed();

            assert_eq!(
                ext_receiver_setup.ot_extension_choices.len(),
                ot_ext_choices.len() + base_ot_count as usize + SSP as usize
            );

            let start = Instant::now();
            let base_ot_choices = base_ot_choices
                .into_iter()
                .map(|b| b % 2 != 0)
                .collect::<Vec<_>>();
            let ext_sender_setup = OTExtensionSenderSetup::new::<SSP>(
                ote_config,
                U.clone(),
                rlc.clone(),
                base_ot_choices,
                base_ot_receiver_keys,
            )
            .unwrap();
            let sender_setup_time = start.elapsed();

            let messages = (0..extended_ot_count)
                .map(|_| {
                    (
                        {
                            let mut bytes = vec![0u8; message_size];
                            rng.fill_bytes(&mut bytes);
                            bytes
                        },
                        {
                            let mut bytes = vec![0u8; message_size];
                            rng.fill_bytes(&mut bytes);
                            bytes
                        },
                    )
                })
                .collect::<Vec<_>>();

            let start = Instant::now();
            let encryptions = ext_sender_setup
                .encrypt(messages.clone(), message_size as u32)
                .unwrap();
            let encryption_time = start.elapsed();

            let start = Instant::now();
            let decryptions = ext_receiver_setup
                .decrypt(encryptions, message_size as u32)
                .unwrap();
            let decryption_time = start.elapsed();

            assert_eq!(decryptions.len(), extended_ot_count);
            cfg_into_iter!(decryptions)
                .enumerate()
                .for_each(|(i, dec)| {
                    if !ext_receiver_setup.ot_extension_choices[i] {
                        assert_eq!(dec, messages[i].0);
                    } else {
                        assert_eq!(dec, messages[i].1);
                    }
                    assert_eq!(dec.len(), message_size);
                });

            // Perform Correlated OT extension
            let start = Instant::now();
            let deltas = (0..extended_ot_count)
                .map(|_| {
                    let mut bytes = vec![0u8; message_size];
                    rng.fill_bytes(&mut bytes);
                    move |m: &Vec<u8>| xor(m, &bytes)
                })
                .collect::<Vec<_>>();
            let (messages, encryptions) = ext_sender_setup
                .encrypt_correlated(deltas.clone(), message_size as u32)
                .unwrap();
            let cot_encryption_time = start.elapsed();

            let start = Instant::now();
            let decryptions = ext_receiver_setup
                .decrypt_correlated(encryptions, message_size as u32)
                .unwrap();
            let cot_decryption_time = start.elapsed();

            assert_eq!(messages.len(), extended_ot_count);
            assert_eq!(decryptions.len(), extended_ot_count);
            cfg_into_iter!(decryptions)
                .enumerate()
                .for_each(|(i, dec)| {
                    if !ext_receiver_setup.ot_extension_choices[i] {
                        assert_eq!(dec, messages[i].0);
                    } else {
                        assert_eq!(dec, messages[i].1);
                    }
                    assert_eq!(dec.len(), message_size);
                    assert_eq!(messages[i].1, deltas[i](&messages[i].0));
                });

            // Perform Correlated OT extension
            let start = Instant::now();
            let alpha = (0..extended_ot_count)
                .map(|_| (Fr::rand(rng), Fr::rand(rng)))
                .collect::<Vec<_>>();
            let (t_A, tau) = ext_sender_setup
                .transfer::<Fr, Blake2b512>(alpha.clone())
                .unwrap();
            let cot_1_encryption_time = start.elapsed();
            assert_eq!(t_A.len(), tau.len());

            let start = Instant::now();
            let t_B = ext_receiver_setup
                .receive::<Fr, Blake2b512>(tau.clone())
                .unwrap();
            let cot_1_decryption_time = start.elapsed();

            assert_eq!(t_A.len(), t_B.len());
            cfg_into_iter!(t_A.clone().0)
                .zip(t_B.clone().0)
                .enumerate()
                .for_each(|(i, (t_A_i, t_B_i))| {
                    if !ext_receiver_setup.ot_extension_choices[i] {
                        assert_eq!(t_A_i.0, -t_B_i.0);
                        assert_eq!(t_A_i.1, -t_B_i.1);
                    } else {
                        assert_eq!(alpha[i].0 - t_A_i.0, t_B_i.0);
                        assert_eq!(alpha[i].1 - t_A_i.1, t_B_i.1);
                    }
                });

            println!(
                "For {} base OTs and {} extensions",
                base_ot_count, extended_ot_count
            );
            println!(
                "Sender setup takes {:?} and receiver setup takes {:?}",
                sender_setup_time, receiver_setup_time
            );
            println!(
                "Encrypting messages of {} bytes takes {:?} and decryption takes {:?}",
                message_size, encryption_time, decryption_time
            );
            println!(
                "Doing Correlated OT takes {:?} and decryption takes {:?}",
                cot_encryption_time, cot_decryption_time
            );
            println!(
                "Doing Correlated OT takes {:?} and decryption takes {:?}",
                cot_1_encryption_time, cot_1_decryption_time
            );

            if check_serialization {
                test_serialization!(OTExtensionReceiverSetup, ext_receiver_setup);
                test_serialization!(BitMatrix, U);
                test_serialization!(RLC, rlc);
                test_serialization!(OTExtensionSenderSetup, ext_sender_setup);
                test_serialization!(SenderOutput<Fr>, t_A);
                test_serialization!(CorrelationTag<Fr>, tau);
                test_serialization!(ReceiverOutput<Fr>, t_B);
            }
        }

        let mut checked = false;
        for (base_ot_count, extended_ot_count) in [
            (256, 1024),
            (256, 2048),
            (512, 2048),
            (512, 4096),
            (1024, 4096),
            (1024, 8192),
        ] {
            let choices = (0..extended_ot_count)
                .map(|_| u8::rand(&mut rng) % 2 != 0)
                .collect();
            check::<128, 80>(
                &mut rng,
                base_ot_count,
                extended_ot_count,
                choices,
                1024,
                &B,
                !checked,
            );
            checked = true;
        }
    }
}
