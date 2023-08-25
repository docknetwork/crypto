//! OT based on the paper [Efficient oblivious transfer protocols](https://dl.acm.org/doi/10.5555/365411.365502).
//! Protocol is described in section 3.1. Allows to run `m` instances of 1-of-n chosen message OTs.

use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, log2, rand::RngCore, vec, vec::Vec, UniformRand};
use digest::{ExtendableOutput, Update};
use itertools::Itertools;

use crate::{util::xor, Message};
use dock_crypto_utils::msm::WindowTable;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{configs::OTConfig, error::OTError};
use sha3::Shake256;

/// Setup for running multiple 1-of-n OTs
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct OTSenderSetup<G: AffineRepr> {
    pub ot_config: OTConfig,
    pub r: G::ScalarField,
    /// C_i * r
    pub C_r: Vec<G>,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct OTReceiver<G: AffineRepr> {
    pub ot_config: OTConfig,
    pub choices: Vec<u16>,
    pub k: Vec<G::ScalarField>,
    pub pk: Vec<G>,
    pub dk: Vec<G>,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SenderPubKey<G: AffineRepr>(
    /// g * r
    pub G,
    /// C
    pub Vec<G>,
);

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ReceiverPubKey<G: AffineRepr>(pub Vec<G>);

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SenderEncryptions(Vec<(Vec<Message>, Vec<u8>)>);

impl<G: AffineRepr> OTSenderSetup<G> {
    /// Setup done only once
    pub fn new<R: RngCore>(rng: &mut R, ot_config: OTConfig, g: &G) -> (Self, SenderPubKey<G>) {
        let r = G::ScalarField::rand(rng);
        let r_repr = r.into_bigint();
        let g_r = g.mul_bigint(&r_repr).into_affine();
        let C_proj = (0..ot_config.num_messages - 1)
            .map(|_| G::Group::rand(rng))
            .collect::<Vec<_>>();
        let C_r = G::Group::normalize_batch(
            &cfg_iter!(C_proj)
                .map(|c| c.mul_bigint(&r_repr))
                .collect::<Vec<_>>(),
        );
        (
            Self { ot_config, r, C_r },
            SenderPubKey(g_r, G::Group::normalize_batch(&C_proj)),
        )
    }

    pub fn encrypt<R: RngCore>(
        &self,
        rng: &mut R,
        pk_not: ReceiverPubKey<G>,
        messages: Vec<Vec<Message>>,
    ) -> Result<SenderEncryptions, OTError> {
        let m = self.ot_config.num_ot as usize;
        let n = self.ot_config.num_messages as usize;
        if pk_not.0.len() != m {
            return Err(OTError::IncorrectReceiverPubKeySize(
                self.ot_config.num_ot,
                pk_not.0.len() as u16,
            ));
        }
        if messages.len() != m {
            return Err(OTError::IncorrectMessageBatchSize(
                self.ot_config.num_ot,
                messages.len() as u16,
            ));
        }
        if !messages.iter().all(|m| m.len() == n) {
            return Err(OTError::IncorrectNoOfMessages(self.ot_config.num_messages));
        }

        let R = (0..m)
            .map(|_| {
                let mut bytes = vec![0u8; log2(m) as usize];
                rng.fill_bytes(&mut bytes);
                bytes
            })
            .collect::<Vec<_>>();

        let C_r = cfg_iter!(self.C_r)
            .map(|c| c.into_group())
            .collect::<Vec<_>>();
        let r_repr = self.r.into_bigint();
        let enc: Vec<_> = cfg_into_iter!(R)
            .enumerate()
            .map(|(i, R)| {
                let pk_not_i = pk_not.0[i].mul_bigint(r_repr);
                let mut pk_i = cfg_into_iter!(0..n - 1)
                    .map(|j| C_r[j] - pk_not_i)
                    .collect::<Vec<_>>();
                pk_i.insert(0, pk_not_i);
                let enc: Vec<_> = cfg_iter!(messages[i])
                    .enumerate()
                    .map(|(j, m)| {
                        let pad = hash_to_otp(
                            j as u16,
                            &pk_i[j],
                            &R,
                            m.len()
                                .try_into()
                                .map_err(|_| OTError::MessageIsTooLong(m.len()))?,
                        );

                        Ok(xor(&pad, m))
                    })
                    .collect::<Result<_, OTError>>()?;

                Ok((enc, R))
            })
            .collect::<Result<Vec<_>, OTError>>()?;
        Ok(SenderEncryptions(enc))
    }
}

impl<G: AffineRepr> OTReceiver<G> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        ot_config: OTConfig,
        choices: Vec<u16>,
        pub_key: SenderPubKey<G>,
        g: &G,
    ) -> Result<(Self, ReceiverPubKey<G>), OTError> {
        ot_config.verify_receiver_choices(&choices)?;
        if pub_key.1.len() != ot_config.num_messages as usize - 1 {
            return Err(OTError::IncorrectSenderPubKeySize(
                pub_key.1.len() as u16,
                ot_config.num_messages,
            ));
        }

        let k = (0..ot_config.num_ot)
            .map(|_| G::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let g_table = WindowTable::new(ot_config.num_ot as usize, g.into_group());
        let g_r_table = WindowTable::new(ot_config.num_ot as usize, pub_key.0.into_group());
        let (pk, pk_not, dk) = cfg_into_iter!(0..ot_config.num_ot as usize)
            .map(|i| {
                let pk = g_table.multiply(&k[i]);
                let dk = g_r_table.multiply(&k[i]);

                // For keeping the computation constant time
                let pk_times_2 = pk.double();
                let choice = choices[i];
                let pk_not = if choice == 0 {
                    // When choice == 0, pk_not = pk
                    pk_times_2 - pk
                } else {
                    pub_key.1[choice as usize - 1].into_group() - pk
                };

                (pk, pk_not, dk)
            })
            .collect::<Vec<_>>()
            .into_iter()
            .multiunzip::<(Vec<_>, Vec<_>, Vec<_>)>();
        Ok((
            Self {
                ot_config,
                choices,
                k,
                pk: G::Group::normalize_batch(&pk),
                dk: G::Group::normalize_batch(&dk),
            },
            ReceiverPubKey(G::Group::normalize_batch(&pk_not)),
        ))
    }

    pub fn decrypt(
        &self,
        sender_encryptions: SenderEncryptions,
        message_size: u32,
    ) -> Result<Vec<Message>, OTError> {
        if sender_encryptions.0.len() != self.ot_config.num_ot as usize {
            return Err(OTError::IncorrectMessageBatchSize(
                self.ot_config.num_ot,
                sender_encryptions.0.len() as u16,
            ));
        }
        if !sender_encryptions
            .0
            .iter()
            .all(|(m, _)| m.len() == self.ot_config.num_messages as usize)
        {
            return Err(OTError::IncorrectNoOfMessages(self.ot_config.num_messages));
        }
        Ok(cfg_into_iter!(sender_encryptions.0)
            .enumerate()
            .map(|(i, (m, r))| {
                let pad = hash_to_otp(self.choices[i], &self.dk[i], &r, message_size);
                let m = &m[self.choices[i] as usize];
                xor(&pad, m)
            })
            .collect())
    }
}

/// Create a one time pad of required size
fn hash_to_otp<G: CanonicalSerialize>(index: u16, pk: &G, R: &[u8], pad_size: u32) -> Vec<u8> {
    let mut bytes = index.to_be_bytes().to_vec();
    pk.serialize_compressed(&mut bytes).unwrap();
    bytes.extend_from_slice(R);
    let mut pad = vec![0; pad_size as usize];
    let mut hasher = Shake256::default();
    hasher.update(&bytes);
    hasher.finalize_xof_into(&mut pad);
    pad
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use std::time::Instant;

    #[test]
    fn naor_pinkas_ot() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let g = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);

        fn check(
            rng: &mut StdRng,
            m: u16,
            n: u16,
            choices: Vec<u16>,
            g: &<Bls12_381 as Pairing>::G1Affine,
        ) {
            let ot_config = OTConfig {
                num_ot: m,
                num_messages: n,
            };
            let start = Instant::now();
            let (sender_setup, sender_pk) = OTSenderSetup::new(rng, ot_config, g);
            println!(
                "Sender setup for {} 1-of-{} OTs in {:?}",
                m,
                n,
                start.elapsed()
            );

            let start = Instant::now();
            let (receiver, pk_not) =
                OTReceiver::new(rng, ot_config, choices, sender_pk, g).unwrap();
            println!(
                "Receiver inits {} 1-of-{} OTs in {:?}",
                m,
                n,
                start.elapsed()
            );

            let message_size = 200;
            let messages = (0..m)
                .map(|_| {
                    (0..n)
                        .map(|_| {
                            let mut bytes = vec![0u8; message_size];
                            rng.fill_bytes(&mut bytes);
                            bytes
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();

            let start = Instant::now();
            let encryptions = sender_setup.encrypt(rng, pk_not, messages.clone()).unwrap();
            println!(
                "Sender encrypts messages for {} 1-of-{} OTs in {:?}",
                m,
                n,
                start.elapsed()
            );

            let start = Instant::now();
            let decryptions = receiver.decrypt(encryptions, message_size as u32).unwrap();
            println!(
                "Receiver decrypts messages for {} 1-of-{} OTs in {:?}",
                m,
                n,
                start.elapsed()
            );
            for i in 0..m as usize {
                assert_eq!(messages[i][receiver.choices[i] as usize], decryptions[i]);
            }
        }

        check(&mut rng, 1, 2, vec![0], &g);
        check(&mut rng, 1, 2, vec![1], &g);
        check(&mut rng, 1, 3, vec![0], &g);
        check(&mut rng, 1, 3, vec![1], &g);
        check(&mut rng, 1, 3, vec![2], &g);
        check(&mut rng, 2, 2, vec![0, 0], &g);
        check(&mut rng, 2, 2, vec![0, 1], &g);
        check(&mut rng, 2, 2, vec![1, 0], &g);
        check(&mut rng, 2, 2, vec![1, 1], &g);
        check(&mut rng, 3, 2, vec![1, 1, 1], &g);
        check(&mut rng, 3, 2, vec![0, 0, 0], &g);
        check(&mut rng, 3, 3, vec![0, 1, 2], &g);
        check(&mut rng, 3, 3, vec![1, 2, 2], &g);
        check(&mut rng, 3, 3, vec![1, 0, 2], &g);
        check(&mut rng, 3, 5, vec![4, 0, 1], &g);
        check(&mut rng, 4, 2, vec![1, 0, 1, 1], &g);
        check(&mut rng, 4, 3, vec![2, 1, 0, 1], &g);
        check(&mut rng, 4, 4, vec![3, 2, 1, 0], &g);
        check(&mut rng, 4, 8, vec![7, 6, 5, 4], &g);

        let choices = (0..32).map(|_| u16::rand(&mut rng) % 2).collect();
        check(&mut rng, 32, 2, choices, &g);

        let choices = (0..64).map(|_| u16::rand(&mut rng) % 2).collect();
        check(&mut rng, 64, 2, choices, &g);

        let choices = (0..128).map(|_| u16::rand(&mut rng) % 2).collect();
        check(&mut rng, 128, 2, choices, &g);

        let choices = (0..192).map(|_| u16::rand(&mut rng) % 2).collect();
        check(&mut rng, 192, 2, choices, &g);
    }
}
