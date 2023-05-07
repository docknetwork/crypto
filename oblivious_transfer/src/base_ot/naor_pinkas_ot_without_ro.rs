//! OT based on the paper [Efficient oblivious transfer protocols](https://dl.acm.org/doi/10.5555/365411.365502)
//! which does not use random oracle.
//! Protocol is described in section 4.1. Allows to run `m` instances of 1-of-n chosen message OTs.

use ark_ec::{AffineRepr, CurveGroup};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, ops::Mul, rand::RngCore, vec::Vec, UniformRand};
use itertools::Itertools;

use crate::{configs::OTConfig, error::OTError, util::multiples_of_g};
use dock_crypto_utils::msm::WindowTable;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Reusable setup done by receiver
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct OTReceiverSetup<G: AffineRepr> {
    pub a: G::ScalarField,
    pub X: G,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ReceiverPubKey<G: AffineRepr>(
    pub Vec<G>, // Y
    pub Vec<G>, // Z_0
);

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct OTReceiver<G: AffineRepr> {
    pub ot_config: OTConfig,
    pub choices: Vec<u16>,
    pub b: Vec<G::ScalarField>,
    pub Z: Vec<G>,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SenderEncryptions<G: AffineRepr>(Vec<Vec<(G, G)>>);

impl<G: AffineRepr> OTReceiverSetup<G> {
    pub fn new<R: RngCore>(rng: &mut R, g: &G) -> Self {
        let a = G::ScalarField::rand(rng);
        let X = g.mul(&a).into_affine();
        Self { a, X }
    }
}

impl<G: AffineRepr> OTReceiver<G> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        ot_config: OTConfig,
        choices: Vec<u16>,
        setup: &OTReceiverSetup<G>,
        g: &G,
    ) -> Result<(Self, ReceiverPubKey<G>), OTError> {
        ot_config.verify_receiver_choices(&choices)?;
        let b = (0..ot_config.num_ot)
            .map(|_| G::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let g_table = WindowTable::new(ot_config.num_ot as usize, g.into_group());
        let X_table = WindowTable::new(ot_config.num_ot as usize, setup.X.into_group());
        let (Y, Z, Z_not) = cfg_into_iter!(0..ot_config.num_ot as usize)
            .map(|i| {
                let y = g_table.multiply(&b[i]);
                let z = X_table.multiply(&b[i]);
                let z_not = z - g_table.multiply(&G::ScalarField::from(choices[i]));
                (y, z, z_not)
            })
            .collect::<Vec<_>>()
            .into_iter()
            .multiunzip::<(Vec<_>, Vec<_>, Vec<_>)>();
        Ok((
            Self {
                ot_config,
                choices,
                b,
                Z: G::Group::normalize_batch(&Z),
            },
            ReceiverPubKey(
                G::Group::normalize_batch(&Y),
                G::Group::normalize_batch(&Z_not),
            ),
        ))
    }

    pub fn decrypt(&self, sender_encryptions: SenderEncryptions<G>) -> Result<Vec<G>, OTError> {
        if sender_encryptions.0.len() != self.ot_config.num_ot as usize {
            return Err(OTError::IncorrectMessageBatchSize(
                self.ot_config.num_ot,
                sender_encryptions.0.len() as u16,
            ));
        }
        if !sender_encryptions
            .0
            .iter()
            .all(|m| m.len() == self.ot_config.num_messages as usize)
        {
            return Err(OTError::IncorrectNoOfMessages(self.ot_config.num_messages));
        }
        let msgs = cfg_into_iter!(sender_encryptions.0)
            .enumerate()
            .map(|(i, enc)| {
                let (e, w) = enc[self.choices[i] as usize];
                e.into_group() - w.mul(self.b[i])
            })
            .collect::<Vec<_>>();
        Ok(G::Group::normalize_batch(&msgs))
    }
}

impl<G: AffineRepr> SenderEncryptions<G> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        ot_config: OTConfig,
        pub_key: ReceiverPubKey<G>,
        messages: Vec<Vec<G>>,
        setup: &OTReceiverSetup<G>,
        g: &G,
    ) -> Result<Self, OTError> {
        let m = ot_config.num_ot as usize;
        let n = ot_config.num_messages as usize;
        if pub_key.0.len() != m {
            return Err(OTError::IncorrectReceiverPubKeySize(
                ot_config.num_ot,
                pub_key.0.len() as u16,
            ));
        }
        if pub_key.1.len() != m {
            return Err(OTError::IncorrectReceiverPubKeySize(
                ot_config.num_ot,
                pub_key.1.len() as u16,
            ));
        }
        if messages.len() != m {
            return Err(OTError::IncorrectMessageBatchSize(
                ot_config.num_ot,
                messages.len() as u16,
            ));
        }
        if !messages.iter().all(|m| m.len() == n) {
            return Err(OTError::IncorrectNoOfMessages(ot_config.num_messages));
        }
        let mn = m * n;
        let s = (0..mn)
            .map(|_| G::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let r = (0..mn)
            .map(|_| G::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let g_table = WindowTable::new(mn, g.into_group());
        let X_table = WindowTable::new(mn, setup.X.into_group());
        let g_i = multiples_of_g(g.into_group(), n - 1);
        let enc = cfg_into_iter!(0..m)
            .map(|i| {
                let Y_table = WindowTable::new(n, pub_key.0[i].into_group());
                cfg_into_iter!(0..n)
                    .map(|j| {
                        let s = s[i * n + j];
                        let r = r[i * n + j];
                        let w = X_table.multiply(&s) + g_table.multiply(&r);
                        // z_j = z_not[i] + g * i
                        let z_j = if j == 0 {
                            pub_key.1[i].into_group()
                        } else {
                            g_i[j - 1] + pub_key.1[i]
                        };
                        let k = z_j.mul(&s) + Y_table.multiply(&r);
                        let enc_m = k + messages[i][j];
                        (enc_m.into_affine(), w.into_affine())
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        Ok(Self(enc))
    }
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

            let receiver_setup = OTReceiverSetup::new(rng, g);

            let start = Instant::now();
            let (receiver, rec_pk) =
                OTReceiver::new(rng, ot_config, choices, &receiver_setup, g).unwrap();
            println!(
                "Receiver inits {} 1-of-{} OTs in {:?}",
                m,
                n,
                start.elapsed()
            );

            let messages = (0..m)
                .map(|_| {
                    (0..n)
                        .map(|_| <Bls12_381 as Pairing>::G1Affine::rand(rng))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();

            let start = Instant::now();
            let encryptions = SenderEncryptions::new(
                rng,
                ot_config,
                rec_pk,
                messages.clone(),
                &receiver_setup,
                g,
            )
            .unwrap();
            println!(
                "Sender encrypts messages for {} 1-of-{} OTs in {:?}",
                m,
                n,
                start.elapsed()
            );

            let start = Instant::now();
            let decryptions = receiver.decrypt(encryptions).unwrap();
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
