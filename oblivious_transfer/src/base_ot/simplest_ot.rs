//! Implements OT based on the paper [The Simplest Protocol for Oblivious Transfer](https://eprint.iacr.org/2015/267).
//! Implements Verified OT to guard against a malicious receiver as described in protocol 7 and called Verified Simplest OT (VSOT), of
//! the paper [Secure Two-party Threshold ECDSA from ECDSA Assumptions](https://eprint.iacr.org/2018/499)
//! This module first implements a Random OT (ROT) which can then be used to realize an OT with actual messages
//! Allows to run multiple instances of 1-of-n ROTs (Random OT).

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, rand::RngCore, vec, vec::Vec, UniformRand};
use digest::{Digest, ExtendableOutput, Update};
use dock_crypto_utils::{msm::WindowTable, serde_utils::ArkObjectBytes};
use itertools::Itertools;
use schnorr_pok::{
    compute_random_oracle_challenge,
    discrete_log::{PokDiscreteLog, PokDiscreteLogProtocol},
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::Zeroize;

use crate::{error::OTError, util, Bit, Key};

use crate::util::{is_multiple_of_8, multiples_of_g};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::configs::OTConfig;
use sha3::{Sha3_256, Shake256};

/// Public key created by base OT sender and sent to the receiver
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct SenderPubKey<G: AffineRepr>(#[serde_as(as = "ArkObjectBytes")] pub G);

/// Public key created by the base OT receiver and sent to the sender
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct ReceiverPubKeys<G: AffineRepr>(#[serde_as(as = "Vec<ArkObjectBytes>")] pub Vec<G>);

/// Setup for running multiple 1-of-n OTs
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct ROTSenderSetup<G: AffineRepr> {
    pub ot_config: OTConfig,
    #[serde_as(as = "ArkObjectBytes")]
    pub y: G::ScalarField,
    #[serde_as(as = "ArkObjectBytes")]
    pub S: G,
}

// TODO: Make it use const generic for key size and replace byte vector with slice
/// Sender's keys for multiple 1-of-n ROTs
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Zeroize,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct ROTSenderKeys(pub Vec<Vec<Key>>);

// TODO: Make it use const generic for key size and replace byte vector with slice
/// Receiver's keys for multiple 1-of-n ROTs
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Zeroize,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct ROTReceiverKeys(pub Vec<Key>);

/// Sender's keys for multiple 1-of-2 ROTs
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Zeroize,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct OneOfTwoROTSenderKeys(pub Vec<(Key, Key)>);

#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct HashedKey(pub Vec<u8>);

#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct DoubleHashedKey(pub Vec<u8>);

/// The OT sender acts as a challenger and creates the challenges. Used in Verified Simplest OT
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct VSROTChallenger {
    pub double_hashed_keys_0: Vec<DoubleHashedKey>,
    pub hashed_keys: Vec<(HashedKey, HashedKey)>,
}

/// The OT receiver receives challenges from the OT sender and verifies the challenges and sends
/// responses. Used in Verified Simplest OT
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct VSROTResponder {
    pub choices: Vec<Bit>,
    pub hashed_keys: Vec<HashedKey>,
    pub challenges: Challenges,
}

/// Sent by the OT sender
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct Challenges(pub Vec<Vec<u8>>);

/// Sent by the OT receiver as response to `Challenges`
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct Responses(pub Vec<Vec<u8>>);

impl<G: AffineRepr> ReceiverPubKeys<G> {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Challenges {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Responses {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl<G: AffineRepr> ROTSenderSetup<G> {
    /// Initialize a sender of the Random OT protocol and return the public key to be sent to the receiver
    pub fn new<R: RngCore>(rng: &mut R, ot_config: OTConfig, B: &G) -> (Self, SenderPubKey<G>) {
        let y = G::ScalarField::rand(rng);
        let S = B.mul(&y).into();
        (Self { ot_config, y, S }, SenderPubKey(S))
    }

    /// Initialize a sender for Verified Simplest OT protocol and return the public key and the proof of
    /// knowledge of the secret key to be sent to the receiver
    pub fn new_verifiable<R: RngCore, D: Digest>(
        rng: &mut R,
        num_ot: u16,
        B: &G,
    ) -> Result<(Self, SenderPubKey<G>, PokDiscreteLog<G>), OTError> {
        let (setup, S) = Self::new(rng, OTConfig::new_2_message(num_ot)?, B);
        let blinding = G::ScalarField::rand(rng);
        let schnorr_protocol = PokDiscreteLogProtocol::init(setup.y.clone(), blinding, B);
        let mut challenge_bytes = vec![];
        schnorr_protocol
            .challenge_contribution(B, &S.0, &mut challenge_bytes)
            .map_err(|e| OTError::SchnorrError(e))?;
        // TODO: Need Transcript here
        let challenge = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        let schnorr_proof = schnorr_protocol.gen_proof(&challenge);
        Ok((setup, S, schnorr_proof))
    }

    /// Derive the sender's keys using receiver's public key
    pub fn derive_keys<const KEY_SIZE: u16>(
        &self,
        R: ReceiverPubKeys<G>,
    ) -> Result<ROTSenderKeys, OTError> {
        if R.len() != self.ot_config.num_ot as usize {
            return Err(OTError::IncorrectReceiverPubKeySize(
                self.ot_config.num_ot,
                R.len() as u16,
            ));
        }
        if !is_multiple_of_8(KEY_SIZE as usize) {
            return Err(OTError::BaseOTKeySizeMustBeMultipleOf8(KEY_SIZE));
        }

        let y = self.y.into_bigint();
        let T = self.S.mul_bigint(&y);
        let jT = multiples_of_g(T, self.ot_config.num_messages as usize - 1);

        let yR = cfg_iter!(R.0).map(|r| r.mul_bigint(&y)).collect::<Vec<_>>();
        let keys = cfg_into_iter!(0..self.ot_config.num_ot as usize)
            .map(|i| {
                cfg_into_iter!(0..self.ot_config.num_messages as usize)
                    .map(|j| {
                        let jt = if j == 0 {
                            yR[i].into_affine()
                        } else {
                            (yR[i] - jT[j - 1]).into_affine()
                        };
                        hash_to_otp::<G, KEY_SIZE>(i as u32, &self.S, &R.0[i], &jt)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        Ok(ROTSenderKeys(keys))
    }
}

impl ROTReceiverKeys {
    /// Create symmetric keys and the public keys of receiver of the Random OT protocol.
    pub fn new<R: RngCore, G: AffineRepr, const KEY_SIZE: u16>(
        rng: &mut R,
        ot_config: OTConfig,
        choices: Vec<u16>,
        S: SenderPubKey<G>,
        B: &G,
    ) -> Result<(Self, ReceiverPubKeys<G>), OTError> {
        ot_config.verify_receiver_choices(&choices)?;
        if !is_multiple_of_8(KEY_SIZE as usize) {
            return Err(OTError::BaseOTKeySizeMustBeMultipleOf8(KEY_SIZE));
        }
        let x = (0..ot_config.num_ot)
            .map(|_| G::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let R;
        let xS;
        if ot_config.num_ot > 1 {
            let s_table = WindowTable::new(ot_config.num_ot as usize, S.0.into_group());
            let b_table = WindowTable::new(ot_config.num_messages as usize, B.into_group());
            // TODO: Possible optmz is using WindowTable::multiply_many and creating multiples of S and B and adding them later
            R = G::Group::normalize_batch(
                &cfg_iter!(choices)
                    .zip(cfg_iter!(x))
                    .map(|(c, x)| s_table.multiply(&G::ScalarField::from(*c)) + b_table.multiply(x))
                    .collect::<Vec<_>>(),
            );
            xS = G::Group::normalize_batch(
                &cfg_iter!(x)
                    .map(|x| s_table.multiply(x))
                    .collect::<Vec<_>>(),
            );
        } else {
            R = vec![
                (S.0.mul(G::ScalarField::from(choices[0].clone())) + B.mul(&x[0])).into_affine(),
            ];
            xS = vec![S.0.mul(&x[0]).into_affine()]
        }
        let keys = cfg_iter!(xS)
            .enumerate()
            .map(|(i, xs)| hash_to_otp::<G, KEY_SIZE>(i as u32, &S.0, &R[i], xs))
            .collect::<Vec<_>>();
        Ok((Self(keys), ReceiverPubKeys(R)))
    }

    /// Create symmetric keys and the public keys of receiver of the Verified Simplest OT protocol.
    /// Verifies the proof of knowledge of secret key.
    pub fn new_verifiable<R: RngCore, G: AffineRepr, D: Digest, const KEY_SIZE: u16>(
        rng: &mut R,
        num_ot: u16,
        choices: Vec<Bit>,
        S: SenderPubKey<G>,
        schnorr_proof: &PokDiscreteLog<G>,
        B: &G,
    ) -> Result<(Self, ReceiverPubKeys<G>), OTError> {
        let mut challenge_bytes = vec![];
        schnorr_proof
            .challenge_contribution(B, &S.0, &mut challenge_bytes)
            .map_err(|e| OTError::SchnorrError(e))?;
        let challenge = compute_random_oracle_challenge::<G::ScalarField, D>(&challenge_bytes);
        if !schnorr_proof.verify(&S.0, B, &challenge) {
            return Err(OTError::InvalidSchnorrProof);
        }
        Self::new::<_, _, KEY_SIZE>(
            rng,
            OTConfig::new_2_message(num_ot)?,
            cfg_into_iter!(choices).map(|c| u16::from(c)).collect(),
            S,
            B,
        )
    }
}

impl VSROTChallenger {
    /// OT sender creates challenges for the receiver. Refers to step 5 of the VSOT protocol
    pub fn new(derived_keys: &OneOfTwoROTSenderKeys) -> Result<(Self, Challenges), OTError> {
        if derived_keys.len() == 0 {
            return Err(OTError::NeedNonZeroNumberOfDerivedKeys);
        }
        let (challenges, double_hashed_keys_0, hashed_keys) = cfg_iter!(derived_keys.0)
            .enumerate()
            .map(|(i, keys)| {
                let hash_key_0 = hash_key(&keys.0, i as u16);
                let hash_key_1 = hash_key(&keys.1, i as u16);
                let double_hash_key_0 = hash_key(&hash_key_0, i as u16);
                let double_hash_key_1 = hash_key(&hash_key_1, i as u16);
                let challenge = util::xor(&double_hash_key_0, &double_hash_key_1);
                (
                    challenge,
                    DoubleHashedKey(double_hash_key_0),
                    (HashedKey(hash_key_0), HashedKey(hash_key_1)),
                )
            })
            .collect::<Vec<_>>()
            .into_iter()
            .multiunzip::<(Vec<_>, Vec<_>, Vec<_>)>();
        Ok((
            Self {
                double_hashed_keys_0,
                hashed_keys,
            },
            Challenges(challenges),
        ))
    }

    /// OT sender verifier responses to the challenges from the receiver and if valid sends the hashed
    /// keys to the receiver. Refers to step 7 of the VSOT protocol
    pub fn verify_responses(
        self,
        responses: Responses,
    ) -> Result<Vec<(HashedKey, HashedKey)>, OTError> {
        if responses.len() != self.double_hashed_keys_0.len() {
            return Err(OTError::IncorrectNoOfResponses(
                responses.len() as u16,
                self.double_hashed_keys_0.len() as u16,
            ));
        }
        let res = cfg_into_iter!(0..responses.len()).try_for_each(|i| {
            if responses.0[i] == self.double_hashed_keys_0[i].0 {
                Ok(())
            } else {
                Err(i as u16)
            }
        });
        if let Err(i) = res {
            Err(OTError::InvalidResponseAtIndex(i))
        } else {
            Ok(self.hashed_keys)
        }
    }
}

impl VSROTResponder {
    /// OT receiver receives challenges from the sender and creates responses. Refers to step 6 of the VSOT protocol
    pub fn new(
        derived_keys: &ROTReceiverKeys,
        choices: Vec<Bit>,
        challenges: Challenges,
    ) -> Result<(Self, Responses), OTError> {
        if derived_keys.len() == 0 {
            return Err(OTError::NeedNonZeroNumberOfDerivedKeys);
        }
        if derived_keys.len() != challenges.len() {
            return Err(OTError::IncorrectNoOfChallenges(
                derived_keys.len() as u16,
                challenges.len() as u16,
            ));
        }
        if derived_keys.len() != choices.len() {
            return Err(OTError::IncorrectNoOfBaseOTChoices(
                derived_keys.len() as u16,
                choices.len() as u16,
            ));
        }
        let (hashed_keys, responses) = cfg_iter!(derived_keys.0)
            .enumerate()
            .map(|(i, key)| {
                let hashed_key = hash_key(key, i as u16);
                let mut resp = hash_key(&hashed_key, i as u16);
                // Evaluating both arms of `if` block to prevent side channel
                if choices[i] {
                    resp = util::xor(&resp, &challenges.0[i]);
                } else {
                    // TODO: Move this out and ensure each challenges.0[i] is of same size
                    let zero = vec![0; challenges.0[i].len()];
                    resp = util::xor(&resp, &zero);
                }
                (HashedKey(hashed_key), resp)
            })
            .collect::<Vec<_>>()
            .into_iter()
            .multiunzip::<(Vec<_>, Vec<_>)>();
        Ok((
            Self {
                hashed_keys,
                choices,
                challenges,
            },
            Responses(responses),
        ))
    }

    /// OT receiver verifies that the hashed keys are correct. Refers to step 8 of the VSOT protocol
    pub fn verify_sender_hashed_keys(
        &self,
        sender_hashed_keys: Vec<(HashedKey, HashedKey)>,
    ) -> Result<(), OTError> {
        if sender_hashed_keys.len() != self.choices.len() {
            return Err(OTError::IncorrectNoOfBaseOTChoices(
                sender_hashed_keys.len() as u16,
                self.choices.len() as u16,
            ));
        }
        let res = cfg_into_iter!(0..sender_hashed_keys.len()).try_for_each(|i| {
            let (k_0, k_1) = &sender_hashed_keys[i];
            let check1 = if self.choices[i] {
                self.hashed_keys[i] == *k_1
            } else {
                self.hashed_keys[i] == *k_0
            };
            if !check1 {
                return Err(i as u16);
            }
            let double_hash_key_0 = hash_key(&k_0.0, i as u16);
            let double_hash_key_1 = hash_key(&k_1.0, i as u16);
            let challenge = util::xor(&double_hash_key_0, &double_hash_key_1);
            let check2 = challenge == self.challenges.0[i];
            if !check2 {
                return Err(i as u16);
            }
            Ok(())
        });
        if let Err(i) = res {
            Err(OTError::InvalidHashedKeyAtIndex(i))
        } else {
            Ok(())
        }
    }
}

impl TryFrom<ROTSenderKeys> for OneOfTwoROTSenderKeys {
    type Error = OTError;

    fn try_from(keys: ROTSenderKeys) -> Result<Self, Self::Error> {
        let mut r = Vec::with_capacity(keys.0.len());
        for mut k in keys.0 {
            if k.len() != 2 {
                return Err(OTError::NumberOfKeysExpectedToBe2(k.len()));
            }
            let k0 = k.remove(0);
            let k1 = k.remove(0);
            r.push((k0, k1))
        }
        Ok(OneOfTwoROTSenderKeys(r))
    }
}

impl ROTSenderKeys {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl ROTReceiverKeys {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl OneOfTwoROTSenderKeys {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

// TODO: Make it use const generic for key size and generic digest
pub fn hash_to_otp<G: CanonicalSerialize, const KEY_SIZE: u16>(
    index: u32,
    s: &G,
    r: &G,
    input: &G,
) -> Vec<u8> {
    let mut bytes = index.to_be_bytes().to_vec();
    s.serialize_compressed(&mut bytes).unwrap();
    r.serialize_compressed(&mut bytes).unwrap();
    input.serialize_compressed(&mut bytes).unwrap();
    index.serialize_compressed(&mut bytes).unwrap();
    let mut key = vec![0; KEY_SIZE as usize / 8];
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, &bytes);
    hasher.finalize_xof_into(&mut key);
    key
}

// TODO: Make it use const generic for key size and generic digest
pub fn hash_key(key: &[u8], index: u16) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, index.to_be_bytes());
    Digest::update(&mut hasher, &key);
    hasher.finalize().to_vec()
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
    use blake2::Blake2b512;
    use std::time::Instant;
    use test_utils::{test_serialization, G1};

    pub fn do_1_of_2_base_ot<const KEY_SIZE: u16>(
        rng: &mut StdRng,
        base_ot_count: u16,
        B: &G1,
    ) -> (Vec<u16>, OneOfTwoROTSenderKeys, ROTReceiverKeys) {
        let ot_config = OTConfig::new_2_message(base_ot_count).unwrap();

        let (base_ot_sender_setup, S) = ROTSenderSetup::new(rng, ot_config, B);

        let base_ot_choices = (0..base_ot_count)
            .map(|_| u16::rand(rng) % 2)
            .collect::<Vec<_>>();
        let (base_ot_receiver_keys, R) =
            ROTReceiverKeys::new::<_, _, KEY_SIZE>(rng, ot_config, base_ot_choices.clone(), S, B)
                .unwrap();

        let base_ot_sender_keys = OneOfTwoROTSenderKeys::try_from(
            base_ot_sender_setup.derive_keys::<KEY_SIZE>(R).unwrap(),
        )
        .unwrap();
        (base_ot_choices, base_ot_sender_keys, base_ot_receiver_keys)
    }

    pub fn check_base_ot_keys(
        choices: &[Bit],
        receiver_keys: &ROTReceiverKeys,
        sender_keys: &OneOfTwoROTSenderKeys,
    ) {
        for i in 0..sender_keys.len() {
            if choices[i] {
                assert_eq!(sender_keys.0[i].1, receiver_keys.0[i]);
            } else {
                assert_eq!(sender_keys.0[i].0, receiver_keys.0[i]);
            }
        }
    }

    #[test]
    fn simplest_rot() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let B = G1::rand(&mut rng);

        fn check<const KEY_SIZE: u16>(
            rng: &mut StdRng,
            m: u16,
            n: u16,
            choices: Vec<u16>,
            B: &G1,
            check_serialization: bool,
        ) {
            let ot_config = OTConfig {
                num_ot: m,
                num_messages: n,
            };
            let (sender_setup, S) = ROTSenderSetup::new(rng, ot_config, B);

            let start = Instant::now();
            let (receiver_keys, R) = ROTReceiverKeys::new::<_, _, KEY_SIZE>(
                rng,
                ot_config,
                choices.clone(),
                S.clone(),
                B,
            )
            .expect("Error in creating keys for OT receiver");
            assert_eq!(R.len(), ot_config.num_ot as usize);

            let string = format!("{} byte keys for {} 1-of-{}", KEY_SIZE, m, n);

            println!("Receiver gets {} ROTs in {:?}", string, start.elapsed());

            let start = Instant::now();
            let sender_keys = sender_setup
                .derive_keys::<KEY_SIZE>(R.clone())
                .expect("Error in creating keys for OT sender");
            println!("Sender creates {} ROTs in {:?}", string, start.elapsed());

            assert_eq!(sender_keys.len(), ot_config.num_ot as usize);
            assert_eq!(receiver_keys.len(), ot_config.num_ot as usize);
            for i in 0..m as usize {
                assert_eq!(sender_keys.0[i].len(), ot_config.num_messages as usize);
                for j in 0..ot_config.num_messages as usize {
                    if j == choices[i] as usize {
                        assert_eq!(sender_keys.0[i][j], receiver_keys.0[i]);
                    } else {
                        assert_ne!(sender_keys.0[i][j], receiver_keys.0[i]);
                    }
                }
            }

            if check_serialization {
                test_serialization!(ROTSenderSetup<G1>, sender_setup);
                test_serialization!(SenderPubKey<G1>, S);
                test_serialization!(ROTReceiverKeys, receiver_keys);
                test_serialization!(ReceiverPubKeys<G1>, R);
                test_serialization!(ROTSenderKeys, sender_keys);
            }
        }

        check::<128>(&mut rng, 1, 2, vec![0], &B, true);
        check::<128>(&mut rng, 1, 2, vec![1], &B, true);
        check::<128>(&mut rng, 1, 3, vec![0], &B, true);
        check::<128>(&mut rng, 1, 3, vec![1], &B, true);
        check::<128>(&mut rng, 1, 3, vec![2], &B, true);
        check::<128>(&mut rng, 2, 2, vec![0, 0], &B, true);
        check::<128>(&mut rng, 2, 2, vec![0, 1], &B, true);
        check::<128>(&mut rng, 2, 2, vec![1, 0], &B, false);
        check::<128>(&mut rng, 2, 2, vec![1, 1], &B, false);
        check::<128>(&mut rng, 3, 2, vec![1, 1, 1], &B, false);
        check::<128>(&mut rng, 3, 2, vec![0, 0, 0], &B, false);
        check::<128>(&mut rng, 3, 3, vec![0, 1, 2], &B, false);
        check::<128>(&mut rng, 3, 3, vec![1, 2, 2], &B, false);
        check::<128>(&mut rng, 3, 3, vec![1, 0, 2], &B, false);
        check::<128>(&mut rng, 3, 5, vec![4, 0, 1], &B, false);
        check::<128>(&mut rng, 4, 2, vec![1, 0, 1, 1], &B, false);
        check::<128>(&mut rng, 4, 3, vec![2, 1, 0, 1], &B, false);
        check::<128>(&mut rng, 4, 4, vec![3, 2, 1, 0], &B, false);
        check::<128>(&mut rng, 4, 8, vec![7, 6, 5, 4], &B, false);

        let choices = (0..32).map(|_| u16::rand(&mut rng) % 2).collect();
        check::<128>(&mut rng, 32, 2, choices, &B, false);

        let choices = (0..64).map(|_| u16::rand(&mut rng) % 2).collect();
        check::<128>(&mut rng, 64, 2, choices, &B, false);

        let choices = (0..128).map(|_| u16::rand(&mut rng) % 2).collect();
        check::<128>(&mut rng, 128, 2, choices, &B, false);

        let choices = (0..192).map(|_| u16::rand(&mut rng) % 2).collect();
        check::<128>(&mut rng, 192, 2, choices, &B, false);
    }

    #[test]
    fn verified_simplest_rot() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let B = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);

        fn check<const KEY_SIZE: u16>(
            rng: &mut StdRng,
            num_base_ot: u16,
            choices: Vec<Bit>,
            B: &G1,
            check_serialization: bool,
        ) {
            let start = Instant::now();
            let (sender_setup, S, schnorr_proof) =
                ROTSenderSetup::new_verifiable::<StdRng, Blake2b512>(rng, num_base_ot, B)
                    .expect("Error in setup for OT sender");
            println!(
                "Sender setup time for {} 1-of-2 VROTs is {:?}",
                num_base_ot,
                start.elapsed()
            );

            let string = format!("{} byte keys for {}", KEY_SIZE, num_base_ot);

            let start = Instant::now();
            let (receiver_keys, R) =
                ROTReceiverKeys::new_verifiable::<
                    StdRng,
                    <Bls12_381 as Pairing>::G1Affine,
                    Blake2b512,
                    KEY_SIZE,
                >(rng, num_base_ot, choices.clone(), S, &schnorr_proof, B)
                .expect("Error in creating keys for OT receiver");
            println!(
                "Receiver gets {} 1-of-2 VROTs in {:?}",
                string,
                start.elapsed()
            );

            let start = Instant::now();
            let sender_keys = sender_setup
                .derive_keys::<KEY_SIZE>(R)
                .expect("Error in creating keys for OT sender");
            println!(
                "Sender creates {} 1-of-2 VROTs in {:?}",
                string,
                start.elapsed()
            );

            let sender_keys = OneOfTwoROTSenderKeys::try_from(sender_keys).unwrap();
            let start = Instant::now();
            let (sender_challenger, challenges) =
                VSROTChallenger::new(&sender_keys).expect("Error in creating keys challenges");
            println!(
                "Sender creates challenge for {} 1-of-2 VROTs in {:?}",
                num_base_ot,
                start.elapsed()
            );

            let start = Instant::now();
            let (receiver_responder, responses) =
                VSROTResponder::new(&receiver_keys, choices.clone(), challenges.clone())
                    .expect("Error in creating responses");
            println!(
                "Receiver creates responses for {} 1-of-2 VROTs in {:?}",
                num_base_ot,
                start.elapsed()
            );

            let mut bad_responses = responses.clone();
            rng.fill_bytes(&mut bad_responses.0[0]);
            let err = sender_challenger.clone().verify_responses(bad_responses);
            if let OTError::InvalidResponseAtIndex(j) = err.err().unwrap() {
                assert_eq!(j, 0);
            } else {
                assert!(false);
            }

            let start = Instant::now();
            let hashed_keys = sender_challenger
                .clone()
                .verify_responses(responses.clone())
                .expect("Error in verifying responses");
            println!(
                "Sender verifies responses for {} 1-of-2 VROTs in {:?}",
                num_base_ot,
                start.elapsed()
            );

            let start = Instant::now();
            receiver_responder
                .verify_sender_hashed_keys(hashed_keys)
                .expect("Error in verifying hashed keys from OT sender");
            println!(
                "Receiver verifies hashed keys for {} 1-of-2 VROTs in {:?}",
                num_base_ot,
                start.elapsed()
            );

            assert_eq!(sender_keys.len(), num_base_ot as usize);
            assert_eq!(receiver_keys.len(), num_base_ot as usize);
            check_base_ot_keys(&choices, &receiver_keys, &sender_keys);

            if check_serialization {
                test_serialization!(OneOfTwoROTSenderKeys, sender_keys);
                test_serialization!(VSROTChallenger, sender_challenger);
                test_serialization!(Challenges, challenges);
                test_serialization!(VSROTResponder, receiver_responder);
                test_serialization!(Responses, responses);
            }
        }

        check::<128>(&mut rng, 1, vec![false], &B, true);
        check::<128>(&mut rng, 1, vec![false], &B, true);
        check::<128>(&mut rng, 2, vec![false, false], &B, true);
        check::<128>(&mut rng, 2, vec![false, true], &B, true);
        check::<128>(&mut rng, 2, vec![true, false], &B, false);
        check::<128>(&mut rng, 2, vec![true, true], &B, false);
        check::<128>(&mut rng, 3, vec![true, true, true], &B, false);
        check::<128>(&mut rng, 3, vec![false, false, false], &B, false);
        check::<128>(&mut rng, 3, vec![true, false, true], &B, true);

        let choices = (0..32).map(|_| u16::rand(&mut rng) % 2 != 0).collect();
        check::<128>(&mut rng, 32, choices, &B, false);

        let choices = (0..64).map(|_| u16::rand(&mut rng) % 2 != 0).collect();
        check::<128>(&mut rng, 64, choices, &B, false);

        let choices = (0..128).map(|_| u16::rand(&mut rng) % 2 != 0).collect();
        check::<128>(&mut rng, 128, choices, &B, false);

        let choices = (0..192).map(|_| u16::rand(&mut rng) % 2 != 0).collect();
        check::<128>(&mut rng, 192, choices, &B, false);
    }
}
