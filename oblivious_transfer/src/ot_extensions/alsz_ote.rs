//! OT Extension based on the paper [More Efficient Oblivious Transfer Extensions](https://eprint.iacr.org/2016/602)
//! Implements protocols 4, 5, 7 and 9.
//! Symbols from paper:
//! kappa -> symmetric security parameter which equals size of key from base OT
//! rho -> statistical security parameter when using actively secure OT extension (protocol 5)
//! n -> bit size of OT messages
//! l -> number of base OTs, set to kappa + rho when using actively secure OT extension else kappa
//! m -> number of OTs extensions

use crate::{
    aes_prng::{AesRng, SEED_SIZE as AES_RNG_SEED_SIZE},
    base_ot::simplest_ot::{OneOfTwoROTSenderKeys, ROTReceiverKeys},
    util::{boolvec_to_u8vec, divide_by_8, transpose, u8vec_to_boolvec, xor, xor_in_place},
    Bit, BitMatrix, Key, Message,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    cfg_into_iter,
    collections::BTreeMap,
    rand::{RngCore, SeedableRng},
    vec,
    vec::Vec,
};
use digest::{ExtendableOutput, Update};
use dock_crypto_utils::join;
use itertools::Itertools;
use sha3::Shake256;

use crate::{configs::OTEConfig, error::OTError, util::is_multiple_of_8};

#[cfg(feature = "parallel")]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct ConsistencyCheckHashes(pub BTreeMap<(u16, u16), (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>);

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct OTExtensionReceiverSetup {
    pub ote_config: OTEConfig,
    /// Choices used in OT extension
    pub ot_extension_choices: Vec<Bit>,
    /// `extended_ot_count x base_ot_count` bit-matrix
    pub T: BitMatrix,
}

#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct OTExtensionSenderSetup {
    pub ote_config: OTEConfig,
    /// Choices used in base OT, packed
    pub base_ot_choices: Vec<u8>,
    /// `extended_ot_count x base_ot_count` bit-matrix
    pub Q: BitMatrix,
}

impl OTExtensionReceiverSetup {
    /// For protocol 4. Assumes base OT done and keys are correct
    pub fn new(
        ote_config: OTEConfig,
        ot_ext_choices: Vec<Bit>,
        base_ot_keys: OneOfTwoROTSenderKeys,
    ) -> Result<(Self, BitMatrix), OTError> {
        // TODO: This can be improved by passing choices as `packed`, i.e. each u8 contains 8 choices
        Self::check_ote_choices_count(&ot_ext_choices, &ote_config)?;
        Self::check_base_ot_keys_count(&base_ot_keys, &ote_config)?;
        // TODO: Check base ot key size is kappa
        let column_size = ote_config.column_byte_size() as u32;
        let packed_choices = boolvec_to_u8vec(&ot_ext_choices);
        // Following matrices T and U will be treated as `base_ot_count x extended_ot_count` matrices where each row of size m bits will be used
        let matrix_byte_size = ote_config.matrix_byte_size()?;
        let mut T = vec![0; matrix_byte_size];
        let mut U = vec![0; matrix_byte_size];
        for (i, (k0, k1)) in base_ot_keys.0.into_iter().enumerate() {
            Self::fill_t_u_matrices(
                &mut T,
                &mut U,
                &k0,
                &k1,
                &packed_choices,
                i,
                i,
                column_size as u32,
            );
        }
        let T = transpose(
            &T,
            ote_config.num_base_ot as usize,
            ote_config.num_ot_extensions as usize,
        );
        Ok((
            Self {
                ote_config,
                ot_extension_choices: ot_ext_choices,
                T: BitMatrix(T),
            },
            BitMatrix(U),
        ))
    }

    /// For protocol 5. Assumes base OT done and keys are correct
    pub fn new_with_active_security<R: RngCore, const STATISTICAL_SECURITY_PARAMETER: u16>(
        rng: &mut R,
        ote_config: OTEConfig,
        mut ot_ext_choices: Vec<Bit>,
        base_ot_keys: OneOfTwoROTSenderKeys,
    ) -> Result<(Self, BitMatrix, ConsistencyCheckHashes), OTError> {
        if !is_multiple_of_8(STATISTICAL_SECURITY_PARAMETER as usize) {
            return Err(OTError::SecurityParameterShouldBeMultipleOf8(
                STATISTICAL_SECURITY_PARAMETER,
            ));
        }
        Self::check_ote_choices_count(&ot_ext_choices, &ote_config)?;
        Self::check_base_ot_keys_count(&base_ot_keys, &ote_config)?;

        let mut tau = vec![0; STATISTICAL_SECURITY_PARAMETER as usize];
        rng.fill_bytes(&mut tau);
        let mut tau_bits = u8vec_to_boolvec(&tau);
        ot_ext_choices.append(&mut tau_bits);

        let packed_choices = boolvec_to_u8vec(&ot_ext_choices);
        let (matrix_byte_size, column_size_in_bits, column_size) =
            get_matrix_and_column_byte_size_for_actively_secure::<STATISTICAL_SECURITY_PARAMETER>(
                &ote_config,
            );
        let mut T = vec![0; matrix_byte_size];
        let mut U = vec![0; matrix_byte_size];
        let mut prgs = Vec::with_capacity(ote_config.num_base_ot as usize);
        for (i, (k0, k1)) in base_ot_keys.0.into_iter().enumerate() {
            let (k_0, k_1) = Self::fill_t_u_matrices(
                &mut T,
                &mut U,
                &k0,
                &k1,
                &packed_choices,
                i,
                i,
                column_size as u32,
            );
            prgs.push((k_0, k_1));
        }
        let mut hashes = BTreeMap::new();
        for i in 0..ote_config.num_base_ot {
            for j in i + 1..ote_config.num_base_ot {
                let prg_i = &prgs[i as usize];
                let prg_j = &prgs[j as usize];
                let packed_choices_len = packed_choices
                    .len()
                    .try_into()
                    .map_err(|_| OTError::TooManyChoices(packed_choices.len()))?;

                let (i_0, i_1, i_2, i_3) = join!(
                    hash_prg(i, j, &xor(&prg_i.0, &prg_j.0), packed_choices_len),
                    hash_prg(i, j, &xor(&prg_i.0, &prg_j.1), packed_choices_len),
                    hash_prg(i, j, &xor(&prg_i.1, &prg_j.0), packed_choices_len),
                    hash_prg(i, j, &xor(&prg_i.1, &prg_j.1), packed_choices_len)
                );
                hashes.insert((i, j), (i_0, i_1, i_2, i_3));
            }
        }
        // TODO: Shorten transpose matrix
        let T = transpose(&T, ote_config.num_base_ot as usize, column_size_in_bits);
        Ok((
            Self {
                ote_config,
                ot_extension_choices: ot_ext_choices,
                T: BitMatrix(T),
            },
            BitMatrix(U),
            ConsistencyCheckHashes(hashes),
        ))
    }

    /// `extended_ot_count` and `base_ot_count` are called `m` and `l` in the paper respectively
    pub fn new_for_receiver_random(
        ote_config: OTEConfig,
        base_ot_keys: OneOfTwoROTSenderKeys,
    ) -> Result<(Self, BitMatrix), OTError> {
        Self::check_base_ot_keys_count(&base_ot_keys, &ote_config)?;
        let column_size = ote_config.column_byte_size();

        let mut packed_choices = vec![0; column_size];
        let mut T = vec![0; ote_config.matrix_byte_size()?];
        let mut U = vec![0; ote_config.matrix_byte_size_for_random()?];
        for (i, (k0, k1)) in base_ot_keys.0.into_iter().enumerate() {
            if i == 0 {
                let t_i = &mut T[0..column_size];
                key_to_aes_rng(&k0).fill_bytes(t_i);
                // choice = G(k0) + G(k1)
                key_to_aes_rng(&k1).fill_bytes(&mut packed_choices);
                xor_in_place(&mut packed_choices, t_i);
            } else {
                Self::fill_t_u_matrices(
                    &mut T,
                    &mut U,
                    &k0,
                    &k1,
                    &packed_choices,
                    i,
                    i - 1,
                    column_size as u32,
                );
            }
        }
        let T = transpose(
            &T,
            ote_config.num_base_ot as usize,
            ote_config.num_ot_extensions as usize,
        );
        Ok((
            Self {
                ote_config,
                ot_extension_choices: u8vec_to_boolvec(&packed_choices),
                T: BitMatrix(T),
            },
            BitMatrix(U),
        ))
    }

    pub fn decrypt(
        &self,
        encryptions: Vec<(Message, Message)>,
        message_size: u32,
    ) -> Result<Vec<Message>, OTError> {
        Self::decrypt_(
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
        Self::decrypt_correlated_(
            self.ote_config,
            &self.T,
            &self.ot_extension_choices,
            encryptions,
            message_size,
        )
    }

    pub fn decrypt_random(&self, message_size: u32) -> Vec<Message> {
        let row_byte_size = self.ote_config.row_byte_size();
        cfg_into_iter!(0..self.ote_config.num_ot_extensions as usize)
            .map(|i| {
                let t = &self.T.0[i * row_byte_size..(i + 1) * row_byte_size as usize];
                hash_to_otp(i as u32, &t, message_size)
            })
            .collect()
    }

    pub(crate) fn decrypt_(
        ote_config: OTEConfig,
        T: &BitMatrix,
        ot_extension_choices: &[Bit],
        encryptions: Vec<(Message, Message)>,
        message_size: u32,
    ) -> Result<Vec<Message>, OTError> {
        if encryptions.len() != ote_config.num_ot_extensions as usize {
            return Err(OTError::IncorrectNoOfEncryptionsToDecrypt(
                ote_config.num_ot_extensions as usize,
                encryptions.len(),
            ));
        }
        let row_byte_size = ote_config.row_byte_size();
        Ok(cfg_into_iter!(encryptions)
            .enumerate()
            .map(|(i, (e1, e2))| {
                let t = &T.0[i * row_byte_size..(i + 1) * row_byte_size];
                xor(
                    if !ot_extension_choices[i] { &e1 } else { &e2 },
                    &hash_to_otp(i as u32, &t, message_size),
                )
            })
            .collect())
    }

    pub fn decrypt_correlated_(
        ote_config: OTEConfig,
        T: &BitMatrix,
        ot_extension_choices: &[Bit],
        encryptions: Vec<Message>,
        message_size: u32,
    ) -> Result<Vec<Message>, OTError> {
        if encryptions.len() != ote_config.num_ot_extensions as usize {
            return Err(OTError::IncorrectNoOfEncryptionsToDecrypt(
                ote_config.num_ot_extensions as usize,
                encryptions.len(),
            ));
        }
        let row_byte_size = ote_config.row_byte_size();
        let zero = vec![0; message_size as usize];
        Ok(cfg_into_iter!(encryptions)
            .enumerate()
            .map(|(i, e)| {
                let t = &T.0[i * row_byte_size..(i + 1) * row_byte_size];
                xor(
                    if !ot_extension_choices[i] { &zero } else { &e },
                    &hash_to_otp(i as u32, &t, message_size),
                )
            })
            .collect())
    }

    fn fill_t_u_matrices(
        T: &mut [u8],
        U: &mut [u8],
        k0: &Key,
        k1: &Key,
        packed_choices: &[u8],
        t_row_index: usize,
        u_row_index: usize,
        column_size: u32,
    ) -> (Vec<u8>, Vec<u8>) {
        let t_i =
            &mut T[t_row_index * column_size as usize..(t_row_index + 1) * column_size as usize];
        let u_i =
            &mut U[u_row_index * column_size as usize..(u_row_index + 1) * column_size as usize];
        join!(
            key_to_aes_rng(k0).fill_bytes(t_i),
            key_to_aes_rng(k1).fill_bytes(u_i)
        );
        let k_0 = t_i.to_vec();
        let k_1 = u_i.to_vec();
        xor_in_place(u_i, t_i);
        xor_in_place(u_i, packed_choices);
        (k_0, k_1)
    }

    fn check_ote_choices_count(
        ot_ext_choices: &[Bit],
        ote_config: &OTEConfig,
    ) -> Result<(), OTError> {
        if ote_config.num_ot_extensions as usize != ot_ext_choices.len() {
            return Err(OTError::IncorrectNumberOfOTExtensionChoices(
                ote_config.num_ot_extensions as usize,
                ot_ext_choices.len(),
            ));
        }
        Ok(())
    }

    fn check_base_ot_keys_count(
        base_ot_keys: &OneOfTwoROTSenderKeys,
        ote_config: &OTEConfig,
    ) -> Result<(), OTError> {
        if ote_config.num_base_ot as usize != base_ot_keys.len() {
            return Err(OTError::IncorrectNumberOfBaseOTKeys(
                ote_config.num_base_ot,
                base_ot_keys.len() as u16,
            ));
        }
        Ok(())
    }
}

impl OTExtensionSenderSetup {
    /// For protocol 4. Assumes base OT done and keys are correct
    pub fn new(
        ote_config: OTEConfig,
        U: BitMatrix,
        base_ot_choices: Vec<Bit>,
        base_ot_keys: ROTReceiverKeys,
    ) -> Result<Self, OTError> {
        // TODO: This can be improved by passing s as `packed`
        Self::check_base_ot_choices_and_keys(&base_ot_choices, &base_ot_keys, &ote_config)?;
        let matrix_byte_size = ote_config.matrix_byte_size()?;
        if matrix_byte_size != U.0.len() {
            return Err(OTError::IncorrectSizeForU(matrix_byte_size, U.0.len()));
        }
        // TODO: Check base ot key size is kappa
        let column_size = ote_config.column_byte_size();
        let mut Q = vec![0; matrix_byte_size];
        let zero = vec![0; column_size];
        for (i, k) in base_ot_keys.0.into_iter().enumerate() {
            Self::fill_q_matrix(
                &mut Q,
                &U.0,
                &k,
                &base_ot_choices,
                &zero,
                i,
                i,
                column_size as u32,
            );
        }
        let Q = transpose(
            &Q,
            ote_config.num_base_ot as usize,
            ote_config.num_ot_extensions as usize,
        );
        let base_ot_choices = boolvec_to_u8vec(&base_ot_choices);
        Ok(Self {
            ote_config,
            base_ot_choices,
            Q: BitMatrix(Q),
        })
    }

    /// For protocol 5. Assumes base OT done and keys are correct
    pub fn new_with_active_security<const STATISTICAL_SECURITY_PARAMETER: u16>(
        ote_config: OTEConfig,
        U: BitMatrix,
        base_ot_choices: Vec<Bit>,
        base_ot_keys: ROTReceiverKeys,
        consistency_check_hashes: ConsistencyCheckHashes,
    ) -> Result<Self, OTError> {
        // TODO: This can be improved by passing s as `packed`
        Self::check_base_ot_choices_and_keys(&base_ot_choices, &base_ot_keys, &ote_config)?;
        if !is_multiple_of_8(STATISTICAL_SECURITY_PARAMETER as usize) {
            return Err(OTError::SecurityParameterShouldBeMultipleOf8(
                STATISTICAL_SECURITY_PARAMETER,
            ));
        }
        let (matrix_byte_size, column_size_in_bits, column_size) =
            get_matrix_and_column_byte_size_for_actively_secure::<STATISTICAL_SECURITY_PARAMETER>(
                &ote_config,
            );
        if matrix_byte_size != U.0.len() {
            return Err(OTError::IncorrectSizeForU(matrix_byte_size, U.0.len()));
        }
        let mut Q = vec![0; matrix_byte_size];
        let zero = vec![0; column_size];
        let mut prgs = Vec::with_capacity(ote_config.num_base_ot as usize);
        for (i, k) in base_ot_keys.0.into_iter().enumerate() {
            let k = Self::fill_q_matrix(
                &mut Q,
                &U.0,
                &k,
                &base_ot_choices,
                &zero,
                i,
                i,
                column_size as u32,
            );
            prgs.push(k);
        }
        for i in 0..ote_config.num_base_ot {
            for j in i + 1..ote_config.num_base_ot {
                if let Some(hashes) = consistency_check_hashes.0.get(&(i, j)) {
                    let base_ot_choices_i = base_ot_choices[i as usize];
                    let base_ot_choices_j = base_ot_choices[j as usize];

                    let (h, h_inv) = if !base_ot_choices_i && !base_ot_choices_j {
                        (&hashes.0, &hashes.3)
                    } else if !base_ot_choices_i && base_ot_choices_j {
                        (&hashes.1, &hashes.2)
                    } else if base_ot_choices_i && !base_ot_choices_j {
                        (&hashes.2, &hashes.1)
                    } else {
                        (&hashes.3, &hashes.0)
                    };

                    let xor_a_b = xor(&prgs[i as usize], &prgs[j as usize]);
                    if h != &hash_prg(i, j, &xor_a_b, column_size as u32) {
                        return Err(OTError::ConsistencyCheckFailed(i, j));
                    }
                    let start_i = i as usize * column_size;
                    let end_i = start_i + column_size;
                    let u_i = &U.0[start_i..end_i];
                    let start_j = j as usize * column_size;
                    let end_j = start_j + column_size;
                    let u_j = &U.0[start_j..end_j];
                    let mut xor_a_b_u = xor(&xor_a_b, u_i);
                    xor_in_place(&mut xor_a_b_u, u_j);
                    if h_inv != &hash_prg(i, j, &xor_a_b_u, column_size as u32) {
                        return Err(OTError::ConsistencyCheckFailed(i, j));
                    }
                    if u_i == u_j {
                        return Err(OTError::ConsistencyCheckFailed(i, j));
                    }
                } else {
                    return Err(OTError::MissingConsistencyCheck(i, j));
                }
            }
        }
        // TODO: Shorten transpose
        let Q = transpose(&Q, ote_config.num_base_ot as usize, column_size_in_bits);
        let s = boolvec_to_u8vec(&base_ot_choices);
        Ok(Self {
            ote_config,
            base_ot_choices: s,
            Q: BitMatrix(Q),
        })
    }

    /// Initialize sender for receiver random OT
    pub fn new_for_receiver_random(
        ote_config: OTEConfig,
        U: BitMatrix,
        base_ot_choices: Vec<Bit>,
        base_ot_keys: ROTReceiverKeys,
    ) -> Result<Self, OTError> {
        // TODO: This can be improved by passing s as `packed`
        Self::check_base_ot_choices_and_keys(&base_ot_choices, &base_ot_keys, &ote_config)?;
        let matrix_byte_size = ote_config.matrix_byte_size_for_random()?;
        if matrix_byte_size != U.0.len() {
            return Err(OTError::IncorrectSizeForU(matrix_byte_size, U.0.len()));
        }
        let column_size = ote_config.column_byte_size();
        let mut Q = vec![0; ote_config.matrix_byte_size()?];
        let zero = vec![0; column_size];
        for (i, k) in base_ot_keys.0.into_iter().enumerate() {
            if i == 0 {
                let q_i = &mut Q[0..column_size];
                key_to_aes_rng(&k).fill_bytes(q_i);
            } else {
                Self::fill_q_matrix(
                    &mut Q,
                    &U.0,
                    &k,
                    &base_ot_choices,
                    &zero,
                    i,
                    i - 1,
                    column_size as u32,
                );
            }
        }
        let Q = transpose(
            &Q,
            ote_config.num_base_ot as usize,
            ote_config.num_ot_extensions as usize,
        );
        let base_ot_choices = boolvec_to_u8vec(&base_ot_choices);
        Ok(Self {
            ote_config,
            base_ot_choices,
            Q: BitMatrix(Q),
        })
    }

    pub fn encrypt(
        &self,
        messages: Vec<(Message, Message)>,
        message_size: u32,
    ) -> Result<Vec<(Message, Message)>, OTError> {
        Self::encrypt_(
            self.ote_config,
            &self.Q,
            &self.base_ot_choices,
            messages,
            message_size,
        )
    }

    /// For correlated OT
    pub fn encrypt_correlated<F: Sync + Sized + Fn(&Message) -> Message>(
        &self,
        deltas: Vec<F>,
        message_size: u32,
    ) -> Result<(Vec<(Message, Message)>, Vec<Message>), OTError> {
        Self::encrypt_correlated_(
            self.ote_config,
            &self.Q,
            &self.base_ot_choices,
            deltas,
            message_size,
        )
    }

    /// For Sender Random OT
    pub fn encrypt_random(&self, message_size: u32) -> Vec<(Message, Message)> {
        let row_byte_size = self.ote_config.row_byte_size();
        cfg_into_iter!(0..self.ote_config.num_ot_extensions as usize)
            .map(|i| {
                let q = &self.Q.0[i * row_byte_size..(i + 1) * row_byte_size];
                let x1 = hash_to_otp(i as u32, &q, message_size);
                let x2 = hash_to_otp(i as u32, &xor(&q, &self.base_ot_choices), message_size);
                (x1, x2)
            })
            .collect()
    }

    pub(crate) fn encrypt_(
        ote_config: OTEConfig,
        Q: &BitMatrix,
        base_ot_choices: &[u8],
        messages: Vec<(Message, Message)>,
        message_size: u32,
    ) -> Result<Vec<(Message, Message)>, OTError> {
        if messages.len() != ote_config.num_ot_extensions as usize {
            return Err(OTError::IncorrectNoOfMessagesToEncrypt(
                ote_config.num_ot_extensions as usize,
                messages.len(),
            ));
        }
        let row_byte_size = ote_config.row_byte_size();
        Ok(cfg_into_iter!(messages)
            .enumerate()
            .map(|(i, (m1, m2))| {
                let q = &Q.0[i * row_byte_size..(i + 1) * row_byte_size];
                let e1 = xor(&m1, &hash_to_otp(i as u32, &q, message_size));
                let e2 = xor(
                    &m2,
                    &hash_to_otp(i as u32, &xor(&q, base_ot_choices), message_size),
                );
                (e1, e2)
            })
            .collect())
    }

    pub fn encrypt_correlated_<F: Sync + Sized + Fn(&Message) -> Message>(
        ote_config: OTEConfig,
        Q: &BitMatrix,
        s: &[u8],
        deltas: Vec<F>,
        message_size: u32,
    ) -> Result<(Vec<(Message, Message)>, Vec<Message>), OTError> {
        if deltas.len() != ote_config.num_ot_extensions as usize {
            return Err(OTError::IncorrectNoOfCorrelations(
                ote_config.num_ot_extensions as usize,
                deltas.len(),
            ));
        }
        let row_byte_size = ote_config.row_byte_size();
        Ok(cfg_into_iter!(deltas)
            .enumerate()
            .map(|(i, delta)| {
                let q = &Q.0[i * row_byte_size..(i + 1) * row_byte_size];
                let x1 = hash_to_otp(i as u32, &q, message_size);
                let x2 = delta(&x1);
                let e = xor(&x2, &hash_to_otp(i as u32, &xor(&q, &s), message_size));
                ((x1, x2), e)
            })
            .collect::<Vec<_>>()
            .into_iter()
            .multiunzip())
    }

    fn fill_q_matrix(
        Q: &mut [u8],
        U: &[u8],
        k: &Key,
        s: &[Bit],
        zero: &[u8],
        q_row_index: usize,
        u_row_index: usize,
        column_size: u32,
    ) -> Vec<u8> {
        let q_i =
            &mut Q[q_row_index * column_size as usize..(q_row_index + 1) * column_size as usize];
        key_to_aes_rng(k).fill_bytes(q_i);
        let k = q_i.to_vec();
        let start = u_row_index * column_size as usize;
        let end = start + column_size as usize;
        // Constant time
        if s[q_row_index] {
            xor_in_place(q_i, &U[start..end]);
        } else {
            xor_in_place(q_i, zero);
        }
        k
    }

    fn check_base_ot_choices_and_keys(
        base_ot_choices: &[Bit],
        base_ot_keys: &ROTReceiverKeys,
        ote_config: &OTEConfig,
    ) -> Result<(), OTError> {
        if base_ot_choices.len() != ote_config.num_base_ot as usize {
            return Err(OTError::IncorrectNoOfBaseOTChoices(
                base_ot_choices.len() as u16,
                ote_config.num_base_ot,
            ));
        }
        if ote_config.num_base_ot as usize != base_ot_keys.len() {
            return Err(OTError::IncorrectNumberOfBaseOTKeys(
                ote_config.num_base_ot,
                base_ot_keys.len() as u16,
            ));
        }
        Ok(())
    }
}

fn hash_prg(i: u16, j: u16, input: &[u8], output_size: u32) -> Vec<u8> {
    let mut bytes = i.to_le_bytes().to_vec();
    bytes.extend_from_slice(&j.to_le_bytes());
    bytes.extend_from_slice(input);
    let mut out = vec![0; output_size as usize];
    let mut hasher = Shake256::default();
    hasher.update(&bytes);
    hasher.finalize_xof_into(&mut out);
    out
}

fn key_to_aes_seed(key: &Key) -> [u8; AES_RNG_SEED_SIZE] {
    assert_eq!(key.len(), AES_RNG_SEED_SIZE);
    let mut k = [0; AES_RNG_SEED_SIZE];
    k.copy_from_slice(key);
    k
}

fn key_to_aes_rng(key: &Key) -> AesRng {
    AesRng::from_seed(key_to_aes_seed(key))
}

/// Create a one time pad of required size
fn hash_to_otp(index: u32, q: &[u8], pad_size: u32) -> Vec<u8> {
    let mut bytes = index.to_be_bytes().to_vec();
    bytes.extend_from_slice(q);
    let mut pad = vec![0; pad_size as usize];
    let mut hasher = Shake256::default();
    hasher.update(&bytes);
    hasher.finalize_xof_into(&mut pad);
    pad
}

fn get_matrix_and_column_byte_size_for_actively_secure<
    const STATISTICAL_SECURITY_PARAMETER: u16,
>(
    ote_config: &OTEConfig,
) -> (usize, usize, usize) {
    let column_size_in_bits =
        ote_config.num_ot_extensions + STATISTICAL_SECURITY_PARAMETER as u32 * 8;
    let column_size = divide_by_8(column_size_in_bits);
    let matrix_byte_size = divide_by_8(column_size_in_bits * ote_config.num_base_ot as u32);

    (
        matrix_byte_size as usize,
        column_size_in_bits as usize,
        column_size as usize,
    )
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{base_ot::simplest_ot::tests::do_1_of_2_base_ot, configs::OTConfig};
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };

    #[test]
    fn alsz() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let B = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);

        fn check<const KEY_SIZE: u16>(
            rng: &mut StdRng,
            base_ot_count: u16,
            extended_ot_count: usize,
            ot_ext_choices: Vec<bool>,
            message_size: u32,
            B: &<Bls12_381 as Pairing>::G1Affine,
        ) {
            let message_size = message_size as usize;
            // Perform base OT with roles reversed
            let (base_ot_choices, base_ot_sender_keys, base_ot_receiver_keys) =
                do_1_of_2_base_ot::<KEY_SIZE>(rng, base_ot_count, B);

            let ote_config = OTEConfig::new(base_ot_count, extended_ot_count as u32).unwrap();

            // Perform OT extension
            let (ext_receiver_setup, U) = OTExtensionReceiverSetup::new(
                ote_config,
                ot_ext_choices.clone(),
                base_ot_sender_keys,
            )
            .unwrap();
            assert_eq!(ext_receiver_setup.ot_extension_choices, ot_ext_choices);

            let base_ot_choices = base_ot_choices
                .into_iter()
                .map(|b| b % 2 != 0)
                .collect::<Vec<_>>();
            let ext_sender_setup =
                OTExtensionSenderSetup::new(ote_config, U, base_ot_choices, base_ot_receiver_keys)
                    .unwrap();

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

            let encryptions = ext_sender_setup
                .encrypt(messages.clone(), message_size as u32)
                .unwrap();
            let decryptions = ext_receiver_setup
                .decrypt(encryptions, message_size as u32)
                .unwrap();
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
            let decryptions = ext_receiver_setup
                .decrypt_correlated(encryptions, message_size as u32)
                .unwrap();
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

            // Perform Sender Random OT extension
            let messages = ext_sender_setup.encrypt_random(message_size as u32);
            let decryptions = ext_receiver_setup.decrypt_random(message_size as u32);
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
        }

        for (base_ot_count, extended_ot_count) in [(256, 1024), (512, 2048), (1024, 4096)] {
            let choices = (0..extended_ot_count)
                .map(|_| u8::rand(&mut rng) % 2 != 0)
                .collect();
            let base_ot_config = OTConfig::new_for_alsz_ote(base_ot_count).unwrap();
            check::<128>(
                &mut rng,
                base_ot_config.num_ot,
                extended_ot_count,
                choices,
                1024,
                &B,
            );
        }
    }

    #[test]
    fn alsz_random() {
        // Test for receiver random OT, protocol 9 from the paper
        let mut rng = StdRng::seed_from_u64(0u64);
        let B = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);

        fn check<const KEY_SIZE: u16>(
            rng: &mut StdRng,
            base_ot_count: u16,
            extended_ot_count: usize,
            message_size: u32,
            B: &<Bls12_381 as Pairing>::G1Affine,
        ) {
            let message_size = message_size as usize;
            // Perform base OT with roles reversed
            let (base_ot_choices, base_ot_sender_keys, base_ot_receiver_keys) =
                do_1_of_2_base_ot::<KEY_SIZE>(rng, base_ot_count, B);

            let ote_config = OTEConfig::new(base_ot_count, extended_ot_count as u32).unwrap();

            // Perform Receiver Random OT extension
            let (ext_receiver_setup, U) =
                OTExtensionReceiverSetup::new_for_receiver_random(ote_config, base_ot_sender_keys)
                    .unwrap();

            let base_ot_choices = base_ot_choices
                .into_iter()
                .map(|b| b % 2 != 0)
                .collect::<Vec<_>>();
            let ext_sender_setup = OTExtensionSenderSetup::new_for_receiver_random(
                ote_config,
                U,
                base_ot_choices,
                base_ot_receiver_keys,
            )
            .unwrap();

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

            let encryptions = ext_sender_setup
                .encrypt(messages.clone(), message_size as u32)
                .unwrap();
            let decryptions = ext_receiver_setup
                .decrypt(encryptions, message_size as u32)
                .unwrap();
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

            // Perform Random OT extension
            let messages = ext_sender_setup.encrypt_random(message_size as u32);
            let decryptions = ext_receiver_setup.decrypt_random(message_size as u32);
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
        }

        for (base_ot_count, extended_ot_count) in [(256, 1024), (512, 2048), (1024, 4096)] {
            let base_ot_config = OTConfig::new_for_alsz_ote(base_ot_count).unwrap();
            check::<128>(&mut rng, base_ot_config.num_ot, extended_ot_count, 1024, &B);
        }
    }

    #[test]
    fn alsz_with_active_security() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let B = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);

        fn check<const KEY_SIZE: u16, const SSP: u16>(
            rng: &mut StdRng,
            base_ot_count: u16,
            extended_ot_count: usize,
            ot_ext_choices: Vec<bool>,
            message_size: u32,
            B: &<Bls12_381 as Pairing>::G1Affine,
        ) {
            let message_size = message_size as usize;
            // Perform base OT with roles reversed
            let (base_ot_choices, base_ot_sender_keys, base_ot_receiver_keys) =
                do_1_of_2_base_ot::<KEY_SIZE>(rng, base_ot_count, B);

            let ote_config = OTEConfig::new(base_ot_count, extended_ot_count as u32).unwrap();

            // Perform OT extension
            let (ext_receiver_setup, U, hashes) =
                OTExtensionReceiverSetup::new_with_active_security::<_, SSP>(
                    rng,
                    ote_config,
                    ot_ext_choices.clone(),
                    base_ot_sender_keys,
                )
                .unwrap();
            assert_eq!(
                hashes.0.len(),
                (base_ot_count as usize) * (base_ot_count as usize - 1) / 2
            );

            let base_ot_choices = base_ot_choices
                .into_iter()
                .map(|b| b % 2 != 0)
                .collect::<Vec<_>>();
            let ext_sender_setup = OTExtensionSenderSetup::new_with_active_security::<SSP>(
                ote_config,
                U,
                base_ot_choices,
                base_ot_receiver_keys,
                hashes,
            )
            .unwrap();

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

            let encryptions = ext_sender_setup
                .encrypt(messages.clone(), message_size as u32)
                .unwrap();
            let decryptions = ext_receiver_setup
                .decrypt(encryptions, message_size as u32)
                .unwrap();
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
        }

        for (base_ot_count, extended_ot_count) in [(256, 1024), (512, 2048), (1024, 4096)] {
            let choices = (0..extended_ot_count)
                .map(|_| u8::rand(&mut rng) % 2 != 0)
                .collect();
            let base_ot_config =
                OTConfig::new_for_alsz_ote_with_active_security(base_ot_count, 80).unwrap();
            check::<128, 80>(
                &mut rng,
                base_ot_config.num_ot,
                extended_ot_count,
                choices,
                1024,
                &B,
            );
        }
    }
}
