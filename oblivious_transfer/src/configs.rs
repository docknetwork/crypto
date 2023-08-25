use crate::{
    error::OTError,
    util::{self, divide_by_8},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use serde::{Deserialize, Serialize};

/// Config of a base OT
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    CanonicalDeserialize,
    CanonicalSerialize,
    Serialize,
    Deserialize,
)]
pub struct OTConfig {
    /// Number of OTs
    pub num_ot: u16,
    /// Number of possible messages in a single OT, `n` = 2 in a 1-of-2 OT
    pub num_messages: u16,
}

impl OTConfig {
    pub fn new(num_ot: u16, num_messages: u16) -> Result<Self, OTError> {
        if num_ot == 0 {
            return Err(OTError::NeedNonZeroNumberOfOTs);
        }
        if num_messages < 2 {
            return Err(OTError::OTShouldHaveAtLeast2Messages(num_messages));
        }
        Ok(Self {
            num_ot,
            num_messages,
        })
    }

    /// For 1-of-2 OT
    pub fn new_2_message(num_ot: u16) -> Result<Self, OTError> {
        if num_ot == 0 {
            return Err(OTError::NeedNonZeroNumberOfOTs);
        }
        Ok(Self {
            num_ot,
            num_messages: 2,
        })
    }

    pub fn verify_receiver_choices(&self, choices: &[u16]) -> Result<(), OTError> {
        if choices.len() != self.num_ot as usize {
            return Err(OTError::IncorrectNumberOfChoices(
                choices.len() as u16,
                self.num_ot,
            ));
        }
        if !choices.iter().all(|c| *c < self.num_messages) {
            return Err(OTError::InvalidChoice);
        }
        Ok(())
    }

    /// Config for base OT used in ALSZ OT extension
    pub fn new_for_alsz_ote(symmetric_security_parameter: u16) -> Result<Self, OTError> {
        if symmetric_security_parameter == 0 {
            return Err(OTError::NeedNonZeroNumberOfOTs);
        }
        Self::new_2_message(symmetric_security_parameter)
    }

    /// Config for base OT used in ALSZ actively secure OT extension
    pub fn new_for_alsz_ote_with_active_security(
        symmetric_security_parameter: u16,
        statistical_security_parameter: u16,
    ) -> Result<Self, OTError> {
        if symmetric_security_parameter == 0 {
            return Err(OTError::NeedNonZeroNumberOfOTs);
        }
        Self::new_2_message(symmetric_security_parameter + statistical_security_parameter)
    }
}

/// Config of an OT extension where the base OT is a 1-of-2 OT
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    CanonicalDeserialize,
    CanonicalSerialize,
    Serialize,
    Deserialize,
)]
pub struct OTEConfig {
    /// Number of base OTs
    pub num_base_ot: u16,
    /// Number of OT extensions
    pub num_ot_extensions: u32,
}

impl OTEConfig {
    pub fn new(num_base_ot: u16, num_ot_extensions: u32) -> Result<Self, OTError> {
        if !util::is_multiple_of_8(num_base_ot as usize)
            || !util::is_multiple_of_8(num_ot_extensions)
        {
            return Err(OTError::IncorrectOTExtensionConfig(
                num_base_ot,
                num_ot_extensions,
            ));
        }
        Ok(Self {
            num_base_ot,
            num_ot_extensions,
        })
    }

    pub fn matrix_byte_size(&self) -> Result<usize, OTError> {
        let value = divide_by_8(self.num_ot_extensions as u64 * self.num_base_ot as u64);

        value
            .try_into()
            .map_err(|_| OTError::MatrixSizeIsTooBig(value))
            .map(|value: u32| value as usize)
    }

    pub fn matrix_byte_size_for_random(&self) -> Result<usize, OTError> {
        let value = divide_by_8(self.num_ot_extensions as u64 * (self.num_base_ot as u64 - 1));

        value
            .try_into()
            .map_err(|_| OTError::MatrixSizeIsTooBig(value))
            .map(|value: u32| value as usize)
    }

    pub fn column_byte_size(&self) -> usize {
        divide_by_8(self.num_ot_extensions) as usize
    }

    pub fn row_byte_size(&self) -> usize {
        divide_by_8(self.num_base_ot) as usize
    }
}
