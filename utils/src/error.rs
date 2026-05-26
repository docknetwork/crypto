use core::fmt;
use serde::Serialize;

/// Errors from the utils crate
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum UtilsError {
    /// Randomized pairing check failed; the pairing equations did not all hold
    PairingCheckFailed,
    /// Randomized scalar multiplication check failed; the scalar multiplication equations did not all hold
    MultCheckFailed,
}

impl fmt::Display for UtilsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PairingCheckFailed => write!(f, "Randomized pairing check failed"),
            Self::MultCheckFailed => write!(f, "Randomized scalar multiplication check failed"),
        }
    }
}
