//! Serde serialization for `arkworks-rs` objects they themselves don't implement serde

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{io, string::ToString, vec::Vec};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{DeserializeAs, SerializeAs};

pub type ArkObjectBytes = AsCanonical;

// This is taken from the expanded [`serde_with::serde_conv!`] macro but generalized for any `T: CanonicalSerialize + CanonicalDeserialize`

pub struct AsCanonical;
impl AsCanonical {
    pub fn serialize<S, T>(x: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: CanonicalSerialize,
        S: Serializer,
    {
        let size = x.compressed_size();
        let mut bytes = Vec::with_capacity(size);
        x.serialize_compressed(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        Serialize::serialize(&bytes, serializer)
    }
    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        T: CanonicalDeserialize,
        D: Deserializer<'de>,
    {
        let y: Vec<u8> = Deserialize::deserialize(deserializer)?;
        T::deserialize_compressed(y.as_slice()).map_err(serde::de::Error::custom)
    }
}

impl<T> SerializeAs<T> for AsCanonical
where
    T: CanonicalSerialize,
{
    fn serialize_as<S>(x: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Self::serialize(x, serializer)
    }
}
impl<'de, T> DeserializeAs<'de, T> for AsCanonical
where
    T: CanonicalDeserialize,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::deserialize(deserializer)
    }
}

#[derive(Serialize)]
#[serde(remote = "SerializationError")]
pub enum ArkSerializationError {
    /// During serialization, we didn't have enough space to write extra info.
    NotEnoughSpace,
    /// During serialization, the data was invalid.
    InvalidData,
    /// During serialization, non-empty flags were given where none were
    /// expected.
    UnexpectedFlags,
    /// During serialization, we countered an I/O error.
    #[serde(serialize_with = "io_error_string")]
    IoError(io::Error),
}

fn io_error_string<S>(error: &io::Error, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&error.to_string())
}
