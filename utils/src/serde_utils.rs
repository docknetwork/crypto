//! Serde serialization for `arkworks-rs` objects they themselves don't implement serde

use ark_ec::AffineCurve;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{fmt, io, marker::PhantomData, string::ToString, vec, vec::Vec};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserializer, Serialize, Serializer};
use serde_with::{DeserializeAs, SerializeAs};

pub struct FieldBytes;

impl<F: Field> SerializeAs<F> for FieldBytes {
    fn serialize_as<S>(elem: &F, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = vec![];
        CanonicalSerialize::serialize(elem, &mut bytes).map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, F: Field> DeserializeAs<'de, F> for FieldBytes {
    fn deserialize_as<D>(deserializer: D) -> Result<F, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FVisitor<F: Field>(PhantomData<F>);

        impl<'a, F: Field> Visitor<'a> for FVisitor<F> {
            type Value = F;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("expected field element")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'a>,
            {
                let mut bytes: Vec<u8> = Vec::with_capacity(seq.size_hint().unwrap_or(32));
                while let Some(b) = seq.next_element()? {
                    bytes.push(b);
                }
                let f = CanonicalDeserialize::deserialize(bytes.as_slice())
                    .map_err(serde::de::Error::custom)?;
                Ok(f)
            }
        }
        deserializer.deserialize_seq(FVisitor::<F>(PhantomData))
    }
}

pub struct AffineGroupBytes;

impl<G: AffineCurve> SerializeAs<G> for AffineGroupBytes {
    fn serialize_as<S>(elem: &G, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = vec![];
        CanonicalSerialize::serialize(elem, &mut bytes).map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, G: AffineCurve> DeserializeAs<'de, G> for AffineGroupBytes {
    fn deserialize_as<D>(deserializer: D) -> Result<G, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct GVisitor<G: AffineCurve>(PhantomData<G>);

        impl<'a, G: AffineCurve> Visitor<'a> for GVisitor<G> {
            type Value = G;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("expected group element in affine coordinates")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'a>,
            {
                let mut bytes: Vec<u8> = Vec::with_capacity(seq.size_hint().unwrap_or(48));
                while let Some(b) = seq.next_element()? {
                    bytes.push(b);
                }
                let g = CanonicalDeserialize::deserialize(bytes.as_slice())
                    .map_err(serde::de::Error::custom)?;
                Ok(g)
            }
        }
        deserializer.deserialize_seq(GVisitor::<G>(PhantomData))
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

#[macro_export]
macro_rules! impl_for_groth16_struct {
    ($serializer_name: ident, $struct_name: ident, $error_msg: expr) => {
        pub struct $serializer_name;

        impl<E: PairingEngine> SerializeAs<$struct_name<E>> for $serializer_name {
            fn serialize_as<S>(elem: &$struct_name<E>, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut bytes = vec![];
                CanonicalSerialize::serialize(elem, &mut bytes)
                    .map_err(serde::ser::Error::custom)?;
                serializer.serialize_bytes(&bytes)
            }
        }

        impl<'de, E: PairingEngine> DeserializeAs<'de, $struct_name<E>> for $serializer_name {
            fn deserialize_as<D>(deserializer: D) -> Result<$struct_name<E>, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct PVisitor<E: PairingEngine>(PhantomData<E>);

                impl<'a, E: PairingEngine> Visitor<'a> for PVisitor<E> {
                    type Value = $struct_name<E>;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str($error_msg)
                    }

                    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                    where
                        A: SeqAccess<'a>,
                    {
                        let mut bytes = Vec::<u8>::new();
                        while let Some(b) = seq.next_element()? {
                            bytes.push(b);
                        }
                        let p: $struct_name<E> =
                            CanonicalDeserialize::deserialize(bytes.as_slice())
                                .map_err(serde::de::Error::custom)?;
                        Ok(p)
                    }
                }
                deserializer.deserialize_seq(PVisitor::<E>(PhantomData))
            }
        }
    };
}
