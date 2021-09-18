use ark_ec::AffineCurve;
use ark_ff::{PrimeField, SquareRootField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt, marker::PhantomData, vec, vec::Vec};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserializer, Serializer};
use serde_with::{DeserializeAs, SerializeAs};

pub struct PrimeFieldBytes;

impl<F: PrimeField> SerializeAs<F> for PrimeFieldBytes {
    fn serialize_as<S>(elem: &F, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = vec![];
        CanonicalSerialize::serialize(elem, &mut bytes).map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, F: PrimeField> DeserializeAs<'de, F> for PrimeFieldBytes {
    fn deserialize_as<D>(deserializer: D) -> Result<F, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FVisitor<F: PrimeField>(PhantomData<F>);

        impl<'a, F: PrimeField> Visitor<'a> for FVisitor<F> {
            type Value = F;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("expected prime field element")
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

pub struct ScalarFieldBytes;

impl<F: PrimeField + SquareRootField> SerializeAs<F> for ScalarFieldBytes {
    fn serialize_as<S>(elem: &F, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = vec![];
        CanonicalSerialize::serialize(elem, &mut bytes).map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, F: PrimeField + SquareRootField> DeserializeAs<'de, F> for ScalarFieldBytes {
    fn deserialize_as<D>(deserializer: D) -> Result<F, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FVisitor<F: PrimeField + SquareRootField>(PhantomData<F>);

        impl<'a, F: PrimeField + SquareRootField> Visitor<'a> for FVisitor<F> {
            type Value = F;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("expected scalar field element")
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
