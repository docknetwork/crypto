use serde::{Serializer, Deserializer, Deserialize};
use ark_ff::{PrimeField, SquareRootField};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_ec::AffineCurve;
use serde::ser::SerializeSeq;
use ark_std::{
    fmt,
    marker::PhantomData,
    vec, vec::Vec
};
use serde::de::{Visitor, SeqAccess};
use serde_with::{SerializeAs, DeserializeAs};


pub struct PrimeFieldBytes;

impl<F: PrimeField + SquareRootField> SerializeAs<F> for PrimeFieldBytes {
    fn serialize_as<S>(elem: &F, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        // MODULE::serialize(value, serializer)
        let mut bytes = vec![];
        CanonicalSerialize::serialize(elem, &mut bytes).map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, F: PrimeField + SquareRootField> DeserializeAs<'de, F> for PrimeFieldBytes {
    fn deserialize_as<D>(deserializer: D) -> Result<F, D::Error>
        where
            D: Deserializer<'de>,
    {
        // MODULE::deserialize(deserializer)
        struct FVisitor<F: PrimeField + SquareRootField>(PhantomData<F>);

        impl<'a, F: PrimeField + SquareRootField> Visitor<'a> for FVisitor<F> {
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
                let f = CanonicalDeserialize::deserialize(bytes.as_slice()).map_err(serde::de::Error::custom)?;
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
        // MODULE::serialize(value, serializer)
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
                formatter.write_str("expected affine curve element")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'a>,
            {
                let mut bytes: Vec<u8> = Vec::with_capacity(seq.size_hint().unwrap_or(48));
                while let Some(b) = seq.next_element()? {
                    bytes.push(b);
                }
                let g = CanonicalDeserialize::deserialize(bytes.as_slice()).map_err(serde::de::Error::custom)?;
                Ok(g)
            }
        }
        deserializer.deserialize_seq(GVisitor::<G>(PhantomData))
    }
}

pub fn to_prime_field<S, F>(elem: &F, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, F: PrimeField + SquareRootField
{
    let mut bytes = vec![];
    CanonicalSerialize::serialize(elem, &mut bytes).map_err(serde::ser::Error::custom)?;
    serializer.serialize_bytes(&bytes)
    /*let mut seq = serializer.serialize_seq(Some(bytes.len()))?;
    for element in bytes {
        seq.serialize_element(&element)?;
    }
    seq.end()*/
}

pub fn to_affine_group<S, G>(elem: &G, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, G: AffineCurve
{
    let mut bytes = vec![];
    CanonicalSerialize::serialize(elem, &mut bytes).map_err(serde::ser::Error::custom)?;
    serializer.serialize_bytes(&bytes)
    /*let mut seq = serializer.serialize_seq(Some(bytes.len()))?;
    for element in bytes {
        seq.serialize_element(&element)?;
    }
    seq.end()*/
}

pub fn to_affine_group_vec<S, G>(elems: &Vec<G>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, G: AffineCurve
{
    /*let mut bytes = vec![];
    CanonicalSerialize::serialize(elem, &mut bytes).map_err(serde::ser::Error::custom)?;
    serializer.serialize_bytes(&bytes)*/
    let mut seq = serializer.serialize_seq(Some(48*elems.len()))?;
    /*for i in 0..elems.len() {
        seq.serialize_element(&elems[i])?;
    }*/
    seq.end();
    /*for elem in elems {
        let serz = to_affine_group(elem, serializer);
    }*/
    unimplemented!()
}

pub fn from_prime_field<'de, D, F>(deserializer: D) -> Result<F, D::Error>
    where
        D: Deserializer<'de>, F: PrimeField + SquareRootField
{
    struct FVisitor<F: PrimeField + SquareRootField>(PhantomData<F>);

    impl<'a, F: PrimeField + SquareRootField> Visitor<'a> for FVisitor<F> {
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
            let f = CanonicalDeserialize::deserialize(bytes.as_slice()).map_err(serde::de::Error::custom)?;
            Ok(f)
        }
    }
    deserializer.deserialize_seq(FVisitor::<F>(PhantomData))
    // deserializer.deserialize_seq(PkVisitor::<E>(PhantomData))
    /*let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
    CanonicalDeserialize::deserialize(bytes).map_err(serde::de::Error::custom)*/
    // unimplemented!()
}

pub fn from_affine_group<'de, D, G>(deserializer: D) -> Result<G, D::Error>
    where
        D: Deserializer<'de>, G: AffineCurve
{
    struct GVisitor<G: AffineCurve>(PhantomData<G>);

    impl<'a, G: AffineCurve> Visitor<'a> for GVisitor<G> {
        type Value = G;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("expected affine curve element")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'a>,
        {
            let mut bytes: Vec<u8> = Vec::with_capacity(seq.size_hint().unwrap_or(48));
            while let Some(b) = seq.next_element()? {
                bytes.push(b);
            }
            let g = CanonicalDeserialize::deserialize(bytes.as_slice()).map_err(serde::de::Error::custom)?;
            Ok(g)
        }
    }
    deserializer.deserialize_seq(GVisitor::<G>(PhantomData))
    /*println!("in from affine");
    let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
    println!("past deserz");
    CanonicalDeserialize::deserialize(bytes).map_err(serde::de::Error::custom)*/
}
