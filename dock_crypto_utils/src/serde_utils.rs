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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::{PairingEngine, ProjectiveCurve};
    use ark_std::collections::BTreeMap;
    use ark_std::{
        io::{Read, Write},
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use serde::Deserialize;
    use serde_with::serde_as;

    type Fr = <Bls12_381 as PairingEngine>::Fr;
    type G1Proj = <Bls12_381 as PairingEngine>::G1Projective;
    type G2Proj = <Bls12_381 as PairingEngine>::G2Projective;

    #[test]
    fn serde_field() {
        let mut rng = StdRng::seed_from_u64(0u64);

        #[serde_as]
        #[derive(
            Clone,
            Debug,
            PartialEq,
            Eq,
            CanonicalSerialize,
            CanonicalDeserialize,
            Serialize,
            Deserialize,
        )]
        pub struct Temp<F: Field> {
            #[serde_as(as = "FieldBytes")]
            single: F,
            #[serde_as(as = "Vec<FieldBytes>")]
            vec: Vec<F>,
            #[serde_as(as = "BTreeMap<_, FieldBytes>")]
            map: BTreeMap<usize, F>,
        }

        let mut map = BTreeMap::new();
        map.insert(1, Fr::rand(&mut rng));
        map.insert(3, Fr::rand(&mut rng));
        map.insert(4, Fr::rand(&mut rng));
        let t = Temp {
            single: Fr::rand(&mut rng),
            vec: vec![Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng)],
            map,
        };
        let t_ser = serde_json::to_string(&t).unwrap();
        let t_deser = serde_json::from_str::<Temp<Fr>>(&t_ser).unwrap();
        assert_eq!(t, t_deser);
    }

    #[test]
    fn serde_affine_group() {
        let mut rng = StdRng::seed_from_u64(0u64);

        #[serde_as]
        #[derive(
            Clone,
            Debug,
            PartialEq,
            Eq,
            CanonicalSerialize,
            CanonicalDeserialize,
            Serialize,
            Deserialize,
        )]
        pub struct Temp<G: AffineCurve> {
            #[serde_as(as = "AffineGroupBytes")]
            single: G,
            #[serde_as(as = "Vec<AffineGroupBytes>")]
            vec: Vec<G>,
            #[serde_as(as = "BTreeMap<_, AffineGroupBytes>")]
            map: BTreeMap<usize, G>,
        }

        let mut map = BTreeMap::new();
        map.insert(1, G1Proj::rand(&mut rng).into_affine());
        map.insert(3, G1Proj::rand(&mut rng).into_affine());
        map.insert(4, G1Proj::rand(&mut rng).into_affine());
        let t1 = Temp {
            single: G1Proj::rand(&mut rng).into_affine(),
            vec: vec![
                G1Proj::rand(&mut rng).into_affine(),
                G1Proj::rand(&mut rng).into_affine(),
                G1Proj::rand(&mut rng).into_affine(),
            ],
            map,
        };
        let t_ser = serde_json::to_string(&t1).unwrap();
        let t_deser =
            serde_json::from_str::<Temp<<Bls12_381 as PairingEngine>::G1Affine>>(&t_ser).unwrap();
        assert_eq!(t1, t_deser);

        let mut map = BTreeMap::new();
        map.insert(1, G2Proj::rand(&mut rng).into_affine());
        map.insert(3, G2Proj::rand(&mut rng).into_affine());
        map.insert(4, G2Proj::rand(&mut rng).into_affine());
        let t2 = Temp {
            single: G2Proj::rand(&mut rng).into_affine(),
            vec: vec![
                G2Proj::rand(&mut rng).into_affine(),
                G2Proj::rand(&mut rng).into_affine(),
                G2Proj::rand(&mut rng).into_affine(),
            ],
            map,
        };
        let t_ser = serde_json::to_string(&t2).unwrap();
        let t_deser =
            serde_json::from_str::<Temp<<Bls12_381 as PairingEngine>::G2Affine>>(&t_ser).unwrap();
        assert_eq!(t2, t_deser);
    }
}
