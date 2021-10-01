#![cfg_attr(not(feature = "std"), no_std)]

pub mod hashing_utils;
#[cfg(feature = "serde-support")]
pub mod serde_utils;

#[cfg(test)]
mod tests {
    #[cfg(feature = "serde-support")]
    use super::serde_utils::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::PairingEngine;
    use ark_ff::Field;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
    use ark_std::collections::BTreeMap;
    use ark_std::{
        io::{Read, Write},
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    #[cfg(feature = "serde-support")]
    use serde::{Deserialize, Serialize};
    #[cfg(feature = "serde-support")]
    use serde_with::{serde_as, As, Same};

    type Fr = <Bls12_381 as PairingEngine>::Fr;
    type G1Proj = <Bls12_381 as PairingEngine>::G1Projective;
    type G2Proj = <Bls12_381 as PairingEngine>::G2Projective;

    #[test]
    fn serde_111() {
        let mut rng = StdRng::seed_from_u64(0u64);

        // #[serde_as]
        #[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
        #[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
        pub struct Temp<F: Field> {
            #[cfg_attr(feature = "serde-support", serde(with = "As::FieldBytes"))]
            single: F,
            #[cfg_attr(feature = "serde-support", serde(with = "As::Vec<FieldBytes>"))]
            vec: Vec<F>,
            #[cfg_attr(feature = "serde-support", serde(with = "As::BTreeMap<_, FieldBytes>"))]
            map: BTreeMap<usize, F>,
        }

        /*let mut map = BTreeMap::new();
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
        assert_eq!(t, t_deser);*/
    }
}
