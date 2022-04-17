use crate::error::SaverError;
use ark_ff::{BigInteger, PrimeField};
use ark_std::{vec, vec::Vec};

/// Return number of chunks given the bit size of chunk. Considers the size of the field.
pub fn chunks_count<F: PrimeField>(chunk_bit_size: u8) -> u8 {
    let scalar_size = F::size_in_bits();
    let bit_size = chunk_bit_size as usize;
    // ceil(scalar_size / bit_size)
    ((scalar_size + bit_size - 1) / bit_size) as u8
}

/// Given an element `F`, break it into chunks where each chunk is of `chunk_bit_size` bits. This is
/// essentially an n-ary representation where n is chunk_bit_size. Assumes BE
pub fn decompose<F: PrimeField>(message: &F, chunk_bit_size: u8) -> crate::Result<Vec<u8>> {
    let bytes = message.into_repr().to_bytes_be();
    let mut decomposition = vec![];
    match chunk_bit_size {
        4 => {
            for b in bytes {
                decomposition.push(b >> 4);
                decomposition.push(b & 15);
            }
        }
        8 => {
            for b in bytes {
                decomposition.push(b);
            }
        }
        b => return Err(SaverError::UnexpectedBase(b)),
    }
    Ok(decomposition)
}

/// Recreate a field element back from output of `decompose`
pub fn compose<F: PrimeField>(decomposed: &[u8], chunk_bit_size: u8) -> crate::Result<F> {
    match chunk_bit_size {
        4 => {
            if (decomposed.len() % 2) == 1 {
                return Err(SaverError::InvalidDecomposition);
            }
            let mut bytes = vec![];
            for nibbles in decomposed.chunks(2) {
                bytes.push(nibbles[0] * 16 + nibbles[1]);
            }
            Ok(F::from_be_bytes_mod_order(&bytes))
        }
        8 => Ok(F::from_be_bytes_mod_order(&decomposed)),
        b => Err(SaverError::UnexpectedBase(b)),
    }
}

#[cfg(test)]
#[macro_export]
macro_rules! test_serialization {
    ($obj_type:ty, $obj: ident) => {
        let mut serz = vec![];
        CanonicalSerialize::serialize(&$obj, &mut serz).unwrap();
        let deserz: $obj_type = CanonicalDeserialize::deserialize(&serz[..]).unwrap();
        assert_eq!(deserz, $obj);

        let mut serz = vec![];
        $obj.serialize_unchecked(&mut serz).unwrap();
        let deserz: $obj_type = CanonicalDeserialize::deserialize_unchecked(&serz[..]).unwrap();
        assert_eq!(deserz, $obj);

        let mut serz = vec![];
        $obj.serialize_uncompressed(&mut serz).unwrap();
        let deserz: $obj_type = CanonicalDeserialize::deserialize_uncompressed(&serz[..]).unwrap();
        assert_eq!(deserz, $obj);

        // Test JSON serialization
        let ser = serde_json::to_string(&$obj).unwrap();
        let deser = serde_json::from_str::<$obj_type>(&ser).unwrap();
        assert_eq!($obj, deser);
    };
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::PairingEngine;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::SeedableRng;
    use ark_std::UniformRand;

    type Fr = <Bls12_381 as PairingEngine>::Fr;

    #[test]
    fn compose_decompose() {
        let n1 = Fr::from(53u64);
        let n1_decomposed = decompose(&n1, 4).unwrap();
        for i in n1_decomposed[..62].iter() {
            assert_eq!(*i, 0);
        }
        assert_eq!(n1_decomposed[62..], vec![3, 5][..]);
        assert_eq!(n1, compose(&n1_decomposed, 4).unwrap());

        let n1_decomposed = decompose(&n1, 8).unwrap();
        for i in n1_decomposed[..31].iter() {
            assert_eq!(*i, 0);
        }
        assert_eq!(n1_decomposed[31], 53);
        assert_eq!(n1, compose(&n1_decomposed, 8).unwrap());

        let n2 = Fr::from(325u64);
        let n2_decomposed = decompose(&n2, 4).unwrap();
        for i in n2_decomposed[..61].iter() {
            assert_eq!(*i, 0);
        }
        assert_eq!(n2_decomposed[61..], vec![1, 4, 5][..]);
        assert_eq!(n2, compose(&n2_decomposed, 4).unwrap());

        let n2_decomposed = decompose(&n2, 8).unwrap();
        for i in n2_decomposed[..30].iter() {
            assert_eq!(*i, 0);
        }
        assert_eq!(n2_decomposed[30..], vec![1, 69][..]);
        assert_eq!(n2, compose(&n2_decomposed, 8).unwrap());

        let n3 = Fr::from(7986u64);
        let n3_decomposed = decompose(&n3, 4).unwrap();
        for i in n3_decomposed[..60].iter() {
            assert_eq!(*i, 0);
        }
        assert_eq!(n3_decomposed[60..], vec![1, 15, 3, 2][..]);
        assert_eq!(n3, compose(&n3_decomposed, 4).unwrap());

        let n3_decomposed = decompose(&n3, 8).unwrap();
        for i in n3_decomposed[..30].iter() {
            assert_eq!(*i, 0);
        }
        assert_eq!(n3_decomposed[30..], vec![31, 50][..]);
        assert_eq!(n3, compose(&n3_decomposed, 8).unwrap());

        let mut rng = StdRng::seed_from_u64(0u64);
        for _ in 0..100 {
            let n = Fr::rand(&mut rng);
            let decomposed = decompose(&n, 4).unwrap();
            assert_eq!(n, compose(&decomposed, 4).unwrap());

            let decomposed = decompose(&n, 8).unwrap();
            assert_eq!(n, compose(&decomposed, 8).unwrap());
        }
    }
}
