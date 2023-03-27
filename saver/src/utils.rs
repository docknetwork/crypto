use crate::error::SaverError;
use ark_ff::{BigInteger, PrimeField};
use ark_std::vec::Vec;

/// Return number of chunks given the bit size of chunk. Considers the size of the field.
pub fn chunks_count<F: PrimeField>(chunk_bit_size: u8) -> u8 {
    let scalar_size = F::MODULUS_BIT_SIZE as usize;
    let bit_size = chunk_bit_size as usize;
    // ceil(scalar_size / bit_size)
    ((scalar_size + bit_size - 1) / bit_size) as u8
}

pub type CHUNK_TYPE = u16;

/// Given an element `F`, break it into chunks where each chunk is of `chunk_bit_size` bits. This is
/// essentially an n-ary representation where n is `chunk_bit_size`. Returns big-endian representation.
pub fn decompose<F: PrimeField>(message: &F, chunk_bit_size: u8) -> crate::Result<Vec<CHUNK_TYPE>> {
    let bytes = message.into_bigint().to_bytes_be();
    let mut decomposition = Vec::<CHUNK_TYPE>::new();
    match chunk_bit_size {
        4 => {
            for b in bytes {
                decomposition.push((b >> 4) as CHUNK_TYPE);
                decomposition.push((b & 15) as CHUNK_TYPE);
            }
        }
        8 => {
            for b in bytes {
                decomposition.push(b as CHUNK_TYPE);
            }
        }
        16 => {
            // Process 2 bytes at a time
            for bytes_2 in bytes.chunks(2) {
                let mut b = (bytes_2[0] as CHUNK_TYPE) << (8 as CHUNK_TYPE);
                if bytes_2.len() > 1 {
                    b += bytes_2[1] as CHUNK_TYPE;
                }
                decomposition.push(b);
            }
        }
        b => return Err(SaverError::UnexpectedBase(b)),
    }
    Ok(decomposition)
}

/// Recreate a field element back from output of `decompose`. Assumes big-endian representation in `decomposed`
pub fn compose<F: PrimeField>(decomposed: &[CHUNK_TYPE], chunk_bit_size: u8) -> crate::Result<F> {
    match chunk_bit_size {
        4 => {
            if (decomposed.len() % 2) == 1 {
                return Err(SaverError::InvalidDecomposition);
            }
            let mut bytes = Vec::<u8>::with_capacity(decomposed.len() / 2);
            for nibbles in decomposed.chunks(2) {
                bytes.push(((nibbles[0] << 4) + nibbles[1]) as u8);
            }
            Ok(F::from_be_bytes_mod_order(&bytes))
        }
        8 => Ok(F::from_be_bytes_mod_order(
            &decomposed.iter().map(|b| *b as u8).collect::<Vec<u8>>(),
        )),
        16 => {
            let mut bytes = Vec::<u8>::with_capacity(decomposed.len() * 2);
            for byte_2 in decomposed {
                bytes.push((byte_2 >> 8) as u8);
                bytes.push((byte_2 & 255) as u8);
            }
            Ok(F::from_be_bytes_mod_order(&bytes))
        }
        b => Err(SaverError::UnexpectedBase(b)),
    }
}

#[cfg(test)]
#[macro_export]
macro_rules! test_serialization {
    ($obj_type:ty, $obj: ident) => {
        let mut serz = vec![];
        CanonicalSerialize::serialize_compressed(&$obj, &mut serz).unwrap();
        let deserz: $obj_type = CanonicalDeserialize::deserialize_compressed(&serz[..]).unwrap();
        assert_eq!(deserz, $obj);

        let mut serz = vec![];
        $obj.serialize_uncompressed(&mut serz).unwrap();
        let deserz: $obj_type = CanonicalDeserialize::deserialize_uncompressed(&serz[..]).unwrap();
        assert_eq!(deserz, $obj);

        // Test JSON serialization
        let ser = serde_json::to_string(&$obj).unwrap();
        let deser = serde_json::from_str::<$obj_type>(&ser).unwrap();
        assert_eq!($obj, deser);

        // Test Message Pack serialization
        let ser = rmp_serde::to_vec_named(&$obj).unwrap();
        let deser = rmp_serde::from_slice::<$obj_type>(&ser).unwrap();
        assert_eq!($obj, deser);
    };
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_std::{
        rand::{prelude::StdRng, SeedableRng},
        UniformRand,
    };

    type Fr = <Bls12_381 as Pairing>::ScalarField;

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

        let n1_decomposed = decompose(&n1, 16).unwrap();
        for i in n1_decomposed[..15].iter() {
            assert_eq!(*i, 0);
        }
        assert_eq!(n1_decomposed[15], 53);
        assert_eq!(n1, compose(&n1_decomposed, 16).unwrap());

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

        let n2_decomposed = decompose(&n2, 16).unwrap();
        for i in n2_decomposed[..15].iter() {
            assert_eq!(*i, 0);
        }
        assert_eq!(n2_decomposed[15], 325);
        assert_eq!(n2, compose(&n2_decomposed, 16).unwrap());

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

        let n3_decomposed = decompose(&n3, 16).unwrap();
        for i in n3_decomposed[..15].iter() {
            assert_eq!(*i, 0);
        }
        assert_eq!(n3_decomposed[15], 7986);
        assert_eq!(n3, compose(&n3_decomposed, 16).unwrap());

        let n4 = Fr::from(65831u64);
        let n4_decomposed = decompose(&n4, 4).unwrap();
        for i in n4_decomposed[..58].iter() {
            assert_eq!(*i, 0);
        }
        assert_eq!(n4_decomposed[58..], vec![0, 1, 0, 1, 2, 7][..]);
        assert_eq!(n4, compose(&n4_decomposed, 4).unwrap());

        let n4_decomposed = decompose(&n4, 8).unwrap();
        for i in n4_decomposed[..29].iter() {
            assert_eq!(*i, 0);
        }
        assert_eq!(n4_decomposed[29..], vec![1, 1, 39][..]);
        assert_eq!(n4, compose(&n4_decomposed, 8).unwrap());

        let n4_decomposed = decompose(&n4, 16).unwrap();
        for i in n4_decomposed[..14].iter() {
            assert_eq!(*i, 0);
        }
        assert_eq!(n4_decomposed[14..], vec![1, 295][..]);
        assert_eq!(n4, compose(&n4_decomposed, 16).unwrap());

        let mut rng = StdRng::seed_from_u64(0u64);
        for _ in 0..1000 {
            let n = Fr::rand(&mut rng);
            for b in [4, 8, 16] {
                let decomposed = decompose(&n, b).unwrap();
                assert_eq!(n, compose(&decomposed, b).unwrap());
            }
        }
    }
}
