//! OT based on the paper [Endemic Oblivious Transfer](https://eprint.iacr.org/2019/706)
//! Allows to run single instance of 1-of-n ROT (Random OT)

use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, ops::Mul, rand::RngCore, vec::Vec, UniformRand};
use digest::Digest;
use itertools::Itertools;
use zeroize::Zeroize;

use crate::Key;
use dock_crypto_utils::hashing_utils::projective_group_elem_from_try_and_incr;

use crate::error::OTError;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sha3::Sha3_256;

/// 1-of-n OT receiver
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ROTReceiver<G: AffineRepr> {
    /// Number of possible messages in a single OT, `n` = 2 in a 1-of-2 OT
    pub n: u16,
    pub choice: u16,
    pub t: G::ScalarField,
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize, CanonicalSerialize, CanonicalDeserialize)]
pub struct ROTSenderKeys(pub Vec<Key>);

impl<G: AffineRepr> ROTReceiver<G> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        n: u16,
        choice: u16,
        g: &G,
    ) -> Result<(Self, Vec<G>), OTError> {
        if n < 2 {
            return Err(OTError::OTShouldHaveAtLeast2Messages(n));
        }
        if choice >= n {
            return Err(OTError::InvalidChoice);
        }
        let t = G::ScalarField::rand(rng);
        let m = g.mul(t).into_affine();
        let mut r =
            G::Group::normalize_batch(&(0..n - 1).map(|_| G::Group::rand(rng)).collect::<Vec<_>>());
        let r_i = m.into_group() - indexed_hash(choice, r.iter());
        r.insert(choice as usize, r_i.into_affine());
        Ok((Self { n, choice, t }, r))
    }

    pub fn derive_key(&self, m: Vec<G>) -> Key {
        assert_eq!(m.len(), self.n as usize);
        hash_to_key(self.choice, &m[self.choice as usize])
    }
}

impl ROTSenderKeys {
    pub fn new<R: RngCore, G: AffineRepr>(
        rng: &mut R,
        n: u16,
        r: Vec<G>,
    ) -> Result<(Self, Vec<G>), OTError> {
        if n < 2 {
            return Err(OTError::OTShouldHaveAtLeast2Messages(n));
        }
        assert_eq!(r.len(), n as usize);
        let t = (0..n)
            .map(|_| G::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let (m, keys) = cfg_into_iter!(0..n)
            .map(|i| {
                let m_a = r[i as usize].into_group()
                    + indexed_hash(
                        i,
                        r.iter()
                            .enumerate()
                            .filter_map(|(j, r_j)| (j != i as usize).then_some(r_j)),
                    );
                let m_b = m_a.mul(&t[i as usize]);
                (m_b, hash_to_key(i, &m_b))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .multiunzip::<(Vec<_>, Vec<_>)>();
        Ok((Self(keys), G::Group::normalize_batch(&m)))
    }
}

pub fn indexed_hash<'a, I: Iterator<Item = &'a G>, G: AffineRepr>(index: u16, r: I) -> G::Group {
    let mut bytes = index.to_be_bytes().to_vec();
    for r in r {
        r.serialize_compressed(&mut bytes).unwrap();
    }
    // TODO: Replace with hash to curve
    projective_group_elem_from_try_and_incr::<G, Sha3_256>(&bytes)
}

// TODO: Make it use const generic for key size and generic digest
pub fn hash_to_key<G: CanonicalSerialize>(index: u16, item: &G) -> Vec<u8> {
    let mut bytes = index.to_be_bytes().to_vec();
    item.serialize_compressed(&mut bytes).unwrap();
    let mut hasher = Sha3_256::new();
    hasher.update(&bytes);
    hasher.finalize().to_vec()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use std::time::Instant;

    #[test]
    fn endemic_rot() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let g = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);

        fn check(rng: &mut StdRng, n: u16, choice: u16, g: &<Bls12_381 as Pairing>::G1Affine) {
            let start = Instant::now();
            let (receiver, r) = ROTReceiver::new(rng, n, choice, g).unwrap();
            println!(
                "Receiver setup for 1-of-{} ROTs in {:?}",
                n,
                start.elapsed()
            );

            let start = Instant::now();
            let (sender_keys, m) = ROTSenderKeys::new(rng, n, r).unwrap();
            println!(
                "Sender creates keys for 1-of-{} ROTs in {:?}",
                n,
                start.elapsed()
            );

            assert_eq!(sender_keys.0.len(), n as usize);
            let receiver_key = receiver.derive_key(m);
            for i in 0..n as usize {
                if i == choice as usize {
                    assert_eq!(sender_keys.0[i], receiver_key);
                } else {
                    assert_ne!(sender_keys.0[i], receiver_key);
                }
            }
        }

        check(&mut rng, 2, 0, &g);
        check(&mut rng, 2, 1, &g);
        check(&mut rng, 3, 0, &g);
        check(&mut rng, 3, 1, &g);
        check(&mut rng, 3, 2, &g);
        check(&mut rng, 64, 0, &g);
        check(&mut rng, 64, 63, &g);
        check(&mut rng, 128, 0, &g);
        check(&mut rng, 128, 127, &g);
        check(&mut rng, 200, 0, &g);
        check(&mut rng, 200, 199, &g);
    }
}
