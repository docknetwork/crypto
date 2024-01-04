//! Elliptic Curve Integrated Encryption Scheme (ECIES)

use crate::elgamal::keygen;
use aead::{generic_array::GenericArray, Aead, KeyInit};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, vec, vec::Vec};
// use digest::{
//     core_api::{BlockSizeUser, CoreProxy},
//     Digest, FixedOutputReset, HashMarker, OutputSizeUser,
// };
use hkdf::Hkdf;
use sha2::Sha256;

/*pub trait Hash:
Default
+ HashMarker
+ OutputSizeUser<OutputSize = OutputSize<Self>>
+ BlockSizeUser
+ FixedOutputReset
+ CoreProxy
+ Clone
    where
        <Self as CoreProxy>::Core: ProxyHash,
        <<Self as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<<Self as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
}*/

// TODO: Make hash function generic

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Encryption<G: AffineRepr, const KEY_BYTE_SIZE: usize, const NONCE_BYTE_SIZE: usize> {
    pub ephemeral_pk: G,
    pub nonce: [u8; NONCE_BYTE_SIZE],
    pub ciphertext: Vec<u8>,
}

impl<G: AffineRepr, const KEY_BYTE_SIZE: usize, const NONCE_BYTE_SIZE: usize>
    Encryption<G, KEY_BYTE_SIZE, NONCE_BYTE_SIZE>
{
    pub fn encrypt<R: RngCore, A: Aead + KeyInit>(
        rng: &mut R,
        msg: &[u8],
        other_pk: &G,
        gen: &G,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
    ) -> Self {
        let (sk, pk) = keygen::<R, G>(rng, gen);
        let shared_secret = *other_pk * sk.0;
        let mut shared_secret_bytes = vec![];
        shared_secret
            .serialize_compressed(&mut shared_secret_bytes)
            .unwrap();
        let hk = Hkdf::<Sha256>::new(salt, &shared_secret_bytes);
        let mut sym_key = [0u8; KEY_BYTE_SIZE];
        // TODO: Fix unwrap
        hk.expand(info.unwrap_or_else(|| &[]), &mut sym_key)
            .unwrap();
        let mut nonce = [0u8; NONCE_BYTE_SIZE];
        rng.fill_bytes(&mut nonce);
        let cipher = A::new(GenericArray::from_slice(&sym_key));
        // TODO: Fix unwrap
        let ciphertext = cipher
            .encrypt(GenericArray::from_slice(&nonce), msg)
            .unwrap();
        Self {
            ciphertext,
            nonce,
            ephemeral_pk: pk.0,
        }
    }

    pub fn decrypt<A: Aead + KeyInit>(
        self,
        sk: &G::ScalarField,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
    ) -> Vec<u8> {
        let shared_secret = self.ephemeral_pk * sk;
        let mut shared_secret_bytes = vec![];
        shared_secret
            .serialize_compressed(&mut shared_secret_bytes)
            .unwrap();
        let hk = Hkdf::<Sha256>::new(salt, &shared_secret_bytes);
        let mut sym_key = [0u8; KEY_BYTE_SIZE];
        // TODO: Fix unwrap
        hk.expand(info.unwrap_or_else(|| &[]), &mut sym_key)
            .unwrap();
        let cipher = A::new(GenericArray::from_slice(&sym_key));
        // TODO: Fix unwrap
        cipher
            .decrypt(
                &GenericArray::from_slice(&self.nonce),
                self.ciphertext.as_ref(),
            )
            .unwrap()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::{G1Affine, G2Affine};
    use ark_ec::CurveGroup;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use chacha20poly1305::XChaCha20Poly1305;

    #[test]
    fn encrypt_decrypt() {
        let mut rng = StdRng::seed_from_u64(0u64);

        fn check<G: AffineRepr>(rng: &mut StdRng) {
            let gen = G::Group::rand(rng).into_affine();
            let (sk, pk) = keygen(rng, &gen);
            let mut msg = vec![];
            let r = G::ScalarField::rand(rng);
            r.serialize_compressed(&mut msg).unwrap();
            let enc = Encryption::<G, 32, 24>::encrypt::<_, XChaCha20Poly1305>(
                rng, &msg, &pk.0, &gen, None, None,
            );
            let decrypted = enc.decrypt::<XChaCha20Poly1305>(&sk.0, None, None);
            assert_eq!(msg, decrypted);
            let decrypted_r: G::ScalarField =
                CanonicalDeserialize::deserialize_compressed(&decrypted[..]).unwrap();
            assert_eq!(decrypted_r, r);
        }

        check::<G1Affine>(&mut rng);
        check::<G2Affine>(&mut rng);
    }
}
