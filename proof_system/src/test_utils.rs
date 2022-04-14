use ark_bls12_381::fr::Fr;
use ark_bls12_381::Bls12_381;
use ark_std::{
    rand::{rngs::StdRng, RngCore},
    UniformRand,
};
use bbs_plus::setup::{KeypairG2, SignatureParamsG1};
use bbs_plus::signature::SignatureG1;
use std::collections::HashSet;

pub fn sig_setup<R: RngCore>(
    rng: &mut R,
    message_count: usize,
) -> (
    Vec<Fr>,
    SignatureParamsG1<Bls12_381>,
    KeypairG2<Bls12_381>,
    SignatureG1<Bls12_381>,
) {
    let messages: Vec<Fr> = (0..message_count)
        .into_iter()
        .map(|_| Fr::rand(rng))
        .collect();
    let params = SignatureParamsG1::<Bls12_381>::generate_using_rng(rng, message_count);
    let keypair = KeypairG2::<Bls12_381>::generate_using_rng(rng, &params);
    let sig = SignatureG1::<Bls12_381>::new(rng, &messages, &keypair.secret_key, &params).unwrap();
    sig.verify(&messages, &keypair.public_key, &params).unwrap();
    (messages, params, keypair, sig)
}

pub fn sig_setup_given_messages<R: RngCore>(
    rng: &mut R,
    messages: &[Fr],
) -> (
    SignatureParamsG1<Bls12_381>,
    KeypairG2<Bls12_381>,
    SignatureG1<Bls12_381>,
) {
    let params = SignatureParamsG1::<Bls12_381>::generate_using_rng(rng, messages.len());
    let keypair = KeypairG2::<Bls12_381>::generate_using_rng(rng, &params);
    let sig = SignatureG1::<Bls12_381>::new(rng, messages, &keypair.secret_key, &params).unwrap();
    sig.verify(&messages, &keypair.public_key, &params).unwrap();
    (params, keypair, sig)
}

#[macro_export]
macro_rules! test_serialization {
    ($obj_type:ty, $obj: ident, $Instant: ident) => {
        let mut serz = vec![];
        CanonicalSerialize::serialize(&$obj, &mut serz).unwrap();
        println!("Serialized byte size: {}", serz.len());
        let start = $Instant::now();
        let deserz: $obj_type = CanonicalDeserialize::deserialize(&serz[..]).unwrap();
        println!("Deserialized time: {:?}", start.elapsed());
        assert_eq!(deserz, $obj);

        let mut serz = vec![];
        $obj.serialize_unchecked(&mut serz).unwrap();
        println!("Serialized byte size: {}", serz.len());
        let start = $Instant::now();
        let deserz: $obj_type = CanonicalDeserialize::deserialize_unchecked(&serz[..]).unwrap();
        println!("Deserialized unchecked time: {:?}", start.elapsed());
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
    ($obj_type:ty, $obj: ident) => {
        let mut serz = vec![];
        CanonicalSerialize::serialize(&$obj, &mut serz).unwrap();
        println!("Serialized byte size: {}", serz.len());
        let deserz: $obj_type = CanonicalDeserialize::deserialize(&serz[..]).unwrap();
        assert_eq!(deserz, $obj);

        let mut serz = vec![];
        $obj.serialize_unchecked(&mut serz).unwrap();
        println!("Serialized byte size: {}", serz.len());
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
