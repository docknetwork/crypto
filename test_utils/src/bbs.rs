use ark_bls12_381::{Bls12_381, Fr};
use ark_std::{rand::RngCore, UniformRand};
use bbs_plus::prelude::{
    KeypairG2, Signature23G1, SignatureG1, SignatureParams23G1, SignatureParamsG1,
};

pub fn bbs_plus_sig_setup<R: RngCore>(
    rng: &mut R,
    message_count: u32,
) -> (
    Vec<Fr>,
    SignatureParamsG1<Bls12_381>,
    KeypairG2<Bls12_381>,
    SignatureG1<Bls12_381>,
) {
    let messages: Vec<Fr> = (0..message_count).map(|_| Fr::rand(rng)).collect();
    let (params, keypair, sig) = bbs_plus_sig_setup_given_messages(rng, &messages);
    (messages, params, keypair, sig)
}

pub fn bbs_plus_sig_setup_given_messages<R: RngCore>(
    rng: &mut R,
    messages: &[Fr],
) -> (
    SignatureParamsG1<Bls12_381>,
    KeypairG2<Bls12_381>,
    SignatureG1<Bls12_381>,
) {
    let params = SignatureParamsG1::<Bls12_381>::generate_using_rng(rng, messages.len() as u32);
    let keypair = KeypairG2::<Bls12_381>::generate_using_rng(rng, &params);
    let sig = SignatureG1::<Bls12_381>::new(rng, messages, &keypair.secret_key, &params).unwrap();
    sig.verify(messages, keypair.public_key.clone(), params.clone())
        .unwrap();
    (params, keypair, sig)
}

pub fn bbs_sig_setup<R: RngCore>(
    rng: &mut R,
    message_count: u32,
) -> (
    Vec<Fr>,
    SignatureParams23G1<Bls12_381>,
    KeypairG2<Bls12_381>,
    Signature23G1<Bls12_381>,
) {
    let messages: Vec<Fr> = (0..message_count).map(|_| Fr::rand(rng)).collect();
    let (params, keypair, sig) = bbs_sig_setup_given_messages(rng, &messages);
    (messages, params, keypair, sig)
}

pub fn bbs_sig_setup_given_messages<R: RngCore>(
    rng: &mut R,
    messages: &[Fr],
) -> (
    SignatureParams23G1<Bls12_381>,
    KeypairG2<Bls12_381>,
    Signature23G1<Bls12_381>,
) {
    let params = SignatureParams23G1::<Bls12_381>::generate_using_rng(rng, messages.len() as u32);
    let keypair = KeypairG2::<Bls12_381>::generate_using_rng_and_bbs23_params(rng, &params);
    let sig = Signature23G1::<Bls12_381>::new(rng, messages, &keypair.secret_key, &params).unwrap();
    sig.verify(messages, keypair.public_key.clone(), params.clone())
        .unwrap();
    (params, keypair, sig)
}
