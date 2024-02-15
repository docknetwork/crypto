use ark_bls12_381::{Fr, G1Affine};
use ark_std::{rand::RngCore, UniformRand};
use blake2::Blake2b512;
use kvac::bddt_2016::{
    mac::MAC,
    setup::{MACParams, SecretKey},
};

pub fn bddt16_mac_setup<R: RngCore>(
    rng: &mut R,
    message_count: u32,
) -> (Vec<Fr>, MACParams<G1Affine>, SecretKey<Fr>, MAC<G1Affine>) {
    let messages: Vec<Fr> = (0..message_count).map(|_| Fr::rand(rng)).collect();
    let (params, keypair, mac) = bddt16_mac_setup_given_messages(rng, &messages);
    (messages, params, keypair, mac)
}

pub fn bddt16_mac_setup_given_messages<R: RngCore>(
    rng: &mut R,
    messages: &[Fr],
) -> (MACParams<G1Affine>, SecretKey<Fr>, MAC<G1Affine>) {
    let params = MACParams::<G1Affine>::new::<Blake2b512>(b"test", messages.len() as u32);
    let sk = SecretKey::new(rng);
    let mac = MAC::new(rng, &messages, &sk, &params).unwrap();
    (params, sk, mac)
}
