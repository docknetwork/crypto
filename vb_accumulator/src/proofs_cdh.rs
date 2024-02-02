//! Alternate implementation of zero knowledge proof protocols for membership and non-membership witnesses. The protocol for proving
//! membership is the protocol for proof of knowledge of weak-BB signature proposed by Camenisch et. al where the prover does not do pairings.
//! The protocol for proving non-membership is an extension of this protocol as:
//! Non membership witness is `(C, d)`, accumulator value is `V`, non-member is `y`, secret key is `alpha` and public generators `P`
//! and `P_tilde` satisfying the relation `C*(y + alpha) + P*d = V`.Both prover and verifier have access to a public generator `Q` such that
//! discrete log of `Q` wrt `P` is not known.
//! 1. Prover picks a random `r` from Z_p.
//! 2. Prover randomizes the witness as `(C' = C * r, d' = d * r)`
//! 3. Prover creates `C_bar = V * r - C * y * r - P * d * r = V * r - C' * y - P * d'` and `J = Q * d * r = Q * d'` and
//! sends both to the verifier
//! 4. Prover creates proof for knowledge of `r`, `y`, `d'` in the relations `C_bar = V * r - C' * y - P * d'` and `J = Q * d'`.
//! 5. Verifier checks proofs from point 4 and that `C'` and `J` are not 0 (ensuring D is not 0).
//! 6. Verifier checks `e(C_bar, P_tilde) = e(C', pk)`

use crate::{
    error::VBAccumulatorError,
    prelude::{MembershipWitness, NonMembershipWitness, PreparedPublicKey, PreparedSetupParams},
    setup::SetupParams,
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, ops::Neg, rand::RngCore, vec, vec::Vec, UniformRand};
use core::mem;
use dock_crypto_utils::{
    randomized_pairing_check::RandomizedPairingChecker, serde_utils::ArkObjectBytes,
};
use schnorr_pok::{
    discrete_log::{PokDiscreteLog, PokDiscreteLogProtocol},
    SchnorrCommitment, SchnorrResponse,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use short_group_sig::weak_bb_sig_pok_cdh::{PoKOfSignatureG1, PoKOfSignatureG1Protocol};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A wrapper over the protocol for proof of knowledge of weak-BB signature. The accumulator witness is the weak-BB signature and the
/// accumulator value becomes g1 in that protocol
#[derive(Default, Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct MembershipProofProtocol<E: Pairing>(pub PoKOfSignatureG1Protocol<E>);

/// A wrapper over the proof of knowledge of weak-BB signature
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct MembershipProof<E: Pairing>(pub PoKOfSignatureG1<E>);

/// An extension over the protocol for proof of knowledge of weak-BB signature.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct NonMembershipProofProtocol<E: Pairing> {
    /// The randomized witness `C'`
    #[zeroize(skip)]
    pub C_prime: E::G1Affine,
    /// `V * r - C' * y - P * d'`
    #[zeroize(skip)]
    pub C_bar: E::G1Affine,
    /// The commitment to the randomized witness `Q * d'`
    #[zeroize(skip)]
    pub J: E::G1Affine,
    /// For relation `C_bar = V * r - C' * y - P * d'`
    pub sc_comm_1: SchnorrCommitment<E::G1Affine>,
    /// (r, y, d')
    sc_wits_1: (E::ScalarField, E::ScalarField, E::ScalarField),
    /// For relation `J = Q * d'`
    pub sc_comm_2: PokDiscreteLogProtocol<E::G1Affine>,
}

#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct NonMembershipProof<E: Pairing> {
    /// The randomized witness `C'`
    #[serde_as(as = "ArkObjectBytes")]
    pub C_prime: E::G1Affine,
    /// `V * r - C' * y - P * d'`
    #[serde_as(as = "ArkObjectBytes")]
    pub C_bar: E::G1Affine,
    /// The commitment to the randomized witness `Q * d'`
    #[serde_as(as = "ArkObjectBytes")]
    pub J: E::G1Affine,
    /// For relation `C_bar = V * r - C' * y - P * d'`
    #[serde_as(as = "ArkObjectBytes")]
    pub t_1: E::G1Affine,
    pub sc_resp_1: SchnorrResponse<E::G1Affine>,
    /// For relation `J = Q * d'`
    pub sc_2: PokDiscreteLog<E::G1Affine>,
}

impl<E: Pairing> MembershipProofProtocol<E> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        element: E::ScalarField,
        element_blinding: Option<E::ScalarField>,
        accumulator_value: &E::G1Affine,
        witness: &MembershipWitness<E::G1Affine>,
    ) -> Self {
        Self(PoKOfSignatureG1Protocol::init(
            rng,
            witness,
            element,
            element_blinding,
            accumulator_value,
        ))
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        accumulator_value: &E::G1Affine,
        writer: W,
    ) -> Result<(), VBAccumulatorError> {
        self.0.challenge_contribution(accumulator_value, writer)?;
        Ok(())
    }

    pub fn gen_proof(
        self,
        challenge: &E::ScalarField,
    ) -> Result<MembershipProof<E>, VBAccumulatorError> {
        let proof = self.0.clone().gen_proof(challenge);
        Ok(MembershipProof(proof))
    }
}

impl<E: Pairing> MembershipProof<E> {
    pub fn verify(
        &self,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
    ) -> Result<(), VBAccumulatorError> {
        let params = params.into();
        self.0
            .verify(challenge, pk.into().0, accumulator_value, params.P_tilde)?;
        Ok(())
    }

    pub fn verify_with_randomized_pairing_checker(
        &self,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<(), VBAccumulatorError> {
        let params = params.into();
        self.0.verify_with_randomized_pairing_checker(
            challenge,
            pk.into().0,
            accumulator_value,
            params.P_tilde,
            pairing_checker,
        )?;
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        accumulator_value: &E::G1Affine,
        writer: W,
    ) -> Result<(), VBAccumulatorError> {
        self.0.challenge_contribution(accumulator_value, writer)?;
        Ok(())
    }

    pub fn get_schnorr_response_for_element(&self) -> &E::ScalarField {
        self.0.get_resp_for_message()
    }
}

impl<E: Pairing> NonMembershipProofProtocol<E> {
    pub fn init<R: RngCore>(
        rng: &mut R,
        element: E::ScalarField,
        element_blinding: Option<E::ScalarField>,
        accumulator_value: E::G1Affine,
        witness: &NonMembershipWitness<E::G1Affine>,
        params: &SetupParams<E>,
        Q: impl Into<E::G1Affine>,
    ) -> Self {
        let r = E::ScalarField::rand(rng);
        let element_blinding = element_blinding.unwrap_or_else(|| E::ScalarField::rand(rng));
        let Q = Q.into();
        let d_prime = witness.d * r;
        let C_prime = witness.C * r;
        let C_prime_neg = C_prime.neg();
        let g1_neg = params.P.into_group().neg();
        // C_bar = accumulator_value * r - C' * element - g1 * d * r
        let C_bar =
            (accumulator_value * r + C_prime_neg * element + g1_neg * d_prime).into_affine();
        let d_prime_blinding = E::ScalarField::rand(rng);
        // J = Q * d * r
        let J = (Q * d_prime).into_affine();
        let sc_comm_1 = SchnorrCommitment::new(
            &[accumulator_value, C_prime_neg.into(), g1_neg.into()],
            vec![
                E::ScalarField::rand(rng),
                element_blinding,
                d_prime_blinding,
            ],
        );
        let sc_wits_1 = (r, element, d_prime);
        let sc_comm_2 = PokDiscreteLogProtocol::init(d_prime, d_prime_blinding, &Q);

        Self {
            C_prime: C_prime.into(),
            C_bar,
            J,
            sc_comm_1,
            sc_comm_2,
            sc_wits_1,
        }
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        accumulator_value: &E::G1Affine,
        params: &SetupParams<E>,
        Q: &E::G1Affine,
        writer: W,
    ) -> Result<(), VBAccumulatorError> {
        Self::compute_challenge_contribution(
            &self.C_prime,
            &self.C_bar,
            &self.J,
            accumulator_value,
            params,
            Q,
            &self.sc_comm_1.t,
            &self.sc_comm_2.t,
            writer,
        )
    }

    pub fn gen_proof(
        mut self,
        challenge: &E::ScalarField,
    ) -> Result<NonMembershipProof<E>, VBAccumulatorError> {
        Ok(NonMembershipProof {
            C_prime: self.C_prime,
            C_bar: self.C_bar,
            J: self.J,
            t_1: self.sc_comm_1.t,
            sc_resp_1: self.sc_comm_1.response(
                &[self.sc_wits_1.0, self.sc_wits_1.1, self.sc_wits_1.2],
                challenge,
            )?,
            sc_2: mem::take(&mut self.sc_comm_2).gen_proof(challenge),
        })
    }

    pub fn compute_challenge_contribution<W: Write>(
        C_prime: &E::G1Affine,
        C_bar: &E::G1Affine,
        J: &E::G1Affine,
        accumulator_value: &E::G1Affine,
        params: &SetupParams<E>,
        Q: &E::G1Affine,
        t_1: &E::G1Affine,
        t_2: &E::G1Affine,
        mut writer: W,
    ) -> Result<(), VBAccumulatorError> {
        C_bar.serialize_compressed(&mut writer)?;
        C_prime.serialize_compressed(&mut writer)?;
        J.serialize_compressed(&mut writer)?;
        accumulator_value.serialize_compressed(&mut writer)?;
        params.P.serialize_compressed(&mut writer)?;
        Q.serialize_compressed(&mut writer)?;
        t_1.serialize_compressed(&mut writer)?;
        t_2.serialize_compressed(&mut writer)?;
        Ok(())
    }
}

impl<E: Pairing> NonMembershipProof<E> {
    pub fn verify(
        &self,
        accumulator_value: E::G1Affine,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        Q: impl Into<E::G1Affine>,
    ) -> Result<(), VBAccumulatorError> {
        let params = params.into();
        self.verify_except_pairing(accumulator_value, challenge, &params, Q)?;
        if !E::multi_pairing(
            [
                E::G1Prepared::from(self.C_bar),
                E::G1Prepared::from(-(self.C_prime.into_group())),
            ],
            [params.P_tilde, pk.into().0],
        )
        .is_zero()
        {
            return Err(VBAccumulatorError::IncorrectRandomizedWitness);
        }
        Ok(())
    }

    pub fn verify_with_randomized_pairing_checker(
        &self,
        accumulator_value: E::G1Affine,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        Q: impl Into<E::G1Affine>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<(), VBAccumulatorError> {
        let params = params.into();
        self.verify_except_pairing(accumulator_value, challenge, &params, Q)?;
        pairing_checker.add_sources(&self.C_prime, pk.into().0, &self.C_bar, params.P_tilde);
        Ok(())
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        accumulator_value: &E::G1Affine,
        params: &SetupParams<E>,
        Q: &E::G1Affine,
        writer: W,
    ) -> Result<(), VBAccumulatorError> {
        NonMembershipProofProtocol::<E>::compute_challenge_contribution(
            &self.C_prime,
            &self.C_bar,
            &self.J,
            accumulator_value,
            params,
            Q,
            &self.t_1,
            &self.sc_2.t,
            writer,
        )
    }

    pub fn get_schnorr_response_for_element(&self) -> &E::ScalarField {
        self.sc_resp_1.get_response(1).unwrap()
    }

    fn verify_except_pairing(
        &self,
        accumulator_value: E::G1Affine,
        challenge: &E::ScalarField,
        params: &PreparedSetupParams<E>,
        Q: impl Into<E::G1Affine>,
    ) -> Result<(), VBAccumulatorError> {
        if self.C_prime.is_zero() {
            return Err(VBAccumulatorError::CannotBeZero);
        }
        if self.J.is_zero() {
            return Err(VBAccumulatorError::CannotBeZero);
        }
        self.sc_resp_1.is_valid(
            &[
                accumulator_value,
                self.C_prime.into_group().neg().into(),
                params.P.into_group().neg().into(),
            ],
            &self.C_bar,
            &self.t_1,
            challenge,
        )?;
        if !self.sc_2.verify(&self.J, &Q.into(), challenge) {
            return Err(VBAccumulatorError::IncorrectRandomizedWitness);
        }
        // d'(=d*r) is same in both relations
        if *self.sc_resp_1.get_response(2)? != self.sc_2.response {
            return Err(VBAccumulatorError::IncorrectRandomizedWitness);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::positive::{tests::setup_positive_accum, Accumulator};
    use std::time::{Duration, Instant};

    use crate::universal::tests::setup_universal_accum;
    use ark_bls12_381::{Bls12_381, Fr, G1Affine};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use schnorr_pok::compute_random_oracle_challenge;

    #[test]
    fn membership_proof_positive_accumulator() {
        // Proof of knowledge of membership witness
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, mut accumulator, mut state) = setup_positive_accum(&mut rng);
        let prepared_params = PreparedSetupParams::from(params.clone());
        let prepared_pk = PreparedPublicKey::from(keypair.public_key.clone());

        let mut elems = vec![];
        let mut witnesses = vec![];
        let count = 10;

        for _ in 0..count {
            let elem = Fr::rand(&mut rng);
            accumulator = accumulator
                .add(elem, &keypair.secret_key, &mut state)
                .unwrap();
            elems.push(elem);
        }

        for i in 0..count {
            let w = accumulator
                .get_membership_witness(&elems[i], &keypair.secret_key, &state)
                .unwrap();
            assert!(accumulator.verify_membership(&elems[i], &w, &keypair.public_key, &params));
            witnesses.push(w);
        }

        let mut proof_create_duration = Duration::default();
        let mut proof_verif_duration = Duration::default();

        for i in 0..count {
            let start = Instant::now();
            let protocol = MembershipProofProtocol::init(
                &mut rng,
                elems[i],
                None,
                accumulator.value(),
                &witnesses[i],
            );
            let mut chal_bytes_prover = vec![];
            protocol
                .challenge_contribution(accumulator.value(), &mut chal_bytes_prover)
                .unwrap();
            let challenge_prover =
                compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);
            let proof = protocol.gen_proof(&challenge_prover).unwrap();
            proof_create_duration += start.elapsed();

            let start = Instant::now();
            let mut chal_bytes_verifier = vec![];
            proof
                .challenge_contribution(accumulator.value(), &mut chal_bytes_verifier)
                .unwrap();
            let challenge_verifier =
                compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);
            proof
                .verify(
                    accumulator.value(),
                    &challenge_verifier,
                    prepared_pk.clone(),
                    prepared_params.clone(),
                )
                .unwrap();
            proof_verif_duration += start.elapsed();
        }

        println!(
            "Time to create {} membership proofs is {:?}",
            count, proof_create_duration
        );
        println!(
            "Time to verify {} membership proofs is {:?}",
            count, proof_verif_duration
        );
    }

    #[test]
    fn non_membership_proof_universal_accumulator() {
        // Proof of knowledge of non-membership witness
        let max = 100;
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, mut accumulator, initial_elems, mut state) =
            setup_universal_accum(&mut rng, max);

        let prepared_params = PreparedSetupParams::from(params.clone());
        let prepared_pk = PreparedPublicKey::from(keypair.public_key.clone());

        let Q = G1Affine::rand(&mut rng);

        let mut elems = vec![];
        let mut witnesses = vec![];
        let count = 10;

        for _ in 0..50 {
            accumulator = accumulator
                .add(
                    Fr::rand(&mut rng),
                    &keypair.secret_key,
                    &initial_elems,
                    &mut state,
                )
                .unwrap();
        }

        for _ in 0..count {
            let elem = Fr::rand(&mut rng);
            let w = accumulator
                .get_non_membership_witness(&elem, &keypair.secret_key, &mut state, &params)
                .unwrap();
            assert!(accumulator.verify_non_membership(&elem, &w, &keypair.public_key, &params));
            elems.push(elem);
            witnesses.push(w);
        }

        let mut proof_create_duration = Duration::default();
        let mut proof_verif_duration = Duration::default();

        for i in 0..count {
            let start = Instant::now();
            let protocol = NonMembershipProofProtocol::<Bls12_381>::init(
                &mut rng,
                elems[i],
                None,
                *accumulator.value(),
                &witnesses[i],
                &params,
                Q.clone(),
            );

            let mut chal_bytes_prover = vec![];
            protocol
                .challenge_contribution(accumulator.value(), &params, &Q, &mut chal_bytes_prover)
                .unwrap();
            let challenge_prover =
                compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);
            let proof = protocol.gen_proof(&challenge_prover).unwrap();
            proof_create_duration += start.elapsed();

            let start = Instant::now();
            let mut chal_bytes_verifier = vec![];
            proof
                .challenge_contribution(accumulator.value(), &params, &Q, &mut chal_bytes_verifier)
                .unwrap();
            let challenge_verifier =
                compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);
            proof
                .verify(
                    *accumulator.value(),
                    &challenge_verifier,
                    prepared_pk.clone(),
                    prepared_params.clone(),
                    Q.clone(),
                )
                .unwrap();
            proof_verif_duration += start.elapsed();
        }

        println!(
            "Time to create {} non-membership proofs is {:?}",
            count, proof_create_duration
        );
        println!(
            "Time to verify {} non-membership proofs is {:?}",
            count, proof_verif_duration
        );
    }
}
