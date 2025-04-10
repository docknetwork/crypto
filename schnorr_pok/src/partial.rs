use crate::{
    discrete_log::{PokDiscreteLogProtocol, PokPedersenCommitmentProtocol},
    error::SchnorrError,
    SchnorrCommitment,
};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    iter,
    ops::{Add, Neg},
    vec,
    vec::Vec,
};
use dock_crypto_utils::{
    expect_equality, randomized_mult_checker::RandomizedMultChecker, serde_utils::ArkObjectBytes,
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Same};

/// Response during step 3 of the Schnorr protocol to prove knowledge of 1 or more discrete logs.
/// This is called partial because it does not contain the responses for all the witnesses. This is
/// used when more than one Schnorr protocol is used and some witnesses are to be proved equal among them.
/// Also useful in case of a single Schnorr protocol if some witnesses are to be proved equal.
/// Eg. when proving knowledge of witnesses `m1`, `m2`, `m3`, `m4` in `C = G1 * m1 + G2 * m2 + G3 * m3 + G4 * m4`,
/// if `m1` and `m3` are also witnesses of another Schnorr protocol then this will contain only the responses
/// for `m2` and `m4`. During verification, the responses for `m1` and `m3` will be given to it.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct PartialSchnorrResponse<G: AffineRepr> {
    /// Key of the map is the witness index and value is the response for that witnesses.
    #[serde_as(as = "BTreeMap<Same, ArkObjectBytes>")]
    pub responses: BTreeMap<usize, G::ScalarField>,
    pub total_responses: usize,
}

/// Proof of knowledge of discrete log but does not contain the response as the response comes from another protocol
/// running with it which has the same witness (discrete log)
#[serde_as]
#[derive(
    Default,
    Clone,
    PartialEq,
    Eq,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct PartialPokDiscreteLog<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub t: G,
}

/// Proof of knowledge of 2 discrete logs but contains the response of only 1, i.e. when proving knowledge of witnesses
/// `a` and `b` in `C = G * a + H * b`, contains the response only for witness `a`. This is because response for `b` will
/// come from another Schnorr protocol which also has `b` as one of the witnesses
#[serde_as]
#[derive(
    Default,
    Clone,
    PartialEq,
    Eq,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct Partial1PokPedersenCommitment<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub t: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub response1: G::ScalarField,
}

/// Proof of knowledge of 2 discrete logs but contains the response of only 1, i.e. when proving knowledge of witnesses
/// `a` and `b` in `C = G * a + H * b`, contains the response only for witness `b`. This is because response for `a` will
/// come from another Schnorr protocol which also has `a` as one of the witnesses
#[serde_as]
#[derive(
    Default,
    Clone,
    PartialEq,
    Eq,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct Partial2PokPedersenCommitment<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub t: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub response2: G::ScalarField,
}

/// Proof of knowledge of 2 discrete logs but contains the response for neither, i.e. when proving knowledge of witnesses
/// `a` and `b` in `C = G * a + H * b`, contains no response. This is because response for `a` and `b` will come from
/// another Schnorr protocol which also has `a` and `b` as their witnesses
#[serde_as]
#[derive(
    Default,
    Clone,
    PartialEq,
    Eq,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct PartialPokPedersenCommitment<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub t: G,
}

impl<G: AffineRepr> SchnorrCommitment<G> {
    /// The key of the map is the index for which response has to be generated.
    pub fn partial_response(
        &self,
        witnesses: BTreeMap<usize, G::ScalarField>,
        challenge: &G::ScalarField,
    ) -> Result<PartialSchnorrResponse<G>, SchnorrError> {
        let mut responses = BTreeMap::new();
        for (i, w) in witnesses {
            let b = self
                .blindings
                .get(i)
                .ok_or_else(|| SchnorrError::MissingBlindingAtIndex(i))?;
            responses.insert(i, w * challenge + b);
        }
        Ok(PartialSchnorrResponse {
            responses,
            total_responses: self.blindings.len(),
        })
    }
}

impl<G: AffineRepr> PokDiscreteLogProtocol<G> {
    pub fn gen_partial_proof(self) -> PartialPokDiscreteLog<G> {
        PartialPokDiscreteLog { t: self.t }
    }
}

impl<G: AffineRepr> PokPedersenCommitmentProtocol<G> {
    /// Generate proof when no response has to be generated.
    pub fn gen_partial_proof(self) -> PartialPokPedersenCommitment<G> {
        PartialPokPedersenCommitment { t: self.t }
    }

    /// Generate proof when only response for witness1 has to be generated.
    pub fn gen_partial1_proof(
        self,
        challenge: &G::ScalarField,
    ) -> Partial1PokPedersenCommitment<G> {
        Partial1PokPedersenCommitment {
            t: self.t,
            response1: self.blinding1 + (self.witness1 * *challenge),
        }
    }

    /// Generate proof when only response for witness2 has to be generated.
    pub fn gen_partial2_proof(
        self,
        challenge: &G::ScalarField,
    ) -> Partial2PokPedersenCommitment<G> {
        Partial2PokPedersenCommitment {
            t: self.t,
            response2: self.blinding2 + (self.witness2 * *challenge),
        }
    }
}

impl<G: AffineRepr> PartialSchnorrResponse<G> {
    /// Keys of `missing_responses` are the witness indices whose response was generated while creating this. Instead,
    /// these come from some other Schnorr protocol.
    pub fn is_valid(
        &self,
        bases: &[G],
        y: &G,
        t: &G,
        challenge: &G::ScalarField,
        missing_responses: BTreeMap<usize, G::ScalarField>,
    ) -> Result<(), SchnorrError> {
        let full_resp = self.pre_verify(bases, missing_responses)?;
        if (G::Group::msm_unchecked(bases, &full_resp)
            .add(y.mul_bigint((-*challenge).into_bigint())))
        .into_affine()
            == *t
        {
            Ok(())
        } else {
            Err(SchnorrError::InvalidResponse)
        }
    }

    /// Same as `Self::is_valid` except it uses `RandomizedMultChecker` to combine the scalar multiplication checks into a single
    pub fn verify_using_randomized_mult_checker(
        &self,
        bases: Vec<G>,
        y: G,
        t: G,
        challenge: &G::ScalarField,
        missing_responses: BTreeMap<usize, G::ScalarField>,
        rmc: &mut RandomizedMultChecker<G>,
    ) -> Result<(), SchnorrError> {
        let full_resp = self.pre_verify(&bases, missing_responses)?;
        rmc.add_many(
            bases.into_iter().chain(iter::once(y)),
            full_resp.iter().chain(iter::once(&-*challenge)),
            t,
        );
        Ok(())
    }

    /// Get indices for which it does not have any response. These responses will be fetched from other protocols.
    pub fn get_missing_response_indices(&self) -> BTreeSet<usize> {
        let mut ids = BTreeSet::new();
        for i in 0..self.total_responses {
            if !self.responses.contains_key(&i) {
                ids.insert(i);
            }
        }
        ids
    }

    /// Get response for the specified discrete log
    pub fn get_response(&self, idx: usize) -> Result<&G::ScalarField, SchnorrError> {
        match self.responses.get(&idx) {
            Some(r) => Ok(r),
            None => Err(SchnorrError::MissingResponseAtIndex(idx)),
        }
    }

    pub fn pre_verify(
        &self,
        bases: &[G],
        missing_responses: BTreeMap<usize, G::ScalarField>,
    ) -> Result<Vec<G::ScalarField>, SchnorrError> {
        expect_equality!(
            self.total_responses,
            bases.len(),
            SchnorrError::ExpectedSameSizeSequences
        );
        expect_equality!(
            self.responses.len() + missing_responses.len(),
            bases.len(),
            SchnorrError::ExpectedSameSizeSequences
        );
        let mut full_resp =
            vec![G::ScalarField::zero(); self.responses.len() + missing_responses.len()];
        for (i, r) in missing_responses {
            // Will ensurer that `self.responses` and `missing_responses` are disjoint
            if self.responses.contains_key(&i) {
                return Err(SchnorrError::FoundCommonIndexInOwnAndReceivedResponses(i));
            }
            full_resp[i] = r;
        }
        for (i, r) in &self.responses {
            full_resp[*i] = *r;
        }
        Ok(full_resp)
    }
}

impl<G: AffineRepr> PartialPokDiscreteLog<G> {
    pub fn verify(
        &self,
        y: &G,
        base: &G,
        challenge: &G::ScalarField,
        response: &G::ScalarField,
    ) -> bool {
        let mut expected = base.mul_bigint(response.into_bigint());
        expected -= y.mul_bigint(challenge.into_bigint());
        expected.into_affine() == self.t
    }

    pub fn verify_using_randomized_mult_checker(
        &self,
        y: G,
        base: G,
        challenge: &G::ScalarField,
        response: &G::ScalarField,
        rmc: &mut RandomizedMultChecker<G>,
    ) {
        rmc.add_2(base, response, y, &challenge.neg(), self.t)
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        base: &G,
        y: &G,
        writer: W,
    ) -> Result<(), SchnorrError> {
        PokDiscreteLogProtocol::compute_challenge_contribution(base, y, &self.t, writer)
    }
}

impl<G: AffineRepr> PartialPokPedersenCommitment<G> {
    pub fn verify(
        &self,
        y: &G,
        base1: &G,
        base2: &G,
        challenge: &G::ScalarField,
        response1: &G::ScalarField,
        response2: &G::ScalarField,
    ) -> bool {
        let mut expected = base1.mul_bigint(response1.into_bigint());
        expected += base2.mul_bigint(response2.into_bigint());
        expected -= y.mul_bigint(challenge.into_bigint());
        expected.into_affine() == self.t
    }

    pub fn verify_using_randomized_mult_checker(
        &self,
        y: G,
        base1: G,
        base2: G,
        challenge: &G::ScalarField,
        response1: &G::ScalarField,
        response2: &G::ScalarField,
        rmc: &mut RandomizedMultChecker<G>,
    ) {
        rmc.add_3(
            base1,
            response1,
            base2,
            response2,
            y,
            &challenge.neg(),
            self.t,
        )
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        base1: &G,
        base2: &G,
        y: &G,
        writer: W,
    ) -> Result<(), SchnorrError> {
        PokPedersenCommitmentProtocol::compute_challenge_contribution(
            base1, base2, y, &self.t, writer,
        )
    }
}

impl<G: AffineRepr> Partial1PokPedersenCommitment<G> {
    pub fn verify(
        &self,
        y: &G,
        base1: &G,
        base2: &G,
        challenge: &G::ScalarField,
        response2: &G::ScalarField,
    ) -> bool {
        let mut expected = base1.mul_bigint(self.response1.into_bigint());
        expected += base2.mul_bigint(response2.into_bigint());
        expected -= y.mul_bigint(challenge.into_bigint());
        expected.into_affine() == self.t
    }

    /// Same as `Self::verify` except it uses `RandomizedMultChecker` to combine the scalar multiplication checks into a single
    pub fn verify_using_randomized_mult_checker(
        &self,
        y: G,
        base1: G,
        base2: G,
        challenge: &G::ScalarField,
        response2: &G::ScalarField,
        rmc: &mut RandomizedMultChecker<G>,
    ) {
        rmc.add_3(
            base1,
            &self.response1,
            base2,
            response2,
            y,
            &challenge.neg(),
            self.t,
        )
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        base1: &G,
        base2: &G,
        y: &G,
        writer: W,
    ) -> Result<(), SchnorrError> {
        PokPedersenCommitmentProtocol::compute_challenge_contribution(
            base1, base2, y, &self.t, writer,
        )
    }
}

impl<G: AffineRepr> Partial2PokPedersenCommitment<G> {
    pub fn verify(
        &self,
        y: &G,
        base1: &G,
        base2: &G,
        challenge: &G::ScalarField,
        response1: &G::ScalarField,
    ) -> bool {
        let mut expected = base1.mul_bigint(response1.into_bigint());
        expected += base2.mul_bigint(self.response2.into_bigint());
        expected -= y.mul_bigint(challenge.into_bigint());
        expected.into_affine() == self.t
    }

    /// Same as `Self::verify` except it uses `RandomizedMultChecker` to combine the scalar multiplication checks into a single
    pub fn verify_using_randomized_mult_checker(
        &self,
        y: G,
        base1: G,
        base2: G,
        challenge: &G::ScalarField,
        response1: &G::ScalarField,
        rmc: &mut RandomizedMultChecker<G>,
    ) {
        rmc.add_3(
            base1,
            response1,
            base2,
            &self.response2,
            y,
            &challenge.neg(),
            self.t,
        )
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        base1: &G,
        base2: &G,
        y: &G,
        writer: W,
    ) -> Result<(), SchnorrError> {
        PokPedersenCommitmentProtocol::compute_challenge_contribution(
            base1, base2, y, &self.t, writer,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pok_generalized_pedersen::compute_random_oracle_challenge;
    use ark_bls12_381::{Fr, G1Affine, G1Projective};
    use ark_ec::VariableBaseMSM;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;

    #[test]
    fn discrete_log_partial() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let count = 10;
        let bases_1 = (0..count)
            .into_iter()
            .map(|_| G1Affine::rand(&mut rng))
            .collect::<Vec<_>>();
        let bases_2 = (0..count)
            .into_iter()
            .map(|_| G1Affine::rand(&mut rng))
            .collect::<Vec<_>>();
        let witnesses_1 = (0..count)
            .into_iter()
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let common_wit_indices = BTreeSet::from([0, 3, 4, 5, 8]);
        let mut witnesses_2 = (0..count)
            .into_iter()
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        for i in &common_wit_indices {
            witnesses_2[*i] = witnesses_1[*i].clone();
        }
        let y_1 = G1Projective::msm_unchecked(&bases_1, &witnesses_1).into_affine();
        let y_2 = G1Projective::msm_unchecked(&bases_2, &witnesses_2).into_affine();

        let blindings_1 = (0..count)
            .into_iter()
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let mut blindings_2 = (0..count)
            .into_iter()
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        for i in &common_wit_indices {
            blindings_2[*i] = blindings_1[*i].clone();
        }

        let comm_1 = SchnorrCommitment::new(&bases_1, blindings_1);
        let comm_2 = SchnorrCommitment::new(&bases_2, blindings_2);

        let challenge = Fr::rand(&mut rng);

        let resp_1 = comm_1.response(&witnesses_1, &challenge).unwrap();
        resp_1
            .is_valid(&bases_1, &y_1, &comm_1.t, &challenge)
            .unwrap();

        let mut diff_wits = BTreeMap::new();
        for i in 0..count {
            if !common_wit_indices.contains(&i) {
                diff_wits.insert(i, witnesses_2[i]);
            }
        }
        let resp_2 = comm_2.partial_response(diff_wits, &challenge).unwrap();
        assert_eq!(resp_2.get_missing_response_indices(), common_wit_indices);
        let missing_responses = resp_1.get_responses(&common_wit_indices).unwrap();
        resp_2
            .is_valid(
                &bases_2,
                &y_2,
                &comm_2.t,
                &challenge,
                missing_responses.clone(),
            )
            .unwrap();

        for i in common_wit_indices {
            assert!(resp_2.get_response(i).is_err());
        }

        // Verify using RandomizedMultChecker
        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        resp_1
            .verify_using_randomized_mult_checker(bases_1, y_1, comm_1.t, &challenge, &mut checker)
            .unwrap();
        resp_2
            .verify_using_randomized_mult_checker(
                bases_2,
                y_2,
                comm_2.t,
                &challenge,
                missing_responses,
                &mut checker,
            )
            .unwrap();
        assert!(checker.verify());
    }

    #[test]
    fn ped_comm_partial() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let base1 = G1Affine::rand(&mut rng);
        let base2 = G1Affine::rand(&mut rng);
        let base3 = G1Affine::rand(&mut rng);
        let base4 = G1Affine::rand(&mut rng);
        let base5 = G1Affine::rand(&mut rng);
        let base6 = G1Affine::rand(&mut rng);
        let base7 = G1Affine::rand(&mut rng);
        let base8 = G1Affine::rand(&mut rng);
        let witness1 = Fr::rand(&mut rng);
        let witness2 = Fr::rand(&mut rng);
        let witness3 = Fr::rand(&mut rng);
        let witness4 = Fr::rand(&mut rng);

        let y_1 = (base1 * witness1).into_affine();
        let y_2 = (base2 * witness1).into_affine();

        let blinding1 = Fr::rand(&mut rng);
        let protocol_1 = PokDiscreteLogProtocol::init(witness1, blinding1, &base1);
        let protocol_2 = PokDiscreteLogProtocol::init(witness1, blinding1, &base2);

        let mut chal_contrib_prover = vec![];
        protocol_1
            .challenge_contribution(&base1, &y_1, &mut chal_contrib_prover)
            .unwrap();
        protocol_2
            .challenge_contribution(&base2, &y_2, &mut chal_contrib_prover)
            .unwrap();
        let challenge_prover =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib_prover);
        let proof_1 = protocol_1.gen_proof(&challenge_prover);
        let proof_2 = protocol_2.gen_partial_proof();

        let mut chal_contrib_verifier = vec![];
        proof_1
            .challenge_contribution(&base1, &y_1, &mut chal_contrib_verifier)
            .unwrap();
        proof_2
            .challenge_contribution(&base2, &y_2, &mut chal_contrib_verifier)
            .unwrap();
        let challenge_verifier =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib_verifier);

        assert_eq!(chal_contrib_prover, chal_contrib_verifier);
        assert_eq!(challenge_prover, challenge_verifier);

        assert!(proof_1.verify(&y_1, &base1, &challenge_verifier));
        assert!(proof_2.verify(&y_2, &base2, &challenge_verifier, &proof_1.response));

        let y_1 = (base1 * witness1 + base2 * witness2).into_affine();
        let y_2 = (base3 * witness1 + base4 * witness2).into_affine();
        let y_3 = (base5 * witness1 + base6 * witness3).into_affine();
        let y_4 = (base7 * witness4 + base8 * witness2).into_affine();

        let blinding2 = Fr::rand(&mut rng);
        let blinding3 = Fr::rand(&mut rng);
        let blinding4 = Fr::rand(&mut rng);

        let protocol_1 = PokPedersenCommitmentProtocol::init(
            witness1, blinding1, &base1, witness2, blinding2, &base2,
        );
        let protocol_2 = PokPedersenCommitmentProtocol::init(
            witness1, blinding1, &base3, witness2, blinding2, &base4,
        );
        let protocol_3 = PokPedersenCommitmentProtocol::init(
            witness1, blinding1, &base5, witness3, blinding3, &base6,
        );
        let protocol_4 = PokPedersenCommitmentProtocol::init(
            witness4, blinding4, &base7, witness2, blinding2, &base8,
        );

        let mut chal_contrib_prover = vec![];
        protocol_1
            .challenge_contribution(&base1, &base2, &y_1, &mut chal_contrib_prover)
            .unwrap();
        protocol_2
            .challenge_contribution(&base3, &base4, &y_2, &mut chal_contrib_prover)
            .unwrap();
        protocol_3
            .challenge_contribution(&base5, &base6, &y_3, &mut chal_contrib_prover)
            .unwrap();
        protocol_4
            .challenge_contribution(&base7, &base8, &y_4, &mut chal_contrib_prover)
            .unwrap();
        let challenge_prover =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib_prover);

        let proof_1 = protocol_1.gen_proof(&challenge_prover);
        let proof_2 = protocol_2.gen_partial_proof();
        let proof_3 = protocol_3.gen_partial2_proof(&challenge_prover);
        let proof_4 = protocol_4.gen_partial1_proof(&challenge_prover);

        let mut chal_contrib_verifier = vec![];
        proof_1
            .challenge_contribution(&base1, &base2, &y_1, &mut chal_contrib_verifier)
            .unwrap();
        proof_2
            .challenge_contribution(&base3, &base4, &y_2, &mut chal_contrib_verifier)
            .unwrap();
        proof_3
            .challenge_contribution(&base5, &base6, &y_3, &mut chal_contrib_verifier)
            .unwrap();
        proof_4
            .challenge_contribution(&base7, &base8, &y_4, &mut chal_contrib_verifier)
            .unwrap();

        let challenge_verifier =
            compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib_verifier);

        assert_eq!(chal_contrib_prover, chal_contrib_verifier);
        assert_eq!(challenge_prover, challenge_verifier);
        assert!(proof_1.verify(&y_1, &base1, &base2, &challenge_verifier));
        assert!(proof_2.verify(
            &y_2,
            &base3,
            &base4,
            &challenge_verifier,
            &proof_1.response1,
            &proof_1.response2
        ));
        assert!(proof_3.verify(
            &y_3,
            &base5,
            &base6,
            &challenge_verifier,
            &proof_1.response1
        ));
        assert!(proof_4.verify(
            &y_4,
            &base7,
            &base8,
            &challenge_verifier,
            &proof_1.response2
        ));

        // Verify using RandomizedMultChecker
        let mut checker = RandomizedMultChecker::new_using_rng(&mut rng);
        proof_1.verify_using_randomized_mult_checker(
            y_1,
            base1,
            base2,
            &challenge_verifier,
            &mut checker,
        );
        proof_2.verify_using_randomized_mult_checker(
            y_2,
            base3,
            base4,
            &challenge_verifier,
            &proof_1.response1,
            &proof_1.response2,
            &mut checker,
        );
        proof_3.verify_using_randomized_mult_checker(
            y_3,
            base5,
            base6,
            &challenge_verifier,
            &proof_1.response1,
            &mut checker,
        );
        proof_4.verify_using_randomized_mult_checker(
            y_4,
            base7,
            base8,
            &challenge_verifier,
            &proof_1.response2,
            &mut checker,
        );
        assert!(checker.verify());
    }
}
