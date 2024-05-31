//! Schnorr protocol for proving knowledge of discrete logs, i.e. given prover and verifier both know (`A1`, `Y1`)
//! and prover additionally knows `B1`, prove that `e(A1, B1) = Y1`. Similarly, proving `e(A2, B2) = Y2` when only
//! prover knows `A2` but both know (`B2`, `Y2`).
//!
//! To prove knowledge of a single discrete log, i.e. given public `Y1` and `A1`, prove knowledge of `B1` in `e(A1, B1) = Y1`:
//! 1. Prover chooses a random `R1` and computes `T1 = e(A1, R1)`
//! 2. Hashes `T1` towards getting a challenge `c`.
//! 3. Computes response `S1 = R1 + c*B1` and sends it to the verifier.
//! 4. Verifier checks if `e(A1, S1) = T1 + Y1*c`. This works because `e(A1, S1) = e(A1, R1 + c*B1) = e(A1, R1) + e(A1, c*B1) = T1 + c*e(A1, B1) = T1 + c*Y1`.
//!
//! Similar protocol would work for proving knowledge of `A2` in `e(A2, B2) = Y2`.
//!

use crate::error::SchnorrError;
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    CurveGroup,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Write, vec::Vec};
use dock_crypto_utils::{
    pair_g1_g2, pair_g2_g1, randomized_pairing_check::RandomizedPairingChecker,
    serde_utils::ArkObjectBytes,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zeroize::{Zeroize, ZeroizeOnDrop};

macro_rules! impl_protocol {
        (
            $(#[$protocol_doc:meta])*
            $protocol: ident, $proof: ident, $witness_group: path, $other_group: path, $other_group_prepared: path, $pairing: tt) => {

            $(#[$protocol_doc])*
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
                Zeroize,
                ZeroizeOnDrop,
            )]
            pub struct $protocol<E: Pairing> {
                /// Commitment to randomness
                #[zeroize(skip)]
                #[serde_as(as = "ArkObjectBytes")]
                pub t: PairingOutput<E>,
                /// Randomness chosen by the prover
                #[serde_as(as = "ArkObjectBytes")]
                blinding: $witness_group,
                /// Prover's secret
                #[serde_as(as = "ArkObjectBytes")]
                witness: $witness_group,
            }

            #[serde_as]
            #[derive(
                Default, Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
            )]
            pub struct $proof<E: Pairing> {
                #[serde_as(as = "ArkObjectBytes")]
                pub t: PairingOutput<E>,
                #[serde_as(as = "ArkObjectBytes")]
                pub response: $witness_group,
            }

            impl<E: Pairing> $protocol<E> {
                pub fn init(witness: $witness_group, blinding: $witness_group, other: &$other_group) -> Self {
                    let t = $pairing!(E::pairing, other, blinding);
                    Self {
                        t,
                        blinding,
                        witness,
                    }
                }

                pub fn challenge_contribution<W: Write>(
                    &self,
                    other: &$other_group,
                    y: &PairingOutput<E>,
                    writer: W,
                ) -> Result<(), SchnorrError> {
                    Self::compute_challenge_contribution(other, y, &self.t, writer)
                }

                pub fn gen_proof(self, challenge: &E::ScalarField) -> $proof<E> {
                    $proof {
                        t: self.t,
                        response: (self.blinding + self.witness * challenge).into_affine(),
                    }
                }

                pub fn compute_challenge_contribution<W: Write>(
                    other: &$other_group,
                    y: &PairingOutput<E>,
                    t: &PairingOutput<E>,
                    mut writer: W,
                ) -> Result<(), SchnorrError> {
                    other.serialize_compressed(&mut writer)?;
                    y.serialize_compressed(&mut writer)?;
                    t.serialize_compressed(writer).map_err(|e| e.into())
                }
            }

            impl<E: Pairing> $proof<E> {
                pub fn verify(
                    &self,
                    y: &PairingOutput<E>,
                    other: impl Into<$other_group_prepared>,
                    challenge: &E::ScalarField,
                ) -> bool {
                    $pairing!(E::pairing, other, self.response) == (self.t + *y * challenge)
                }

                pub fn challenge_contribution<W: Write>(
                    &self,
                    other: &$other_group,
                    y: &PairingOutput<E>,
                    writer: W,
                ) -> Result<(), SchnorrError> {
                    $protocol::compute_challenge_contribution(other, y, &self.t, writer)
                }
            }
        }
}

impl_protocol!(
    /// Protocol for proving knowledge of discrete log in group G1, i.e. given public `Y` and `B`, prove knowledge of `A` in `e(A, B) = Y`
    PokG1DiscreteLogInPairingProtocol, PokG1DiscreteLogInPairing, E::G1Affine, E::G2Affine, E::G2Prepared, pair_g2_g1
);

impl<E: Pairing> PokG1DiscreteLogInPairing<E> {
    pub fn verify_with_randomized_pairing_checker(
        &self,
        y: &PairingOutput<E>,
        other: impl Into<E::G2Prepared>,
        challenge: &E::ScalarField,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) {
        pairing_checker.add_sources_and_target(&self.response, other, &(self.t + *y * challenge))
    }
}

impl_protocol!(
    /// Protocol for proving knowledge of discrete log in group G2, i.e. given public `Y` and `A`, prove knowledge of `B` in `e(A, B) = Y`
    PokG2DiscreteLogInPairingProtocol, PokG2DiscreteLogInPairing, E::G2Affine, E::G1Affine, E::G1Prepared, pair_g1_g2
);

impl<E: Pairing> PokG2DiscreteLogInPairing<E> {
    pub fn verify_with_randomized_pairing_checker(
        &self,
        y: &PairingOutput<E>,
        other: &E::G1Affine,
        challenge: &E::ScalarField,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) {
        pairing_checker.add_sources_and_target(other, self.response, &(self.t + *y * challenge))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compute_random_oracle_challenge, test_serialization};
    use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
    use ark_ec::pairing::Pairing;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;

    #[test]
    fn discrete_log_proof_in_pairing_group() {
        let mut rng = StdRng::seed_from_u64(0u64);

        macro_rules! check {
            ($protocol:ident, $proof:ident, $witness_group:ident, $other_group:ident, $other_group_prepared:ident, $pairing: tt) => {
                let base = $other_group::rand(&mut rng);
                let witness = $witness_group::rand(&mut rng);
                let y = $pairing!(Bls12_381::pairing, base, witness);
                let blinding = $witness_group::rand(&mut rng);

                let protocol = $protocol::<Bls12_381>::init(witness, blinding, &base);
                let mut chal_contrib_prover = vec![];
                protocol
                    .challenge_contribution(&base, &y, &mut chal_contrib_prover)
                    .unwrap();
                test_serialization!($protocol<Bls12_381>, protocol);

                let challenge_prover =
                    compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib_prover);
                let proof = protocol.gen_proof(&challenge_prover);

                let mut chal_contrib_verifier = vec![];
                proof
                    .challenge_contribution(&base, &y, &mut chal_contrib_verifier)
                    .unwrap();

                let challenge_verifier =
                    compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib_verifier);
                assert!(proof.verify(&y, &base, &challenge_verifier));
                assert_eq!(chal_contrib_prover, chal_contrib_verifier);
                assert_eq!(challenge_prover, challenge_verifier);

                test_serialization!($proof<Bls12_381>, proof);

                // Check with prepared
                let base_prepared = <Bls12_381 as Pairing>::$other_group_prepared::from(base);
                assert!(proof.verify(&y, base_prepared, &challenge_verifier));

                // Check with randomized pairing checker
                let count = 3;
                let bases = (0..count)
                    .into_iter()
                    .map(|_| $other_group::rand(&mut rng))
                    .collect::<Vec<_>>();
                let witnesses = (0..count)
                    .into_iter()
                    .map(|_| $witness_group::rand(&mut rng))
                    .collect::<Vec<_>>();
                let ys = (0..count)
                    .into_iter()
                    .map(|i| $pairing!(Bls12_381::pairing, bases[i], witnesses[i]))
                    .collect::<Vec<_>>();
                let blindings = (0..count)
                    .into_iter()
                    .map(|_| $witness_group::rand(&mut rng))
                    .collect::<Vec<_>>();

                let challenge = Fr::rand(&mut rng);
                let mut proofs = vec![];
                for i in 0..count {
                    let protocol =
                        $protocol::<Bls12_381>::init(witnesses[i], blindings[i], &bases[i]);
                    let proof = protocol.gen_proof(&challenge);
                    assert!(proof.verify(&ys[i], &bases[i], &challenge));
                    proofs.push(proof);
                }

                for lazy in [true, false] {
                    let mut checker =
                        RandomizedPairingChecker::<Bls12_381>::new_using_rng(&mut rng, lazy);
                    for i in 0..count {
                        proofs[i].verify_with_randomized_pairing_checker(
                            &ys[i],
                            &bases[i],
                            &challenge,
                            &mut checker,
                        );
                    }
                    assert!(checker.verify());
                }
            };
        }

        check!(
            PokG1DiscreteLogInPairingProtocol,
            PokG1DiscreteLogInPairing,
            G1Affine,
            G2Affine,
            G2Prepared,
            pair_g2_g1
        );
        check!(
            PokG2DiscreteLogInPairingProtocol,
            PokG2DiscreteLogInPairing,
            G2Affine,
            G1Affine,
            G1Prepared,
            pair_g1_g2
        );
    }
}
