#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

//! Zero knowledge proof protocols for membership and non-membership witnesses from section 7 of
//! the paper. The paper only describes the non-membership proof but the membership proof is similar
//! with the relationships involving `d` omitted. See the documentation of relevant objects for more detail.
//!
//! # Examples
//!
//! ```
//! use ark_bls12_381::Bls12_381;
//! use vb_accumulator::setup::{Keypair, SetupParams};
//! use vb_accumulator::positive::{PositiveAccumulator, Accumulator};
//! use vb_accumulator::witness::MembershipWitness;
//! use vb_accumulator::proofs::{MembershipProofProtocol, MembershipProvingKey};
//! use vb_accumulator::persistence::State;
//!
//! let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);
//! let keypair = Keypair::<Bls12_381>::generate(&mut rng, &params);
//! let public_key = &keypair.public_key;
//!
//! let accumulator = PositiveAccumulator::initialize(&params);
//!
//! // Add elements
//!
//! // Create membership witness for existing `elem`
//! let m_wit = accumulator
//!                 .get_membership_witness(&elem, &keypair.secret_key, &state)
//!                 .unwrap();
//!
//! // The prover and verifier should agree on the proving key
//! let prk = MembershipProvingKey::generate_using_rng(&mut rng);
//!
//! // Prover initializes the protocol
//! let protocol = MembershipProofProtocol::init(
//!                 &mut rng,
//!                 &elem,
//!                 None,
//!                 &m_wit,
//!                 &keypair.public_key,
//!                 &params,
//!                 &prk,
//!             );
//!
//! // `challenge_bytes` is the stream where the protocol's challenge contribution will be written
//!
//! protocol
//!                 .challenge_contribution(
//!                     accumulator.value(),
//!                     &keypair.public_key,
//!                     &params,
//!                     &prk,
//!                     &mut challenge_bytes,
//!                 )
//!                 .unwrap();
//!
//! // Generate `challenge` from `challenge_bytes`, see tests for example
//!
//! let proof = protocol.gen_proof(&challenge);
//!
//! // Verifiers should check that the parameters and public key are valid before verifying
//! // any witness. This just needs to be done once when the verifier fetches/receives them.
//!
//! assert!(params.is_valid());
//! assert!(public_key.is_valid());
//!
//! // Verifier should independently generate the `challenge`
//!
//! // `challenge_bytes` is the stream where the proof's challenge contribution will be written
//! proof
//!                 .challenge_contribution(
//!                     accumulator.value(),
//!                     public_key,
//!                     &params,
//!                     &prk,
//!                     &mut chal_bytes_verifier,
//!                 )
//!                 .unwrap();
//!
//! // Generate `challenge` from `challenge_bytes`, see tests for example
//! proof
//!                 .verify(
//!                     &accumulator.value(),
//!                     &challenge,
//!                     public_key,
//!                     &params,
//!                     &prk,
//!                 )
//!                 .unwrap();
//!
//! // Non-membership proof has a similar API, see tests for example.
//! ```

use crate::{
    error::VBAccumulatorError,
    setup::{
        NonMembershipProvingKey, PreparedPublicKey, PreparedSetupParams, PublicKey, SetupParams,
    },
    witness::{MembershipWitness, NonMembershipWitness},
};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    scalar_mul::wnaf::WnafContext,
    AffineRepr, CurveGroup, Group,
};
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt::Debug, io::Write, rand::RngCore, vec::Vec, UniformRand};
use dock_crypto_utils::serde_utils::*;
use schnorr_pok::{error::SchnorrError, SchnorrChallengeContributor};
use zeroize::{Zeroize, ZeroizeOnDrop};

use dock_crypto_utils::{msm::WindowTable, randomized_pairing_check::RandomizedPairingChecker};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use short_group_sig::common::ProvingKey;

/// Common elements of the randomized witness between membership and non-membership witness
#[serde_as]
#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    Zeroize,
    ZeroizeOnDrop,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(bound = "")]
pub struct RandomizedWitness<G: AffineRepr> {
    #[serde_as(as = "ArkObjectBytes")]
    pub E_C: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub T_sigma: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub T_rho: G,
}

/// Common elements of the blindings (Schnorr protocol) between membership and non-membership witness
#[serde_as]
#[derive(
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
#[serde(bound = "")]
pub struct Blindings<F: PrimeField> {
    #[serde_as(as = "ArkObjectBytes")]
    pub sigma: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub rho: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub delta_sigma: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub delta_rho: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub r_y: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub r_sigma: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub r_rho: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub r_delta_sigma: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub r_delta_rho: F,
}

/// Common elements of the commitment (Schnorr protocol, step 1) between membership and non-membership witness
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct SchnorrCommit<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub R_E: PairingOutput<E>,
    #[serde_as(as = "ArkObjectBytes")]
    pub R_sigma: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub R_rho: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub R_delta_sigma: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub R_delta_rho: E::G1Affine,
}

/// Common elements of the response (Schnorr protocol, step 3) between membership and non-membership witness
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct SchnorrResponse<F: PrimeField> {
    #[serde_as(as = "ArkObjectBytes")]
    pub s_y: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub s_sigma: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub s_rho: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub s_delta_sigma: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub s_delta_rho: F,
}

/// Randomized membership witness
#[serde_as]
#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    Zeroize,
    ZeroizeOnDrop,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(bound = "")]
pub struct MembershipRandomizedWitness<G: AffineRepr>(pub RandomizedWitness<G>);

/// Blindings used during membership proof protocol
#[serde_as]
#[derive(
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
#[serde(bound = "")]
pub struct MembershipBlindings<F: PrimeField>(pub Blindings<F>);

/// Commitments from various Schnorr protocols used during membership proof protocol
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct MembershipSchnorrCommit<E: Pairing>(pub SchnorrCommit<E>);

/// Responses from various Schnorr protocols used during membership proof protocol
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct MembershipSchnorrResponse<F: PrimeField>(pub SchnorrResponse<F>);

/// Proof of knowledge of the member and the membership witness
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
#[serde(bound = "")]
pub struct MembershipProof<E: Pairing> {
    pub randomized_witness: MembershipRandomizedWitness<E::G1Affine>,
    pub schnorr_commit: MembershipSchnorrCommit<E>,
    pub schnorr_response: MembershipSchnorrResponse<E::ScalarField>,
}

/// Protocol for proving knowledge of the member and the membership witness
#[serde_as]
#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    Zeroize,
    ZeroizeOnDrop,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct MembershipProofProtocol<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub element: E::ScalarField,
    #[serde(bound = "")]
    pub randomized_witness: MembershipRandomizedWitness<E::G1Affine>,
    #[zeroize(skip)]
    #[serde(bound = "")]
    pub schnorr_commit: MembershipSchnorrCommit<E>,
    #[serde(bound = "")]
    pub schnorr_blindings: MembershipBlindings<E::ScalarField>,
}

/// Randomized non-membership witness
#[serde_as]
#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    Zeroize,
    ZeroizeOnDrop,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct NonMembershipRandomizedWitness<G: AffineRepr> {
    #[serde(
        bound = "RandomizedWitness<G>: Serialize, for<'a> RandomizedWitness<G>: Deserialize<'a>"
    )]
    pub C: RandomizedWitness<G>,
    #[serde_as(as = "ArkObjectBytes")]
    pub E_d: G,
    #[serde_as(as = "ArkObjectBytes")]
    pub E_d_inv: G,
}

/// Blindings used during non-membership proof protocol
#[serde_as]
#[derive(
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
pub struct NonMembershipBlindings<F: PrimeField> {
    #[serde(bound = "Blindings<F>: Serialize, for<'a> Blindings<F>: Deserialize<'a>")]
    pub C: Blindings<F>,
    #[serde_as(as = "ArkObjectBytes")]
    pub tau: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub pi: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub r_u: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub r_v: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub r_w: F,
}

/// Commitments from various Schnorr protocols used during non-membership proof protocol
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct NonMembershipSchnorrCommit<E: Pairing> {
    #[serde(bound = "SchnorrCommit<E>: Serialize, for<'a> SchnorrCommit<E>: Deserialize<'a>")]
    pub C: SchnorrCommit<E>,
    #[serde_as(as = "ArkObjectBytes")]
    pub R_A: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub R_B: E::G1Affine,
}

/// Responses from various Schnorr protocols used during non-membership proof protocol
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct NonMembershipSchnorrResponse<F: PrimeField> {
    #[serde(bound = "SchnorrResponse<F>: Serialize, for<'a> SchnorrResponse<F>: Deserialize<'a>")]
    pub C: SchnorrResponse<F>,
    #[serde_as(as = "ArkObjectBytes")]
    pub s_u: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub s_v: F,
    #[serde_as(as = "ArkObjectBytes")]
    pub s_w: F,
}

/// Proof of knowledge of the non-member and the non-membership witness
#[serde_as]
#[derive(
    Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct NonMembershipProof<E: Pairing> {
    #[serde(
        bound = "NonMembershipRandomizedWitness<E::G1Affine>: Serialize, for<'a> NonMembershipRandomizedWitness<E::G1Affine>: Deserialize<'a>"
    )]
    pub randomized_witness: NonMembershipRandomizedWitness<E::G1Affine>,
    #[serde(
        bound = "NonMembershipSchnorrCommit<E>: Serialize, for<'a> NonMembershipSchnorrCommit<E>: Deserialize<'a>"
    )]
    pub schnorr_commit: NonMembershipSchnorrCommit<E>,
    #[serde(
        bound = "NonMembershipBlindings<E::ScalarField>: Serialize, for<'a> NonMembershipBlindings<E::ScalarField>: Deserialize<'a>"
    )]
    pub schnorr_response: NonMembershipSchnorrResponse<E::ScalarField>,
}

/// Protocol for proving knowledge of the non-member and the non-membership witness
#[serde_as]
#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    Zeroize,
    ZeroizeOnDrop,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct NonMembershipProofProtocol<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub element: E::ScalarField,
    #[serde_as(as = "ArkObjectBytes")]
    pub d: E::ScalarField,
    #[serde(
        bound = "NonMembershipRandomizedWitness<E::G1Affine>: Serialize, for<'a> NonMembershipRandomizedWitness<E::G1Affine>: Deserialize<'a>"
    )]
    pub randomized_witness: NonMembershipRandomizedWitness<E::G1Affine>,
    #[zeroize(skip)]
    #[serde(
        bound = "NonMembershipSchnorrCommit<E>: Serialize, for<'a> NonMembershipSchnorrCommit<E>: Deserialize<'a>"
    )]
    pub schnorr_commit: NonMembershipSchnorrCommit<E>,
    #[serde(
        bound = "NonMembershipBlindings<E::ScalarField>: Serialize, for<'a> NonMembershipBlindings<E::ScalarField>: Deserialize<'a>"
    )]
    pub schnorr_blindings: NonMembershipBlindings<E::ScalarField>,
}

impl<G> SchnorrChallengeContributor for RandomizedWitness<G>
where
    G: AffineRepr,
{
    fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), SchnorrError> {
        self.E_C.serialize_compressed(&mut writer)?;
        self.T_sigma.serialize_compressed(&mut writer)?;
        self.T_rho
            .serialize_compressed(&mut writer)
            .map_err(|e| e.into())
    }
}

impl<E: Pairing> SchnorrChallengeContributor for SchnorrCommit<E> {
    fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), SchnorrError> {
        self.R_E.serialize_compressed(&mut writer)?;
        self.R_sigma.serialize_compressed(&mut writer)?;
        self.R_rho.serialize_compressed(&mut writer)?;
        self.R_delta_sigma.serialize_compressed(&mut writer)?;
        self.R_delta_rho
            .serialize_compressed(&mut writer)
            .map_err(|e| e.into())
    }
}

impl<G> SchnorrChallengeContributor for MembershipRandomizedWitness<G>
where
    G: AffineRepr,
{
    fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), SchnorrError> {
        self.0.challenge_contribution(writer)
    }
}

impl<E: Pairing> SchnorrChallengeContributor for MembershipSchnorrCommit<E> {
    fn challenge_contribution<W: Write>(&self, writer: W) -> Result<(), SchnorrError> {
        self.0.challenge_contribution(writer)
    }
}

impl<G> SchnorrChallengeContributor for NonMembershipRandomizedWitness<G>
where
    G: AffineRepr,
{
    fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), SchnorrError> {
        self.C.challenge_contribution(&mut writer)?;
        self.E_d.serialize_compressed(&mut writer)?;
        self.E_d_inv
            .serialize_compressed(&mut writer)
            .map_err(|e| e.into())
    }
}

impl<E: Pairing> SchnorrChallengeContributor for NonMembershipSchnorrCommit<E> {
    fn challenge_contribution<W: Write>(&self, mut writer: W) -> Result<(), SchnorrError> {
        self.C.challenge_contribution(&mut writer)?;
        self.R_A.serialize_compressed(&mut writer)?;
        self.R_B
            .serialize_compressed(&mut writer)
            .map_err(|e| e.into())
    }
}

impl<F: PrimeField> SchnorrResponse<F> {
    pub fn get_response_for_element(&self) -> &F {
        &self.s_y
    }
}

/// Protocol to prove knowledge of (non)member and corresponding witness in zero knowledge. It commits
/// to the (non)member and the witness, does Schnorr proofs of knowledge of these committed values and
/// satisfies the witness verification (pairing) equation with the committed values.
/// The Schnorr protocol variant used here is different from the one used in the paper as in the
/// paper, the prover commits to randomness (blindings), computes challenge, then responses and sends the
/// commitments to (non)member and witness and the responses to the verifier and the
/// verifier independently computes the commitments to randomness using the responses and hashes them
/// to compare with the challenge for equality.
/// Whereas in the implementation, the prover sends
/// the commitments to both the randomness (blindings) and (non)member and witness, computes the
/// challenge and then the responses and sends all the commitments and the responses to the verifier.
/// The verifier then computes a challenge independently, computes its own commitments to randomness
/// and compares them for equality with the prover's given commitments. Below are the 2 variants of Schnorr:
///     Schnorr protocol for relation: Given `G` and `Y`, prove knowledge of `x` in `x * G = Y`
///
/// Variant used in the paper:
///     1. Prover creates `r` and then `T = r * G`.
///     2. Prover computes challenge as `c = Hash(G||Y||T)`.
///     3. Prover creates response `s = r + c*x` and sends `c` and `s` to the Verifier as proof.
///     4. Verifier creates `T'` as `T' = s * G - c * Y` and computes `c'` as `c' = Hash(G||Y||T')`
///     5. Proof if valid if `c == c'`
///
/// Variant used in the implementation:
///     1. Prover creates `r` and then `T = r * G`.
///     2. Prover computes challenge as `c = Hash(G||Y||T)`.
///     3. Prover creates response `s = r + c*x` and sends `T` and `s` to the Verifier as proof.
///     4. Verifier computes `c'` as `c'` as `c' = Hash(G||Y||T')`.
///     5. Verifier checks if `s * G - c * Y` equals `T`. If they are equal then proof is valid
///
/// The 1st variant makes us for shorter proof when knowledge of multiple witnesses is to be proved.
/// But the 2nd variant was used to integrate with other sub-protocols. Also the 2nd variant allows
/// for better errors as we know exactly which response was invalid.
///
/// The paper describes the no-membership protocol only but the membership protocol can be obtained
/// by omitting `d` and its corresponding relations. Following (from the paper) is the pairing check
/// relation to be satisfied for non-membership proofs
///   `e(E_c, P_tilde)^y * e(Z, P_tilde)^{-delta_sigma - delta_rho} * e(Z, Q_tilde)^{-sigma - rho} * e(K, P_tilde)^-tau = e(V, P_tilde) / (e(E_c, Q_tilde) * e(E_d, P_tilde))`
///  with `E_c`, `E_d`, etc defined in the paper. For membership proof, he pairing check relation to
///  be satisfied is
///   `e(E_c, P_tilde)^y * e(Z, P_tilde)^{-delta_sigma - delta_rho} * e(Z, Q_tilde)^{-sigma - rho} = e(V, P_tilde) / (e(E_c, Q_tilde)`
///   Note that there is no `E_d` or `E_{d^-1}` and thus relations proving knowledge of them are omitted
pub(crate) trait ProofProtocol<E: Pairing> {
    /// Randomize the witness and compute commitments for step 1 of the Schnorr protocol.
    /// `element` is the accumulator (non)member about which the proof is being created.
    /// `element_blinding` is the randomness used for `element` in the Schnorr protocol and is useful
    /// when `element` is used in some other relation as well.
    /// `pairing_extra` is used when creating non-membership proofs and is included in this function
    /// only because its efficient to do a multi-pairing.
    fn randomize_witness_and_compute_commitments<R: RngCore>(
        rng: &mut R,
        element: &E::ScalarField,
        element_blinding: Option<E::ScalarField>,
        witness: &E::G1Affine,
        pairing_extra: Option<E::G1>,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
        prk: &ProvingKey<E::G1Affine>,
    ) -> (
        RandomizedWitness<E::G1Affine>,
        SchnorrCommit<E>,
        Blindings<E::ScalarField>,
    ) {
        // TODO: Since proving key is fixed, these tables can be created just once and stored.
        // There are multiple multiplications with X, Y and Z so create tables for them. 20 multiplications
        // is the upper bound
        let X_table = WindowTable::new(20, prk.X.into_group());
        let Y_table = WindowTable::new(20, prk.Y.into_group());
        let Z_table = WindowTable::new(20, prk.Z.into_group());

        // To prove e(witness, element*P_tilde + Q_tilde) == e(accumulated, P_tilde)
        let sigma = E::ScalarField::rand(rng);
        let rho = E::ScalarField::rand(rng);
        // Commitment to witness
        // E_C = witness + (sigma + rho) * prk.Z
        let mut E_C = Z_table.multiply(&(sigma + rho));
        E_C += witness;

        // T_sigma = sigma * prk.X
        let T_sigma = X_table.multiply(&sigma);
        // T_rho = rho * prk.Y;
        let T_rho = Y_table.multiply(&rho);
        let delta_sigma = *element * sigma;
        let delta_rho = *element * rho;

        // Commit phase of Schnorr
        // Create blindings for pairing equation
        let r_y = element_blinding.unwrap_or_else(|| E::ScalarField::rand(rng)); // blinding for proving knowledge of element
        let r_sigma = E::ScalarField::rand(rng);
        let r_delta_sigma = E::ScalarField::rand(rng);
        let r_rho = E::ScalarField::rand(rng);
        let r_delta_rho = E::ScalarField::rand(rng);

        // Compute R_E using a multi-pairing
        // R_E = e(E_C, params.P_tilde)^r_y * e(prk.Z, params.P_tilde)^(-r_delta_sigma - r_delta_rho) * e(prk.Z, Q_tilde)^(-r_sigma - r_rho) * pairing_extra
        // Here `pairing_extra` refers to `K * -r_v` and is used to for creating the pairing `e(K, P_tilde)^{-r_v} as e(-r_v * K, P_tilde)` for non-membership proof
        // Thus, R_E = e(r_y * E_C, params.P_tilde) * e((-r_delta_sigma - r_delta_rho) * prk.Z, params.P_tilde) * e((-r_sigma - r_rho) * prk.Z, Q_tilde) * e(-r_v * K, P_tilde)
        // Further simplifying, R_E = e(r_y * E_C + (-r_delta_sigma - r_delta_rho) * prk.Z + -r_v * K, params.P_tilde) * e((-r_sigma - r_rho) * prk.Z, Q_tilde)

        // r_y * E_C
        let E_C_times_r_y = E_C.mul_bigint(r_y.into_bigint());
        // (-r_delta_sigma - r_delta_rho) * prk.Z
        let z_p = Z_table.multiply(&(-r_delta_sigma - r_delta_rho));
        let mut p = E_C_times_r_y + z_p;
        // In case of non-membership add -r_v * K
        if pairing_extra.is_some() {
            p += pairing_extra.unwrap();
        }

        let P_tilde_prepared = E::G2Prepared::from(params.P_tilde);
        let R_E = E::multi_pairing(
            [
                // e(r_y * E_C + (-r_delta_sigma - r_delta_rho) * prk.Z + -r_v * K, params.P_tilde)
                p.into_affine(),
                // e((-r_sigma - r_rho) * prk.Z, Q_tilde)
                Z_table.multiply(&(-r_sigma - r_rho)).into_affine(),
            ],
            [P_tilde_prepared, E::G2Prepared::from(pk.0)],
        );

        // R_sigma = r_sigma * prk.X
        let R_sigma = X_table.multiply(&r_sigma);
        // R_rho = r_rho * prk.Y
        let R_rho = Y_table.multiply(&r_rho);

        // R_delta_sigma = r_y * T_sigma - r_delta_sigma * prk.X
        let mut R_delta_sigma = T_sigma;
        R_delta_sigma *= r_y;
        R_delta_sigma -= X_table.multiply(&r_delta_sigma);

        // R_delta_rho = r_y * T_rho - r_delta_rho * prk.Y;
        let mut R_delta_rho = T_rho;
        R_delta_rho *= r_y;
        R_delta_rho -= Y_table.multiply(&r_delta_rho);
        (
            RandomizedWitness {
                E_C: E_C.into_affine(),
                T_sigma: T_sigma.into_affine(),
                T_rho: T_rho.into_affine(),
            },
            SchnorrCommit {
                R_E,
                R_sigma: R_sigma.into_affine(),
                R_rho: R_rho.into_affine(),
                R_delta_sigma: R_delta_sigma.into_affine(),
                R_delta_rho: R_delta_rho.into_affine(),
            },
            Blindings {
                sigma,
                rho,
                delta_sigma,
                delta_rho,
                r_y,
                r_sigma,
                r_rho,
                r_delta_sigma,
                r_delta_rho,
            },
        )
    }

    /// Contribution to the overall challenge (when using this protocol with others) of this protocol
    fn compute_challenge_contribution<W: Write>(
        randomized_witness: &impl SchnorrChallengeContributor,
        schnorr_commit: &impl SchnorrChallengeContributor,
        accumulator_value: &E::G1Affine,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
        prk: &impl SchnorrChallengeContributor,
        mut writer: W,
    ) -> Result<(), VBAccumulatorError> {
        randomized_witness.challenge_contribution(&mut writer)?;
        schnorr_commit.challenge_contribution(&mut writer)?;
        accumulator_value.serialize_compressed(&mut writer)?;
        pk.serialize_compressed(&mut writer)?;
        params.serialize_compressed(&mut writer)?;
        params.serialize_compressed(&mut writer)?;
        prk.challenge_contribution(&mut writer)
            .map_err(|e| e.into())
    }

    /// Compute responses for the Schnorr protocols
    fn compute_responses(
        element: &E::ScalarField,
        blindings: &Blindings<E::ScalarField>,
        challenge: &E::ScalarField,
    ) -> SchnorrResponse<E::ScalarField> {
        // Response phase of Schnorr
        let s_y = blindings.r_y + (*challenge * *element);
        let s_sigma = blindings.r_sigma + (*challenge * blindings.sigma);
        let s_rho = blindings.r_rho + (*challenge * blindings.rho);
        let s_delta_sigma = blindings.r_delta_sigma + (*challenge * blindings.delta_sigma);
        let s_delta_rho = blindings.r_delta_rho + (*challenge * blindings.delta_rho);

        SchnorrResponse {
            s_y,
            s_sigma,
            s_rho,
            s_delta_sigma,
            s_delta_rho,
        }
    }

    /// Verifies the (non)membership relation of the randomized witness and (non)member.
    /// `pairing_extra` is used when verifying non-membership proofs and is included in this function
    /// only because its efficient to do a multi-pairing.
    fn verify_proof(
        randomized_witness: &RandomizedWitness<E::G1Affine>,
        schnorr_commit: &SchnorrCommit<E>,
        schnorr_response: &SchnorrResponse<E::ScalarField>,
        pairing_extra: Option<E::G1>,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        prk: &ProvingKey<E::G1Affine>,
    ) -> Result<(), VBAccumulatorError> {
        let (p, q) = Self::verify_proof_except_pairings(
            randomized_witness,
            schnorr_commit,
            schnorr_response,
            pairing_extra,
            accumulator_value,
            challenge,
            prk,
        )?;
        let R_E = E::multi_pairing([p, q], [params.into().P_tilde, pk.into().0]);
        if R_E != schnorr_commit.R_E {
            return Err(VBAccumulatorError::PairingResponseInvalid);
        }

        Ok(())
    }

    fn verify_proof_with_randomized_pairing_checker(
        randomized_witness: &RandomizedWitness<E::G1Affine>,
        schnorr_commit: &SchnorrCommit<E>,
        schnorr_response: &SchnorrResponse<E::ScalarField>,
        pairing_extra: Option<E::G1>,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        prk: &ProvingKey<E::G1Affine>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<(), VBAccumulatorError> {
        let (p, q) = Self::verify_proof_except_pairings(
            randomized_witness,
            schnorr_commit,
            schnorr_response,
            pairing_extra,
            accumulator_value,
            challenge,
            prk,
        )?;
        pairing_checker.add_multiple_sources_and_target(
            &[p, q],
            [params.into().P_tilde, pk.into().0],
            &schnorr_commit.R_E,
        );
        Ok(())
    }

    /// Verify the proof except the pairing equations. This is useful when doing several verifications (of this
    /// protocol or others) and the pairing equations are combined in a randomized pairing check.
    fn verify_proof_except_pairings(
        randomized_witness: &RandomizedWitness<E::G1Affine>,
        schnorr_commit: &SchnorrCommit<E>,
        schnorr_response: &SchnorrResponse<E::ScalarField>,
        pairing_extra: Option<E::G1>,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        prk: &ProvingKey<E::G1Affine>,
    ) -> Result<(E::G1Affine, E::G1Affine), VBAccumulatorError> {
        let (context, X_table, Y_table, Z_table, T_sigma_table, T_rho_table, E_C_table) =
            Self::get_tables(prk, randomized_witness);
        Self::verify_schnorr_proofs(
            schnorr_commit,
            schnorr_response,
            challenge,
            &context,
            &X_table,
            &Y_table,
            &T_sigma_table,
            &T_rho_table,
        )?;

        Ok(Self::get_g1_for_pairing_checks(
            schnorr_response,
            pairing_extra,
            accumulator_value,
            challenge,
            &context,
            &E_C_table,
            &Z_table,
        ))
    }

    /// There are multiple multiplications with X, Y and Z which can be done in variable time so use wNAF.
    fn get_tables(
        prk: &ProvingKey<E::G1Affine>,
        randomized_witness: &RandomizedWitness<E::G1Affine>,
    ) -> (
        WnafContext,
        Vec<E::G1>,
        Vec<E::G1>,
        Vec<E::G1>,
        Vec<E::G1>,
        Vec<E::G1>,
        Vec<E::G1>,
    ) {
        let context = WnafContext::new(4);
        // TODO: Since proving key is fixed, these tables can be created just once and stored.
        let X_table = context.table(prk.X.into_group());
        let Y_table = context.table(prk.Y.into_group());
        let Z_table = context.table(prk.Z.into_group());

        let T_sigma_table = context.table(randomized_witness.T_sigma.into_group());
        let T_rho_table = context.table(randomized_witness.T_rho.into_group());
        let E_C_table = context.table(randomized_witness.E_C.into_group());
        (
            context,
            X_table,
            Y_table,
            Z_table,
            T_sigma_table,
            T_rho_table,
            E_C_table,
        )
    }

    /// The verifier recomputes various `R_`s values given the responses from the proof and the challenge
    /// and compares them with the `R_`s from the proof for equality
    fn verify_schnorr_proofs(
        schnorr_commit: &SchnorrCommit<E>,
        schnorr_response: &SchnorrResponse<E::ScalarField>,
        challenge: &E::ScalarField,
        context: &WnafContext,
        X_table: &[E::G1],
        Y_table: &[E::G1],
        T_sigma_table: &[E::G1],
        T_rho_table: &[E::G1],
    ) -> Result<(), VBAccumulatorError> {
        // R_sigma = schnorr_response.s_sigma * prk.X - challenge * randomized_witness.T_sigma
        let mut R_sigma = context
            .mul_with_table(X_table, &schnorr_response.s_sigma)
            .unwrap();
        R_sigma -= context.mul_with_table(T_sigma_table, challenge).unwrap();
        if R_sigma.into_affine() != schnorr_commit.R_sigma {
            return Err(VBAccumulatorError::SigmaResponseInvalid);
        }

        // R_rho = schnorr_response.s_rho * prk.Y - challenge * randomized_witness.T_rho;
        let mut R_rho = context
            .mul_with_table(Y_table, &schnorr_response.s_rho)
            .unwrap();
        R_rho -= context.mul_with_table(T_rho_table, challenge).unwrap();
        if R_rho.into_affine() != schnorr_commit.R_rho {
            return Err(VBAccumulatorError::RhoResponseInvalid);
        }

        // R_delta_sigma = schnorr_response.s_y * randomized_witness.T_sigma - schnorr_response.s_delta_sigma * prk.X;
        let mut R_delta_sigma = context
            .mul_with_table(T_sigma_table, &schnorr_response.s_y)
            .unwrap();
        R_delta_sigma -= context
            .mul_with_table(X_table, &schnorr_response.s_delta_sigma)
            .unwrap();
        if R_delta_sigma.into_affine() != schnorr_commit.R_delta_sigma {
            return Err(VBAccumulatorError::DeltaSigmaResponseInvalid);
        }

        // R_delta_rho = schnorr_response.s_y * randomized_witness.T_rho - schnorr_response.s_delta_rho * prk.Y;
        let mut R_delta_rho = context
            .mul_with_table(T_rho_table, &schnorr_response.s_y)
            .unwrap();
        R_delta_rho -= context
            .mul_with_table(Y_table, &schnorr_response.s_delta_rho)
            .unwrap();
        if R_delta_rho.into_affine() != schnorr_commit.R_delta_rho {
            return Err(VBAccumulatorError::DeltaRhoResponseInvalid);
        }
        Ok(())
    }

    fn get_g1_for_pairing_checks(
        schnorr_response: &SchnorrResponse<E::ScalarField>,
        pairing_extra: Option<E::G1>,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        context: &WnafContext,
        E_C_table: &[E::G1],
        Z_table: &[E::G1],
    ) -> (E::G1Affine, E::G1Affine) {
        // R_E = e(E_C, params.P_tilde)^s_y * e(prk.Z, params.P_tilde)^(-s_delta_sigma - s_delta_rho) * e(prk.Z, Q_tilde)^(-s_sigma - s_rho) * e(V, params.P_tilde)^-challenge * e(E_C, Q_tilde)^challenge * pairing_extra
        // Here `pairing_extra` refers to `E_d * -challenge` and `K * -s_v` and is used to for creating the pairings `e(E_d, P_tilde)^challenge` as `e(challenge * E_d, P_tilde)` and `e(K, P_tilde)^{-s_v}` as `e(-s_v * K, P_tilde)`
        // Thus, R_E = e(s_y * E_C, params.P_tilde) * e((s_delta_sigma - s_delta_rho) * Z, params.P_tilde) * e((s_sigma - s_rho) * Z, Q_tilde) * e(-challenge * V, params.P_tilde) * e(challenge * E_C, Q_tilde) * e(challenge * E_d, P_tilde) * e(-s_v * K, P_tilde)
        // Further simplifying, R_E = e(s_y * E_C + (s_delta_sigma - s_delta_rho) * Z + -challenge * V + challenge * E_d + -s_v * K, params.P_tilde) * e((s_sigma - s_rho) * Z + challenge * E_C, Q_tilde)

        // s_y * E_C
        let E_C_p = context
            .mul_with_table(E_C_table, &schnorr_response.s_y)
            .unwrap();
        // (s_delta_sigma - s_delta_rho) * Z
        let z_p = context
            .mul_with_table(
                Z_table,
                &(-schnorr_response.s_delta_sigma - schnorr_response.s_delta_rho),
            )
            .unwrap();
        // -challenge * V
        let a = accumulator_value.mul_bigint((-*challenge).into_bigint());
        let mut p = E_C_p + z_p + a;
        // In case of non-membership add challenge * E_d + -s_v * K
        if pairing_extra.is_some() {
            p += pairing_extra.unwrap();
        }

        // (s_sigma - s_rho) * Z
        let z_q = context
            .mul_with_table(
                Z_table,
                &(-schnorr_response.s_sigma - schnorr_response.s_rho),
            )
            .unwrap();
        // challenge * E_C
        let E_C_q = context.mul_with_table(E_C_table, challenge).unwrap();
        let q = z_q + E_C_q;
        (p.into_affine(), q.into_affine())
    }
}

impl<E: Pairing> ProofProtocol<E> for MembershipProofProtocol<E> {}

impl<E: Pairing> MembershipProofProtocol<E> {
    /// Initialize a membership proof protocol. Delegates to [`randomize_witness_and_compute_commitments`]
    ///
    /// [`randomize_witness_and_compute_commitments`]: ProofProtocol::randomize_witness_and_compute_commitments
    pub fn init<R: RngCore>(
        rng: &mut R,
        element: E::ScalarField,
        element_blinding: Option<E::ScalarField>,
        witness: &MembershipWitness<E::G1Affine>,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
        prk: impl AsRef<ProvingKey<E::G1Affine>>,
    ) -> Self {
        let (rw, sc, bl) = Self::randomize_witness_and_compute_commitments(
            rng,
            &element,
            element_blinding,
            &witness.0,
            None,
            pk,
            params,
            prk.as_ref(),
        );
        Self {
            element,
            randomized_witness: MembershipRandomizedWitness(rw),
            schnorr_commit: MembershipSchnorrCommit(sc),
            schnorr_blindings: MembershipBlindings(bl),
        }
    }

    /// Contribution of this protocol to the overall challenge (when using this protocol as a sub-protocol).
    /// Delegates to [`compute_challenge_contribution`]
    ///
    /// [`compute_challenge_contribution`]: ProofProtocol::compute_challenge_contribution
    pub fn challenge_contribution<W: Write>(
        &self,
        accumulator_value: &E::G1Affine,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
        prk: impl AsRef<ProvingKey<E::G1Affine>>,
        writer: W,
    ) -> Result<(), VBAccumulatorError> {
        Self::compute_challenge_contribution(
            &self.randomized_witness,
            &self.schnorr_commit,
            accumulator_value,
            pk,
            params,
            prk.as_ref(),
            writer,
        )
    }

    /// Create membership proof once the overall challenge is ready. Delegates to [`compute_responses`]
    ///
    /// [`compute_responses`]: ProofProtocol::compute_responses
    pub fn gen_proof(
        self,
        challenge: &E::ScalarField,
    ) -> Result<MembershipProof<E>, VBAccumulatorError> {
        let resp = Self::compute_responses(&self.element, &self.schnorr_blindings.0, challenge);
        Ok(MembershipProof {
            randomized_witness: self.randomized_witness.clone(),
            schnorr_commit: self.schnorr_commit.clone(),
            schnorr_response: MembershipSchnorrResponse(resp),
        })
    }
}

impl<E: Pairing> ProofProtocol<E> for NonMembershipProofProtocol<E> {}

impl<E: Pairing> NonMembershipProofProtocol<E> {
    /// Initialize a non-membership proof protocol. Create blindings for proving `witness.d != 0` and
    /// then delegates to [`randomize_witness_and_compute_commitments`]
    ///
    /// [`randomize_witness_and_compute_commitments`]: ProofProtocol::randomize_witness_and_compute_commitments
    pub fn init<R: RngCore>(
        rng: &mut R,
        element: E::ScalarField,
        element_blinding: Option<E::ScalarField>,
        witness: &NonMembershipWitness<E::G1Affine>,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
        prk: &NonMembershipProvingKey<E::G1Affine>,
    ) -> Self {
        // TODO: Since proving key is fixed, these tables can be created just once and stored.
        // There are multiple multiplications with P and K so create tables for them. 20 multiplications
        // is the upper bound
        let P_table = WindowTable::new(20, params.P.into_group());
        let K_table = WindowTable::new(20, prk.K.into_group());

        // To prove non-zero d of witness
        let tau = E::ScalarField::rand(rng); // blinding in commitment to d
        let pi = E::ScalarField::rand(rng);

        // Commitment to d
        // E_d = witness.d * pk.P + tau * prk.K
        let mut E_d = P_table.multiply(&witness.d);
        E_d += K_table.multiply(&tau);

        // Commitment to d^-1
        // E_d_inv = 1/witness.d * pk.P + pi * prk.K;
        let mut E_d_inv = P_table.multiply(&witness.d.inverse().unwrap());
        E_d_inv += K_table.multiply(&pi);

        // Create blindings for d != 0
        let r_u = E::ScalarField::rand(rng); // blinding for proving knowledge of d
        let r_v = E::ScalarField::rand(rng); // blinding for proving knowledge of tau
        let r_w = E::ScalarField::rand(rng);

        // R_A = r_u * pk.P + r_v * prk.K;
        let mut R_A = P_table.multiply(&r_u);
        R_A += K_table.multiply(&r_v);

        // R_B = r_u * E_d_inv + r_w * prk.K;
        let mut R_B = E_d_inv;
        R_B *= r_u;
        R_B += K_table.multiply(&r_w);

        // new R_E = e(E_C, params.P_tilde)^r_y * e(prk.Z, params.P_tilde)^(-r_delta_sigma - r_delta_rho) * e(prk.Z, Q_tilde)^(-r_sigma - r_rho) * e(prk.K, params.P_tilde)^-r_v
        // sc.R_E = e(E_C, params.P_tilde)^r_y * e(prk.Z, params.P_tilde)^(-r_delta_sigma - r_delta_rho) * e(prk.Z, Q_tilde)^(-r_sigma - r_rho)
        // => new R_E = e(prk.K, params.P_tilde)^-r_v * sc.R_E = e(-r_v * prk.K, params.P_tilde) * sc.R_E
        let (rw, sc, bl) = Self::randomize_witness_and_compute_commitments(
            rng,
            &element,
            element_blinding,
            &witness.C,
            Some(K_table.multiply(&-r_v)),
            pk,
            params,
            &prk.XYZ,
        );

        Self {
            element,
            d: witness.d,
            randomized_witness: NonMembershipRandomizedWitness {
                C: rw,
                E_d: E_d.into_affine(),
                E_d_inv: E_d_inv.into_affine(),
            },
            schnorr_commit: NonMembershipSchnorrCommit {
                C: sc,
                R_A: R_A.into_affine(),
                R_B: R_B.into_affine(),
            },
            schnorr_blindings: NonMembershipBlindings {
                C: bl,
                tau,
                pi,
                r_u,
                r_v,
                r_w,
            },
        }
    }

    /// Contribution of this protocol to the overall challenge (when using this protocol as a sub-protocol).
    /// Delegates to [`compute_challenge_contribution`]
    ///
    /// [`compute_challenge_contribution`]: ProofProtocol::compute_challenge_contribution
    pub fn challenge_contribution<W: Write>(
        &self,
        accumulator_value: &E::G1Affine,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
        prk: &NonMembershipProvingKey<E::G1Affine>,
        mut writer: W,
    ) -> Result<(), VBAccumulatorError> {
        Self::compute_challenge_contribution(
            &self.randomized_witness,
            &self.schnorr_commit,
            accumulator_value,
            pk,
            params,
            &prk.XYZ,
            &mut writer,
        )
    }

    /// Create membership proof once the overall challenge is ready. Computes the response for `witness.d`
    /// and then delegates to [`compute_responses`]
    ///
    /// [`compute_responses`]: ProofProtocol::compute_responses
    pub fn gen_proof(
        self,
        challenge: &E::ScalarField,
    ) -> Result<NonMembershipProof<E>, VBAccumulatorError> {
        // For d != 0
        let challenge_times_d = *challenge * self.d;
        let s_u = self.schnorr_blindings.r_u + challenge_times_d;
        let s_v = self.schnorr_blindings.r_v + (*challenge * self.schnorr_blindings.tau);
        let s_w = self.schnorr_blindings.r_w - (challenge_times_d * self.schnorr_blindings.pi);

        let resp = Self::compute_responses(&self.element, &self.schnorr_blindings.C, challenge);

        Ok(NonMembershipProof {
            randomized_witness: self.randomized_witness.clone(),
            schnorr_commit: self.schnorr_commit.clone(),
            schnorr_response: NonMembershipSchnorrResponse {
                C: resp,
                s_u,
                s_v,
                s_w,
            },
        })
    }
}

impl<E: Pairing> MembershipProof<E> {
    /// Challenge contribution for this proof
    pub fn challenge_contribution<W: Write>(
        &self,
        accumulator_value: &E::G1Affine,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
        prk: impl AsRef<ProvingKey<E::G1Affine>>,
        writer: W,
    ) -> Result<(), VBAccumulatorError> {
        MembershipProofProtocol::compute_challenge_contribution(
            &self.randomized_witness,
            &self.schnorr_commit,
            accumulator_value,
            pk,
            params,
            prk.as_ref(),
            writer,
        )
    }

    /// Verify this proof. Delegates to [`verify_proof`]
    ///
    /// [`verify_proof`]: ProofProtocol::verify_proof
    pub fn verify(
        &self,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        prk: impl AsRef<ProvingKey<E::G1Affine>>,
    ) -> Result<(), VBAccumulatorError> {
        <MembershipProofProtocol<E> as ProofProtocol<E>>::verify_proof(
            &self.randomized_witness.0,
            &self.schnorr_commit.0,
            &self.schnorr_response.0,
            None,
            accumulator_value,
            challenge,
            pk,
            params,
            prk.as_ref(),
        )
    }

    pub fn verify_with_randomized_pairing_checker(
        &self,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        prk: impl AsRef<ProvingKey<E::G1Affine>>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<(), VBAccumulatorError> {
        <MembershipProofProtocol<E> as ProofProtocol<E>>::verify_proof_with_randomized_pairing_checker(
            &self.randomized_witness.0,
            &self.schnorr_commit.0,
            &self.schnorr_response.0,
            None,
            accumulator_value,
            challenge,
            pk,
            params,
            prk.as_ref(),
            pairing_checker
        )
    }

    /// Get response for Schnorr protocol for the member. This is useful when the member is also used
    /// in another relation that is proven along this protocol.
    pub fn get_schnorr_response_for_element(&self) -> &E::ScalarField {
        self.schnorr_response.0.get_response_for_element()
    }
}

impl<E: Pairing> NonMembershipProof<E> {
    /// Challenge contribution for this proof
    pub fn challenge_contribution<W: Write>(
        &self,
        accumulator_value: &E::G1Affine,
        pk: &PublicKey<E>,
        params: &SetupParams<E>,
        prk: &NonMembershipProvingKey<E::G1Affine>,
        mut writer: W,
    ) -> Result<(), VBAccumulatorError> {
        NonMembershipProofProtocol::compute_challenge_contribution(
            &self.randomized_witness,
            &self.schnorr_commit,
            accumulator_value,
            pk,
            params,
            &prk.XYZ,
            &mut writer,
        )
    }

    /// Verify this proof. Verify the responses for the relation `witness.d != 0` and then delegates
    /// to [`verify_proof`]
    ///
    /// [`verify_proof`]: ProofProtocol::verify_proof
    pub fn verify(
        &self,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        prk: &NonMembershipProvingKey<E::G1Affine>,
    ) -> Result<(), VBAccumulatorError> {
        let params = params.into();
        let pairing_extra = self.verify_except_pairings(challenge, &params.P, prk)?;

        <NonMembershipProofProtocol<E> as ProofProtocol<E>>::verify_proof(
            &self.randomized_witness.C,
            &self.schnorr_commit.C,
            &self.schnorr_response.C,
            Some(pairing_extra),
            accumulator_value,
            challenge,
            pk,
            params,
            &prk.XYZ,
        )
    }

    pub fn verify_with_randomized_pairing_checker(
        &self,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        pk: impl Into<PreparedPublicKey<E>>,
        params: impl Into<PreparedSetupParams<E>>,
        prk: &NonMembershipProvingKey<E::G1Affine>,
        pairing_checker: &mut RandomizedPairingChecker<E>,
    ) -> Result<(), VBAccumulatorError> {
        let params = params.into();
        let pairing_extra = self.verify_except_pairings(challenge, &params.P, prk)?;

        <NonMembershipProofProtocol<E> as ProofProtocol<E>>::verify_proof_with_randomized_pairing_checker(
            &self.randomized_witness.C,
            &self.schnorr_commit.C,
            &self.schnorr_response.C,
            Some(pairing_extra),
            accumulator_value,
            challenge,
            pk,
            params,
            &prk.XYZ,
            pairing_checker
        )
    }

    /// Get response for Schnorr protocol for the non-member. This is useful when the non-member is also used
    /// in another relation that is proven along this protocol.
    pub fn get_schnorr_response_for_element(&self) -> &E::ScalarField {
        self.schnorr_response.C.get_response_for_element()
    }

    /// There are multiple multiplications with K, P and E_d which can be done in variable time so use wNAF.
    pub fn get_tables(
        prk: &NonMembershipProvingKey<E::G1Affine>,
        P: &E::G1Affine,
        E_d: &E::G1Affine,
    ) -> (WnafContext, Vec<E::G1>, Vec<E::G1>, Vec<E::G1>) {
        let context = WnafContext::new(4);
        let K_table = context.table(prk.K.into_group());
        let P_table = context.table(P.into_group());
        let E_d_table = context.table(E_d.into_group());
        (context, K_table, P_table, E_d_table)
    }

    pub fn verify_schnorr_proofs(
        &self,
        challenge: &E::ScalarField,
        context: &WnafContext,
        K_table: &[E::G1],
        P_table: &[E::G1],
        E_d_table: &[E::G1],
    ) -> Result<(), VBAccumulatorError> {
        // R_A = schnorr_response.s_u * params.P + schnorr_response.s_v * prk.K - challenge * randomized_witness.E_d;
        let mut R_A = context
            .mul_with_table(P_table, &self.schnorr_response.s_u)
            .unwrap();
        R_A += context
            .mul_with_table(K_table, &self.schnorr_response.s_v)
            .unwrap();
        R_A -= context.mul_with_table(E_d_table, challenge).unwrap();

        if R_A.into_affine() != self.schnorr_commit.R_A {
            return Err(VBAccumulatorError::E_d_ResponseInvalid);
        }

        // R_B = schnorr_response.s_w * prk.K + schnorr_response.s_u * randomized_witness.E_d_inv - challenge * params.P;
        let mut R_B = context
            .mul_with_table(K_table, &self.schnorr_response.s_w)
            .unwrap();
        R_B += self
            .randomized_witness
            .E_d_inv
            .mul_bigint(self.schnorr_response.s_u.into_bigint());
        R_B -= context.mul_with_table(P_table, challenge).unwrap();

        if R_B.into_affine() != self.schnorr_commit.R_B {
            return Err(VBAccumulatorError::E_d_inv_ResponseInvalid);
        }
        Ok(())
    }

    pub fn get_pairing_contribution(
        &self,
        challenge: &E::ScalarField,
        context: &WnafContext,
        K_table: &[E::G1],
        E_d_table: &[E::G1],
    ) -> E::G1 {
        // -schnorr_response.s_v * prk.K + challenge * randomized_witness.E_d
        context
            .mul_with_table(K_table, &-self.schnorr_response.s_v)
            .unwrap()
            + context.mul_with_table(E_d_table, challenge).unwrap()
    }

    /// Verify the proof except the pairing equations. This is useful when doing several verifications (of this
    /// protocol or others) and the pairing equations are combined in a randomized pairing check.
    fn verify_except_pairings(
        &self,
        challenge: &E::ScalarField,
        P: &E::G1Affine,
        prk: &NonMembershipProvingKey<E::G1Affine>,
    ) -> Result<E::G1, VBAccumulatorError> {
        let (context, K_table, P_table, E_d_table) =
            Self::get_tables(prk, P, &self.randomized_witness.E_d);

        self.verify_schnorr_proofs(challenge, &context, &K_table, &P_table, &E_d_table)?;
        Ok(self.get_pairing_contribution(challenge, &context, &K_table, &E_d_table))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        positive::{tests::setup_positive_accum, Accumulator},
        test_serialization,
        universal::tests::setup_universal_accum,
    };

    use crate::setup::MembershipProvingKey;
    use ark_bls12_381::Bls12_381;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use schnorr_pok::compute_random_oracle_challenge;
    use std::time::{Duration, Instant};

    type Fr = <Bls12_381 as Pairing>::ScalarField;

    #[test]
    fn membership_proof_positive_accumulator() {
        // Proof of knowledge of membership witness
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, mut accumulator, mut state) = setup_positive_accum(&mut rng);
        let prk = MembershipProvingKey::generate_using_rng(&mut rng);
        let prepared_params = PreparedSetupParams::from(params.clone());
        let prepared_pk = PreparedPublicKey::from(keypair.public_key.clone());

        test_serialization!(MembershipProvingKey<<Bls12_381 as Pairing>::G1Affine>, prk);

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
        let mut proof_verif_with_prepared_duration = Duration::default();
        let mut proof_verif_with_rand_pair_check_duration = Duration::default();
        let mut proof_verif_with_prepared_and_rand_pair_check_duration = Duration::default();

        let mut pairing_checker = RandomizedPairingChecker::new_using_rng(&mut rng, true);

        for i in 0..count {
            let start = Instant::now();
            let protocol = MembershipProofProtocol::init(
                &mut rng,
                elems[i],
                None,
                &witnesses[i],
                &keypair.public_key,
                &params,
                &prk,
            );
            proof_create_duration += start.elapsed();

            test_serialization!(MembershipProofProtocol<Bls12_381>, protocol);

            let mut chal_bytes_prover = vec![];
            protocol
                .challenge_contribution(
                    accumulator.value(),
                    &keypair.public_key,
                    &params,
                    &prk,
                    &mut chal_bytes_prover,
                )
                .unwrap();
            let challenge_prover =
                compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

            let start = Instant::now();
            let proof = protocol.gen_proof(&challenge_prover).unwrap();
            proof_create_duration += start.elapsed();

            // Proof can be serialized
            test_serialization!(MembershipProof<Bls12_381>, proof);

            let mut chal_bytes_verifier = vec![];
            proof
                .challenge_contribution(
                    accumulator.value(),
                    &keypair.public_key,
                    &params,
                    &prk,
                    &mut chal_bytes_verifier,
                )
                .unwrap();
            let challenge_verifier =
                compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);

            assert_eq!(challenge_prover, challenge_verifier);

            let start = Instant::now();
            proof
                .verify(
                    accumulator.value(),
                    &challenge_verifier,
                    keypair.public_key.clone(),
                    params.clone(),
                    &prk,
                )
                .unwrap();
            proof_verif_duration += start.elapsed();

            let start = Instant::now();
            proof
                .verify(
                    accumulator.value(),
                    &challenge_verifier,
                    prepared_pk.clone(),
                    prepared_params.clone(),
                    &prk,
                )
                .unwrap();
            proof_verif_with_prepared_duration += start.elapsed();

            let start = Instant::now();
            proof
                .verify_with_randomized_pairing_checker(
                    accumulator.value(),
                    &challenge_verifier,
                    keypair.public_key.clone(),
                    params.clone(),
                    &prk,
                    &mut pairing_checker,
                )
                .unwrap();
            proof_verif_with_rand_pair_check_duration += start.elapsed();

            let start = Instant::now();
            proof
                .verify_with_randomized_pairing_checker(
                    accumulator.value(),
                    &challenge_verifier,
                    prepared_pk.clone(),
                    prepared_params.clone(),
                    &prk,
                    &mut pairing_checker,
                )
                .unwrap();
            proof_verif_with_prepared_and_rand_pair_check_duration += start.elapsed();

            // Randomizing accumulator and witness
            let random = Fr::rand(&mut rng);
            let randomized_accum = (*accumulator.value() * random).into_affine();
            let randomized_wit = MembershipWitness((witnesses[i].0 * random).into_affine());
            let protocol = MembershipProofProtocol::init(
                &mut rng,
                elems[i],
                None,
                &randomized_wit,
                &keypair.public_key,
                &params,
                &prk,
            );
            let challenge = Fr::rand(&mut rng);
            let proof = protocol.gen_proof(&challenge).unwrap();
            proof
                .verify(
                    &randomized_accum,
                    &challenge,
                    keypair.public_key.clone(),
                    params.clone(),
                    &prk,
                )
                .unwrap();
        }

        let start = Instant::now();
        assert!(pairing_checker.verify());
        proof_verif_with_rand_pair_check_duration += start.elapsed();

        println!(
            "Time to create {} membership proofs is {:?}",
            count, proof_create_duration
        );
        println!(
            "Time to verify {} membership proofs is {:?}",
            count, proof_verif_duration
        );
        println!(
            "Time to verify {} membership proofs using prepared params is {:?}",
            count, proof_verif_with_prepared_duration
        );
        println!(
            "Time to verify {} membership proofs using randomized pairing checker is {:?}",
            count, proof_verif_with_rand_pair_check_duration
        );
        println!(
            "Time to verify {} membership proofs using prepared params and randomized pairing checker is {:?}",
            count, proof_verif_with_prepared_and_rand_pair_check_duration
        );
    }

    #[test]
    fn non_membership_proof_universal_accumulator() {
        // Proof of knowledge of non-membership witness
        let max = 100;
        let mut rng = StdRng::seed_from_u64(0u64);

        let (params, keypair, mut accumulator, initial_elems, mut state) =
            setup_universal_accum(&mut rng, max);
        let prk = NonMembershipProvingKey::generate_using_rng(&mut rng);

        let prepared_params = PreparedSetupParams::from(params.clone());
        let prepared_pk = PreparedPublicKey::from(keypair.public_key.clone());

        test_serialization!(
            NonMembershipProvingKey<<Bls12_381 as Pairing>::G1Affine>,
            prk
        );

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
        let mut proof_verif_with_prepared_duration = Duration::default();
        let mut proof_verif_with_rand_pair_check_duration = Duration::default();
        let mut proof_verif_with_prepared_and_rand_pair_check_duration = Duration::default();

        let mut pairing_checker = RandomizedPairingChecker::new_using_rng(&mut rng, true);

        for i in 0..count {
            let start = Instant::now();
            let protocol = NonMembershipProofProtocol::init(
                &mut rng,
                elems[i],
                None,
                &witnesses[i],
                &keypair.public_key,
                &params,
                &prk,
            );
            proof_create_duration += start.elapsed();

            test_serialization!(NonMembershipProofProtocol<Bls12_381>, protocol);

            let mut chal_bytes_prover = vec![];
            protocol
                .challenge_contribution(
                    accumulator.value(),
                    &keypair.public_key,
                    &params,
                    &prk,
                    &mut chal_bytes_prover,
                )
                .unwrap();
            let challenge_prover =
                compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);

            let start = Instant::now();
            let proof = protocol.gen_proof(&challenge_prover).unwrap();
            proof_create_duration += start.elapsed();

            let mut chal_bytes_verifier = vec![];
            proof
                .challenge_contribution(
                    accumulator.value(),
                    &keypair.public_key,
                    &params,
                    &prk,
                    &mut chal_bytes_verifier,
                )
                .unwrap();
            let challenge_verifier =
                compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);

            assert_eq!(challenge_prover, challenge_verifier);

            test_serialization!(NonMembershipProof<Bls12_381>, proof);

            let start = Instant::now();
            proof
                .verify(
                    accumulator.value(),
                    &challenge_verifier,
                    keypair.public_key.clone(),
                    params.clone(),
                    &prk,
                )
                .unwrap();
            proof_verif_duration += start.elapsed();

            let start = Instant::now();
            proof
                .verify(
                    accumulator.value(),
                    &challenge_verifier,
                    prepared_pk.clone(),
                    prepared_params.clone(),
                    &prk,
                )
                .unwrap();
            proof_verif_with_prepared_duration += start.elapsed();

            let start = Instant::now();
            proof
                .verify_with_randomized_pairing_checker(
                    accumulator.value(),
                    &challenge_verifier,
                    keypair.public_key.clone(),
                    params.clone(),
                    &prk,
                    &mut pairing_checker,
                )
                .unwrap();
            proof_verif_with_rand_pair_check_duration += start.elapsed();

            let start = Instant::now();
            proof
                .verify_with_randomized_pairing_checker(
                    accumulator.value(),
                    &challenge_verifier,
                    prepared_pk.clone(),
                    prepared_params.clone(),
                    &prk,
                    &mut pairing_checker,
                )
                .unwrap();
            proof_verif_with_prepared_and_rand_pair_check_duration += start.elapsed();

            // Randomizing accumulator and witness
            let random = Fr::rand(&mut rng);
            let randomized_accum = (*accumulator.value() * random).into_affine();
            let randomized_wit = NonMembershipWitness {
                d: witnesses[i].d * random,
                C: (witnesses[i].C * random).into_affine(),
            };
            let protocol = NonMembershipProofProtocol::init(
                &mut rng,
                elems[i],
                None,
                &randomized_wit,
                &keypair.public_key,
                &params,
                &prk,
            );
            let challenge = Fr::rand(&mut rng);
            let proof = protocol.gen_proof(&challenge).unwrap();
            proof
                .verify(
                    &randomized_accum,
                    &challenge,
                    keypair.public_key.clone(),
                    params.clone(),
                    &prk,
                )
                .unwrap();
        }

        let start = Instant::now();
        assert!(pairing_checker.verify());
        proof_verif_with_rand_pair_check_duration += start.elapsed();

        println!(
            "Time to create {} non-membership proofs is {:?}",
            count, proof_create_duration
        );
        println!(
            "Time to verify {} non-membership proofs is {:?}",
            count, proof_verif_duration
        );
        println!(
            "Time to verify {} non-membership proofs using prepared params is {:?}",
            count, proof_verif_with_prepared_duration
        );
        println!(
            "Time to verify {} non-membership proofs using randomized pairing checker is {:?}",
            count, proof_verif_with_rand_pair_check_duration
        );
        println!(
            "Time to verify {} non-membership proofs using prepared params and randomized pairing checker is {:?}",
            count, proof_verif_with_prepared_and_rand_pair_check_duration
        );
    }
}
