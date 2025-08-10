use crate::error::SSError;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, collections::BTreeMap, vec, vec::Vec};
use core::fmt::Debug;
use digest::Digest;
#[cfg(feature = "serde")]
use dock_crypto_utils::serde_utils::ArkObjectBytes;
use dock_crypto_utils::{affine_group_element_from_byte_slices, commitment::PedersenCommitmentKey};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::{serde_as, Same};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// ShareId must be greater than 0
pub type ShareId = u16;

/// ParticipantId must be greater than 0
pub type ParticipantId = u16;

/// Share used in Shamir secret sharing and Feldman verifiable secret sharing
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(
    Default,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Zeroize,
    ZeroizeOnDrop,
    CanonicalSerialize,
    CanonicalDeserialize,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Share<F: PrimeField> {
    #[zeroize(skip)]
    pub id: ShareId,
    #[zeroize(skip)]
    pub threshold: ShareId,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub share: F,
}

/// Collection of `Share`s. A sufficient number of `Share`s reconstruct the secret.
/// Expects unique shares, i.e. each share has a different `ShareId` and each has the same threshold.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct Shares<F: PrimeField>(pub Vec<Share<F>>);

/// Share used in Pedersen verifiable secret sharing
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(
    Default,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Zeroize,
    ZeroizeOnDrop,
    CanonicalSerialize,
    CanonicalDeserialize,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerifiableShare<F: PrimeField> {
    #[zeroize(skip)]
    pub id: ShareId,
    #[zeroize(skip)]
    pub threshold: ShareId,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub secret_share: F,
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))]
    pub blinding_share: F,
}

/// Collection of `VerifiableShares`s. A sufficient number of `VerifiableShares`s reconstruct the secret.
/// Expects unique shares, i.e. each share has a different `ShareId` and each has the same threshold.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct VerifiableShares<F: PrimeField>(pub Vec<VerifiableShare<F>>);

/// Commitments to coefficients of the polynomial created during secret sharing. Each commitment
/// in the vector could be a Pedersen commitment or a computationally hiding and computationally binding
/// commitment (scalar multiplication of the coefficient with a public group element). The former is used
/// in Pedersen secret sharing and the latter in Feldman
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Default, Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CommitmentToCoefficients<G: AffineRepr>(
    #[cfg_attr(feature = "serde", serde_as(as = "Vec<ArkObjectBytes>"))] pub Vec<G>,
);

impl<F: PrimeField> From<(ShareId, ShareId, F)> for Share<F> {
    fn from((i, t, s): (ShareId, ShareId, F)) -> Self {
        Share {
            id: i,
            threshold: t,
            share: s,
        }
    }
}

impl<F: PrimeField> Shares<F> {
    pub fn threshold(&self) -> ShareId {
        self.0[0].threshold
    }
}

impl<G: AffineRepr> From<Vec<G>> for CommitmentToCoefficients<G> {
    fn from(coeffs: Vec<G>) -> Self {
        CommitmentToCoefficients(coeffs)
    }
}

impl<G: AffineRepr> CommitmentToCoefficients<G> {
    /// The constant coefficient is the secret and thus returns the commitment to that.
    pub fn commitment_to_secret(&self) -> &G {
        &self.0[0]
    }

    /// The degree of the polynomial whose coefficients were committed
    pub fn poly_degree(&self) -> usize {
        self.0.len() - 1
    }

    pub fn supports_threshold(&self, threshold: ShareId) -> bool {
        threshold as usize - 1 == self.poly_degree()
    }
}

pub trait SecretShare<G: AffineRepr>:
    Clone + Sized + Debug + CanonicalSerialize + CanonicalDeserialize + Zeroize + ZeroizeOnDrop
{
    type Value;

    type CommKey;

    fn new(id: ParticipantId, threshold: ShareId, value: Self::Value) -> Self;

    fn compute_final(shares: Vec<Self>) -> Self::Value;

    fn check<'a>(
        &self,
        commitment_coeffs: &CommitmentToCoefficients<G>,
        ck: &'a Self::CommKey,
    ) -> Result<(), SSError>;

    fn id(&self) -> ParticipantId;

    fn threshold(&self) -> ShareId;
}

impl<G: AffineRepr> SecretShare<G> for Share<G::ScalarField> {
    type Value = G::ScalarField;
    type CommKey = G;

    fn new(id: ParticipantId, threshold: ShareId, value: Self::Value) -> Self {
        Share {
            id,
            threshold,
            share: value,
        }
    }

    fn compute_final(shares: Vec<Self>) -> Self::Value {
        cfg_into_iter!(shares)
            .map(|s| s.share)
            .sum::<G::ScalarField>()
    }

    fn check<'a>(
        &self,
        commitment_coeffs: &CommitmentToCoefficients<G>,
        ck: &'a Self::CommKey,
    ) -> Result<(), SSError> {
        self.verify(commitment_coeffs, ck)
    }

    fn id(&self) -> ParticipantId {
        self.id
    }

    fn threshold(&self) -> ShareId {
        self.threshold
    }
}

impl<G: AffineRepr> SecretShare<G> for VerifiableShare<G::ScalarField> {
    type Value = (G::ScalarField, G::ScalarField);
    type CommKey = PedersenCommitmentKey<G>;

    fn new(id: ParticipantId, threshold: ShareId, value: Self::Value) -> Self {
        let (secret_share, blinding_share) = value;
        VerifiableShare {
            id,
            threshold,
            secret_share,
            blinding_share,
        }
    }

    fn compute_final(shares: Vec<Self>) -> Self::Value {
        let mut final_s_share = G::ScalarField::zero();
        let mut final_t_share = G::ScalarField::zero();
        for share in shares {
            final_s_share += share.secret_share;
            final_t_share += share.blinding_share;
        }
        (final_s_share, final_t_share)
    }

    fn check<'a>(
        &self,
        commitment_coeffs: &CommitmentToCoefficients<G>,
        ck: &'a Self::CommKey,
    ) -> Result<(), SSError> {
        self.verify(commitment_coeffs, ck)
    }

    fn id(&self) -> ParticipantId {
        self.id
    }

    fn threshold(&self) -> ShareId {
        self.threshold
    }
}

/// Used by a participant to store received shares and commitment coefficients.
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct SharesAccumulator<G: AffineRepr, S: SecretShare<G>> {
    pub participant_id: ParticipantId,
    pub threshold: ShareId,
    /// Stores its own and received shares
    #[cfg_attr(feature = "serde", serde_as(as = "BTreeMap<Same, ArkObjectBytes>"))]
    pub shares: BTreeMap<ParticipantId, S>,
    pub coeff_comms: BTreeMap<ParticipantId, CommitmentToCoefficients<G>>,
}

impl<G: AffineRepr, S: SecretShare<G>> Zeroize for SharesAccumulator<G, S> {
    fn zeroize(&mut self) {
        self.shares.values_mut().for_each(|v| v.zeroize())
    }
}

impl<G: AffineRepr, S: SecretShare<G>> Drop for SharesAccumulator<G, S> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<G: AffineRepr, S: SecretShare<G>> SharesAccumulator<G, S> {
    pub fn new(id: ParticipantId, threshold: ShareId) -> Self {
        Self {
            participant_id: id,
            threshold,
            shares: Default::default(),
            coeff_comms: Default::default(),
        }
    }

    /// Called by a participant when it creates a share for itself
    pub fn add_self_share(&mut self, share: S, commitment_coeffs: CommitmentToCoefficients<G>) {
        self.update_unchecked(self.participant_id, share, commitment_coeffs)
    }

    /// Called by a participant when it receives a share from another participant
    pub fn add_received_share<'a>(
        &mut self,
        sender_id: ParticipantId,
        share: S,
        commitment_coeffs: CommitmentToCoefficients<G>,
        ck: &S::CommKey,
    ) -> Result<(), SSError> {
        if sender_id == self.participant_id {
            return Err(SSError::SenderIdSameAsReceiver(
                sender_id,
                self.participant_id,
            ));
        }
        if self.shares.contains_key(&sender_id) {
            return Err(SSError::AlreadyProcessedFromSender(sender_id));
        }
        self.update(sender_id, share, commitment_coeffs, ck.into())
    }

    /// Compute the final share after receiving shares from all other participants.
    pub fn gen_final_share(
        participant_id: ParticipantId,
        threshold: ShareId,
        shares: BTreeMap<ParticipantId, S>,
        coeff_comms: BTreeMap<ParticipantId, CommitmentToCoefficients<G>>,
        ck: &S::CommKey,
    ) -> Result<S, SSError> {
        // Check early that sufficient shares present
        let len = shares.len() as ShareId;
        if threshold > len {
            return Err(SSError::BelowThreshold(threshold, len));
        }

        let final_share = S::compute_final(shares.values().cloned().collect());
        let mut final_comm_coeffs = vec![G::Group::zero(); threshold as usize];

        for comm in coeff_comms.values() {
            for i in 0..threshold as usize {
                final_comm_coeffs[i] += comm.0[i];
            }
        }
        let comm_coeffs = G::Group::normalize_batch(&final_comm_coeffs).into();
        let final_share = S::new(participant_id, threshold, final_share);
        SecretShare::check(&final_share, &comm_coeffs, ck)?;
        Ok(final_share)
    }

    /// Update accumulator on share sent by another party. If the share verifies, stores it.
    fn update(
        &mut self,
        id: ParticipantId,
        share: S,
        commitment_coeffs: CommitmentToCoefficients<G>,
        ck: &S::CommKey,
    ) -> Result<(), SSError> {
        if self.participant_id != share.id() {
            return Err(SSError::UnequalParticipantAndShareId(
                self.participant_id,
                share.id(),
            ));
        }
        if self.threshold != share.threshold() {
            return Err(SSError::UnequalThresholdInReceivedShare(
                self.threshold,
                share.threshold(),
            ));
        }
        SecretShare::check(&share, &commitment_coeffs, ck)?;
        self.update_unchecked(id, share, commitment_coeffs);
        Ok(())
    }

    /// Update accumulator on share created by self. Assumes the share is valid
    fn update_unchecked(
        &mut self,
        id: ParticipantId,
        share: S,
        commitment_coeffs: CommitmentToCoefficients<G>,
    ) {
        self.shares.insert(id, share);
        self.coeff_comms.insert(id, commitment_coeffs);
    }
}

impl<G: AffineRepr> SharesAccumulator<G, VerifiableShare<G::ScalarField>> {
    /// Called by a participant when it has received shares from all participants. Computes the final
    /// share of the distributed secret
    pub fn finalize(
        mut self,
        ck: &PedersenCommitmentKey<G>,
    ) -> Result<VerifiableShare<G::ScalarField>, SSError> {
        let shares = core::mem::take(&mut self.shares);
        let comms = core::mem::take(&mut self.coeff_comms);
        Self::gen_final_share(self.participant_id, self.threshold, shares, comms, ck)
    }
}

impl<G: AffineRepr> SharesAccumulator<G, Share<G::ScalarField>> {
    /// Called by a participant when it has received shares from all participants. Computes the final
    /// share of the distributed secret, own public key and the threshold public key
    pub fn finalize(mut self, ck: &G) -> Result<(Share<G::ScalarField>, G, G), SSError> {
        let shares = core::mem::take(&mut self.shares);
        let comms = core::mem::take(&mut self.coeff_comms);
        Self::gen_final_share_and_public_key(self.participant_id, self.threshold, shares, comms, ck)
    }

    /// Compute the final share after receiving shares from all other participants. Also returns
    /// own public key and the threshold public key
    pub fn gen_final_share_and_public_key(
        participant_id: ParticipantId,
        threshold: ShareId,
        shares: BTreeMap<ParticipantId, Share<G::ScalarField>>,
        coeff_comms: BTreeMap<ParticipantId, CommitmentToCoefficients<G>>,
        ck: &G,
    ) -> Result<(Share<G::ScalarField>, G, G), SSError> {
        let mut threshold_pk = G::Group::zero();
        for comm in coeff_comms.values() {
            threshold_pk += comm.commitment_to_secret();
        }
        let final_share =
            Self::gen_final_share(participant_id, threshold, shares, coeff_comms, ck)?;
        let pk = ck.mul_bigint(final_share.share.into_bigint()).into_affine();
        Ok((final_share, pk, threshold_pk.into_affine()))
    }
}

/// The elliptic curve base point which is multiplied by the secret key to generate the public key
#[cfg_attr(feature = "serde", cfg_eval::cfg_eval, serde_with::serde_as)]
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicKeyBase<G: AffineRepr>(
    #[cfg_attr(feature = "serde", serde_as(as = "ArkObjectBytes"))] pub G,
);

impl<G: AffineRepr> PublicKeyBase<G> {
    pub fn new<D: Digest>(label: &[u8]) -> Self {
        Self(affine_group_element_from_byte_slices!(label))
    }
}

/// Return the Lagrange basis polynomial at x = 0 given the `x` coordinates.
/// `(x_coords[0]) * (x_coords[1]) * ... / ((x_coords[0] - i) * (x_coords[1] - i) * ...)`
/// Assumes all `x` coordinates are distinct and appropriate number of coordinates are provided
pub fn lagrange_basis_at_0<F: PrimeField>(x_coords: &[ShareId], i: ShareId) -> Result<F, SSError> {
    let mut numerator = F::one();
    let mut denominator = F::one();
    let i_f = F::from(i as u64);
    for x in x_coords {
        // Ensure no x-coordinate can be 0 since we are evaluating basis polynomial at 0
        if *x == 0 {
            return Err(SSError::XCordCantBeZero);
        }
        if *x == i {
            continue;
        }
        let x = F::from(*x as u64);
        numerator *= x;
        denominator *= x - i_f;
    }
    denominator.inverse_in_place().unwrap();
    Ok(numerator * denominator)
}

/// Return the Lagrange basis polynomial at x = 0 for each of the given `x` coordinates. Faster than
/// doing multiple calls to `lagrange_basis_at_0`
pub fn lagrange_basis_at_0_for_all<F: PrimeField>(
    x_coords: Vec<ShareId>,
) -> Result<Vec<F>, SSError> {
    let x = cfg_into_iter!(x_coords.as_slice())
        .map(|x| F::from(*x as u64))
        .collect::<Vec<_>>();
    // Ensure no x-coordinate can be 0 since we are evaluating basis polynomials at 0
    if cfg_iter!(x).any(|x_i| x_i.is_zero()) {
        return Err(SSError::XCordCantBeZero);
    }

    // Product of all `x`, i.e. \prod_{i}(x_i}
    let product = cfg_iter!(x).product::<F>();

    let r = cfg_into_iter!(x.clone())
        .map(move |i| {
            let mut denominator = cfg_iter!(x)
                .filter(|&j| &i != j)
                .map(|&j| j - i)
                .product::<F>();
            denominator.inverse_in_place().unwrap();

            // The numerator is of the form `x_1*x_2*...x_{i-1}*x_{i+1}*x_{i+2}*..` which is a product of all
            // `x` except `x_i` and thus can be calculated as \prod_{i}(x_i} * (1 / x_i)
            let numerator = product * i.inverse().unwrap();

            denominator * numerator
        })
        .collect::<Vec<_>>();
    Ok(r)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_std::{
        rand::{prelude::StdRng, SeedableRng},
        UniformRand,
    };
    use std::time::Instant;

    #[test]
    fn cannot_compute_lagrange_basis_at_0_with_0_as_x_coordinate() {
        assert!(lagrange_basis_at_0::<Fr>(&[0, 1, 2, 4], 2).is_err());
        assert!(lagrange_basis_at_0::<Fr>(&[1, 0, 2, 4], 2).is_err());
        assert!(lagrange_basis_at_0_for_all::<Fr>(vec![1, 0, 2, 4]).is_err());
        assert!(lagrange_basis_at_0_for_all::<Fr>(vec![1, 3, 0, 4]).is_err());
    }

    #[test]
    fn compare_lagrange_basis_at_0() {
        let mut rng = StdRng::seed_from_u64(0u64);

        let count = 20;
        let x = (0..count)
            .map(|_| ShareId::rand(&mut rng))
            .collect::<Vec<_>>();

        let start = Instant::now();
        let single = cfg_iter!(x)
            .map(|i| lagrange_basis_at_0(&x, *i).unwrap())
            .collect::<Vec<Fr>>();
        println!("For {} x, single took {:?}", count, start.elapsed());

        let start = Instant::now();
        let multiple = lagrange_basis_at_0_for_all(x).unwrap();
        println!("For {} x, multiple took {:?}", count, start.elapsed());

        assert_eq!(single, multiple);
    }
}
