use crate::{common::generate_secret_key_for_base, error::SmcRangeProofError};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter, io::Write, rand::RngCore, vec::Vec};
use digest::Digest;
use dock_crypto_utils::{
    concat_slices, hashing_utils::affine_group_elem_from_try_and_incr,
    msm::multiply_field_elems_with_same_group_elem,
};
use short_group_sig::{
    common::{SignatureParams, SignatureParamsWithPairing},
    weak_bb_sig::{gen_sig, PublicKeyG2, SecretKey, SignatureG1},
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Public params to prove set membership in a specific set. It contains the BB sig params, public key, the set and the
/// BB signatures on each set member.
#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SetMembershipCheckParams<E: Pairing> {
    pub bb_sig_params: SignatureParams<E>,
    pub bb_pk: PublicKeyG2<E>,
    pub set: Vec<E::ScalarField>,
    pub sigs: Vec<SignatureG1<E>>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SetMembershipCheckParamsKV<G: AffineRepr> {
    pub bb_sig_params: G,
    pub set: Vec<G::ScalarField>,
    pub sigs: Vec<G>,
}

/// Same as `SetMembershipCheckParams` but contains the precomputed pairing for a more efficient protocol execution
// Note: PartialEq cannot be implemented because of `SignatureParamsWithPairing` even when `SignatureParamsWithPairing` implements PartialEq.
// This is because of G2Prepared
// #[derive(Clone, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SetMembershipCheckParamsWithPairing<E: Pairing> {
    pub bb_sig_params: SignatureParamsWithPairing<E>,
    pub bb_pk: PublicKeyG2<E>,
    pub set: Vec<E::ScalarField>,
    pub sigs: Vec<SignatureG1<E>>,
}

impl<E: Pairing> From<SetMembershipCheckParams<E>> for SetMembershipCheckParamsWithPairing<E> {
    fn from(params: SetMembershipCheckParams<E>) -> Self {
        let bb_sig_params = SignatureParamsWithPairing::from(params.bb_sig_params.clone());
        Self {
            bb_sig_params,
            bb_pk: params.bb_pk,
            set: params.set,
            sigs: params.sigs,
        }
    }
}

macro_rules! impl_common_functions {
    ($mem_type: ty, $sig_type: path) => {
        /// No. of set members these params support
        pub fn supported_set_size(&self) -> usize {
            self.set.len()
        }

        /// The maximum base these params support for range-proof.
        pub fn get_max_base_for_range_proof(&self) -> u16 {
            self.supported_set_size() as u16
        }

        /// Check if the given base can be used with these params
        pub fn validate_base(&self, base: u16) -> Result<(), SmcRangeProofError> {
            // If params support a larger base, then its fine.
            if self.get_max_base_for_range_proof() < base {
                return Err(SmcRangeProofError::UnsupportedBase(
                    base,
                    self.get_max_base_for_range_proof(),
                ));
            }
            Ok(())
        }

        /// Get signature for the given member
        pub fn get_sig_for_member(
            &self,
            member: &$mem_type,
        ) -> Result<&$sig_type, SmcRangeProofError> {
            let member_idx = match self.set.iter().position(|&s| s == *member) {
                Some(m) => m,
                None => return Err(SmcRangeProofError::CannotFindElementInSet),
            };
            Ok(&self.sigs[member_idx])
        }
    };
}

impl<E: Pairing> SetMembershipCheckParams<E> {
    /// Create new params for a given set and return the BB secret key. The secret key should be discarded. `label` is to
    /// generate the BB sig params
    pub fn new<R: RngCore, D: Digest>(
        rng: &mut R,
        label: &[u8],
        set: Vec<E::ScalarField>,
    ) -> (Self, SecretKey<E::ScalarField>) {
        let sig_params = SignatureParams::new::<D>(label);
        Self::new_given_sig_params(rng, set, sig_params)
    }

    /// Create new params when the set-membership check protocol is used for a range proof. The set in
    /// this case consists of elements `(0, 1, 2, 3, ..., base-1)`
    pub fn new_for_range_proof<R: RngCore, D: Digest>(
        rng: &mut R,
        label: &[u8],
        base: u16,
    ) -> (Self, SecretKey<E::ScalarField>) {
        let sig_params = SignatureParams::new::<D>(label);
        Self::new_for_range_proof_given_sig_params(rng, base, sig_params)
    }

    /// Same as `Self::new` except that it accepts already created BB sig params
    pub fn new_given_sig_params<R: RngCore>(
        rng: &mut R,
        set: Vec<E::ScalarField>,
        sig_params: SignatureParams<E>,
    ) -> (Self, SecretKey<E::ScalarField>) {
        let sk = SecretKey::new(rng);
        Self::new_given_sig_params_and_secret_key(set, sig_params, sk)
    }

    pub fn new_given_sig_params_and_secret_key(
        set: Vec<E::ScalarField>,
        sig_params: SignatureParams<E>,
        sk: SecretKey<E::ScalarField>,
    ) -> (Self, SecretKey<E::ScalarField>) {
        let pk = PublicKeyG2::generate_using_secret_key(&sk, &sig_params);
        let sigs = cfg_iter!(set)
            .map(|i| SignatureG1::new(i, &sk, &sig_params))
            .collect();
        (
            Self {
                bb_sig_params: sig_params,
                bb_pk: pk,
                set,
                sigs,
            },
            sk,
        )
    }

    /// Same as `Self::new_for_range_proof` except that it accepts already created BB sig params
    pub fn new_for_range_proof_given_sig_params<R: RngCore>(
        rng: &mut R,
        base: u16,
        sig_params: SignatureParams<E>,
    ) -> (Self, SecretKey<E::ScalarField>) {
        let set = cfg_into_iter!(0..base)
            .map(|i| E::ScalarField::from(i))
            .collect();
        let sk = generate_secret_key_for_base::<R, E::ScalarField>(rng, base);
        Self::new_given_sig_params_and_secret_key(set, sig_params, sk)
    }

    /// Verify each signature in the params
    pub fn verify(&self) -> Result<(), SmcRangeProofError> {
        let params = SetMembershipCheckParamsWithPairing::from(self.clone());
        params.verify()
    }

    pub fn serialize_for_schnorr_protocol<W: Write>(
        &self,
        mut writer: W,
    ) -> Result<(), SmcRangeProofError> {
        self.bb_sig_params.g1.serialize_compressed(&mut writer)?;
        self.bb_sig_params.g2.serialize_compressed(&mut writer)?;
        self.bb_pk.0.serialize_compressed(&mut writer)?;
        Ok(())
    }

    impl_common_functions!(E::ScalarField, SignatureG1<E>);
}

impl<E: Pairing> SetMembershipCheckParamsWithPairing<E> {
    pub fn verify(&self) -> Result<(), SmcRangeProofError> {
        if self.sigs.len() != self.set.len() {
            return Err(SmcRangeProofError::InvalidSetMembershipSetup);
        }
        let gm = multiply_field_elems_with_same_group_elem(
            self.bb_sig_params.g2.into_group(),
            &self.set,
        );
        let r = gm.iter().zip(self.sigs.iter()).all(|(gm_i, sig)| {
            sig.is_non_zero() && (E::pairing(sig.0, self.bb_pk.0 + gm_i) == self.bb_sig_params.g1g2)
        });
        if !r {
            return Err(SmcRangeProofError::InvalidSetMembershipSetup);
        }
        Ok(())
    }

    pub fn serialize_for_schnorr_protocol<W: Write>(
        &self,
        mut writer: W,
    ) -> Result<(), SmcRangeProofError> {
        self.bb_sig_params.g1.serialize_compressed(&mut writer)?;
        self.bb_sig_params.g2.serialize_compressed(&mut writer)?;
        self.bb_pk.0.serialize_compressed(&mut writer)?;
        Ok(())
    }

    impl_common_functions!(E::ScalarField, SignatureG1<E>);
}

impl<G: AffineRepr> SetMembershipCheckParamsKV<G> {
    /// Create new params for a given set and return the BB secret key. The secret key should be discarded. `label` is to
    /// generate the BB sig params
    pub fn new<R: RngCore, D: Digest>(
        rng: &mut R,
        label: &[u8],
        set: Vec<G::ScalarField>,
    ) -> (Self, SecretKey<G::ScalarField>) {
        let sig_params =
            affine_group_elem_from_try_and_incr::<G, D>(&concat_slices![label, b" : g1"]);
        Self::new_given_sig_params(rng, set, sig_params)
    }

    /// Create new params when the set-membership check protocol is used for a range proof. The set in
    /// this case consists of elements `(0, 1, 2, 3, ..., base-1)`
    pub fn new_for_range_proof<R: RngCore, D: Digest>(
        rng: &mut R,
        label: &[u8],
        base: u16,
    ) -> (Self, SecretKey<G::ScalarField>) {
        let sig_params =
            affine_group_elem_from_try_and_incr::<G, D>(&concat_slices![label, b" : g1"]);
        Self::new_for_range_proof_given_sig_params(rng, base, sig_params)
    }

    /// Same as `Self::new` except that it accepts already created BB sig params
    pub fn new_given_sig_params<R: RngCore>(
        rng: &mut R,
        set: Vec<G::ScalarField>,
        sig_params: G,
    ) -> (Self, SecretKey<G::ScalarField>) {
        let sk = SecretKey::new(rng);
        Self::new_given_sig_params_and_secret_key(set, sig_params, sk)
    }

    pub fn new_for_range_proof_given_sig_params<R: RngCore>(
        rng: &mut R,
        base: u16,
        sig_params: G,
    ) -> (Self, SecretKey<G::ScalarField>) {
        let set = cfg_into_iter!(0..base)
            .map(|i| G::ScalarField::from(i))
            .collect();
        let sk = generate_secret_key_for_base::<R, G::ScalarField>(rng, base);
        Self::new_given_sig_params_and_secret_key(set, sig_params, sk)
    }

    pub fn new_given_sig_params_and_secret_key(
        set: Vec<G::ScalarField>,
        sig_params: G,
        sk: SecretKey<G::ScalarField>,
    ) -> (Self, SecretKey<G::ScalarField>) {
        let sigs = cfg_iter!(set)
            .map(|i| gen_sig::<G>(i, &sk, &sig_params))
            .collect();
        (
            Self {
                bb_sig_params: sig_params,
                set,
                sigs,
            },
            sk,
        )
    }

    pub fn serialize_for_schnorr_protocol<W: Write>(
        &self,
        mut writer: W,
    ) -> Result<(), SmcRangeProofError> {
        self.bb_sig_params.serialize_compressed(&mut writer)?;
        Ok(())
    }

    impl_common_functions!(G::ScalarField, G);
}
