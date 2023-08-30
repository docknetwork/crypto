use crate::aggregation::key::PreparedVKey;
use ark_ec::{pairing::Pairing, scalar_mul::fixed_base::FixedBase, AffineRepr, CurveGroup, Group};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    format,
    io::{Read, Write},
    ops::MulAssign,
    rand::Rng,
    string::ToString,
    vec::Vec,
    One, UniformRand,
};

use super::{
    error::AggregationError,
    key::{VKey, WKey},
};

/// Maximum size of the generic SRS constructed from Filecoin and Zcash power of
/// taus.
///
/// <https://github.com/nikkolasg/taupipp/blob/baca1426266bf39416c45303e35c966d69f4f8b4/src/bin/assemble.rs#L12>
pub const MAX_SRS_SIZE: usize = (2 << 19) + 1;

/// It contains the maximum number of raw elements of the SRS needed to
/// aggregate and verify Groth16 proofs. One can derive specialized prover and
/// verifier key for _specific_ size of aggregations by calling
/// `srs.specialize(n)`. The specialized prover key also contains precomputed
/// tables that drastically increase prover's performance.  This GenericSRS is
/// usually formed from the transcript of two distinct power of taus ceremony
/// ,in other words from two distinct Groth16 CRS.
/// See [there](https://github.com/nikkolasg/taupipp) a way on how to generate
/// this GenesisSRS.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct GenericSRS<E: Pairing> {
    /// $\{g^a^i\}_{i=0}^{N}$ where N is the smallest size of the two Groth16 CRS.
    pub g_alpha_powers: Vec<E::G1Affine>,
    /// $\{h^a^i\}_{i=0}^{N}$ where N is the smallest size of the two Groth16 CRS.
    pub h_alpha_powers: Vec<E::G2Affine>,
    /// $\{g^b^i\}_{i=n}^{N}$ where N is the smallest size of the two Groth16 CRS.
    pub g_beta_powers: Vec<E::G1Affine>,
    /// $\{h^b^i\}_{i=0}^{N}$ where N is the smallest size of the two Groth16 CRS.
    pub h_beta_powers: Vec<E::G2Affine>,
}

/// ProverSRS is the specialized SRS version for the prover for a specific number of proofs to
/// aggregate. It contains as well the commitment keys for this specific size.
/// Note the size must be a power of two for the moment - if it is not, padding must be
/// applied.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProverSRS<E: Pairing> {
    /// number of proofs to aggregate
    pub n: u32,
    /// $\{g^a^i\}_{i=0}^{2n-1}$ where n is the number of proofs to be aggregated
    /// We take all powers instead of only ones from n -> 2n-1 (w commitment key
    /// is formed from these powers) since the prover will create a shifted
    /// polynomial of degree 2n-1 when doing the KZG opening proof.
    pub g_alpha_powers_table: Vec<E::G1Affine>,
    /// $\{h^a^i\}_{i=0}^{n-1}$ - here we don't need to go to 2n-1 since v
    /// commitment key only goes up to n-1 exponent.
    pub h_alpha_powers_table: Vec<E::G2Affine>,
    /// $\{g^b^i\}_{i=0}^{2n-1}$
    pub g_beta_powers_table: Vec<E::G1Affine>,
    /// $\{h^b^i\}_{i=0}^{n-1}$
    pub h_beta_powers_table: Vec<E::G2Affine>,
    /// commitment key using in MIPP and TIPP
    pub vkey: VKey<E>,
    /// commitment key using in TIPP
    pub wkey: WKey<E>,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PreparedProverSRS<E: Pairing> {
    /// number of proofs to aggregate
    pub n: u32,
    /// $\{g^a^i\}_{i=0}^{2n-1}$ where n is the number of proofs to be aggregated
    /// We take all powers instead of only ones from n -> 2n-1 (w commitment key
    /// is formed from these powers) since the prover will create a shifted
    /// polynomial of degree 2n-1 when doing the KZG opening proof.
    pub g_alpha_powers_table: Vec<E::G1Affine>,
    /// $\{h^a^i\}_{i=0}^{n-1}$ - here we don't need to go to 2n-1 since v
    /// commitment key only goes up to n-1 exponent.
    pub h_alpha_powers_table: Vec<E::G2Affine>,
    /// $\{g^b^i\}_{i=0}^{2n-1}$
    pub g_beta_powers_table: Vec<E::G1Affine>,
    /// $\{h^b^i\}_{i=0}^{n-1}$
    pub h_beta_powers_table: Vec<E::G2Affine>,
    /// commitment key using in MIPP and TIPP
    pub vkey: VKey<E>,
    pub prepared_vkey: PreparedVKey<E>,
    /// commitment key using in TIPP
    pub wkey: WKey<E>,
}

/// Contains the necessary elements to verify an aggregated Groth16 proof; it is of fixed size
/// regardless of the number of proofs aggregated. However, a prover SRS will be determined by
/// the number of proofs being aggregated.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierSRS<E: Pairing> {
    pub n: u32,
    pub g: E::G1Affine,
    pub h: E::G2Affine,
    pub g_alpha: E::G1Affine,
    pub g_beta: E::G1Affine,
    pub h_alpha: E::G2Affine,
    pub h_beta: E::G2Affine,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifierSRSProjective<E: Pairing> {
    pub n: u32,
    pub g: E::G1,
    pub h: E::G2,
    pub g_alpha: E::G1,
    pub g_beta: E::G1,
    pub h_alpha: E::G2,
    pub h_beta: E::G2,
}

impl<E: Pairing> PartialEq for GenericSRS<E> {
    fn eq(&self, other: &Self) -> bool {
        self.g_alpha_powers == other.g_alpha_powers
            && self.g_beta_powers == other.g_beta_powers
            && self.h_alpha_powers == other.h_alpha_powers
            && self.h_beta_powers == other.h_beta_powers
    }
}

impl<E: Pairing> ProverSRS<E> {
    /// Returns true if commitment keys have the exact required length.
    /// It is necessary for the IPP scheme to work that commitment
    /// key have the exact same number of arguments as the number of proofs to
    /// aggregate.
    pub fn has_correct_len(&self, n: usize) -> bool {
        self.vkey.has_correct_len(n) && self.wkey.has_correct_len(n)
    }

    pub fn len(&self) -> usize {
        self.vkey.a.len()
    }
}

impl<E: Pairing> VerifierSRS<E> {
    pub fn to_projective(&self) -> VerifierSRSProjective<E> {
        VerifierSRSProjective {
            n: self.n,
            g: self.g.into_group(),
            h: self.h.into_group(),
            g_alpha: self.g_alpha.into_group(),
            g_beta: self.g_beta.into_group(),
            h_alpha: self.h_alpha.into_group(),
            h_beta: self.h_beta.into_group(),
        }
    }
}

impl<E: Pairing> From<ProverSRS<E>> for PreparedProverSRS<E> {
    fn from(srs: ProverSRS<E>) -> Self {
        let prepared_vkey = PreparedVKey::from(&srs.vkey);
        Self {
            n: srs.n,
            g_alpha_powers_table: srs.g_alpha_powers_table,
            h_alpha_powers_table: srs.h_alpha_powers_table,
            g_beta_powers_table: srs.g_beta_powers_table,
            h_beta_powers_table: srs.h_beta_powers_table,
            vkey: srs.vkey,
            prepared_vkey,
            wkey: srs.wkey,
        }
    }
}

impl<E: Pairing> PreparedProverSRS<E> {
    /// Returns true if commitment keys have the exact required length.
    /// It is necessary for the IPP scheme to work that commitment
    /// key have the exact same number of arguments as the number of proofs to
    /// aggregate.
    pub fn has_correct_len(&self, n: usize) -> bool {
        self.vkey.has_correct_len(n) && self.wkey.has_correct_len(n)
    }

    pub fn len(&self) -> usize {
        self.vkey.a.len()
    }

    pub fn extract_prepared(self) -> (PreparedVKey<E>, ProverSRS<E>) {
        let PreparedProverSRS {
            n,
            g_alpha_powers_table,
            h_alpha_powers_table,
            g_beta_powers_table,
            h_beta_powers_table,
            vkey,
            prepared_vkey,
            wkey,
        } = self;
        (
            prepared_vkey,
            ProverSRS {
                n,
                g_alpha_powers_table,
                h_alpha_powers_table,
                g_beta_powers_table,
                h_beta_powers_table,
                vkey,
                wkey,
            },
        )
    }
}

impl<E: Pairing> GenericSRS<E> {
    /// specializes returns the prover and verifier SRS for a specific number of
    /// proofs to aggregate. The number of proofs MUST BE a power of two, it
    /// panics otherwise. The number of proofs must be inferior to half of the
    /// size of the generic srs otherwise it panics.
    pub fn specialize(&self, num_proofs: u32) -> (ProverSRS<E>, VerifierSRS<E>) {
        assert!(num_proofs.is_power_of_two());
        let n = num_proofs as usize;

        let tn = 2 * n as usize; // size of the CRS we need
        assert!(self.g_alpha_powers.len() >= tn);
        assert!(self.h_alpha_powers.len() >= tn);
        assert!(self.g_beta_powers.len() >= tn);
        assert!(self.h_beta_powers.len() >= tn);

        // when doing the KZG opening we need _all_ coefficients from 0
        // to 2n-1 because the polynomial is of degree 2n-1.
        let g_low = 0;
        let g_up = tn;
        let h_low = 0;
        let h_up = h_low + n;
        // TODO  precompute window
        let g_alpha_powers_table = self.g_alpha_powers[g_low..g_up].to_vec();
        let g_beta_powers_table = self.g_beta_powers[g_low..g_up].to_vec();
        let h_alpha_powers_table = self.h_alpha_powers[h_low..h_up].to_vec();
        let h_beta_powers_table = self.h_beta_powers[h_low..h_up].to_vec();

        let v1 = self.h_alpha_powers[h_low..h_up].to_vec();
        let v2 = self.h_beta_powers[h_low..h_up].to_vec();
        let vkey = VKey::<E> { a: v1, b: v2 };
        assert!(vkey.has_correct_len(n));
        // however, here we only need the "right" shifted bases for the
        // commitment scheme.
        let w1 = self.g_alpha_powers[n..g_up].to_vec();
        let w2 = self.g_beta_powers[n..g_up].to_vec();
        let wkey = WKey::<E> { a: w1, b: w2 };
        assert!(wkey.has_correct_len(n));
        let pk = ProverSRS::<E> {
            g_alpha_powers_table,
            g_beta_powers_table,
            h_alpha_powers_table,
            h_beta_powers_table,
            vkey,
            wkey,
            n: num_proofs,
        };
        let vk = VerifierSRS::<E> {
            n: num_proofs,
            g: self.g_alpha_powers[0],
            h: self.h_alpha_powers[0],
            g_alpha: self.g_alpha_powers[1],
            g_beta: self.g_beta_powers[1],
            h_alpha: self.h_alpha_powers[1],
            h_beta: self.h_beta_powers[1],
        };
        (pk, vk)
    }

    pub fn write<W: Write>(&self, mut writer: W) -> Result<(), AggregationError> {
        (self.g_alpha_powers.len() as u32).serialize_compressed(&mut writer)?;
        write_vec(
            &mut writer,
            &self
                .g_alpha_powers
                .iter()
                .map(|e| e.into_group())
                .collect::<Vec<E::G1>>(),
        )?;
        write_vec(
            &mut writer,
            &self
                .g_beta_powers
                .iter()
                .map(|e| e.into_group())
                .collect::<Vec<E::G1>>(),
        )?;
        write_vec(
            &mut writer,
            &self
                .h_alpha_powers
                .iter()
                .map(|e| e.into_group())
                .collect::<Vec<E::G2>>(),
        )?;
        write_vec(
            &mut writer,
            &self
                .h_beta_powers
                .iter()
                .map(|e| e.into_group())
                .collect::<Vec<E::G2>>(),
        )?;
        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> Result<Self, AggregationError> {
        let len = u32::deserialize_uncompressed(&mut reader)
            .map_err(|e| AggregationError::Serialization(e.to_string()))?;
        if len > MAX_SRS_SIZE as u32 {
            return Err(AggregationError::InvalidSRS(
                format!("SRS len {} > maximum {}", len, MAX_SRS_SIZE).to_string(),
            ));
        }

        let g_alpha_powers = read_vec(len, &mut reader)
            .map_err(|e| AggregationError::Serialization(e.to_string()))?;
        let g_beta_powers = read_vec(len, &mut reader)
            .map_err(|e| AggregationError::Serialization(e.to_string()))?;
        let h_alpha_powers = read_vec(len, &mut reader)
            .map_err(|e| AggregationError::Serialization(e.to_string()))?;
        let h_beta_powers = read_vec(len, &mut reader)
            .map_err(|e| AggregationError::Serialization(e.to_string()))?;

        Ok(Self {
            g_alpha_powers,
            g_beta_powers,
            h_alpha_powers,
            h_beta_powers,
        })
    }
}

/// Generates a SRS of the given size. It must NOT be used in production, only
/// in testing, as this is insecure given we know the secret exponent of the SRS.
pub fn setup_fake_srs<E: Pairing, R: Rng>(rng: &mut R, size: u32) -> GenericSRS<E> {
    let alpha = E::ScalarField::rand(rng);
    let beta = E::ScalarField::rand(rng);
    let g = E::G1::generator();
    let h = E::G2::generator();

    let mut g_alpha_powers = Vec::new();
    let mut g_beta_powers = Vec::new();
    let mut h_alpha_powers = Vec::new();
    let mut h_beta_powers = Vec::new();

    #[cfg(feature = "parallel")]
    rayon::scope(|s| {
        let alpha = &alpha;
        let h = &h;
        let g = &g;
        let beta = &beta;
        let g_alpha_powers = &mut g_alpha_powers;
        s.spawn(move |_| {
            *g_alpha_powers = structured_generators_scalar_power(2 * size as usize, g, alpha);
        });
        let g_beta_powers = &mut g_beta_powers;
        s.spawn(move |_| {
            *g_beta_powers = structured_generators_scalar_power(2 * size as usize, g, beta);
        });

        let h_alpha_powers = &mut h_alpha_powers;
        s.spawn(move |_| {
            *h_alpha_powers = structured_generators_scalar_power(2 * size as usize, h, alpha);
        });

        let h_beta_powers = &mut h_beta_powers;
        s.spawn(move |_| {
            *h_beta_powers = structured_generators_scalar_power(2 * size as usize, h, beta);
        });
    });

    #[cfg(not(feature = "parallel"))]
    {
        g_alpha_powers = structured_generators_scalar_power(2 * size as usize, &g, &alpha);
        g_beta_powers = structured_generators_scalar_power(2 * size as usize, &g, &beta);
        h_alpha_powers = structured_generators_scalar_power(2 * size as usize, &h, &alpha);
        h_beta_powers = structured_generators_scalar_power(2 * size as usize, &h, &beta);
    }

    debug_assert!(h_alpha_powers[0] == E::G2Affine::generator());
    debug_assert!(h_beta_powers[0] == E::G2Affine::generator());
    debug_assert!(g_alpha_powers[0] == E::G1Affine::generator());
    debug_assert!(g_beta_powers[0] == E::G1Affine::generator());
    GenericSRS {
        g_alpha_powers,
        g_beta_powers,
        h_alpha_powers,
        h_beta_powers,
    }
}

pub(crate) fn structured_generators_scalar_power<G: CurveGroup>(
    num: usize,
    g: &G,
    s: &G::ScalarField,
) -> Vec<G::Affine> {
    assert!(num > 0);
    let mut powers_of_scalar = Vec::with_capacity(num);
    let mut pow_s = G::ScalarField::one();
    for _ in 0..num {
        powers_of_scalar.push(pow_s);
        pow_s.mul_assign(s);
    }
    let scalar_bits = G::ScalarField::MODULUS_BIT_SIZE as usize;
    let window_size = FixedBase::get_mul_window_size(num);
    let g_table = FixedBase::get_window_table::<G>(scalar_bits, window_size, g.clone());
    let powers_of_g =
        FixedBase::msm::<G>(scalar_bits, window_size, &g_table, &powers_of_scalar[..]);
    G::normalize_batch(&powers_of_g)
}

fn write_vec<G: CurveGroup, W: Write>(mut w: W, v: &[G]) -> Result<(), SerializationError> {
    for p in v {
        p.serialize_compressed(&mut w)?;
    }
    Ok(())
}

fn read_vec<G: CanonicalDeserialize, R: Read>(
    len: u32,
    mut r: R,
) -> Result<Vec<G>, SerializationError> {
    (0..len)
        .map(|_| G::deserialize_compressed(&mut r))
        .collect()
}
