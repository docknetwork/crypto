use crate::error::Error;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, vec, vec::Vec, UniformRand};
use core::ops::{Add, Sub};
use dock_crypto_utils::commitment::PedersenCommitmentKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A Pedersen commitment to a value. Encapsulates the `value` and `randomness` as well.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct CommitmentWithOpening<G: AffineRepr> {
    #[zeroize(skip)]
    pub comm: G,
    pub value: G::ScalarField,
    pub randomness: G::ScalarField,
}

/// A pair of Pedersen commitment, one for each coordinate of an Elliptic curve point.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct PointCommitment<G: AffineRepr> {
    /// Pedersen commitment of `x` coordinate
    pub x: G,
    /// Pedersen commitment of `y` coordinate
    pub y: G,
}

/// A pair of Pedersen commitment, one for each coordinate of an Elliptic curve point. Encapsulates the coordinates
/// and randomness in each commitment as well.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PointCommitmentWithOpening<G: AffineRepr> {
    /// `x` coordinate
    pub x: G::ScalarField,
    /// Randomness in the commitment of `x` coordinate
    pub r_x: G::ScalarField,
    /// `y` coordinate
    pub y: G::ScalarField,
    /// Randomness in the commitment of `y` coordinate
    pub r_y: G::ScalarField,
    #[zeroize(skip)]
    pub comm: PointCommitment<G>,
}

impl<C: AffineRepr> PointCommitmentWithOpening<C> {
    pub fn new<R: RngCore, P: AffineRepr>(
        rng: &mut R,
        point: &P,
        comm_key: &PedersenCommitmentKey<C>,
    ) -> Result<Self, Error> {
        let r_x = C::ScalarField::rand(rng);
        let r_y = C::ScalarField::rand(rng);
        Self::new_given_randomness(point, r_x, r_y, comm_key)
    }

    /// `r_x` and `r_y` are randomness in the Pedersen commitments to x and y coordinates respectively
    pub fn new_given_randomness<P: AffineRepr>(
        point: &P,
        r_x: C::ScalarField,
        r_y: C::ScalarField,
        comm_key: &PedersenCommitmentKey<C>,
    ) -> Result<Self, Error> {
        let (x, y) = point_coords_as_scalar_field_elements::<P, C>(point)?;
        Ok(Self::new_given_randomness_and_coords(
            x, y, r_x, r_y, comm_key,
        ))
    }

    pub fn new_given_randomness_and_coords(
        x: C::ScalarField,
        y: C::ScalarField,
        r_x: C::ScalarField,
        r_y: C::ScalarField,
        comm_key: &PedersenCommitmentKey<C>,
    ) -> Self {
        let comm_x = comm_key.commit(&x, &r_x);
        let comm_y = comm_key.commit(&y, &r_y);
        Self {
            x,
            y,
            r_x,
            r_y,
            comm: PointCommitment {
                x: comm_x,
                y: comm_y,
            },
        }
    }
}

impl<G: AffineRepr> Add for &PointCommitment<G> {
    type Output = PointCommitment<G>;

    fn add(self, rhs: Self) -> Self::Output {
        PointCommitment {
            x: (self.x + rhs.x).into_affine(),
            y: (self.y + rhs.y).into_affine(),
        }
    }
}

impl<G: AffineRepr> Sub for &PointCommitment<G> {
    type Output = PointCommitment<G>;

    fn sub(self, rhs: Self) -> Self::Output {
        PointCommitment {
            x: (self.x.into_group() - rhs.x).into_affine(),
            y: (self.y.into_group() - rhs.y).into_affine(),
        }
    }
}

impl<G: AffineRepr> Add for &PointCommitmentWithOpening<G> {
    type Output = PointCommitmentWithOpening<G>;

    fn add(self, rhs: Self) -> Self::Output {
        PointCommitmentWithOpening {
            x: self.x + rhs.x,
            r_x: self.r_x + rhs.r_x,
            y: self.y + rhs.y,
            r_y: self.r_y + rhs.r_y,
            comm: &self.comm + &rhs.comm,
        }
    }
}

impl<G: AffineRepr> Sub for &PointCommitmentWithOpening<G> {
    type Output = PointCommitmentWithOpening<G>;

    fn sub(self, rhs: Self) -> Self::Output {
        PointCommitmentWithOpening {
            x: self.x - rhs.x,
            r_x: self.r_x - rhs.r_x,
            y: self.y - rhs.y,
            r_y: self.r_y - rhs.r_y,
            comm: &self.comm - &rhs.comm,
        }
    }
}

impl<G: AffineRepr> CommitmentWithOpening<G> {
    pub fn new<R: RngCore>(
        rng: &mut R,
        value: G::ScalarField,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> Self {
        let randomness = G::ScalarField::rand(rng);
        let comm = comm_key.commit(&value, &randomness);
        Self {
            value,
            randomness,
            comm,
        }
    }

    pub fn new_given_randomness(
        value: G::ScalarField,
        randomness: G::ScalarField,
        comm_key: &PedersenCommitmentKey<G>,
    ) -> Self {
        let comm = comm_key.commit(&value, &randomness);
        Self {
            value,
            randomness,
            comm,
        }
    }
}

/// Converts the `x` and `y` coordinates of the point in group `P` as scalars of group `G`
/// Expects the extension degree of `P`'s base field to be 1 and expects the base field of `P` to be same as
/// scalar field of `G`
pub fn point_coords_as_scalar_field_elements<P: AffineRepr, G: AffineRepr>(
    point: &P,
) -> Result<(G::ScalarField, G::ScalarField), Error> {
    if G::ScalarField::MODULUS.to_bytes_le()
        != <P::BaseField as Field>::BasePrimeField::MODULUS.to_bytes_le()
    {
        return Err(Error::ScalarFieldBaseFieldMismatch);
    }
    if P::BaseField::extension_degree() != 1 {
        return Err(Error::CannotCommitToExtensionOfDegree(
            P::BaseField::extension_degree(),
        ));
    }
    let xy = point.xy().ok_or(Error::PointAtInfinity)?;
    let mut bytes = vec![];
    let x = {
        for b in xy.0.to_base_prime_field_elements() {
            bytes = b.into_bigint().to_bytes_le();
        }
        G::ScalarField::from_le_bytes_mod_order(&bytes)
    };
    let y = {
        for b in xy.1.to_base_prime_field_elements() {
            bytes = b.into_bigint().to_bytes_le();
        }
        G::ScalarField::from_le_bytes_mod_order(&bytes)
    };
    Ok((x, y))
}

/// Converts an element of a base field `B` to an element of the scalar field `S`.
/// Expects the extension degree of `B`'s base field to be 1
pub fn from_base_field_to_scalar_field<B: Field, S: PrimeField>(c: &B) -> S {
    let mut bytes = vec![];
    for b in c.to_base_prime_field_elements() {
        bytes = b.into_bigint().to_bytes_le();
    }
    S::from_le_bytes_mod_order(&bytes)
}
