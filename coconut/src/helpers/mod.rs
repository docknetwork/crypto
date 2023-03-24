use alloc::{format, string::String, vec::Vec};

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use ark_std::{cfg_into_iter, cfg_iter, rand::RngCore};

use dock_crypto_utils::msm::multiply_field_elems_with_same_group_elem;

use schnorr_pok::error::SchnorrError;

pub mod owned_pairs;
pub mod pairs;
pub mod with_schnorr_and_blindings;
pub mod with_schnorr_response;

pub use dock_crypto_utils::aliases::*;
pub use dock_crypto_utils::extend_some::*;
pub use dock_crypto_utils::iter::{self, *};
pub use dock_crypto_utils::try_iter::{self, *};
pub use iter::*;
pub use owned_pairs::*;
pub use pairs::*;
pub use try_iter::*;
pub use with_schnorr_and_blindings::*;
pub use with_schnorr_response::*;

use dock_crypto_utils::{impl_indexed_iter, impl_into_indexed_iter, join};

/// Generates an iterator of randoms producing `count` elements using the supplied `rng`.
pub fn n_rand<T: UniformRand, R: RngCore>(
    rng: &'_ mut R,
    count: usize,
) -> impl Iterator<Item = T> + '_ {
    (0..count).map(move |_| rand(rng))
}

/// Generates a random using given `rng`.
pub fn rand<T: UniformRand, R: RngCore>(rng: &mut R) -> T {
    UniformRand::rand(rng)
}

#[cfg(test)]
/// Skips up to `n` elements from the iterator using supplied random generator.
pub fn skip_up_to_n<'rng, I>(
    rng: &'rng mut impl ark_std::rand::RngCore,
    iter: I,
    mut allowed_to_skip: usize,
) -> impl Iterator<Item = I::Item> + 'rng
where
    I: IntoIterator + 'rng,
{
    iter.into_iter().filter(move |_| {
        use ark_std::rand::Rng;

        let res = allowed_to_skip == 0 || rng.gen_bool(0.5);
        if !res {
            allowed_to_skip -= 1;
        }

        res
    })
}

/// TODO remove when `SchnorrError` will derive `Eq`, `PartialEq`, `Clone`
pub fn schnorr_error(err: SchnorrError) -> String {
    format!("{:?}", err)
}

/// Produces points by multiplying supplied base by the provided scalars.
pub fn points<G: AffineRepr>(base: &G, scalars: &[G::ScalarField]) -> Vec<G> {
    let group = base.into_group();
    let products = multiply_field_elems_with_same_group_elem(group, scalars);

    G::Group::normalize_batch(&products)
}

/// `l_{i ∈ S} = \prod_{j ∈ S, j != i}((0 - j) / (i - j))`
#[allow(non_snake_case)]
pub fn lagrange_basis_at_0<F: PrimeField>(
    S: impl_into_indexed_iter!(<Item = impl Into<F>>),
) -> impl_indexed_iter!(<Item = F>) {
    let items: Vec<_> = cfg_into_iter!(S).map(Into::into).collect();
    let all_i_prod: F = cfg_iter!(items).product();

    cfg_into_iter!(items.clone()).map(move |i| {
        let (num, den) = join!(all_i_prod / i, {
            let mut prod: F = cfg_iter!(items)
                .filter(|&j| &i != j)
                .map(|&j| j - i)
                .product();
            prod.inverse_in_place().unwrap();

            prod
        });

        num * den
    })
}
