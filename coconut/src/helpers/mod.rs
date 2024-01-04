//! Miscellaneous helpers and re-exports from `dock_crypto_utils`.

use alloc::{format, string::String, vec::Vec};

use ark_ff::PrimeField;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use ark_std::{cfg_into_iter, cfg_iter};

use schnorr_pok::error::SchnorrError;

pub mod with_schnorr_and_blindings;
pub mod with_schnorr_response;

pub use utils::{
    aliases::*, extend_some::*, iter::*, misc::*, owned_pairs::*, pairs::*, try_iter::*,
};
pub use with_schnorr_and_blindings::*;
pub use with_schnorr_response::*;

use utils::{impl_indexed_iter, impl_into_indexed_iter, join};

/// TODO remove when `SchnorrError` will derive `Eq`, `PartialEq`, `Clone`
pub fn schnorr_error(err: SchnorrError) -> String {
    format!("{:?}", err)
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
