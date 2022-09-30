use ark_ec::ProjectiveCurve;
use ark_std::{cfg_into_iter, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::iter::{IntoParallelIterator, ParallelIterator};

pub fn batch_normalize_projective_into_affine<G: ProjectiveCurve>(mut v: Vec<G>) -> Vec<G::Affine> {
    G::batch_normalization(&mut v);
    cfg_into_iter!(v).map(|v| v.into()).collect()
}
