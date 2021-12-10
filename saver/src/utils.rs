use ark_ec::ProjectiveCurve;

pub(crate) fn batch_normalize_projective_into_affine<G: ProjectiveCurve>(
    mut v: Vec<G>,
) -> Vec<G::Affine> {
    G::batch_normalization(&mut v);
    v.into_iter().map(|v| v.into()).collect()
}
