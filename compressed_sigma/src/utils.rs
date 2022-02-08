use ark_ec::AffineCurve;
use ark_std::vec::Vec;

use crate::transforms::Homomorphism;

pub fn pad_homomorphisms_to_have_same_size<
    G: AffineCurve,
    F: Homomorphism<G::ScalarField, Output = G>,
>(
    fs: &[F],
) -> Vec<F> {
    let mut max_size = 0;
    for f in fs {
        if f.size() > max_size {
            max_size = f.size();
        }
    }
    fs.iter().map(|f| f.pad(max_size)).collect()
}

macro_rules! impl_simple_homomorphism {
    ($name: ident, $preimage_type: ty, $image_type: ty) => {
        impl Homomorphism<$preimage_type> for $name<$image_type> {
            type Output = $image_type;
            fn eval(&self, x: &[$preimage_type]) -> Self::Output {
                VariableBaseMSM::multi_scalar_mul(
                    &self.constants,
                    x.iter()
                        .map(|x| x.into_repr())
                        .collect::<Vec<_>>()
                        .as_slice(),
                )
                .into_affine()
            }

            fn scale(&self, scalar: &$preimage_type) -> Self {
                let s = scalar.into_repr();
                let scaled = self.constants.iter().map(|c| c.mul(s)).collect::<Vec<_>>();
                Self {
                    constants: batch_normalize_projective_into_affine(scaled),
                }
            }

            fn add(&self, other: &Self) -> Self {
                Self {
                    constants: self
                        .constants
                        .iter()
                        .zip(other.constants.iter())
                        .map(|(a, b)| *a + *b)
                        .collect::<Vec<_>>(),
                }
            }

            fn split_in_half(&self) -> (Self, Self) {
                (
                    Self {
                        constants: self.constants[..self.constants.len() / 2].to_vec(),
                    },
                    Self {
                        constants: self.constants[self.constants.len() / 2..].to_vec(),
                    },
                )
            }

            fn size(&self) -> usize {
                self.constants.len()
            }

            fn pad(&self, new_size: usize) -> Self {
                if self.constants.len() < new_size {
                    let mut new_consts = self.constants.clone();
                    for _ in 0..new_size - self.constants.len() {
                        new_consts.push(<$image_type>::zero())
                    }
                    Self {
                        constants: new_consts,
                    }
                } else {
                    self.clone()
                }
            }
        }
    };
}
