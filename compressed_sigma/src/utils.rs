use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_std::{vec, vec::Vec};
use dock_crypto_utils::msm::multiply_field_elems_with_same_group_elem;

use crate::transforms::{Homomorphism, LinearForm};

/// Pad given homomorphisms such that all have the same size after padding
pub fn pad_homomorphisms_to_have_same_size<
    G: AffineRepr,
    F: Homomorphism<G::ScalarField, Output = G>,
>(
    fs: &[F],
) -> Vec<F> {
    let mut max_size = 0;
    for f in fs {
        if f.size() > max_size as usize {
            max_size = f.size() as u32;
        }
    }
    fs.iter().map(|f| f.pad(max_size)).collect()
}

/// Pad given linear forms such that all have the same size after padding
pub fn pad_linear_forms_to_have_same_size<F: PrimeField, L: LinearForm<F>>(fs: &[L]) -> Vec<L> {
    let mut max_size = 0;
    for f in fs {
        if f.size() > max_size as usize {
            max_size = f.size() as u32;
        }
    }
    fs.iter().map(|f| f.pad(max_size)).collect()
}

/// Return the response of an amortized sigma protocol
pub fn amortized_response<F: PrimeField>(
    max_size: u32,
    c_powers: &[F],
    r: &[F],
    x: Vec<&[F]>,
) -> Vec<F> {
    let s = x.len();
    let mut z = vec![];
    for i in 0..max_size as usize {
        // z_i = r_i + \sum_{j in 1..s}({x_j}_i * {c_powers}_j)
        let mut z_i = r[i];
        for j in 0..s {
            if s > j && x[j].len() > i {
                z_i += c_powers[j] * x[j][i];
            }
        }
        z.push(z_i);
    }
    z
}

/// Given `elem` and number `n`, return `n` powers of `elem` as `[elem, elem^2, elem^3, ..., elem^n]`
pub fn get_n_powers<F: PrimeField>(elem: F, n: usize) -> Vec<F> {
    let mut powers = vec![elem; n];
    for i in 1..n {
        powers[i] = powers[i - 1] * elem;
    }
    powers
}

/// Returns vector `[g * i * coeff, g * i^2 * coeff, g * i^3 * coeff, ..., g * i^n * coeff]`
pub fn multiples_with_n_powers_of_i<G: AffineRepr>(
    g: &G,
    i: G::ScalarField,
    n: usize,
    coeff: &G::ScalarField,
) -> Vec<G> {
    let mut i_powers = vec![i * coeff];
    for j in 1..n {
        i_powers.push(i_powers[j - 1] * i);
    }
    G::Group::normalize_batch(&multiply_field_elems_with_same_group_elem(
        g.into_group(),
        &i_powers,
    ))
}

/// In each round `i`, current `g` is split in 2 halves, `g_l` and `g_r` and new `g` is created as `c_i*g_l + g_r`
/// where `g_l` and `g_r` are left and right halves respectively and `c_i` is the challenge for that round.
/// This is done until `g` is of size 2. This means that all elements of the original `g` that are
/// on the left side in that round would be multiplied by the challenge of that round
pub fn get_g_multiples_for_verifying_compression<F: PrimeField>(
    g_len: usize,
    challenges: &[F],
    z_prime_0: &F,
    z_prime_1: &F,
) -> Vec<F> {
    let mut g_multiples = vec![F::one(); g_len];

    // For each round, divide g into an even number of equal sized partitions and each even
    // numbered (left) partition's elements are multiplied by challenge of that round
    for i in 0..challenges.len() {
        let partitions = 1 << (i + 1);
        let partition_size = g_len / partitions;
        // Only multiply the even-indexed partition elements by the challenge
        for j in (0..partitions).step_by(2) {
            for l in 0..partition_size {
                g_multiples[j * partition_size + l] *= challenges[i];
            }
        }
    }

    // The even numbered (left of each partition of the last round) elements of original are multiplied
    // by z'_0 and odd numbered (right of each partition of the last round) elements are multiplied by z'_1
    for i in 0..g_multiples.len() {
        if (i % 2) == 0 {
            g_multiples[i] *= z_prime_0;
        } else {
            g_multiples[i] *= z_prime_1;
        }
    }
    g_multiples
}

/// Convert field element vector from `[c_1, c_2, c_3, ..., c_n]` to `[c_1*c_2*...*c_n, c_2*c_3*...*c_n, c_3*...*c_n, ..., c_{n-1}*c_n, c_n, 1]`
pub fn elements_to_element_products<F: PrimeField>(mut elements: Vec<F>) -> Vec<F> {
    for i in (1..elements.len()).rev() {
        let c = elements[i - 1] * elements[i];
        elements[i - 1] = c;
    }
    elements.push(F::one());
    elements
}

macro_rules! impl_simple_linear_form {
    ($name: ident, $type: ty) => {
        impl LinearForm<$type> for $name {
            fn eval(&self, x: &[$type]) -> $type {
                self.constants
                    .iter()
                    .zip(x.iter())
                    .fold(Fr::zero(), |accum, (c, i)| accum + *c * i)
            }

            fn scale(&self, scalar: &$type) -> Self {
                Self {
                    constants: self
                        .constants
                        .iter()
                        .map(|c| *c * scalar)
                        .collect::<Vec<_>>(),
                }
            }

            fn add(&self, other: &Self) -> Self {
                Self {
                    constants: self
                        .constants
                        .iter()
                        .zip(other.constants.iter())
                        .map(|(a, b)| *a + b)
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

            fn pad(&self, new_size: u32) -> Self {
                let mut new_consts = self.constants.clone();
                if self.constants.len() < new_size as usize {
                    for _ in 0..new_size as usize - self.constants.len() {
                        new_consts.push(<$type>::zero())
                    }
                    Self {
                        constants: new_consts,
                    }
                } else {
                    Self {
                        constants: new_consts,
                    }
                }
            }
        }
    };
}

macro_rules! impl_simple_homomorphism {
    ($name: ident, $preimage_type: ty, $image_type: ty) => {
        impl Homomorphism<$preimage_type> for $name<$image_type> {
            type Output = $image_type;
            fn eval(&self, x: &[$preimage_type]) -> Result<Self::Output, CompSigmaError> {
                Ok(
                    <$image_type as AffineRepr>::Group::msm_unchecked(&self.constants, x)
                        .into_affine(),
                )
            }

            fn scale(&self, scalar: &$preimage_type) -> Self {
                let s = scalar.into_bigint();
                let scaled = self
                    .constants
                    .iter()
                    .map(|c| c.mul_bigint(s))
                    .collect::<Vec<_>>();
                Self {
                    constants: <$image_type as AffineRepr>::Group::normalize_batch(&scaled),
                }
            }

            fn add(&self, other: &Self) -> Result<Self, CompSigmaError> {
                Ok(Self {
                    constants: self
                        .constants
                        .iter()
                        .zip(other.constants.iter())
                        .map(|(a, b)| (*a + *b).into())
                        .collect::<Vec<_>>(),
                })
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

            fn pad(&self, new_size: u32) -> Self {
                if self.constants.len() < new_size as usize {
                    let mut new_consts = self.constants.clone();
                    for _ in 0..new_size as usize - self.constants.len() {
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
