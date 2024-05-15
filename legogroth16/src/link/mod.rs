pub mod error;
pub mod snark;
mod utils;

pub use snark::*;
pub use utils::*;

#[cfg(test)]
mod test {
    use super::{PESubspaceSnark, SparseMatrix, SubspaceSnark, PP};
    use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
    use ark_ec::{AffineRepr, CurveGroup, Group};
    use ark_ff::{One, PrimeField, UniformRand, Zero};
    use ark_std::{
        ops::Add,
        rand::{rngs::StdRng, SeedableRng},
        vec,
        vec::Vec,
    };

    #[test]
    fn test_basic() {
        // Prove knowledge of all `x_i` in `y = \sum_i g_i * x_i`
        let mut rng = StdRng::seed_from_u64(0u64);
        let g1 = G1Projective::rand(&mut rng).into_affine();
        let g2 = G2Projective::rand(&mut rng).into_affine();

        let mut pp = PP::<G1Affine, G2Affine> { l: 1, t: 2, g1, g2 };

        let mut m = SparseMatrix::new(1, 2);
        m.insert_row_slice(0, 0, vec![g1, g1]).unwrap();

        let x: Vec<Fr> = vec![Fr::one(), Fr::zero()];

        let x_bad: Vec<Fr> = vec![Fr::one(), Fr::one()];

        let y: Vec<G1Affine> = vec![g1];

        let (ek, vk) = PESubspaceSnark::<Bls12_381>::keygen(&mut rng, &pp, &m).unwrap();

        let pi = PESubspaceSnark::<Bls12_381>::prove(&mut pp, &ek, &x).unwrap();
        let pi_bad = PESubspaceSnark::<Bls12_381>::prove(&mut pp, &ek, &x_bad).unwrap();

        PESubspaceSnark::<Bls12_381>::verify(&pp, &vk, &y, &pi).unwrap();
        assert!(PESubspaceSnark::<Bls12_381>::verify(&pp, &vk, &y, &pi_bad).is_err());
    }

    #[test]
    fn test_basic_1() {
        // Prove knowledge of all `w_i` in `y = \sum_i h_i * w_i`
        let mut rng = StdRng::seed_from_u64(0u64);
        let g1 = G1Projective::rand(&mut rng).into_affine();
        let g2 = G2Projective::rand(&mut rng).into_affine();

        let mut pp = PP::<G1Affine, G2Affine> { l: 1, t: 2, g1, g2 };

        let h1 = G1Projective::rand(&mut rng).into_affine();
        let h2 = G1Projective::rand(&mut rng).into_affine();
        let mut m = SparseMatrix::new(1, 2);
        m.insert_row_slice(0, 0, vec![h1, h2]).unwrap();

        let two = Fr::one() + Fr::one();
        let three = Fr::one() + two;

        // Correct witness
        let w: Vec<Fr> = vec![two, three];
        // Incorrect witness
        let w_bad: Vec<Fr> = vec![Fr::one(), Fr::one()];

        // y is a Pedersen-like commitment to `two` and `three` and bases `h1` and `h2`, i.e `y = h1 * two + h2 * three`
        let y: Vec<G1Affine> = vec![h1
            .into_group()
            .mul_bigint(two.into_bigint())
            .add(h2.into_group().mul_bigint(three.into_bigint()))
            .into_affine()];

        let (ek, vk) = PESubspaceSnark::<Bls12_381>::keygen(&mut rng, &pp, &m).unwrap();

        let pi = PESubspaceSnark::<Bls12_381>::prove(&mut pp, &ek, &w).unwrap();
        let pi_bad = PESubspaceSnark::<Bls12_381>::prove(&mut pp, &ek, &w_bad).unwrap();

        PESubspaceSnark::<Bls12_381>::verify(&pp, &vk, &y, &pi).unwrap();
        assert!(PESubspaceSnark::<Bls12_381>::verify(&pp, &vk, &y, &pi_bad).is_err());
    }

    #[test]
    fn test_same_value_different_bases() {
        // Given `bases1 = [h1, h2]` and `bases2 = [h3, h4]`, prove knowledge of `x1, x2 x3` in `y0 = h1 * x0 + h2 * x2` and `y1 = h3 * x1 + h4 * x2`

        let mut rng = StdRng::seed_from_u64(0u64);
        let g1 = G1Projective::rand(&mut rng).into_affine();
        let g2 = G2Projective::rand(&mut rng).into_affine();

        let mut pp = PP::<G1Affine, G2Affine> { l: 2, t: 3, g1, g2 };

        let bases1 = [G1Projective::rand(&mut rng), G1Projective::rand(&mut rng)]
            .iter()
            .map(|p| p.into_affine())
            .collect::<Vec<_>>();
        let bases2 = [G1Projective::rand(&mut rng), G1Projective::rand(&mut rng)]
            .iter()
            .map(|p| p.into_affine())
            .collect::<Vec<_>>();
        let mut m = SparseMatrix::new(2, 3);
        m.insert_row_slice(0, 0, vec![bases1[0]]).unwrap();
        m.insert_row_slice(0, 2, vec![bases1[1]]).unwrap();
        m.insert_row_slice(1, 1, vec![bases2[0], bases2[1]])
            .unwrap();

        let w: Vec<Fr> = vec![Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng)];

        let x: Vec<G1Affine> = vec![
            bases1[0].into_group().mul_bigint(w[0].into_bigint())
                + bases1[1].mul_bigint(w[2].into_bigint()),
            bases2[0].into_group().mul_bigint(w[1].into_bigint())
                + bases2[1].mul_bigint(w[2].into_bigint()),
        ]
        .into_iter()
        .map(|p| p.into_affine())
        .collect::<Vec<_>>();

        let (ek, vk) = PESubspaceSnark::<Bls12_381>::keygen(&mut rng, &pp, &m).unwrap();

        let pi = PESubspaceSnark::<Bls12_381>::prove(&mut pp, &ek, &w).unwrap();

        PESubspaceSnark::<Bls12_381>::verify(&pp, &vk, &x, &pi).unwrap();
    }

    #[test]
    fn test_some_vals_equal() {
        // Given `bases1 = [h1, h2, h3]` and `bases2 = [h4, h5, h6]`, prove knowledge of `x1, x2 x3, x4` in `y0 = h1 * x0 + h2 * x2 + h3 * x3` and `y1 = h4 * x1 + h5 * x2 + h6 * x4`

        let mut rng = StdRng::seed_from_u64(0u64);
        let g1 = G1Projective::rand(&mut rng).into_affine();
        let g2 = G2Projective::rand(&mut rng).into_affine();

        let l = 2;
        let t = 4;
        let mut pp = PP::<G1Affine, G2Affine> { l, t, g1, g2 };

        let bases1 = [
            G1Projective::rand(&mut rng),
            G1Projective::rand(&mut rng),
            G1Projective::rand(&mut rng),
        ]
        .iter()
        .map(|p| p.into_affine())
        .collect::<Vec<_>>();
        let bases2 = [
            G1Projective::rand(&mut rng),
            G1Projective::rand(&mut rng),
            G1Projective::rand(&mut rng),
        ]
        .iter()
        .map(|p| p.into_affine())
        .collect::<Vec<_>>();

        let mut m = SparseMatrix::new(l as usize, t as usize);
        m.insert_row_slice(0, 0, bases1.clone()).unwrap();
        m.insert_row_slice(1, 0, bases2[0..2].to_vec()).unwrap();
        m.insert_row_slice(1, 3, bases2[2..].to_vec()).unwrap();

        let w: Vec<Fr> = vec![
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
        ];

        let x: Vec<G1Affine> = vec![
            bases1[0].into_group().mul_bigint(w[0].into_bigint())
                + bases1[1].mul_bigint(w[1].into_bigint())
                + bases1[2].mul_bigint(w[2].into_bigint()),
            bases2[0].into_group().mul_bigint(w[0].into_bigint())
                + bases2[1].mul_bigint(w[1].into_bigint())
                + bases2[2].mul_bigint(w[3].into_bigint()),
        ]
        .into_iter()
        .map(|p| p.into_affine())
        .collect::<Vec<_>>();

        let (ek, vk) = PESubspaceSnark::<Bls12_381>::keygen(&mut rng, &pp, &m).unwrap();

        let pi = PESubspaceSnark::<Bls12_381>::prove(&mut pp, &ek, &w).unwrap();

        PESubspaceSnark::<Bls12_381>::verify(&pp, &vk, &x, &pi).unwrap();
    }
}
