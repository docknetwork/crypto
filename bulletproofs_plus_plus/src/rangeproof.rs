//! Copied from bulletproofs source mentioned in the paper - <https://github.com/sanket1729/rust-bulletproofs-pp/blob/master/src/rangeproof.rs>
//! Some of the duplicate computation has been removed.
//! Rangeproofs:
//!
//! Notation:
//!
//! Notation follows the bulletproofs++ paper.

use ark_ec::AffineRepr;
use ark_ff::{batch_inversion, Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    cfg_into_iter, cfg_iter, cfg_iter_mut, format, ops::Neg, rand::RngCore, vec, vec::Vec,
    UniformRand,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{
    error::BulletproofsPlusPlusError, setup::SetupParams, util,
    weighted_norm_linear_argument::WeightedNormLinearArgument,
};
use dock_crypto_utils::{
    ff::{add_vecs, hadamard_product, inner_product, powers, powers_starting_from, scale},
    join,
    transcript::Transcript,
};

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
struct Round1Commitments<G: AffineRepr> {
    /// Round 1 output: D (commitment to the number of digits)
    D: G,
    /// Round 1 output: M (commitment to the number of multiplicities)
    M: G,
}

#[derive(Debug, Clone)]
struct Round1Secrets<F: PrimeField> {
    /// Vector of digits committed with G_vec
    d_vec: Vec<F>,
    /// Blinding factor for d in G
    r_d0: F,
    /// Blinding factor for d in H_vec
    r_d1_vec: Vec<F>,
    /// Vector of multiplicities
    m_vec: Vec<F>,
    /// Blinding factor for m in G
    r_m0: F,
    /// Blinding factor for m in H_vec
    r_m1_vec: Vec<F>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
struct Round2Commitments<G: AffineRepr> {
    /// Reciprocal commitment: R
    R: G,
}

#[derive(Debug, Clone)]
struct Round2Secrets<F: PrimeField> {
    /// Reciprocal vector. This is non-zero, but having zero helps in code-dedup
    r_vec: Vec<F>,
    /// Blinding factor for r in G
    r_r0: F,
    /// Blinding factor for r in H_vec
    r_r1_vec: Vec<F>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
struct Round3Commitments<G: AffineRepr> {
    /// Round 3 blinding commitment S
    S: G,
}

#[derive(Debug, Clone)]
struct Round3Secrets<F: PrimeField> {
    /// Round 3 blinding factor b_s
    #[allow(dead_code)]
    r_s0: F,
    /// Final w_v(T) polynomial
    w_poly: Poly<F>,
    /// Final l_v(T) polynomial
    l_poly: Poly<F>,
}

impl<G: AffineRepr> Round1Commitments<G> {
    fn challenge(
        &self,
        base: u16,
        num_bits: u16,
        V: &[G],
        transcript: &mut impl Transcript,
    ) -> G::ScalarField {
        transcript.append_message(b"base", &base.to_le_bytes());
        transcript.append_message(b"num_bits", &num_bits.to_le_bytes());
        for V_i in V {
            transcript.append(b"V", V_i);
        }
        transcript.append(b"D", &self.D);
        transcript.append(b"M", &self.M);
        transcript.challenge_scalar(b"e")
    }
}

impl<G: AffineRepr> Round2Commitments<G> {
    fn challenges(
        &self,
        transcript: &mut impl Transcript,
    ) -> (
        G::ScalarField,
        G::ScalarField,
        G::ScalarField,
        G::ScalarField,
        G::ScalarField,
        G::ScalarField,
    ) {
        transcript.append(b"R", &self.R);
        let x = transcript.challenge_scalar(b"x");
        let y = transcript.challenge_scalar(b"y");
        let r = transcript.challenge_scalar(b"r");
        let lambda = transcript.challenge_scalar(b"lambda");
        let delta = transcript.challenge_scalar(b"delta");
        (x, y, r, r.square(), lambda, delta)
    }
}

impl<G: AffineRepr> Round3Commitments<G> {
    fn challenge(&self, transcript: &mut impl Transcript) -> G::ScalarField {
        transcript.append(b"S", &self.S);
        transcript.challenge_scalar(b"t")
    }
}

/// BP++ Rangeproof Prover state.
/// The prover state across rounds of the protocol.
///
/// # Notation
///
/// In each round of the protocol, the prover computes a commitment of the following form:
///
/// X = r_x0 * G + <x_i, G_i> + <r_x1_i, H_i>. Here
///     - G is the base generator. G_i generators are associated with n_vec in norm argument
/// while H_i generators are associated with r1_vec, l_vec.
///     - X is the output commitment. (in our case: D, M, R, S) for each round
///     - x_i is the witness vector. (in our case: x = {d, m, r, s})
///     - r_x_i is the blinding vector. The blinding for 0 is considered along the G dimension
/// while the blinding from 1 onwards are considered along the H dimension.
#[derive(Debug, Clone)]
pub struct Prover<G: AffineRepr> {
    /// `b` base representation of the value to be proven(2, 4, 8, 16)
    base: u16,
    /// `n` number of bits in the value to be proven(32, 64, 128) in base 2
    num_bits: u16,
    /// The commitments to the values being proven. One commitment each per aggregated proof
    V: Vec<G>,
    /// The corresponding values committed in V. One value each per aggregated proof
    v: Vec<u64>,
    /// Corresponding blinding factors for the commitments in V. One blinding factor each per aggregated proof
    gamma: Vec<G::ScalarField>,
    /// Round 1 commitments
    r1_comm: Option<Round1Commitments<G>>,
    /// Round 1 secrets
    r1_sec: Option<Round1Secrets<G::ScalarField>>,
    /// Round 2 commitments
    r2_comm: Option<Round2Commitments<G>>,
    /// Round 2 secrets
    r2_sec: Option<Round2Secrets<G::ScalarField>>,
    /// Round 3 commitments
    r3_comm: Option<Round3Commitments<G>>,
    /// Round 3 secrets
    r3_sec: Option<Round3Secrets<G::ScalarField>>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<G: AffineRepr> {
    /// `b` base representation of the value to be proven(2, 4, 8, 16)
    base: u16,
    /// Round 1 commitments
    r1_comm: Round1Commitments<G>,
    /// Round 2 commitments
    r2_comm: Round2Commitments<G>,
    /// Round 3 commitments
    r3_comm: Round3Commitments<G>,
    /// norm proof
    norm_proof: WeightedNormLinearArgument<G>,
}

impl<G: AffineRepr> Prover<G> {
    pub fn new(
        num_bits: u16,
        V: Vec<G>,
        v: Vec<u64>,
        gamma: Vec<G::ScalarField>,
    ) -> Result<Self, BulletproofsPlusPlusError> {
        let base = 2;
        Self::new_with_given_base(base, num_bits, V, v, gamma)
    }

    /// Creates a new prover instance.
    pub fn new_with_given_base(
        base: u16,
        num_bits: u16,
        V: Vec<G>,
        v: Vec<u64>,
        gamma: Vec<G::ScalarField>,
    ) -> Result<Self, BulletproofsPlusPlusError> {
        if !base.is_power_of_two() {
            return Err(BulletproofsPlusPlusError::ExpectedPowerOfTwo(format!(
                "base={} but should be a power of 2",
                base
            )));
        }
        if !num_bits.is_power_of_two() {
            return Err(BulletproofsPlusPlusError::ExpectedPowerOfTwo(format!(
                "num_bits={} but should be a power of 2",
                num_bits
            )));
        }
        if num_bits < util::base_bits(base) {
            return Err(BulletproofsPlusPlusError::ValueIncompatibleWithBase(format!("number of bits in value={} which should not be less than number of bits in base={}", num_bits, base)));
        }
        if v.len() != V.len() {
            return Err(BulletproofsPlusPlusError::UnexpectedLengthOfVectors(
                format!(
                    "length of values={} not equal to length of commitments={}",
                    v.len(),
                    V.len()
                ),
            ));
        }
        if v.len() != gamma.len() {
            return Err(BulletproofsPlusPlusError::UnexpectedLengthOfVectors(
                format!(
                    "length of values={} not equal to length of randomness={}",
                    v.len(),
                    gamma.len()
                ),
            ));
        }
        Ok(Self {
            base,
            num_bits,
            V,
            v,
            gamma,
            r1_comm: None,
            r1_sec: None,
            r2_comm: None,
            r2_sec: None,
            r3_comm: None,
            r3_sec: None,
        })
    }

    /// Number of proofs to aggregate
    pub fn num_proofs(&self) -> usize {
        self.V.len()
    }

    /// Obtain the number of digits in the base representation
    /// Num of digits in single proof times the number of proofs
    fn total_num_digits(&self) -> usize {
        self.num_digits_per_proof() as usize * self.num_proofs()
    }

    /// Obtain the number of digits in the base representation
    fn num_digits_per_proof(&self) -> u16 {
        self.num_bits / util::base_bits(self.base)
    }

    /// Round 1: Commit to the base representation of the value and multiplicities
    ///
    /// # The digits commitment: D
    ///
    /// The prover first computes the base representation of the value to be proven.
    /// It first computes the commitment D = r_d0 * G + <d_i, G_i> + <r_d1_vec_i, H_i> where d_i
    /// is the i-th digit of the base b representation of the value to be proven. The values
    /// r_d0 is chosen randomly, while r_d1_vec_i is chosen according to _some_ constraint that we will
    /// explain later. Informally, r_d0 being random is sufficient to prove that the commitment is hiding.
    ///
    /// When aggregating proofs, d_i is the concatenation of the base b representation of all values.
    /// For example, base 4, num_bits = 4, v = [9, 13] (two digits per value).
    ///             d_vec = [1, 2, 1, 3]
    ///                     (1, 2) (1, 3)
    ///                     (4*2 + 1) (4*3 + 1)
    ///                      9        13
    ///
    /// # The multiplicity commitment: M
    ///
    /// The prover computes the commitment M = r_m0 * G + <m_i, G_i> + <r_m1vec_i, H_i> where m_i
    /// is the multiplicity of the i-th digit in the base b representation of the value to be proven.
    /// The values r_m0, and r_m1vec_i are chosen uniformly at random. Similar to the digits commitment,
    /// r_m0 being random is sufficient to prove that the commitment is hiding. Multiplicity denotes
    /// the number of times a digit appears in the base b representation of the value to be proven.
    ///
    /// Now, there are two choices for how we want to commit the multiplicities when aggregating proofs.
    /// 1) Inline multiplicity mode: In this mode, the prover commits to the multiplicities of all digits
    /// one after another by concatenating the base b representation of all values.
    /// For the above example, this would be: a) m_vec for 9 = [0, 1, 1, 0] and m_vec for 13 = [0, 1, 0, 1]
    /// The final m_vec would be [0, 1, 1, 0, 0, 1, 0, 1].
    /// 2) Shared multiplicity mode: In this mode, the prover commits to the multiplicities of all digits
    ///   in the base b representation of all values. For example, base 4, num_bits = 4, v = [9, 13] (two digits per value).
    ///   For the above example, the m_vec would be [0, 1, 1, 0] + [0, 1, 0, 1] = [0, 2, 1, 1].
    ///
    /// For the implementation, we use the shared multiplicity mode. The current implementation is not
    /// compatible for multi-party proving, since the prover needs to know the multiplicities of all
    /// digits in the base b representation of all values. We do not concern with this for now.
    fn round_1<R: RngCore>(&mut self, rng: &mut R, setup_params: &SetupParams<G>) {
        let num_base_bits = util::base_bits(self.base);
        let num_digits_per_proof = self.num_digits_per_proof();
        let total_num_digits = self.total_num_digits();

        // d is a vector containing digits of `base`-representation of all `v`s
        let mut d = Vec::with_capacity(total_num_digits);
        // Shared multiplicity mode for now.
        let mut m = vec![0; self.base as usize];

        // For each `v`, create its `base`-representation and append to `d`
        for v in self.v.iter() {
            let mut v1 = *v;
            for _ in 0..num_digits_per_proof {
                let dig = v1 % self.base as u64;
                d.push(dig);
                // Increase multiplicity by 1
                m[dig as usize] += 1u64;
                v1 = v1 >> num_base_bits;
            }
        }

        let d = d
            .into_iter()
            .map(|x| G::ScalarField::from(x))
            .collect::<Vec<_>>();
        let m = m
            .into_iter()
            .map(|x| G::ScalarField::from(x))
            .collect::<Vec<_>>();

        let mut r_m1_vec = (0..8)
            .map(|_| G::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let mut r_d1_vec = ark_std::iter::repeat(G::ScalarField::zero())
            .take(8)
            .collect::<Vec<_>>();
        // Restrict some values so that the verification equation holds for all T.
        // All other powers can be cancelled by choosing r_s_i adaptively. We only
        // need to worry about T^3 and T^7.
        {
            // Additional t^7 term which cannot be cancelled out:
            // delta*lm_v[0, 6] + ld_v[0, 5] + lr_v[0, 4] => lm_v[6] = 0 && ld_v[5] = -lr_v[4]
            r_m1_vec[6] = G::ScalarField::zero();
            r_d1_vec[5] = G::ScalarField::rand(rng);

            // Additional t^3 term which cannot be cancelled out:
            // delta*lm_v[0, 3] + ld_v[0, 2] + lr_v[0, 1] => lm_v[3] = 0 && ld_v[2] = -lr_v[1]
            r_m1_vec[3] = G::ScalarField::zero();
            r_d1_vec[2] = G::ScalarField::rand(rng);
        }

        let r_d0 = G::ScalarField::rand(rng);
        let r_m0 = G::ScalarField::rand(rng);
        let (D, M) = join!(
            setup_params.compute_commitment(&r_d0, &r_d1_vec, &d),
            setup_params.compute_commitment(&r_m0, &r_m1_vec, &m)
        );

        self.r1_sec = Some(Round1Secrets {
            d_vec: d,
            r_d0,
            r_d1_vec,
            m_vec: m,
            r_m0,
            r_m1_vec,
        });
        self.r1_comm = Some(Round1Commitments { D, M });
    }

    /// Prover Round 2: Prover has committed to d_vec and m_vec in the previous round. Received challenge e.
    ///
    /// # The reciprocal commitment: R
    ///
    /// The prover computes the commitment R = r_r0 * G + <r_i, G_i> + <r_r_i, H_i> where r_i = (1/ (e + d_i))
    /// r_r_i are chosen to be all zeros. As before, the values r_r0 being random is sufficient to prove that the commitment is hiding.
    ///
    fn round_2<R: RngCore>(
        &mut self,
        rng: &mut R,
        e: G::ScalarField,
        setup_params: &SetupParams<G>,
    ) {
        // compute r_i = (1/ (e + d_i))
        let mut r = cfg_iter!(self.r1_sec.as_ref().unwrap().d_vec)
            .map(|x| (e + x))
            .collect::<Vec<_>>();
        batch_inversion(&mut r);

        let mut r_r1_vec = ark_std::iter::repeat(G::ScalarField::zero())
            .take(8)
            .collect::<Vec<_>>();
        {
            // Balance out remaining terms in final l_vec
            r_r1_vec[4] = -self.r1_sec.as_ref().unwrap().r_d1_vec[5].clone(); // T^7
            r_r1_vec[1] = -self.r1_sec.as_ref().unwrap().r_d1_vec[2].clone(); // T^3
        }
        let (r_r0, R) = setup_params.gen_randomness_and_compute_commitment(rng, &r_r1_vec, &r);
        self.r2_sec = Some(Round2Secrets {
            r_vec: r,
            r_r0,
            r_r1_vec,
        });
        self.r2_comm = Some(Round2Commitments { R });
    }

    /// Prover Round 3: Prover has committed to r_vec in the previous round.
    ///                 Received challenge (x, y, q, lambda, delta). Already has e from round 1
    /// lambda is used for aggregation. We skip lambda in this explanation for simplicity.
    /// # Witness algebraic relations:
    ///
    /// There are three relations of interest that we need to prove amongst the committed values. We will first
    /// explain the protocol without aggregation, and then explain how to aggregate the proofs.
    /// 1) v = <d_i, b^i> // We refer to this as "Sum value constraint" where b is the base
    /// 2) r_i = (1/ (e + d_i)) // We refer to this as "Reciprocal value constraint"
    /// 3) <m_i, (1 / (e + i))> = <r_i, 1> // We refer to this as "Range check constraint"
    ///
    /// 3) is the most interesting one and a core contribution of BP++ paper. This proves that
    /// all the digits are in the range [0, b-1]. This can intuitively seen as follows:
    /// Sum_j(m_j/e + i) = Sum_i(1/(e + d_i)) where j = 0..b-1, i = 0..num_digits
    ///
    /// Since e is a random challenge, the above equation is true with high probability for all X.
    /// Sum_j(m_j/X + i) = Sum_i(1/(X + d_i)). Meaning, that d_i are representable using only
    /// (1/X + i) poles where i = 0..b-1. Therefore, d_i must be in the range [0, b-1].
    ///
    /// # Mapping to norm argument:
    ///
    /// To reduce this to norm argument, we construct n and l as follows:
    /// n_vec = s_vec/T + delta*m_vec + d_vec*T + r_vec*T^2 + alpha_m_vec*T^3 + alpha_d_vec*T^2 + alpha_r_vec*T
    /// l_vec = r_s1_vec/T + delta*r_m1_vec + r_d1_vec_vec*T + r_r1_vec*T^2 + 2*gamma*T^3 (blinding factor)
    /// C = S/T + delta*M + D*T + R*T^2 + 2*V*T^3 + _P_ (P is some public value that we will compute as we proceed)
    ///
    /// P = 0
    /// P += <alpha_m_vec*t^3, G_vec> + <alpha_d_vec*t^2, G_vec> + <alpha_r_vec*t, G_vec> (We will update P as we balance other constraints)
    /// The values t denote concrete challenges, while T denotes the unknown challenge. Prover does not know `t` and
    /// must make sure that the above equation holds for all `t`.
    ///
    /// There are a few important points to note here:
    /// 1) All of the vectors are parameterized over unknown T. We want the norm argument to hold for all T,
    /// and in the co-efficient of T^3, is where we will check all our constraints. All other co-efficients
    /// of T^i will be made zero by choosing the r_s_i vector adaptively. In detail, we will choose r_s_i
    /// such that C, n_vec, l_vec following the relation in norm argument.
    /// C = <n_vec, G> + <l_vec, H> + (|n_vec|_q + <l_vec, c_vec>) G for all T.
    /// Here c_vec = y*[1/y, 1/T T, T^2, T^3, T^5, T^6, 0]. Crucially, this is missing T^4 (T^3 constraint), which is where we
    /// will check our constraints.
    /// Because we don't know the value of T(verifier chosen challenge from next round), we must choose r_s_i
    /// such that C, n_vec, l_vec following the relation in norm argument for all T. We can do this by expanding the expression
    /// and solving for r_s_i. But crucially, r_s_i cannot interfere with the co-efficients of T^5. r_s_i also cannot
    /// balance co-efficients above T^7. This is not an issue, because this simply translates into some constraints in
    /// choosing our blinding values. Referring back to Round 1, we can now see why we needed r_d1_vec(4) = -l_m(5). Skipping
    /// some calculation, if we expand n_vec here, we can see that co-eff of T^8 can only be zero is r_d1_vec(4) = -l_m(5).
    ///
    /// 2) We have also added public constants alpha_m_vec, alpha_d_vec, alpha_r_vec to the n_vec. These would be where
    /// we would check our relations. m_vec which has a T power 1, has a corresponding alpha_m_vec with T power 4 so that
    /// when multiplied, the result is in T^5 is alpha_m_vec. Similarly, d_vec has a T power 2, and alpha_d_vec has a
    /// T power 3. This is because we want to check the relations in T^5. We will see how this is done in the next step.
    ///
    /// # Combining constraints with multiple challenges:
    ///
    /// This is a general principle in cryptography and snarks. We can combine multiple constraints into one by
    /// using challenges. If C1 and C2 are two constraints, we can combine them into one constraint C by using
    /// a challenge x. C = C1 + x*C2. This can be extended to multiple constraints. If we have C1, C2, .. Ci.. Cn,
    /// we can use a single challenge q to combine all of them into one constraint C.
    /// C = C1 + q*C2 + q^2*C3 + ... + q^(n-1)*Cn. In the next section, we describe which challenges separate
    /// the constraints.
    ///
    /// # Diving into constraints:
    ///
    /// 1) Sum value constraint: We want to check that v = <d_i, b^i>. If we choose alpha_d_vec = [b^0/q^1, b^1/q^2, b^2/q^3, ...], then
    /// we can check this by checking that <d_i, alpha_d_vec>_q (q weighted norm) = v. This nicely cancels out the q^i
    /// that would have resulted from q weighted norm and brings everything without a power of Q. challenge constraints:
    /// (Q^0, X^0, Y^0)
    ///
    /// 2) Reciprocal constraint: We want to check that 1/(e + d_i) = r_i. We choose alpha_r1 = [e, e, e, ..e_n].
    /// When computing |n_vec|_q = |d_vec*T^2 + r_vec*T^3 + alpha_r_vec*T^2 + alpha_d_vec*T^3 + ....|_q.
    ///
    /// Let's consider the co-eff of q^i and x^0 = 2(d_i*r_i + e*r_i) = 2.
    /// (As per definition of r_i = 1/(e + d_i) =>  r_i*e + r_i*d_i = 1). To check against the constant 2, Verifier adds
    /// a commitment P += 2*T^5*<1_vec, q_pows_vec>G (We will keep on adding more terms to P later).
    ///
    /// So, challenges constraints at Q^i, X^0, Y^0 ensure all the n reciprocal constraints are satisfied.
    ///
    /// 3) Range check constraint: (Check each d_i in [0 b-1])
    ///
    /// Using the main theorem of set membership, we want to check the following:
    ///
    /// Sum_j(m_j/X + i) = Sum_i(1/(X + d_i)) = Sum_i(r_i) where j = 0..b-1, i = 0..n-1.
    /// To do this, we choose alpha_m_vec = [1/(e + 0), 1/(e + 1), 1/(e + 2), ... 1/(e + b-1)].
    /// and alpha_r2_vec = x*[1/q^1, 1/q^2, 1/q^3, ...].
    ///
    /// So, the challenge constraints in Q^0, X^1, Y^0 ensures these constraints are satisfied. Note that the challenge
    /// Y is not really used in these constraints. Y is used to separate out the terms coming in from the linear side(l_vec)
    /// into the the verification equation.
    ///
    ///
    /// # Balancing out everything else:
    ///
    /// We only need to deal with co-effs of T^0, T^5, and T^8 onwards. The co-effs of T^1, T^2, T^3, T^4, T^6, T^7 are
    /// can easily be made zero by choosing r_s_i adaptively. We simply state the constraints here, the constraints are
    /// computed by making sure (n_vec, l_vec and C, c_vec) follow the norm relation for all T's.
    ///
    /// T^0: Choose b_s = |s|^2_q.
    /// T^8: ld_vec(4) = -lm_vec(5)
    /// T^5: ld_vec(2) = -lm_vec(3)
    ///
    /// In our construction, all of the witness values that we want to enforce constraints are in n_vec. We have to
    /// make sure none of the terms from l_vec interfere with the co-efficients of T^5. This is done by choosing
    /// challenge y and making c_vec = y*[T^1, T^2, T^3, T^4, T^6, T^7]. This ensure that resultant co-effs that
    /// can interfere with T^5 coming from linear side(l_vec side) are always multiplied by y. Overall, our verification
    /// equation looks something like:
    ///
    /// T^5 = Q^0X^0Y^0(a) + Q^iX^0Y^0(b) + Q^0X^1Y^0(c) + Q^0X^0Y^1(d)
    /// (a) = Sum-value constraint (1 total constraint)
    /// (b) = Reciprocal constraint in Q^i (n total constraints)
    /// (c) = Range check constraint in Q^0, X^1, Y^0 (1 total constraints)
    /// (d) = Linear side (l_vec side) in Y^1 (1 total constraints)
    ///
    /// The separation of these constraints by different challenges and using the schwartz-zippel lemma, we can
    /// say that all of (a), (b), (c) and (d) are satisfied with high probability. Which is some rough intuition as to why the
    /// protocol is sound. Reasoning about Zk is slightly complicated and we skip that for now.
    ///
    /// Lastly, we also need to add cross public terms to P, which are: (Restating all terms again)
    /// P = 0
    /// P += <alpha_m_vec*t^4, G_vec> + <alpha_d_vec*t^3, G_vec> + <alpha_r1_vec*t^2, G_vec> + <alpha_r2_vec*t^2, G_vec> // Commitments to alpha_i in G_vec
    /// P += 2*T^5*<alpha_d_vec, alpha_r2>*G // Reciprocal constraint public term i G // Referred as v_hat1 in code
    /// P += 2*T^5*x<q_pow_inv*alpha_d_vec, alpha_r1> // Range check constraint public term in G // Referred as v_hat2 in code
    /// P += 2*T^5*<1_vec, q_pows_vec>G // Sum value constant in G // Referred as v_hat3 in code
    /// P += 2*x^2T^8*|alpha_m|_q*G // T^8 public term in G // Referred as v_hat4 in code
    ///
    fn round_3<R: RngCore>(
        &mut self,
        rng: &mut R,
        x: G::ScalarField,
        y: G::ScalarField,
        q: G::ScalarField,
        e: G::ScalarField,
        lambda: G::ScalarField,
        delta: G::ScalarField,
        setup_params: &SetupParams<G>,
    ) {
        let d = self.r1_sec.as_ref().unwrap().d_vec.clone();
        let m = scale(&self.r1_sec.as_ref().unwrap().m_vec, &delta);
        let r = self.r2_sec.as_ref().unwrap().r_vec.clone();
        let r_d1_vec = self.r1_sec.as_ref().unwrap().r_d1_vec.clone();
        let l_m = self.r1_sec.as_ref().unwrap().r_m1_vec.clone();
        let l_r = self.r2_sec.as_ref().unwrap().r_r1_vec.clone();
        // q_inv_pows = (q-1, q^-2, q^-3, ..., q^{-g_vec.len()})
        let q_inv = q.inverse().unwrap();
        let q_inv_pows =
            powers_starting_from(q_inv.clone(), &q_inv, setup_params.G_vec.len() as u32);

        let (alpha_r, alpha_d, alpha_m) = join!(
            alpha_r_q_inv_pow(self.total_num_digits(), x, e, &q_inv_pows, delta),
            alpha_d_q_inv_pow(
                self.base,
                self.num_digits_per_proof(),
                self.num_proofs(),
                &q_inv_pows,
                lambda
            ),
            alpha_m_q_inv_pows(e, x, self.base as usize, &q_inv_pows)
        );

        // let alpha_r = alpha_r_q_inv_pow(self.total_num_digits(), x, e, &q_inv_pows, delta);
        // let alpha_d = alpha_d_q_inv_pow(self.base, self.num_digits_per_proof(), self.num_proofs(), &q_inv_pows, lambda);
        // let alpha_m = alpha_m_q_inv_pows(e, x, self.base as usize, &q_inv_pows);

        let t_2 = add_vecs(&d, &alpha_r);
        let t_3 = add_vecs(&r, &alpha_d);

        let s = (0..setup_params.G_vec.len())
            .map(|_| G::ScalarField::rand(rng))
            .collect::<Vec<_>>();

        let w_vec = Poly {
            coeffs: vec![s.clone(), m.clone(), t_2, t_3, alpha_m],
        };
        let (r_m0, b_d, b_r) = (
            &self.r1_sec.as_ref().unwrap().r_m0,
            &self.r1_sec.as_ref().unwrap().r_d0,
            &self.r2_sec.as_ref().unwrap().r_r0,
        );
        let w_w_q = w_vec.w_q_norm(q);
        // w_w_q here starts from T^-2 and goes till T^6.
        let y_inv = y.inverse().unwrap();
        let c = c_poly(y);

        // gamma_v = \sum_i(2 * lambda_powers_i * gamma_i)
        // double_lambda_powers = (2, 2 * lambda, 2 * lambda^2, 2 * lambda^3, ...)
        let double_lambda_powers =
            powers_starting_from(G::ScalarField::from(2u64), &lambda, self.gamma.len() as u32);
        let gamma_v = inner_product(&self.gamma, &double_lambda_powers);

        let (mut lm1, mut ld1, mut lr1) =
            (vec![-r_m0.clone()], vec![-b_d.clone()], vec![-b_r.clone()]);
        lm1.extend(l_m);
        ld1.extend(r_d1_vec);
        lr1.extend(l_r);

        cfg_iter_mut!(lm1).for_each(|elem| *elem = *elem * delta);

        // Question: Does the following assume that h_vec is always going to be of length 8?
        let mut l_vec = Poly {
            coeffs: vec![
                Vec::new(),
                lm1,
                ld1,
                lr1,
                vec![G::ScalarField::zero(), gamma_v],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ],
        };
        let l_vec_w_q = l_vec.multiply_with_poly_of_constants(&c);

        // l_s = (- w_w_q_i - l_vec_w_q_i)
        let mut l_s = cfg_into_iter!(0..setup_params.H_vec.len() + 1)
            .zip(cfg_iter!(w_w_q).zip(cfg_iter!(l_vec_w_q)))
            .map(|(_, (w_w_q_i, l_vec_w_q_i))| w_w_q_i.neg() + l_vec_w_q_i.neg())
            .collect::<Vec<_>>();

        // let arr = [r_m0, b_d, b_r];
        // for (i, b_i) in arr.into_iter().enumerate() {
        //     let r_s_i = &l_s[i + 2];
        //     l_s[i + 2] = s!(r_s_i + b_i);
        // }
        l_s.remove(5);
        let b_s = l_s.remove(1);
        l_s.push(G::ScalarField::zero());
        cfg_iter_mut!(l_s).for_each(|elem| *elem = *elem * y_inv);

        l_vec.coeffs[0] = l_s.clone();
        let minus_b_s = -b_s;
        // Compute S = s*G_vec + l_s*H_vec - b_s*G
        let S = setup_params.compute_commitment(&minus_b_s, &l_s, &s);

        // Recompute the secret w
        l_vec.coeffs[1].remove(0);
        l_vec.coeffs[2].remove(0);
        l_vec.coeffs[3].remove(0);
        l_vec.coeffs[4].remove(0);
        self.r3_sec = Some(Round3Secrets {
            r_s0: minus_b_s,
            w_poly: w_vec,
            l_poly: l_vec,
        });
        self.r3_comm = Some(Round3Commitments { S });
    }

    /// Round 4:
    /// Run the norm argument on the obtained challenge t. If we have sent the correct commitments, we only
    /// need to evaluate the poly w_vec at t and the poly l_vec at t. and run the norm argument on them
    fn round_4(
        self,
        y: G::ScalarField,
        t: G::ScalarField,
        r: G::ScalarField,
        setup_params: SetupParams<G>,
        transcript: &mut impl Transcript,
    ) -> Result<Proof<G>, BulletproofsPlusPlusError> {
        let r3_sec = self.r3_sec.unwrap();
        let t_pows = TPowers::new(t, setup_params.H_vec.len() as u32);
        let w_eval = r3_sec.w_poly.eval_given_t_powers(&t_pows);
        let l_eval = r3_sec.l_poly.eval_given_t_powers(&t_pows);

        let c_vec = create_c_vec(y, &t_pows);
        let norm_prf = WeightedNormLinearArgument::new(
            l_eval.clone(),
            w_eval.clone(),
            c_vec,
            r,
            setup_params,
            transcript,
        )?;
        Ok(Proof {
            base: self.base,
            r1_comm: self.r1_comm.unwrap(),
            r2_comm: self.r2_comm.unwrap(),
            r3_comm: self.r3_comm.unwrap(),
            norm_proof: norm_prf,
        })
    }

    pub fn prove<R: RngCore>(
        mut self,
        rng: &mut R,
        setup_params: SetupParams<G>,
        transcript: &mut impl Transcript,
    ) -> Result<Proof<G>, BulletproofsPlusPlusError> {
        // Round 1
        self.round_1(rng, &setup_params);
        let e =
            self.r1_comm
                .as_ref()
                .unwrap()
                .challenge(self.base, self.num_bits, &self.V, transcript);

        // Round 2
        self.round_2(rng, e, &setup_params);
        let (x, y, r, q, lambda, delta) = self.r2_comm.as_ref().unwrap().challenges(transcript);

        // Round 3
        self.round_3(rng, x, y, q, e, lambda, delta, &setup_params);
        let t = self.r3_comm.as_ref().unwrap().challenge(transcript);

        // Round 4
        self.round_4(y, t, r, setup_params, transcript)
    }
}

impl<G: AffineRepr> Proof<G> {
    /// Compute the public offsets for P in along G_vec.
    /// This computes
    /// P = alpha_d_vec * t^3 + alpha_r1_vec * t^2 + alpha_r2_vec * t^2 + alpha_m_vec * t^4
    fn g_vec_pub_offsets(
        &self,
        e: G::ScalarField,
        x: G::ScalarField,
        alpha_r_q_inv_pows: &[G::ScalarField],
        t_pows: &TPowers<G::ScalarField>,
        q_inv_pows: &[G::ScalarField],
        alpha_d_q_inv_pows: &[G::ScalarField],
    ) -> Vec<G::ScalarField> {
        let alpha_m = alpha_m_q_inv_pows(e, x, self.base as usize, &q_inv_pows);

        let alpha_d_t_3 = scale(&alpha_d_q_inv_pows, t_pows.nth_power(2));
        let alpha_r_t_2 = scale(alpha_r_q_inv_pows, t_pows.nth_power(1));
        let alpha_m_t_4 = scale(&alpha_m, t_pows.nth_power(3));

        let res = add_vecs(&alpha_d_t_3, &alpha_r_t_2);
        add_vecs(&res, &alpha_m_t_4)
    }

    /// Compute the public offsets for P in along G
    /// This computes v_hat as (explained in prover round 3)
    /// P += 2*T^5*<alpha_d_vec, alpha_r2>*G // Reciprocal constraint public term i G // Referred as v_hat1 in code
    /// P += 2*T^5*x<q_pow_inv*alpha_d_vec, alpha_r1> // Range check constraint public term in G // Referred as v_hat2 in code
    /// P += 2*T^5*<1_vec, q_pows_vec>G // Sum value constant in G // Referred as v_hat3 in code
    /// P += 2*x^2T^8*|alpha_m|_q*G // T^8 public term in G // Referred as v_hat4 in code
    fn g_offset(
        &self,
        alpha_r: &[G::ScalarField],
        alpha_r2: &[G::ScalarField],
        t_cube: &G::ScalarField,
        q_pows: &[G::ScalarField],
        alpha_d_q_inv_pows: &[G::ScalarField],
        alpha_d: &[G::ScalarField],
        total_num_digits: usize,
    ) -> G::ScalarField {
        let two_t_3 = t_cube.double();
        let two_t_3_v = vec![two_t_3; total_num_digits];

        let v_hat_1 = inner_product(&two_t_3_v, q_pows);
        let v_hat_2 = inner_product(&alpha_d, alpha_r2) * two_t_3;
        let v_hat_3 = inner_product(&alpha_d_q_inv_pows, alpha_r) * two_t_3;

        v_hat_1 + v_hat_2 + v_hat_3
    }

    /// Compute the commitment C and run the norm arg on it
    /// C = S + t*M + t^2*D + t^3*R + 2t^5*V + P
    /// P = <g_vec_pub_offsets, G_vec> + g_offset*G
    pub fn verify(
        &self,
        num_bits: u16,
        V: &[G],
        setup_params: &SetupParams<G>,
        transcript: &mut impl Transcript,
    ) -> Result<(), BulletproofsPlusPlusError> {
        let base_bits = util::base_bits(self.base);
        if num_bits < base_bits {
            return Err(BulletproofsPlusPlusError::ValueIncompatibleWithBase(format!("number of bits in value={} which should not be less than number of bits in base={}", num_bits, self.base)));
        }
        // number of digits for 1 proof
        let num_digits_per_proof = num_bits / base_bits;
        let num_proofs = V.len();
        let total_num_digits = num_digits_per_proof as usize * num_proofs;
        let e = self.r1_comm.challenge(self.base, num_bits, V, transcript);
        let (x, y, r, q, lambda, delta) = self.r2_comm.challenges(transcript);
        let t = self.r3_comm.challenge(transcript);
        let t_pows = TPowers::new(t, setup_params.H_vec.len() as u32);

        let c_vec = create_c_vec(y, &t_pows);
        let (t_inv, t_sqr, t_cube) = (
            t_pows.nth_power(-1),
            t_pows.nth_power(2),
            t_pows.nth_power(3),
        );

        // q_pows = (q, q^2, q^3, ..., q^{g_vec.len()})
        let q_pows = powers_starting_from(q.clone(), &q, setup_params.G_vec.len() as u32);

        // q_inv_pows = (q^-1, q^-2, q^-3, ..., q^{-g_vec.len()})
        let mut q_inv_pows = q_pows.clone();
        batch_inversion(&mut q_inv_pows);

        let lambda_powers = powers(&lambda, num_proofs as u32);
        let alpha_d = alpha_d_given_lambda_powers(self.base, num_digits_per_proof, &lambda_powers);
        let alpha_d_q_inv_pow = hadamard_product(&alpha_d, &q_inv_pows);

        let alpha_r2 = alpha_r2(total_num_digits, e);
        let alpha_r = alpha_r(total_num_digits, x, delta);
        let alpha_r_q_inv_pows = alpha_r_q_inv_pow_given_alpha_r(&alpha_r, &alpha_r2, &q_inv_pows);

        // Compute the commitment to the public values
        let g_offset = self.g_offset(
            &alpha_r,
            &alpha_r2,
            t_cube,
            &q_pows,
            &alpha_d_q_inv_pow,
            &alpha_d,
            total_num_digits,
        );
        let mut g_vec_pub_offsets = self.g_vec_pub_offsets(
            e,
            x,
            &alpha_r_q_inv_pows,
            &t_pows,
            &q_inv_pows,
            &alpha_d_q_inv_pow,
        );

        let two_t_cube = t_cube.double();

        // C = <V, lambda_powers> * t^3 * 2 + S * t_inv + M * delta + D * t + R * t^2 + <G_vec, g_vec_pub_offsets> + G * g_offset

        // RHS of above can be created using an MSM
        let msm_size = 5 + V.len() + g_vec_pub_offsets.len();
        let mut bases = Vec::with_capacity(msm_size);
        let mut scalars = Vec::with_capacity(msm_size);

        // For <V, lambda_powers> * t^3 * 2
        bases.extend_from_slice(V);
        scalars.append(&mut scale(&lambda_powers, &two_t_cube));

        // For S * t_inv + M * delta + D * t + R * t^2
        bases.push(self.r3_comm.S);
        bases.push(self.r1_comm.M);
        bases.push(self.r1_comm.D);
        bases.push(self.r2_comm.R);
        scalars.push(*t_inv);
        scalars.push(delta);
        scalars.push(t);
        scalars.push(*t_sqr);

        // For <G_vec, g_vec_pub_offsets>
        bases.extend_from_slice(&setup_params.G_vec[0..g_vec_pub_offsets.len()]);
        scalars.append(&mut g_vec_pub_offsets);

        // For G * g_offset
        bases.push(setup_params.G);
        scalars.push(g_offset);

        self.norm_proof.verify_given_commitment_multiplicands(
            c_vec,
            r,
            bases,
            scalars,
            setup_params,
            transcript,
        )
    }
}

/// Powers of a scalar `t` as `(t^-1, 1, t, t^2, t^3, ...)`
struct TPowers<F: PrimeField>(pub Vec<F>);

impl<F: PrimeField> TPowers<F> {
    fn new(t: F, n: u32) -> Self {
        let t_inv = t.inverse().unwrap();
        Self(powers_starting_from(t_inv, &t, n + 1))
    }

    fn nth_power(&self, i: i32) -> &F {
        assert!(i < (self.0.len() - 1) as i32);
        &self.0[(i + 1) as usize]
    }
}

/// Compute a vector as result of alpha_d X q_inv_pows
/// Size must be number of digits in all proofs combined
fn alpha_d_q_inv_pow<F: PrimeField>(
    base: u16,
    num_digits_per_proof: u16,
    num_proofs: usize,
    q_inv_pows: &[F],
    lambda: F,
) -> Vec<F> {
    let res = alpha_d(base, num_digits_per_proof, num_proofs, lambda);
    hadamard_product(&res, &q_inv_pows)
}

/// Compute a vector of powers of `b` multiplied by powers of `lambda` like this: `(1, b, b^2, b^3, ..., b^{num_digits-1}, lambda, lambda*b, lambda*b^2, lambda*b^3, ..., lambda*b^{num_digits-1}, ..., lambda^{num_proofs-1}, {lambda^{num_proofs-1}}*b, {lambda^{num_proofs-1}}*b^2, {lambda^{num_proofs-1}}*b^3, ..., {lambda^{num_proofs-1}}*b^{num_digits-1})`
/// Size must be number of digits in all proofs combined.
fn alpha_d<F: PrimeField>(
    base: u16,
    num_digits_per_proof: u16,
    num_proofs: usize,
    lambda: F,
) -> Vec<F> {
    let base = F::from(base as u64);
    let lambda_powers = powers(&lambda, num_proofs as u32);
    let base_powers = powers(&base, num_digits_per_proof as u32);
    cfg_into_iter!(lambda_powers)
        .flat_map(|lambda_pow_i| scale(&base_powers, &lambda_pow_i))
        .collect()
}

/// Same as `alpha_d` except that it accepts lambda powers
fn alpha_d_given_lambda_powers<F: PrimeField>(
    base: u16,
    num_digits_per_proof: u16,
    lambda_powers: &[F],
) -> Vec<F> {
    let base = F::from(base as u64);
    let base_powers = powers(&base, num_digits_per_proof as u32);
    cfg_into_iter!(lambda_powers)
        .flat_map(|lambda_pow_i| scale(&base_powers, lambda_pow_i))
        .collect()
}

/// Compute alpha_m = vec![x/e, x/(e + 1), x/(e + 2), ...] X q_inv_pows
fn alpha_m_q_inv_pows<F: PrimeField>(e: F, x: F, n: usize, q_inv_pows: &[F]) -> Vec<F> {
    let res = alpha_m(e, x, n);
    hadamard_product(&res, q_inv_pows)
}

/// Compute alpha_m = vec![x/e, x/(e + 1), x/(e + 2), ...]
fn alpha_m<F: PrimeField>(e: F, x: F, n: usize) -> Vec<F> {
    cfg_into_iter!(0..n)
        .map(|i| x * (e + F::from(i as u64)).inverse().unwrap())
        .collect()
}

/// Compute a vector of scalar ((-x * delta)/((q_inv_pows)_i) + e)
fn alpha_r_q_inv_pow<F: PrimeField>(n: usize, x: F, e: F, q_inv_pows: &[F], delta: F) -> Vec<F> {
    let res = alpha_r(n, x, delta);
    let alpha_r = hadamard_product(&res, q_inv_pows);
    add_vecs(&alpha_r, &alpha_r2(n, e))
}

fn alpha_r_q_inv_pow_given_alpha_r<F: PrimeField>(
    alpha_r: &[F],
    alpha_r2: &[F],
    q_inv_pows: &[F],
) -> Vec<F> {
    add_vecs(&hadamard_product(&alpha_r, q_inv_pows), alpha_r2)
}

/// Compute a vector of scalar -x * delta
fn alpha_r<F: PrimeField>(n: usize, x: F, delta: F) -> Vec<F> {
    cfg_into_iter!(0..n).map(|_| (x * delta).neg()).collect()
}

/// Compute a vector of [e, e, e, e]
fn alpha_r2<F: PrimeField>(n: usize, e: F) -> Vec<F> {
    ark_std::iter::repeat(e).map(|e| e).take(n).collect()
}

/// obtain the c poly
fn c_poly<F: PrimeField>(y: F) -> Poly<F> {
    let zero = F::zero();
    let one = F::one();
    Poly {
        coeffs: vec![
            vec![one],
            vec![y],
            vec![y],
            vec![y],
            vec![y],
            vec![y],
            vec![y],
            vec![y],
            vec![zero],
        ],
    }
}

/// Obtain the non-zero at i position
fn t_pow_in_c(i: usize) -> usize {
    match i {
        0 => 1,
        1 => 0,
        2 => 2,
        3 => 3,
        4 => 4,
        5 => 6,
        6 => 7,
        7 => 8,
        8 => 9,
        _ => unreachable!("i must be in [0, 7]"),
    }
}

fn create_c_vec<F: PrimeField>(y: F, t_pows: &TPowers<F>) -> Vec<F> {
    let (t_inv, t, t2, t3, t5, t6, t7) = (
        t_pows.nth_power(-1),
        t_pows.nth_power(1),
        t_pows.nth_power(2),
        t_pows.nth_power(3),
        t_pows.nth_power(5),
        t_pows.nth_power(6),
        t_pows.nth_power(7),
    );
    vec![
        y * t_inv,
        y * t,
        y * t2,
        y * t3,
        y * t5,
        y * t6,
        y * t7,
        F::zero(),
    ]
}

/// Vector valued polynomial
#[derive(Debug, Clone)]
struct Poly<F: PrimeField> {
    coeffs: Vec<Vec<F>>,
}

impl<F: PrimeField> Poly<F> {
    // evaluate the poly at t
    #[cfg(test)]
    fn eval(&self, t: F) -> Vec<F> {
        let mut res = vec![F::zero(); self.coeffs[0].len()];
        let mut t_pow = t.inverse().unwrap();
        for coeffs in self.coeffs.iter() {
            for (i, coeff) in coeffs.iter().enumerate() {
                res[i] += t_pow * coeff;
            }
            t_pow = t_pow * t;
        }
        res
    }

    // evaluate the poly at t
    fn eval_given_t_powers(&self, t_pows: &TPowers<F>) -> Vec<F> {
        let mut res = vec![F::zero(); self.coeffs[0].len()];
        for (j, coeffs) in self.coeffs.iter().enumerate() {
            for (i, coeff) in coeffs.iter().enumerate() {
                res[i] += *t_pows.nth_power(j as i32 - 1) * coeff;
            }
        }
        res
    }

    // Compute the inner product of two polynomials
    fn w_q_norm(&self, q: F) -> Vec<F> {
        let mut res = vec![F::zero(); 2 * self.coeffs.len() - 1];
        // q_powers = (q, q^2, q^3, q^4, ...)
        let mut q_powers = vec![q];
        for i in 0..self.coeffs.len() {
            for j in 0..self.coeffs.len() {
                let a = &self.coeffs[i];
                let b = &self.coeffs[j];
                let min_len = a.len().min(b.len());
                while q_powers.len() < min_len {
                    q_powers.push(q * q_powers.last().unwrap())
                }
                // inner_prod = \sum_k{a_k * b_k * q_powers_k}
                let mut inner_prod = F::zero();
                for k in 0..min_len {
                    let (a_k, b_k) = (&a[k], &b[k]);
                    inner_prod += *a_k * b_k * q_powers[k];
                }
                res[i + j] += inner_prod;
            }
        }
        res
    }

    // multiply a vector polynomial `c` whose coefficients are constants, i.e. coefficient vectors have only 1 coefficient
    fn multiply_with_poly_of_constants(&self, c: &Poly<F>) -> Vec<F> {
        let mut res = vec![F::zero(); self.coeffs.len() + c.coeffs.len() - 1];
        for l in 0..self.coeffs.len() {
            let l_vec = &self.coeffs[l];
            for i in 0..l_vec.len() {
                let t_pow_in_c = t_pow_in_c(i);
                if t_pow_in_c >= c.coeffs.len() {
                    continue;
                }
                let inner_prod = l_vec[i] * c.coeffs[i][0]; // c_vec has exactly one element
                res[l + t_pow_in_c] += inner_prod;
            }
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::SetupParams;
    use ark_bls12_381::Fr;
    use ark_std::{
        rand::{prelude::StdRng, SeedableRng},
        UniformRand,
    };
    use blake2::Blake2b512;
    use dock_crypto_utils::transcript::new_merlin_transcript;

    // Test prove and verify
    fn test_rangeproof_for_perfect_range<G: AffineRepr>(base: u16, num_bits: u16, v: Vec<u64>) {
        let mut rng = StdRng::seed_from_u64(0u64);

        let mut gamma = vec![];
        for _ in 0..v.len() {
            gamma.push(G::ScalarField::rand(&mut rng));
        }

        let setup_params = SetupParams::<G>::new_for_perfect_range_proof::<Blake2b512>(
            b"test",
            base,
            num_bits,
            v.len() as u32,
        );

        let mut V = vec![];
        for (v_i, gamma_i) in v.iter().zip(gamma.iter()) {
            V.push(setup_params.compute_pedersen_commitment(*v_i, gamma_i));
        }
        let prover = Prover::new_with_given_base(base, num_bits, V.clone(), v, gamma).unwrap();
        let mut transcript = new_merlin_transcript(b"BPP/tests");
        let prf = prover
            .prove(&mut rng, setup_params.clone(), &mut transcript)
            .unwrap();

        let mut transcript = new_merlin_transcript(b"BPP/tests");
        prf.verify(num_bits, &V, &setup_params, &mut transcript)
            .unwrap();
    }

    fn check_for_perfect_range<G: AffineRepr>() {
        test_rangeproof_for_perfect_range::<G>(2, 2, vec![0]);
        for i in 0..16 {
            test_rangeproof_for_perfect_range::<G>(2, 4, vec![i]);
            test_rangeproof_for_perfect_range::<G>(2, 4, vec![i, 15 - i]);
        }
        test_rangeproof_for_perfect_range::<G>(16, 4, vec![7]);
        test_rangeproof_for_perfect_range::<G>(16, 8, vec![243]);
        test_rangeproof_for_perfect_range::<G>(16, 16, vec![12431]);
        test_rangeproof_for_perfect_range::<G>(2, 16, vec![12431]);
        test_rangeproof_for_perfect_range::<G>(4, 16, vec![12431]);
        test_rangeproof_for_perfect_range::<G>(8, 16, vec![12431]);
        test_rangeproof_for_perfect_range::<G>(16, 32, vec![134132, 14354, 981643, 875431]);
        let mut rng = StdRng::seed_from_u64(1u64);
        for _ in 0..10 {
            let mut v = vec![];
            for _ in 0..8 {
                v.push(u64::rand(&mut rng));
            }
            test_rangeproof_for_perfect_range::<G>(16, 64, v);
        }
        for _ in 0..10 {
            let v = u64::rand(&mut rng);
            test_rangeproof_for_perfect_range::<G>(16, 64, vec![v]);
        }
    }

    #[test]
    fn rangeproof_bls12381() {
        check_for_perfect_range::<ark_bls12_381::G1Affine>()
    }

    #[test]
    fn rangeproof_curve25519() {
        check_for_perfect_range::<ark_curve25519::EdwardsAffine>()
    }

    #[test]
    fn rangeproof_ed25519() {
        check_for_perfect_range::<ark_ed25519::EdwardsAffine>()
    }

    #[test]
    fn rangeproof_secp256k1() {
        check_for_perfect_range::<ark_secp256k1::Affine>()
    }

    #[test]
    fn poly() {
        let q = Fr::from(2);
        let a = Poly {
            coeffs: vec![
                vec![Fr::from(1), Fr::from(2)],
                vec![Fr::from(1), Fr::from(2)],
            ],
        };
        let _b = Poly {
            coeffs: vec![
                vec![Fr::from(3), Fr::from(4)],
                vec![Fr::from(3), Fr::from(4)],
            ],
        };
        let res = a.w_q_norm(q);
        assert_eq!(res, vec![Fr::from(18), Fr::from(36), Fr::from(18)]);

        let t = Fr::from(101);
        let t_pows = TPowers::new(t, 2);
        assert_eq!(a.eval(t), a.eval_given_t_powers(&t_pows));
    }
}
