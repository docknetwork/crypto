<!-- cargo-rdme start -->

# Accumulators based on bilinear map (pairings)

## vb_accumulator
Dynamic Positive and Universal accumulators according to the paper: [Dynamic Universal Accumulator with Batch Update over Bilinear Groups](https://eprint.iacr.org/2020/777)
Implements
- a dynamic positive accumulator [`PositiveAccumulator`], that supports membership proofs.
- a dynamic universal accumulator [`UniversalAccumulator`], that supports membership and non-membership proofs.
- a zero knowledge proof of membership and non-membership in the accumulators with [`ProofProtocol`] as described in the paper.
  These are essentially proofs of knowledge of a weak-BB signature
- an alternate and more efficient protocol of zero knowledge proof of membership and non-membership based on a more
  efficient protocol for proving knowledge of a weak-BB signature. This isn't described in the paper.
- keyed verification proofs of membership and non-membership where the verifier knows the secret key

Allows
- single and batch updates (additions, removals or both) to the accumulators.
- single and batch updates to the witness.

Both accumulators implement that trait [`Accumulator`] that contains the common functionality.
Both [`MembershipWitness`] and [`NonMembershipWitness`] can be updated either using secret key or using public
info published by accumulator manager called [`Omega`].
Most of the update logic is in the trait [`Witness`] which is implemented by both [`MembershipWitness`]
and [`NonMembershipWitness`].
The implementation tries to use the same variable names as the paper and thus violate Rust's naming conventions at places.

## kb_accumulator
Dynamic Positive and Universal accumulators according to the paper: [Efficient Constructions of Pairing Based Accumulators](https://eprint.iacr.org/2021/638)
Implements
- a dynamic positive accumulator [`KBPositiveAccumulator`], that supports membership proofs. Based on construction 2 in the paper.
- a dynamic universal accumulator [`KBUniversalAccumulator`], that supports membership and non-membership proofs. Based on construction 3 in the paper
- zero knowledge proofs of membership and non-membership in the accumulators. These are essentially proofs of knowledge of a
  BB signature and weak-BB signature.
- an alternate and more efficient protocol for membership and non-membership proofs
- keyed verification proofs of membership and non-membership where the verifier knows the secret key

Allows batch updates to the accumulator and the witness using the techniques from `vb_accumulator`

The implementation uses type-3 pairings compared to type-1 in the paper.

[`Accumulator`]: https://docs.rs/vb_accumulator/latest/vb_accumulator/positive/trait.Accumulator.html
[`PositiveAccumulator`]: https://docs.rs/vb_accumulator/latest/vb_accumulator/positive/struct.PositiveAccumulator.html
[`UniversalAccumulator`]: https://docs.rs/vb_accumulator/latest/vb_accumulator/universal/struct.UniversalAccumulator.html
[`MembershipWitness`]: https://docs.rs/vb_accumulator/latest/vb_accumulator/witness/struct.MembershipWitness.html
[`NonMembershipWitness`]: https://docs.rs/vb_accumulator/latest/vb_accumulator/witness/struct.NonMembershipWitness.html
[`Witness`]: https://docs.rs/vb_accumulator/latest/vb_accumulator/witness/trait.Witness.html
[`Omega`]: https://docs.rs/vb_accumulator/latest/vb_accumulator/batch_utils/struct.Omega.html
[`ProofProtocol`]: https://docs.rs/vb_accumulator/latest/vb_accumulator/proofs/trait.ProofProtocol.html
[`KBPositiveAccumulator`]: https://docs.rs/vb_accumulator/latest/vb_accumulator/kb_positive_accumulator/adaptive_accumulator/struct.KBPositiveAccumulator.html
[`KBUniversalAccumulator`]: https://docs.rs/vb_accumulator/latest/vb_accumulator/kb_universal_accumulator/accumulator/struct.KBUniversalAccumulator.html

<!-- cargo-rdme end -->
