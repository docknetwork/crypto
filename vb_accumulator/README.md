# vb_accumulator

Dynamic Positive and Universal accumulators according to the paper: [Dynamic Universal Accumulator with Batch Update over Bilinear Groups](https://eprint.iacr.org/2020/777)
Provides a dynamic positive accumulator [`PositiveAccumulator`], that supports membership proofs
Provides a dynamic universal accumulator [`UniversalAccumulator`], that supports membership and non-membership proofs.
Both accumulators implement that trait [`Accumulator`] that contains the common functionality.
Allows single and batch additions to the accumulator
Both [`MembershipWitness`] and [`NonMembershipWitness`] can be updated either using secret key or using public
info published by accumulator manager called [`Omega`]. Most of the update logic is in the trait [`Witness`] which
is implemented by both [`MembershipWitness`] and [`NonMembershipWitness`].
Allows single and batch updates to the witness.
Provides a zero knowledge proof of membership and non-membership in the accumulators with [`ProofProtocol`].
The implementation tries to use the same variable names as the paper and thus violate Rust's naming conventions at places.

[`Accumulator`]: crate::positive::Accumulator
[`PositiveAccumulator`]: crate::positive::PositiveAccumulator
[`UniversalAccumulator`]: crate::universal::UniversalAccumulator
[`MembershipWitness`]: crate::witness::MembershipWitness
[`NonMembershipWitness`]: crate::witness::NonMembershipWitness
[`Witness`]: crate::witness::Witness
[`Omega`]: crate::batch_utils::Omega
[`ProofProtocol`]: crate::proofs::ProofProtocol

License: Apache-2.0
