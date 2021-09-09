# vb_accumulator

Dynamic Positive and Universal accumulators according to the paper: "Dynamic Universal Accumulator with Batch Update over Bilinear Groups" <https://eprint.iacr.org/2020/777>
Provides a dynamic positive accumulator [`PositiveAccumulator`], that supports membership proofs
Provides a dynamic universal accumulator [`UniversalAccumulator`], that supports membership and non-membership proofs
Provides a zero knowledge proof of membership and non-membership in the accumulators with [`ProofProtocol`].
The implementation tries to use the same variable names as the paper and thus violate Rust's naming conventions at places.

[`PositiveAccumulator`]: crate::positive::PositiveAccumulator
[`UniversalAccumulator`]: crate::universal::UniversalAccumulator
[`ProofProtocol`]: crate::proofs::ProofProtocol

License: Apache-2.0
