<!-- cargo-rdme start -->

# Oblivious Transfer (OT), Oblivious Transfer Extensions (OTE) and multi-party protocols based on that.

## Oblivious Transfer protocols

1. [Simplest OT protocol](./src/base_ot/simplest_ot.rs)
2. [Naor Pinkas OT](./src/base_ot/naor_pinkas_ot.rs)
3. [Endemic OT](./src/base_ot/endemic_ot.rs)

## Oblivious Transfer Extensions
1. [ALSZ](./src/ot_extensions/alsz_ote.rs)
2. [KOS](./src/ot_extensions/kos_ote.rs)

## Oblivious Transfer based multiplication
1. [DKLS18](./src/ot_based_multiplication/dkls18_mul_2p.rs) - 2 party multiplication of where each party has a single input
2. [DKLS19](./src/ot_based_multiplication/dkls19_batch_mul_2p.rs) - 2 party batch-multiplication of where each party has multiple inputs, say `n` inputs and those inputs will be multiplied, i.e. a total of `2*n` multiplications will be done with each being between 2 inputs

<!-- cargo-rdme end -->
