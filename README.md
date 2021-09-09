# TBD
Library providing privacy enhancing cryptographic primitives.

## Primitives

1. [Schnorr proof of knowledge protocol](./schnorr) to prove knowledge of discrete log. [This](https://crypto.stanford.edu/cs355/19sp/lec5.pdf) is a good reference. 
2. [BBS+ signature](./bbs_plus) for anonymous credentials. Based on the paper [Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited](https://eprint.iacr.org/2016/663)
3. [Dynamic accumulators, both positive and universal](./vb_accumulator). Based on the paper [Dynamic Universal Accumulator with Batch Update over Bilinear Groups](https://eprint.iacr.org/2020/777)
4. [Proof system](./proof_system) that combines above primitives for use cases like prove knowledge of a BBS+ signature and the corresponding messages and the (non)membership of a certain message in the accumulator.

## Build

`cargo build` or `cargo build --release`

By default, it uses standard library and rayon 

For [no_std] support, build as `cargo build --no-default-features`

For WASM, build as `cargo build --no-default-features --target wasm32-unknown-unknown`

## Benchmarking

Criterion benchmarks [here](./benches)
 