# TBD
Library providing privacy enhancing cryptographic primitives.

## Primitives

1. [Schnorr proof of knowledge protocol](./schnorr_pok) to prove knowledge of discrete log. [This](https://crypto.stanford.edu/cs355/19sp/lec5.pdf) is a good reference. 
2. [BBS+ signature](./bbs_plus) for anonymous credentials. Based on the paper [Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited](https://eprint.iacr.org/2016/663)
3. [Dynamic accumulators, both positive and universal](./vb_accumulator). Based on the paper [Dynamic Universal Accumulator with Batch Update over Bilinear Groups](https://eprint.iacr.org/2020/777)
4. [Proof system](./proof_system) that combines above primitives for use cases like prove knowledge of a BBS+ signature and the corresponding messages and the (non)membership of a certain message in the accumulator.

## Build

`cargo build` or `cargo build --release`

By default, it uses standard library and [rayon](https://github.com/rayon-rs/rayon) for parallelization

To build with standard library but without parallelization, use `cargo build --no-default-features --features=std`

For [no_std] support, build as `cargo build --no-default-features`

For WASM, build as `cargo build --no-default-features --target wasm32-unknown-unknown`

## Test

`cargo test`

The above maybe slower as it runs the tests in debug mode and some tests work on large inputs. 
For running tests faster, run `cargo test --release`


## Benchmarking

[Criterion](https://github.com/bheisler/criterion.rs) benchmarks [here](./benches)

Some tests also print time consumed by the operations, run `cargo test --release -- --nocapure [test name]`