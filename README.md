# TBD

[![CI](https://github.com/docknetwork/crypto/actions/workflows/test.yml/badge.svg)](https://github.com/docknetwork/crypto/actions/workflows/test.yml)
[![Apache-2](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/docknetwork/crypto/blob/main/LICENSE)
[![Dependencies](https://deps.rs/repo/github/docknetwork/crypto/status.svg)](https://deps.rs/repo/github/docknetwork/crypto)

Library providing privacy enhancing cryptographic primitives.

## Primitives

1. [Schnorr proof of knowledge protocol](./schnorr_pok) to prove knowledge of discrete log. [This](https://crypto.stanford.edu/cs355/19sp/lec5.pdf) is a good reference. 
2. [BBS+ signature](./bbs_plus) for anonymous credentials. Based on the paper [Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited](https://eprint.iacr.org/2016/663)
3. [Dynamic accumulators, both positive and universal](./vb_accumulator). Based on the paper [Dynamic Universal Accumulator with Batch Update over Bilinear Groups](https://eprint.iacr.org/2020/777)
4. [Composite proof system](./proof_system) that combines above primitives for use cases like prove knowledge of a BBS+ signature and the corresponding messages and the (non)membership of a certain message(s) in the accumulator. Also numeric bounds (min, max) on the messages can be proved in zero-knowledge and verifiable encryption of messages is also supported.
5. [Verifiable encryption](./saver) using [SAVER](https://eprint.iacr.org/2019/1270).
6. [Compression and amortization of Sigma protocols](./compressed_sigma). This is PoC implementation.

## Composite proof system

The [proof system](./proof_system) that uses above-mentioned primitives. 

## Build

`cargo build` or `cargo build --release`

By default, it uses standard library and [rayon](https://github.com/rayon-rs/rayon) for parallelization

To build with standard library but without parallelization, use `cargo build --no-default-features --features=std`

For `no_std` support, build as `cargo build --no-default-features`

For WASM, build as `cargo build --no-default-features --target wasm32-unknown-unknown`

## Test

`cargo test`

The above maybe slower as it runs the tests in debug mode and some tests work on large inputs. 
For running tests faster, run `cargo test --release`


## Benchmarking

[Criterion](https://github.com/bheisler/criterion.rs) benchmarks [here](./benches)

Some tests also print time consumed by the operations, run `cargo test --release -- --nocapure [test name]`

## WASM wrapper

A WASM wrapper has been created over this repo [here](https://github.com/docknetwork/crypto-wasm). The wrapper is then used to create [this Typescript library](https://github.com/docknetwork/crypto-wasm-ts) which is more ergonomic than using the wrapper as the wrapper contains free floating functions.
