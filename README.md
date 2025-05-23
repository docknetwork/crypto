# TBD

[![CI](https://github.com/docknetwork/crypto/actions/workflows/test.yml/badge.svg)](https://github.com/docknetwork/crypto/actions/workflows/test.yml)
[![Apache-2](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/docknetwork/crypto/blob/main/LICENSE)
[![Dependencies](https://deps.rs/repo/github/docknetwork/crypto/status.svg)](https://deps.rs/repo/github/docknetwork/crypto)

Library providing privacy enhancing cryptographic primitives.

## Primitives

1. [Sigma protocols](./schnorr_pok) to prove knowledge of discrete log, equality, inequality of discrete logs, knowledge of opening of a generalized Pedersen commitment, etc. [This](https://crypto.stanford.edu/cs355/19sp/lec5.pdf) is a good reference. 
2. [BBS and BBS+ signatures](./bbs_plus) for anonymous credentials. BBS+ is based on the paper [Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited](https://eprint.iacr.org/2016/663) and 
   BBS is based on the paper [Revisiting BBS Signatures](https://eprint.iacr.org/2023/275). Also implements the threshold variants of these based on the paper [Threshold BBS+ Signatures for Distributed Anonymous Credential Issuance](https://eprint.iacr.org/2023/602)
3. [Dynamic accumulators, both positive and universal](./vb_accumulator). Based on the papers [Dynamic Universal Accumulator with Batch Update over Bilinear Groups](https://eprint.iacr.org/2020/777) and [Efficient Constructions of Pairing Based Accumulators](https://eprint.iacr.org/2021/638). Implements a keyed-verification variant of these accumulators as well which does not require pairings.
4. [Composite proof system](./proof_system) that combines above primitives for use cases like 
   - prove knowledge of a BBS+ signature and the corresponding messages
   - prove knowledge of a modified PS signature and the corresponding messages
   - equality of signed messages (from same or different signatures) in zero knowledge
   - inequality of signed messages with public or committed values in zero knowledge
   - the (non)membership of a certain signed message(s)in the accumulator
   - numeric bounds (min, max) on the messages can be proved in zero-knowledge 
   - verifiable encryption of signed messages under BBS+ or PS. 
   - zk-SNARK created from R1CS and WASM generated by [Circom](https://docs.circom.io/) with witnesses as BBS+ signed messages (not exclusively though). 
5. [Verifiable encryption](./saver) using [SAVER](https://eprint.iacr.org/2019/1270).
6. [Compression and amortization of Sigma protocols](./compressed_sigma). This is PoC implementation.
7. [Secret sharing schemes and DKG](./secret_sharing_and_dkg). Implements several verifiable secret sharing schemes and DKG from Gennaro and FROST. Also implements protocol to do a distributed DLOG check.
8. [Cocount and PS signatures](./coconut/). Based on the paper [Security Analysis of Coconut, an Attribute-Based Credential Scheme with Threshold Issuance](https://eprint.iacr.org/2022/011)
9. [LegoGroth16](./legogroth16/).  LegoGroth16, the [LegoSNARK](https://eprint.iacr.org/2019/142) variant of [Groth16](https://eprint.iacr.org/2016/260) zkSNARK proof system
10. [Oblivious Transfer (OT) and Oblivious Transfer Extensions (OTE)](./oblivious_transfer).
11. [Short group signatures](./short_group_sig/). BB signature and weak-BB signature and their proofs of knowledge based on the papers [Short Signatures Without Random Oracles](https://eprint.iacr.org/2004/171) and [Scalable Revocation Scheme for Anonymous Credentials Based on n-times Unlinkable Proofs](http://library.usc.edu.ph/ACM/SIGSAC%202017/wpes/p123.pdf).
12. [Keyed-Verification Anonymous Credentials (KVAC)](./kvac). Implements Keyed-Verification Anonymous Credentials (KVAC) schemes.
13. [SyRA](./syra). Implements sybil resilient signatures to be used for generating pseudonyms for low-entropy credential attributes.
14. [Verifiable encryption](./verifiable_encryption) using the paper [Verifiable Encryption from MPC-in-the-Head](https://eprint.iacr.org/2021/1704.pdf).
15. [Utilities](./utils) like inner product, hadamard product, polynomial utilities, solving discrete log, Elgamal encryption, etc.

## Composite proof system

The [proof system](./proof_system) that uses above-mentioned primitives. 

## Build

`cargo build` or `cargo build --release`

By default, it uses standard library and [rayon](https://github.com/rayon-rs/rayon) for parallelization

To build with standard library but without parallelization, use `cargo build --no-default-features --features=std`

For `no_std` support, build as `cargo build --no-default-features --features=wasmer-sys`

For WASM, build as `cargo build --no-default-features --features=wasmer-js --target wasm32-unknown-unknown`

## Test

`cargo test`

The above maybe slower as it runs the tests in debug mode and some tests work on large inputs. 
For running tests faster, run `cargo test --release`

## Benchmarking

[Criterion](https://github.com/bheisler/criterion.rs) benchmarks [here](./benches)

Some tests also print time consumed by the operations, run `cargo test --release -- --nocapture [test name]`

## WASM wrapper

A WASM wrapper has been created over this repo [here](https://github.com/docknetwork/crypto-wasm). 
The wrapper is then used to create [this Typescript library](https://github.com/docknetwork/crypto-wasm-ts) which is more ergonomic 
than using the wrapper as the wrapper contains free floating functions. The Typescript wrapper also contains abstractions for 
anonymous credentials like schemas, credentials, presentations, etc.
