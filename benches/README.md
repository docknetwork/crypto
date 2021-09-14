# Benchmarking primitives in this workspace

Run `cargo bench` to run all the benchmarks and will use the standard library and rayon for parallelization. 
To avoid both standard library and rayon, run `cargo bench --no-default-features` 

For running specific benchmarks, see below

## Schnorr protocol
To run all benchmarks for this, run

`cargo bench --bench=schnorr`

Like others, above uses the standard library and rayon, to avoid both, run

`cargo bench --no-default-features --bench=schnorr`

## BBS+ signatures
To run benchmarks for signing and verifying (both groups G1 and G2), run

`cargo bench --bench=bbs_plus_signature`

For proof of knowledge (signature in G1 only)

`cargo bench --bench=bbs_plus_proof`

## Accumulators

For positive accumulator

`cargo bench --bench=positive_accumulator`

For universal accumulator

`cargo bench --bench=universal_accumulator`

For witness update (both using and without secret key)

`cargo bench --bench=accum_witness_updates`