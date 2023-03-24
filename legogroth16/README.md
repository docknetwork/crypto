<h1 align="center">legogroth16</h1>

This repository contains an implementation of the LegoGroth16, the [LegoSNARK](https://eprint.iacr.org/2019/142) variant of [Groth16](https://eprint.iacr.org/2016/260) zkSNARK proof system.  
This project started as fork of [this](https://github.com/kobigurk/legogro16) but is updated to 
- commit to a subset of the witnesses by specifying the count, say `n`, of the witnesses to commit during CRS generation. 
  By convention, it commits to the first `n` variables allocated for witnesses in the circuit and the proof contains that commitment
- either contain CP_link as well or omit it but only have the proof contain the commitment. The proof here contains 2 commitments (one is same as above)
  to the witness variables but with different commitment keys and randomness.
- creating and verifying proofs for [Circom](https://docs.circom.io) circuits
- proof aggregation using [Snarckpack](https://eprint.iacr.org/2021/529)

The zkSNARK for Linear Subspaces from appendix D of LegoSNARK paper is [here](src/link/snark.rs).

This library is released under the MIT License and the Apache v2 License (see [License](#license)).

## Build guide

Build the library:
```bash
cargo build --release
```

This library comes with unit tests for each of the provided crates. Run the tests with:
```bash
cargo test
```

To build without `std` but with Circom support and proof aggregation, run 
```
cargo build --no-default-features --features=circom,aggregation,wasmer-sys
```

To build for WASM with Circom support and proof aggregation, run
```
cargo build --no-default-features --features=circom,aggregation,wasmer-js --target wasm32-unknown-unknown
```

To run all tests without `std`, run
```
cargo test --no-default-features --features=std,circom,aggregation,wasmer-sys
```

## License

This library is licensed under either of the following licenses, at your discretion.

 * Apache License Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution submitted for inclusion in this library by you shall be dual licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.

## Acknowledgements

This work was supported by:
a Google Faculty Award;
the National Science Foundation;
the UC Berkeley Center for Long-Term Cybersecurity;
and donations from the Ethereum Foundation, the Interchain Foundation, and Qtum.

An earlier version of this library was developed as part of the paper *"[ZEXE: Enabling Decentralized Private Computation][zexe]"*.

[zexe]: https://ia.cr/2018/962
