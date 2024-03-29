# Circom integration

Create SRS and proof using R1CS and WASM generated by Circom programs. 

The expected workflow is:

- Compile a program written in Circom version 2. Use the `-p` flag to specify the BLS12-381 curve as `-p=bls12381` if 
  working with BLS12-381 curve. Omit it if working with BN254 curve.
- Create the circuit [`CircomCircuit`](./circuit.rs) using the R1CS. Either use `CircomCircuit::from_r1cs_file` to read  
  the .r1cs file or create [`R1CS`](./r1cs.rs) directly by using the output [another parser](https://github.com/iden3/r1csfile).
- Use `CircomCircuit::generate_proving_key` to generate the proving key.
- The prover uses `WitnessCalculator` to calculate the values of all wires of the circuit by first initializing using the 
  WASM generated by Circom (.wasm file) and then passing its public and private input signals to `WitnessCalculator::calculate_witnesses`.  
- Prover then creates a `CircomCircuit` using R1CS as above and sets the wires of the circuit calculated in the previous step.
- The `CircomCircuit` can now be used to create the proof.

See [tests](./tests.rs) for example.

Supports only Circom 2 and curves BN128 and BLS12-381 for now. 

Most of the code to parse R1CS and wasm files has been taken from [here](https://github.com/gakonst/ark-circom) and [here](https://github.com/iden3/circom_runtime/blob/master/js/witness_calculator.js)

## Build

```
cargo build --features=circom
```

For no_std

```
cargo build --no-default-features --features=circom,wasmer-sys
```

For wasm target

```
cargo build --no-default-features --features=circom,wasmer-js --target wasm32-unknown-unknown
```

## Compiling Circom circuits

For Bn254 curve, compile as 

```
circom --r1cs --wasm --output=<directory for compiler output for this circuit> <.circom file>
```

For Bls12-381 curve, compile with `-p` flag as

```
circom -p=bls12381 --r1cs --wasm --output=<directory for compiler output for this circuit> <.circom file>
```

## Test

Tests are run for 2 curves, `bn128` and `bls12-381`. The circuits used in the tests are present in [circuits](../../test-vectors/circuits) 
directory and the `.wasm` and `.r1cs` files for both curves are present in their respective directories, for [bn128](../../test-vectors/bn128) 
and [bls12-381](../../test-vectors/bls12-381). 