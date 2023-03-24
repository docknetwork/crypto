use ark_std::string::String;

#[derive(Clone, Debug, PartialEq)]
pub enum CircomError {
    /// Only version 2 of Circom is supported
    UnsupportedVersion(u32),
    /// Only BN128 and BLS12-381 curves are supported
    UnsupportedCurve(String),
    /// The .r1cs file or WASM module is being loaded for the wrong curve, i.e. it might have been
    /// generated for bn128 but being loader of bls12-381 or vice versa.
    IncompatibleWithCurve,
    UnknownWasmFunction(String),
    WasmFunctionCallFailed(String),
    /// Result of calling a WASM function was empty which was unexpected
    WasmFunctionResultEmpty(String),
    /// Result of calling a WASM function did not return as i32 which was unexpected
    WasmFunctionResultNoti32(String),
    /// Required number of inputs not same as the inputs provided.
    IncorrectNumberOfInputsProvided(u32, u32),
    /// Required number of signals for the input not same as the signals provided.
    IncorrectNumberOfSignalsProvided(String, u32, u32),
    /// Contains the error message when opening R1CS file
    UnableToOpenR1CSFile(String),
    /// Contains the error message when opening wasm file
    UnableToLoadWasmModuleFromFile(String),
    UnableToLoadWasmModuleFromBytes(String),
    /// Contains the error message when instantiating WASM module
    WasmInstantiationError(String),
    R1CSFileParsing(String),
}
