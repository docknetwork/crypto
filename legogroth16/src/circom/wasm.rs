//! Largely copied from <https://github.com/gakonst/ark-circom/blob/master/src/witness/circom.rs>

use crate::circom::error::CircomError;
use ark_std::{boxed::Box, string::ToString};
use wasmer::{Function, Instance, Store, Value};

/// Wrapper over the WASM module output by Circom. Used to call the functions defined in WASM module.
#[derive(Clone, Debug)]
pub struct Wasm(Instance);

impl Wasm {
    pub fn new(instance: Instance) -> Self {
        Self(instance)
    }

    pub fn init(&self, store: &mut Store, sanity_check: bool) -> Result<(), CircomError> {
        self.call_func(store, "init", &[Value::I32(sanity_check as i32)])?;
        Ok(())
    }

    /// Get the Circom version used to generate the WASM module
    pub fn get_version(&self, store: &mut Store) -> Result<u32, CircomError> {
        match self.0.exports.get_function("getVersion") {
            Ok(func) => Ok(func
                .call(store, &[])
                .map_err(|_| CircomError::WasmFunctionCallFailed("getVersion".to_string()))?[0]
                .unwrap_i32() as u32),
            // Old Circom didn't have version info
            Err(_) => Ok(1),
        }
    }

    /// Get number of 32-bit chunks needed to represent a field element
    pub fn get_field_num_len32(&self, store: &mut Store) -> Result<u32, CircomError> {
        self.get_u32(store, "getFieldNumLen32", &[])
    }

    /// Move the file cursor to the place where the subgroup order is written in little-endian
    /// order. The order is prime.
    pub fn get_raw_prime(&self, store: &mut Store) -> Result<(), CircomError> {
        self.call_func(store, "getRawPrime", &[])?;
        Ok(())
    }

    /// Read next 32-bytes in little-endian format from the offset `i`
    pub fn read_shared_rw_memory(&self, store: &mut Store, i: u32) -> Result<u32, CircomError> {
        self.get_u32(store, "readSharedRWMemory", &[i.into()])
    }

    /// Write a 32-byte value `v`  in little-endian format at the offset `i`
    pub fn write_shared_rw_memory(
        &self,
        store: &mut Store,
        i: u32,
        v: u32,
    ) -> Result<(), CircomError> {
        self.call_func(store, "writeSharedRWMemory", &[i.into(), v.into()])?;
        Ok(())
    }

    pub fn set_input_signal(
        &self,
        store: &mut Store,
        hmsb: u32,
        hlsb: u32,
        pos: u32,
    ) -> Result<(), CircomError> {
        self.call_func(
            store,
            "setInputSignal",
            &[hmsb.into(), hlsb.into(), pos.into()],
        )?;
        Ok(())
    }

    /// Move the cursor to the `i`th witness in the WASM module.
    pub fn get_witness(&self, store: &mut Store, i: u32) -> Result<(), CircomError> {
        self.call_func(store, "getWitness", &[i.into()])?;
        Ok(())
    }

    /// Return number of wires in the circuit
    pub fn get_witness_count(&self, store: &mut Store) -> Result<u32, CircomError> {
        self.get_u32(store, "getWitnessSize", &[])
    }

    /// Return number of input signals
    pub fn get_input_count(&self, store: &mut Store) -> Result<u32, CircomError> {
        self.get_u32(store, "getInputSize", &[])
    }

    /// Return number of signals for an input signal. For signals that are arrays, it returns the
    /// length of the array otherwise returns 1.
    pub fn get_signal_count(
        &self,
        store: &mut Store,
        hmsb: u32,
        hlsb: u32,
    ) -> Result<u32, CircomError> {
        self.get_u32(store, "getInputSignalSize", &[hmsb.into(), hlsb.into()])
    }

    /// Call the function with given name and return the result as a u32.
    pub fn get_u32(
        &self,
        store: &mut Store,
        name: &str,
        args: &[Value],
    ) -> Result<u32, CircomError> {
        let result = self.call_func(store, name, args)?;
        if result.is_empty() {
            return Err(CircomError::WasmFunctionResultEmpty(name.to_string()));
        }
        result[0]
            .i32()
            .ok_or_else(|| CircomError::WasmFunctionResultEmpty(name.to_string()))
            .map(|i| i as u32)
    }

    /// Call the function with given name and args
    fn call_func(
        &self,
        store: &mut Store,
        name: &str,
        args: &[Value],
    ) -> Result<Box<[Value]>, CircomError> {
        let func = self.func(name)?;
        func.call(store, args)
            .map_err(|_| CircomError::WasmFunctionCallFailed(name.to_string()))
    }

    /// Get the function with given name
    fn func(&self, name: &str) -> Result<&Function, CircomError> {
        self.0
            .exports
            .get_function(name)
            .map_err(|_| CircomError::UnknownWasmFunction(name.to_string()))
    }
}
