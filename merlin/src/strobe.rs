//! Minimal implementation of (parts of) Strobe.

use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
};
use ark_std::{
    fmt,
    io::{Read, Write},
    marker::PhantomData,
    mem::MaybeUninit,
    ptr,
    vec::Vec,
};
use core::ops::{Deref, DerefMut};

use keccak;
use serde::{
    de::{Error, SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserialize, Deserializer, Serialize, Serializer,
};
use zeroize::Zeroize;

/// Strobe R value; security level 128 is hardcoded
const STROBE_R: u8 = 166;

const FLAG_I: u8 = 1;
const FLAG_A: u8 = 1 << 1;
const FLAG_C: u8 = 1 << 2;
const FLAG_T: u8 = 1 << 3;
const FLAG_M: u8 = 1 << 4;
const FLAG_K: u8 = 1 << 5;

fn transmute_state(st: &mut AlignedKeccakState) -> &mut [u64; 25] {
    unsafe { &mut *(st as *mut AlignedKeccakState as *mut [u64; 25]) }
}

/// This is a wrapper around 200-byte buffer that's always 8-byte aligned
/// to make pointers to it safely convertible to pointers to [u64; 25]
/// (since u64 words must be 8-byte aligned)
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
#[repr(align(8))]
pub struct AlignedKeccakState(pub [u8; 200]);

/// A Strobe context for the 128-bit security level.
///
/// Only `meta-AD`, `AD`, `KEY`, and `PRF` operations are supported.
#[derive(Clone, Zeroize, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize)]
pub struct Strobe128 {
    pub state: AlignedKeccakState,
    pub pos: u8,
    pub pos_begin: u8,
    pub cur_flags: u8,
}

impl ::core::fmt::Debug for Strobe128 {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        // Ensure that the Strobe state isn't accidentally logged
        write!(f, "Strobe128: STATE OMITTED")
    }
}

impl Strobe128 {
    pub fn new(protocol_label: &[u8]) -> Strobe128 {
        let initial_state = {
            let mut st = AlignedKeccakState([0u8; 200]);
            st[0..6].copy_from_slice(&[1, STROBE_R + 2, 1, 0, 1, 96]);
            st[6..18].copy_from_slice(b"STROBEv1.0.2");
            keccak::f1600(transmute_state(&mut st));

            st
        };

        let mut strobe = Strobe128 {
            state: initial_state,
            pos: 0,
            pos_begin: 0,
            cur_flags: 0,
        };

        strobe.meta_ad(protocol_label, false);

        strobe
    }

    pub fn meta_ad(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_M | FLAG_A, more);
        self.absorb(data);
    }

    pub fn ad(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_A, more);
        self.absorb(data);
    }

    pub fn prf(&mut self, data: &mut [u8], more: bool) {
        self.begin_op(FLAG_I | FLAG_A | FLAG_C, more);
        self.squeeze(data);
    }

    pub fn key(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_A | FLAG_C, more);
        self.overwrite(data);
    }
}

impl Strobe128 {
    fn run_f(&mut self) {
        self.state[self.pos as usize] ^= self.pos_begin;
        self.state[(self.pos + 1) as usize] ^= 0x04;
        self.state[(STROBE_R + 1) as usize] ^= 0x80;
        keccak::f1600(transmute_state(&mut self.state));
        self.pos = 0;
        self.pos_begin = 0;
    }

    fn absorb(&mut self, data: &[u8]) {
        for byte in data {
            self.state[self.pos as usize] ^= byte;
            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
    }

    fn overwrite(&mut self, data: &[u8]) {
        for byte in data {
            self.state[self.pos as usize] = *byte;
            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
    }

    fn squeeze(&mut self, data: &mut [u8]) {
        for byte in data {
            *byte = self.state[self.pos as usize];
            self.state[self.pos as usize] = 0;
            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
    }

    fn begin_op(&mut self, flags: u8, more: bool) {
        // Check if we're continuing an operation
        if more {
            assert_eq!(
                self.cur_flags, flags,
                "You tried to continue op {:#b} but changed flags to {:#b}",
                self.cur_flags, flags,
            );
            return;
        }

        // Skip adjusting direction information (we just use AD, PRF)
        assert_eq!(
            flags & FLAG_T,
            0u8,
            "You used the T flag, which this implementation doesn't support"
        );

        let old_begin = self.pos_begin;
        self.pos_begin = self.pos + 1;
        self.cur_flags = flags;

        self.absorb(&[old_begin, flags]);

        // Force running F if C or K is set
        let force_f = 0 != (flags & (FLAG_C | FLAG_K));

        if force_f && self.pos != 0 {
            self.run_f();
        }
    }
}

impl Deref for AlignedKeccakState {
    type Target = [u8; 200];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AlignedKeccakState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl CanonicalSerialize for AlignedKeccakState {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.0.serialize_with_mode(&mut writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.0.serialized_size(compress)
    }
}

impl Valid for AlignedKeccakState {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl CanonicalDeserialize for AlignedKeccakState {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        Ok(AlignedKeccakState(
            CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
        ))
    }
}

impl Serialize for AlignedKeccakState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_tuple(200)?;
        for element in &self.0 {
            seq.serialize_element(element)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for AlignedKeccakState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = deserializer.deserialize_seq(ArrayVisitor {
            _phantom: PhantomData,
        })?;
        Ok(Self(s))
    }
}

struct ArrayVisitor<'de> {
    _phantom: PhantomData<&'de [u8; 200]>,
}

impl<'de> Visitor<'de> for ArrayVisitor<'de> {
    type Value = [u8; 200];

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "array of length {}", 200)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut array: MaybeUninit<[u8; 200]> = MaybeUninit::uninit();

        for index in 0..200 {
            // Get next item as Result<Option<T>, A::Error>. Since we know
            // exactly how many elements we should receive, we can flatten
            // this to a Result<T, A::Error>.
            let next = seq
                .next_element::<u8>()
                .and_then(|x| x.ok_or_else(|| Error::invalid_length(200, &self)));

            match next {
                Ok(x) => unsafe {
                    // Safety: We write into the array without reading any
                    // uninitialized memory and writes only occur within the
                    // array bounds at multiples of the array stride.
                    let array_base_ptr = array.as_mut_ptr() as *mut u8;
                    ptr::write(array_base_ptr.add(index), x);
                },
                Err(err) => {
                    // Safety: We need to manually drop the parts we
                    // initialized before we can return.
                    unsafe {
                        let array_base_ptr = array.as_mut_ptr() as *mut u8;

                        for offset in 0..index {
                            ptr::drop_in_place(array_base_ptr.add(offset));
                        }
                    }

                    return Err(err);
                }
            }
        }

        // Safety: We have completely initialized every element
        unsafe { Ok(array.assume_init()) }
    }
}

#[cfg(test)]
mod tests {
    use strobe_rs::{self, SecParam};

    #[test]
    fn test_conformance() {
        let mut s1 = super::Strobe128::new(b"Conformance Test Protocol");
        let mut s2 = strobe_rs::Strobe::new(b"Conformance Test Protocol", SecParam::B128);

        // meta-AD(b"msg"); AD(msg)

        let msg = [99u8; 1024];

        s1.meta_ad(b"ms", false);
        s1.meta_ad(b"g", true);
        s1.ad(&msg, false);

        s2.meta_ad(b"ms", false);
        s2.meta_ad(b"g", true);
        s2.ad(&msg, false);

        // meta-AD(b"prf"); PRF()

        let mut prf1 = [0u8; 32];
        s1.meta_ad(b"prf", false);
        s1.prf(&mut prf1, false);

        let mut prf2 = [0u8; 32];
        s2.meta_ad(b"prf", false);
        s2.prf(&mut prf2, false);

        assert_eq!(prf1, prf2);

        // meta-AD(b"key"); KEY(prf output)

        s1.meta_ad(b"key", false);
        s1.key(&prf1, false);

        s2.meta_ad(b"key", false);
        s2.key(&prf2, false);

        // meta-AD(b"prf"); PRF()

        let mut prf1 = [0u8; 32];
        s1.meta_ad(b"prf", false);
        s1.prf(&mut prf1, false);

        let mut prf2 = [0u8; 32];
        s2.meta_ad(b"prf", false);
        s2.prf(&mut prf2, false);

        assert_eq!(prf1, prf2);
    }
}
