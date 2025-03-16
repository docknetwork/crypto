use ark_std::{collections::BTreeSet, vec::Vec};
use digest::Digest;

#[macro_export]
macro_rules! hash_elem {
    ($elem: expr, $hasher: ident, $buffer: ident) => {{
        $elem.serialize_compressed(&mut $buffer).unwrap();
        DynDigest::update(&mut $hasher, &$buffer);
        $buffer.clear();
    }};
}

/// Use the given challenge to get a set of indices of size `num_indices` where each index is < `num_parties`.
/// Will hash the challenge repeatedly unless the set of required size is created.
pub fn get_unique_indices_to_hide<D: Digest>(
    challenge: &[u8],
    num_indices: u16,
    num_parties: u16,
) -> BTreeSet<u16> {
    // Computes the index of the unopened party. Using set to avoid duplicate indices
    let mut output = BTreeSet::<u16>::new();
    let mut c = challenge.to_vec();
    while (output.len() as u16) < num_indices {
        // Divide the bytearray into 2-byte chunks and each chunk is used to create a u16 < num_parties
        for c_i in c.chunks(2) {
            output.insert(get_bounded_u16_from_u8_slice(c_i, num_parties));
            if output.len() as u16 == num_indices {
                break;
            }
        }
        if output.len() as u16 != num_indices {
            c = D::digest(c.as_slice()).to_vec();
        }
    }

    output
}

/// Use the given challenge to get a list of indices of size `num_indices` where each index is < `num_parties`.
/// Will hash the challenge repeatedly unless the list of required size is created.
pub fn get_indices_to_hide<D: Digest>(
    challenge: &[u8],
    num_indices: u16,
    num_parties: u16,
) -> Vec<u16> {
    // Computes the index of the unopened party in each of the repetitions
    let mut output = Vec::with_capacity(num_indices as usize);
    let mut c = challenge.to_vec();
    while (output.len() as u16) < num_indices {
        // Divide the bytearray into 2-byte chunks and each chunk is used to create a u16 < num_parties
        for c_i in c.chunks(2) {
            output.push(get_bounded_u16_from_u8_slice(c_i, num_parties));
            if output.len() as u16 == num_indices {
                break;
            }
        }
        if output.len() as u16 != num_indices {
            c = D::digest(c.as_slice()).to_vec();
        }
    }

    output
}

#[inline(always)]
fn get_bounded_u16_from_u8_slice(c: &[u8], upper_bound: u16) -> u16 {
    if c.len() == 2 {
        (((c[0] as u16) << 8) | (c[1] as u16)) % upper_bound
    } else {
        c[0] as u16 % upper_bound
    }
}
