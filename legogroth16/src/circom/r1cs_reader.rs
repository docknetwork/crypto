//! R1CS circom file reader
//! Largely copied from <https://github.com/gakonst/ark-circom/blob/master/src/circom/r1cs_reader.rs>
//! Spec: <https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md>

use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalDeserialize;
use ark_std::{collections::BTreeMap, format, io::Read, marker::PhantomData, vec, vec::Vec};
use std::io::{Seek, SeekFrom};

use crate::circom::{
    error::CircomError,
    r1cs::{Constraint, Header, R1CSFile, LC},
    witness::check_subgroup_order,
};

impl<E: Pairing> R1CSFile<E> {
    pub fn new_from_file(path: impl AsRef<std::path::Path>) -> Result<Self, CircomError> {
        let reader = std::fs::File::open(path).map_err(|err| {
            log::error!("Encountered error while opening R1CS file: {:?}", err);
            CircomError::UnableToOpenR1CSFile(format!(
                "Encountered error while opening R1CS file: {:?}",
                err
            ))
        })?;
        Self::new(reader)
    }

    /// reader must implement the Seek trait, for example with a Cursor
    ///
    /// ```rust,ignore
    /// let reader = BufReader::new(Cursor::new(&data[..]));
    /// ```
    pub fn new<R: Read + Seek>(mut reader: R) -> Result<Self, CircomError> {
        let mut magic = [0u8; 4];
        read_exact(&mut reader, &mut magic)?;
        if magic != [0x72, 0x31, 0x63, 0x73] {
            // magic = "r1cs"
            return Err(CircomError::R1CSFileParsing(
                "Invalid magic number".to_string(),
            ));
        }

        let version = read_u32(&mut reader)?;
        if version != 1 {
            return Err(CircomError::R1CSFileParsing(
                "Unsupported version".to_string(),
            ));
        }

        let num_sections = read_u32(&mut reader)?;

        // todo: handle sec_size correctly
        // section type -> file offset
        let mut sec_offsets = BTreeMap::<u32, u64>::new();
        let mut sec_sizes = BTreeMap::<u32, u64>::new();

        // get file offset of each section
        for _ in 0..num_sections {
            let sec_type = read_u32(&mut reader)?;
            let sec_size = read_u64(&mut reader)?;
            let offset = seek(&mut reader, SeekFrom::Current(0))?;
            sec_offsets.insert(sec_type, offset);
            sec_sizes.insert(sec_type, sec_size);
            seek(&mut reader, SeekFrom::Current(sec_size as i64))?;
        }

        let header_type = 1;
        let constraint_type = 2;
        let wire2label_type = 3;

        let header_offset = sec_offsets.get(&header_type).ok_or_else(|| {
            CircomError::R1CSFileParsing("No section offset for header type found".to_string())
        })?;

        seek(&mut reader, SeekFrom::Start(*header_offset))?;

        let header_size = sec_sizes.get(&header_type).ok_or_else(|| {
            CircomError::R1CSFileParsing("No section size for header type found".to_string())
        })?;

        let header = Header::new(&mut reader, *header_size)?;

        let constraint_offset = sec_offsets.get(&constraint_type).ok_or_else(|| {
            CircomError::R1CSFileParsing("No section offset for constraint type found".to_string())
        })?;

        seek(&mut reader, SeekFrom::Start(*constraint_offset))?;

        let constraints = read_constraints::<&mut R, E>(&mut reader, &header)?;

        let wire2label_offset = sec_offsets.get(&wire2label_type).ok_or_else(|| {
            CircomError::R1CSFileParsing("No section offset for wire2label type found".to_string())
        })?;

        seek(&mut reader, SeekFrom::Start(*wire2label_offset))?;

        let wire2label_size = sec_sizes.get(&wire2label_type).ok_or_else(|| {
            CircomError::R1CSFileParsing("No section size for wire2label type found".to_string())
        })?;

        let wire_mapping = read_map(&mut reader, *wire2label_size, &header)?;

        Ok(R1CSFile {
            version,
            header,
            constraints,
            wire_mapping,
        })
    }
}

impl<E: Pairing> Header<E> {
    fn new<R: Read>(mut reader: R, size: u64) -> Result<Header<E>, CircomError> {
        let field_size = read_u32(&mut reader)?;
        if field_size != 32 {
            return Err(CircomError::R1CSFileParsing(
                "This parser only supports 32-byte fields".to_string(),
            ));
        }

        if size != 32 + field_size as u64 {
            return Err(CircomError::R1CSFileParsing(
                "Invalid header section size".to_string(),
            ));
        }

        // Subgroup order is encoded in little endian bytes
        let mut subgroup_order_bytes = vec![0u8; field_size as usize];
        read_exact(&mut reader, &mut subgroup_order_bytes)?;
        let curve = check_subgroup_order::<E>(&subgroup_order_bytes)?;

        Ok(Header {
            field_size,
            subgroup_order: subgroup_order_bytes,
            curve,
            n_wires: read_u32(&mut reader)?,
            n_pub_out: read_u32(&mut reader)?,
            n_pub_in: read_u32(&mut reader)?,
            n_prv_in: read_u32(&mut reader)?,
            n_labels: read_u64(&mut reader)?,
            n_constraints: read_u32(&mut reader)?,
            phantom: PhantomData,
        })
    }
}

fn read_u32<R: Read>(reader: R) -> Result<u32, CircomError> {
    let mut buf = [0; 4];
    read_exact(reader, &mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64<R: Read>(reader: R) -> Result<u64, CircomError> {
    let mut buf = [0; 8];
    read_exact(reader, &mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn read_exact<R: Read>(mut reader: R, buf: &mut [u8]) -> Result<(), CircomError> {
    reader.read_exact(buf).map_err(|err| {
        log::error!("Encountered error while parsing R1CS file: {:?}", err);
        CircomError::R1CSFileParsing(format!(
            "Encountered error while parsing R1CS file: {:?}",
            err
        ))
    })
}

fn seek<R: Read + Seek>(mut reader: R, pos: SeekFrom) -> Result<u64, CircomError> {
    reader.seek(pos).map_err(|err| {
        log::error!("Encountered error while parsing R1CS file: {:?}", err);
        CircomError::R1CSFileParsing(format!(
            "Encountered error while parsing R1CS file: {:?}",
            err
        ))
    })
}

/// Read a linear combination
fn read_lc<R: Read, E: Pairing>(mut reader: R) -> Result<LC<E>, CircomError> {
    let num_terms = read_u32(&mut reader)? as usize;
    let mut terms = Vec::with_capacity(num_terms);
    for _ in 0..num_terms {
        terms.push((
            read_u32(&mut reader)? as usize, // wire_id
            E::ScalarField::deserialize_uncompressed(&mut reader) // coefficient
                .map_err(|err| {
                    log::error!("Encountered error while parsing R1CS file: {:?}", err);
                    CircomError::R1CSFileParsing(format!(
                        "Encountered error while parsing R1CS file: {:?}",
                        err
                    ))
                })?,
        ));
    }
    Ok(LC(terms))
}

/// Read all the constraints where each constraint is a 3-tuple of linear combinations
fn read_constraints<R: Read, E: Pairing>(
    mut reader: R,
    header: &Header<E>,
) -> Result<Vec<Constraint<E>>, CircomError> {
    // todo check section size
    let mut vec = Vec::with_capacity(header.n_constraints as usize);
    for _ in 0..header.n_constraints {
        vec.push({
            let a = read_lc::<&mut R, E>(&mut reader)?;
            let b = read_lc::<&mut R, E>(&mut reader)?;
            let c = read_lc::<&mut R, E>(&mut reader)?;
            Constraint { a, b, c }
        });
    }
    Ok(vec)
}

/// Read the wire to label map. The labels not part of constraints because they were
/// optimized out are not part of this map.
fn read_map<R: Read, E: Pairing>(
    mut reader: R,
    size: u64,
    header: &Header<E>,
) -> Result<Vec<u64>, CircomError> {
    if size != header.n_wires as u64 * 8 {
        return Err(CircomError::R1CSFileParsing(
            "Invalid map section size".to_string(),
        ));
    }
    let mut vec = Vec::with_capacity(header.n_wires as usize);
    for _ in 0..header.n_wires {
        vec.push(read_u64(&mut reader)?);
    }
    if vec[0] != 0 {
        return Err(CircomError::R1CSFileParsing(
            "Wire 0 should always be mapped to 0".to_string(),
        ));
    }
    Ok(vec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circom::{r1cs::Curve, tests::abs_path};
    use ark_bls12_381::Bls12_381;
    use ark_bn254::{Bn254, Fr as BnFr};
    use ark_std::io::{BufReader, Cursor};
    use num_bigint::BigUint;
    use std::str::FromStr;

    /// Some basic checks that should be true for all supported circuits
    fn basic_checks<E: Pairing>(file: &R1CSFile<E>, curve_type: Curve) {
        assert_eq!(file.version, 1);
        assert_eq!(file.header.field_size, 32);
        assert_eq!(file.header.curve, curve_type);

        if curve_type == Curve::Bn128 {
            assert_eq!(
                file.header.subgroup_order,
                BigUint::from_str(
                    "21888242871839275222246405745257275088548364400416034343698204186575808495617"
                )
                .unwrap()
                .to_bytes_le(),
            );
        }

        if curve_type == Curve::Bls12_381 {
            assert_eq!(
                file.header.subgroup_order,
                BigUint::from_str(
                    "52435875175126190479447740508185965837690552500527637822603658699938581184513"
                )
                .unwrap()
                .to_bytes_le(),
            );
        }

        assert!(file.header.n_labels >= file.header.n_wires as u64);
        assert_eq!(file.wire_mapping.len() as u32, file.header.n_wires);
    }

    #[test]
    fn bn_254() {
        let data = hex_literal::hex!(
            "
        72316373
        01000000
        03000000
        01000000 40000000 00000000
        20000000
        010000f0 93f5e143 9170b979 48e83328 5d588181 b64550b8 29a031e1 724e6430
        07000000
        01000000
        02000000
        03000000
        e8030000 00000000
        03000000
        02000000 88020000 00000000
        02000000
        05000000 03000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        06000000 08000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000
        00000000 02000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        02000000 14000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000 0C000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        02000000
        00000000 05000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        02000000 07000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000
        01000000 04000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        04000000 08000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        05000000 03000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        02000000
        03000000 2C000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        06000000 06000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        00000000
        01000000
        06000000 04000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000
        00000000 06000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        02000000 0B000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000 05000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        01000000
        06000000 58020000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000 38000000 00000000
        00000000 00000000
        03000000 00000000
        0a000000 00000000
        0b000000 00000000
        0c000000 00000000
        0f000000 00000000
        44010000 00000000
    "
        );

        let reader = BufReader::new(Cursor::new(&data[..]));
        let file = R1CSFile::<Bn254>::new(reader).unwrap();
        basic_checks(&file, Curve::Bn128);
        assert_eq!(file.header.n_wires, 7);
        assert_eq!(file.header.n_pub_out, 1);
        assert_eq!(file.header.n_pub_in, 2);
        assert_eq!(file.header.n_prv_in, 3);
        assert_eq!(file.header.n_labels, 0x03e8);
        assert_eq!(file.header.n_constraints, 3);

        assert_eq!(file.constraints.len(), 3);
        assert_eq!(file.constraints[0].a.len(), 2);
        assert_eq!(file.constraints[0].a.0[0].0, 5);
        assert_eq!(file.constraints[0].a.0[0].1, BnFr::from(3));
        assert_eq!(file.constraints[2].b.0[0].0, 0);
        assert_eq!(file.constraints[2].b.0[0].1, BnFr::from(6));
        assert_eq!(file.constraints[1].c.len(), 0);

        assert_eq!(file.wire_mapping.len(), 7);
        assert_eq!(file.wire_mapping[1], 3);
    }

    #[test]
    fn input_validation() {
        assert_eq!(
            R1CSFile::<Bn254>::new_from_file(abs_path("test-vectors/bls12-381/multiply2.r1cs"))
                .unwrap_err(),
            CircomError::IncompatibleWithCurve
        );
        assert_eq!(
            R1CSFile::<Bls12_381>::new_from_file(abs_path("test-vectors/bn128/multiply2.r1cs"))
                .unwrap_err(),
            CircomError::IncompatibleWithCurve
        );

        // The `multiply2_goldilocks` files are generated by passing flag `-p=goldilocks` to the Circom compiler
        assert_eq!(
            R1CSFile::<Bn254>::new_from_file(abs_path("test-vectors/multiply2_goldilocks.r1cs"))
                .unwrap_err(),
            CircomError::R1CSFileParsing("This parser only supports 32-byte fields".to_string())
        );
        assert_eq!(
            R1CSFile::<Bls12_381>::new_from_file(abs_path(
                "test-vectors/multiply2_goldilocks.r1cs"
            ))
            .unwrap_err(),
            CircomError::R1CSFileParsing("This parser only supports 32-byte fields".to_string())
        );
    }

    #[test]
    fn multiply2() {
        fn check<E: Pairing>(file: &R1CSFile<E>, curve_type: Curve) {
            basic_checks(&file, curve_type);
            // 4 wires, 1st wire for constant 1, 2nd for input a, 3rd for input b and 4th for input c.
            assert_eq!(file.header.n_wires, 4);
            assert_eq!(file.header.n_labels, 4);
            assert_eq!(file.header.n_pub_out, 1);
            assert_eq!(file.header.n_pub_in, 0);
            assert_eq!(file.header.n_prv_in, 2);
            assert_eq!(file.header.n_constraints, 1);

            assert_eq!(file.constraints.len(), 1);
            assert_eq!(file.constraints[0].a.len(), 1);
            assert_eq!(file.constraints[0].b.len(), 1);
            assert_eq!(file.constraints[0].c.len(), 1);

            assert_eq!(file.wire_mapping, vec![0, 1, 2, 3]);
        }
        check(
            &R1CSFile::<Bn254>::new_from_file(abs_path("test-vectors/bn128/multiply2.r1cs"))
                .unwrap(),
            Curve::Bn128,
        );
        check(
            &R1CSFile::<Bls12_381>::new_from_file(abs_path(
                "test-vectors/bls12-381/multiply2.r1cs",
            ))
            .unwrap(),
            Curve::Bls12_381,
        );
    }

    #[test]
    fn test_1() {
        fn check<E: Pairing>(file: &R1CSFile<E>, curve_type: Curve) {
            basic_checks(&file, curve_type);
            assert_eq!(file.header.n_wires, 4);
            assert_eq!(file.header.n_labels, 5);
            assert_eq!(file.header.n_pub_out, 1);
            assert_eq!(file.header.n_pub_in, 0);
            assert_eq!(file.header.n_prv_in, 1);
            assert_eq!(file.header.n_constraints, 2);

            assert_eq!(file.constraints.len(), 2);
            assert_eq!(file.constraints[0].a.len(), 1);
            assert_eq!(file.constraints[0].b.len(), 1);
            assert_eq!(file.constraints[0].c.len(), 1);
            assert_eq!(file.constraints[1].a.len(), 1);
            assert_eq!(file.constraints[1].b.len(), 1);
            assert_eq!(file.constraints[1].c.len(), 3);

            assert_eq!(file.wire_mapping, vec![0, 1, 2, 3]);
        }

        check(
            &R1CSFile::<Bn254>::new_from_file(abs_path("test-vectors/bn128/test1.r1cs")).unwrap(),
            Curve::Bn128,
        );
        check(
            &R1CSFile::<Bls12_381>::new_from_file(abs_path("test-vectors/bls12-381/test1.r1cs"))
                .unwrap(),
            Curve::Bls12_381,
        );
    }

    #[test]
    fn test_2() {
        fn check<E: Pairing>(file: &R1CSFile<E>, curve_type: Curve) {
            basic_checks(&file, curve_type);
            assert_eq!(file.header.n_wires, 6);
            assert_eq!(file.header.n_labels, 7);
            assert_eq!(file.header.n_pub_out, 1);
            assert_eq!(file.header.n_pub_in, 0);
            assert_eq!(file.header.n_prv_in, 2);
            assert_eq!(file.header.n_constraints, 3);

            assert_eq!(file.constraints.len(), 3);
            assert_eq!(file.constraints[0].a.len(), 1);
            assert_eq!(file.constraints[0].b.len(), 1);
            assert_eq!(file.constraints[0].c.len(), 1);
            assert_eq!(file.constraints[1].a.len(), 1);
            assert_eq!(file.constraints[1].b.len(), 1);
            assert_eq!(file.constraints[1].c.len(), 1);
            assert_eq!(file.constraints[2].a.len(), 1);
            assert_eq!(file.constraints[2].b.len(), 1);
            assert_eq!(file.constraints[2].c.len(), 5);

            assert_eq!(file.wire_mapping, vec![0, 1, 2, 3, 4, 5]);
        }

        check(
            &R1CSFile::<Bn254>::new_from_file(abs_path("test-vectors/bn128/test2.r1cs")).unwrap(),
            Curve::Bn128,
        );
        check(
            &R1CSFile::<Bls12_381>::new_from_file(abs_path("test-vectors/bls12-381/test2.r1cs"))
                .unwrap(),
            Curve::Bls12_381,
        );
    }

    #[test]
    fn test_3() {
        fn check<E: Pairing>(file: &R1CSFile<E>, curve_type: Curve) {
            basic_checks(&file, curve_type);
            assert_eq!(file.header.n_wires, 12);
            assert_eq!(file.header.n_labels, 14);
            assert_eq!(file.header.n_pub_out, 2);
            assert_eq!(file.header.n_pub_in, 2);
            assert_eq!(file.header.n_prv_in, 4);
            assert_eq!(file.header.n_constraints, 5);

            assert_eq!(file.constraints.len(), 5);
            assert_eq!(file.constraints[0].a.len(), 1);
            assert_eq!(file.constraints[0].b.len(), 1);
            assert_eq!(file.constraints[0].c.len(), 1);
            assert_eq!(file.constraints[1].a.len(), 1);
            assert_eq!(file.constraints[1].b.len(), 1);
            assert_eq!(file.constraints[1].c.len(), 1);
            assert_eq!(file.constraints[2].a.len(), 1);
            assert_eq!(file.constraints[2].b.len(), 1);
            assert_eq!(file.constraints[2].c.len(), 3);
            assert_eq!(file.constraints[3].a.len(), 1);
            assert_eq!(file.constraints[3].b.len(), 1);
            assert_eq!(file.constraints[3].c.len(), 1);
            assert_eq!(file.constraints[4].a.len(), 1);
            assert_eq!(file.constraints[4].b.len(), 1);
            assert_eq!(file.constraints[4].c.len(), 2);
        }

        check(
            &R1CSFile::<Bn254>::new_from_file(abs_path("test-vectors/bn128/test3.r1cs")).unwrap(),
            Curve::Bn128,
        );
        check(
            &R1CSFile::<Bls12_381>::new_from_file(abs_path("test-vectors/bls12-381/test3.r1cs"))
                .unwrap(),
            Curve::Bls12_381,
        );
    }

    #[test]
    fn test_4() {
        fn check<E: Pairing>(file: &R1CSFile<E>, curve_type: Curve) {
            basic_checks(&file, curve_type);
            assert_eq!(file.header.n_wires, 40);
            assert_eq!(file.header.n_labels, 42);
            assert_eq!(file.header.n_pub_out, 2);
            assert_eq!(file.header.n_pub_in, 4);
            assert_eq!(file.header.n_prv_in, 4);
            assert_eq!(file.header.n_constraints, 31);
        }

        check(
            &R1CSFile::<Bn254>::new_from_file(abs_path("test-vectors/bn128/test4.r1cs")).unwrap(),
            Curve::Bn128,
        );
        check(
            &R1CSFile::<Bls12_381>::new_from_file(abs_path("test-vectors/bls12-381/test4.r1cs"))
                .unwrap(),
            Curve::Bls12_381,
        );
    }

    #[test]
    fn multiply_n() {
        fn check<E: Pairing>(file: &R1CSFile<E>, curve_type: Curve) {
            basic_checks(&file, curve_type);
            assert_eq!(file.header.n_wires, 600);
            assert_eq!(file.header.n_labels, 602);
            assert_eq!(file.header.n_pub_out, 1);
            assert_eq!(file.header.n_pub_in, 0);
            assert_eq!(file.header.n_prv_in, 300);
            assert_eq!(file.header.n_constraints, 299);

            assert_eq!(file.constraints.len(), 299);
            for i in 0..299 {
                assert_eq!(file.constraints[i].a.len(), 1);
                assert_eq!(file.constraints[i].b.len(), 1);
                assert_eq!(file.constraints[i].c.len(), 1);
            }

            for i in 0..=301 {
                assert_eq!(file.wire_mapping[i], i as u64);
            }
            for i in 302..=599 {
                assert_eq!(file.wire_mapping[i], i as u64 + 1);
            }
        }

        check(
            &R1CSFile::<Bn254>::new_from_file(abs_path("test-vectors/bn128/multiply_n.r1cs"))
                .unwrap(),
            Curve::Bn128,
        );
        check(
            &R1CSFile::<Bls12_381>::new_from_file(abs_path(
                "test-vectors/bls12-381/multiply_n.r1cs",
            ))
            .unwrap(),
            Curve::Bls12_381,
        );
    }

    #[test]
    fn nconstraints() {
        fn check<E: Pairing>(file: &R1CSFile<E>, curve_type: Curve) {
            basic_checks(&file, curve_type);
            assert_eq!(file.header.n_pub_out, 1);
            assert_eq!(file.header.n_pub_in, 0);
            assert_eq!(file.header.n_prv_in, 1);
            assert_eq!(file.header.n_constraints, 2499);

            assert_eq!(file.constraints.len(), 2499);
            for i in 0..2499 {
                assert_eq!(file.constraints[i].a.len(), 1);
                assert_eq!(file.constraints[i].b.len(), 1);
                assert_eq!(file.constraints[i].c.len(), 2);
            }
        }
        check(
            &R1CSFile::<Bn254>::new_from_file(abs_path("test-vectors/bn128/nconstraints.r1cs"))
                .unwrap(),
            Curve::Bn128,
        );
        check(
            &R1CSFile::<Bls12_381>::new_from_file(abs_path(
                "test-vectors/bls12-381/nconstraints.r1cs",
            ))
            .unwrap(),
            Curve::Bls12_381,
        );
    }

    #[test]
    fn multiply2_bounded() {
        basic_checks(
            &R1CSFile::<Bn254>::new_from_file(abs_path(
                "test-vectors/bn128/multiply2_bounded.r1cs",
            ))
            .unwrap(),
            Curve::Bn128,
        );
        basic_checks(
            &R1CSFile::<Bls12_381>::new_from_file(abs_path(
                "test-vectors/bls12-381/multiply2_bounded.r1cs",
            ))
            .unwrap(),
            Curve::Bls12_381,
        );
    }

    #[test]
    fn mimc() {
        basic_checks(
            &R1CSFile::<Bn254>::new_from_file(abs_path("test-vectors/bn128/mimc_bn128.r1cs"))
                .unwrap(),
            Curve::Bn128,
        );
        basic_checks(
            &R1CSFile::<Bls12_381>::new_from_file(abs_path(
                "test-vectors/bls12-381/mimc_bls12_381.r1cs",
            ))
            .unwrap(),
            Curve::Bls12_381,
        );
    }

    #[test]
    fn mimcsponge() {
        basic_checks(
            &R1CSFile::<Bn254>::new_from_file(abs_path("test-vectors/bn128/mimcsponge_bn128.r1cs"))
                .unwrap(),
            Curve::Bn128,
        );
        basic_checks(
            &R1CSFile::<Bls12_381>::new_from_file(abs_path(
                "test-vectors/bls12-381/mimcsponge_bls12_381.r1cs",
            ))
            .unwrap(),
            Curve::Bls12_381,
        );
    }

    #[test]
    fn poseidon() {
        basic_checks(
            &R1CSFile::<Bn254>::new_from_file(abs_path("test-vectors/bn128/poseidon_bn128.r1cs"))
                .unwrap(),
            Curve::Bn128,
        );
    }

    #[test]
    fn less_than_32_bits() {
        basic_checks(
            &R1CSFile::<Bn254>::new_from_file(abs_path("test-vectors/bn128/less_than_32.r1cs"))
                .unwrap(),
            Curve::Bn128,
        );
        basic_checks(
            &R1CSFile::<Bls12_381>::new_from_file(abs_path(
                "test-vectors/bls12-381/less_than_32.r1cs",
            ))
            .unwrap(),
            Curve::Bls12_381,
        );
    }

    #[test]
    fn less_than_public_64_bits() {
        basic_checks(
            &R1CSFile::<Bn254>::new_from_file(abs_path(
                "test-vectors/bn128/less_than_public_64.r1cs",
            ))
            .unwrap(),
            Curve::Bn128,
        );
        basic_checks(
            &R1CSFile::<Bls12_381>::new_from_file(abs_path(
                "test-vectors/bls12-381/less_than_public_64.r1cs",
            ))
            .unwrap(),
            Curve::Bls12_381,
        );
    }

    #[test]
    fn all_different_10() {
        basic_checks(
            &R1CSFile::<Bn254>::new_from_file(abs_path("test-vectors/bn128/all_different_10.r1cs"))
                .unwrap(),
            Curve::Bn128,
        );
        basic_checks(
            &R1CSFile::<Bls12_381>::new_from_file(abs_path(
                "test-vectors/bls12-381/all_different_10.r1cs",
            ))
            .unwrap(),
            Curve::Bls12_381,
        );
    }
}
