#[macro_export]
macro_rules! test_serialization {
    ($obj_type:ty, $obj: expr, $Instant: ident) => {
        let mut serz = vec![];
        CanonicalSerialize::serialize_compressed(&$obj, &mut serz).unwrap();
        println!("Serialized byte size: {}", serz.len());
        let start = $Instant::now();
        let deserz: $obj_type = CanonicalDeserialize::deserialize_compressed(&serz[..]).unwrap();
        println!("Deserialized time: {:?}", start.elapsed());
        assert_eq!(deserz, $obj);

        let mut serz = vec![];
        $obj.serialize_uncompressed(&mut serz).unwrap();
        let deserz: $obj_type = CanonicalDeserialize::deserialize_uncompressed(&serz[..]).unwrap();
        assert_eq!(deserz, $obj);

        // Test JSON serialization
        let ser = serde_json::to_string(&$obj).unwrap();
        let deser = serde_json::from_str::<$obj_type>(&ser).unwrap();
        assert_eq!($obj, deser);

        // Test Message Pack serialization
        let ser = rmp_serde::to_vec_named(&$obj).unwrap();
        let deser = rmp_serde::from_slice::<$obj_type>(&ser).unwrap();
        assert_eq!($obj, deser);
    };
    ($obj_type:ty, $obj: expr) => {
        let mut serz = vec![];
        CanonicalSerialize::serialize_compressed(&$obj, &mut serz).unwrap();
        println!("Serialized byte size: {}", serz.len());
        let deserz: $obj_type = CanonicalDeserialize::deserialize_compressed(&serz[..]).unwrap();
        assert_eq!(deserz, $obj);

        let mut serz = vec![];
        $obj.serialize_uncompressed(&mut serz).unwrap();
        let deserz: $obj_type = CanonicalDeserialize::deserialize_uncompressed(&serz[..]).unwrap();
        assert_eq!(deserz, $obj);

        // Test JSON serialization
        let ser = serde_json::to_string(&$obj).unwrap();
        let deser = serde_json::from_str::<$obj_type>(&ser).unwrap();
        assert_eq!($obj, deser);

        // Test Message Pack serialization
        let ser = rmp_serde::to_vec_named(&$obj).unwrap();
        let deser = rmp_serde::from_slice::<$obj_type>(&ser).unwrap();
        assert_eq!($obj, deser);
    };
}
