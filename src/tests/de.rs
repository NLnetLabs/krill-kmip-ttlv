use crate::error::{Error, ErrorLocation, MalformedTtlvError, SerdeError};
use crate::tests::fixtures;
use crate::tests::util::{make_limited_reader, make_reader, no_response_size_limit, reject_if_response_larger_than};
use crate::types::{
    SerializableTtlvType, TtlvBigInteger, TtlvBoolean, TtlvByteString, TtlvDateTime, TtlvEnumeration, TtlvInteger,
    TtlvLongInteger, TtlvTextString, TtlvType,
};
use crate::{from_reader, from_slice, Config};

use assert_matches::assert_matches;

#[allow(unused_imports)]
use pretty_assertions::{assert_eq, assert_ne};

#[test]
fn test_kmip_10_create_destroy_use_case_create_response_deserialization() {
    use fixtures::kmip_10_create_destroy_use_case::*;

    let test_data = ttlv_bytes();
    let r: ResponseMessage = from_slice(&test_data).unwrap();

    assert_eq!(r.header.ver.major, 1);
    assert_eq!(r.header.ver.minor, 0);
    assert_eq!(r.header.timestamp, 0x000000004AFBE7C2); // This can be made more user friendly
    assert_eq!(r.header.item_count, 1);

    assert_eq!(r.items.len(), 1);

    let item = &r.items[0];
    assert_eq!(item.operation, Operation::Create);
    assert_eq!(item.status, ResultStatus::Success);
    if let ResponsePayload::Create(payload) = &item.payload {
        assert_eq!(payload.object_type, ObjectType::SymmetricKey);
        assert_eq!(&payload.unique_id, "fc8833de-70d2-4ece-b063-fede3a3c59fe");
    } else {
        panic!("Wrong payload");
    }
}

#[test]
fn test_is_variant_applicable_if_equal() {
    use fixtures::variant_selection::*;

    // Verify that the if equal condition on KeyMaterial::TransparentSymmetricKey() is matched when
    // KeyFormatType::TransparentSymmetricKey is used.
    let res = from_slice::<SomeKey>(&some_transparent_key::ttlv_bytes()).unwrap();
    assert_eq!(res.key_format_type, KeyFormatType::TransparentSymmetricKey);
    assert_eq!(res.key_material, KeyMaterial::TransparentSymmetricKey("Blah".into()));
}

#[test]
fn test_is_variant_applicable_if_in() {
    use fixtures::variant_selection::*;

    // Verify that the if in condition on KeyMaterial::Bytes() is matched when KeyFormatType::Raw is used.
    let res = from_slice::<SomeKey>(&some_raw_key::ttlv_bytes()).unwrap();
    assert_eq!(res.key_format_type, KeyFormatType::Raw);
    assert_eq!(res.key_material, KeyMaterial::Bytes(0xFF));

    // Verify that the if in condition on KeyMaterial::Bytes() is matched when KeyFormatType::Opaque is used.
    let res = from_slice::<SomeKey>(&some_opaque_key::ttlv_bytes()).unwrap();
    assert_eq!(res.key_format_type, KeyFormatType::Opaque);
    assert_eq!(res.key_material, KeyMaterial::Bytes(0xF0));
}

#[test]
fn test_is_variant_applicable_if_not_matched() {
    // Verify that the if in condition does NOT match an unknown KeyFormatType enumeration value
    use fixtures::variant_selection::*;
    let res = from_slice::<SomeKey>(&some_unknown_key_type::ttlv_bytes());
    assert!(res.is_err());
}

#[test]
fn test_io_error_insufficient_read_buffer_size() {
    use fixtures::simple::*;

    let full_input_byte_len = ttlv_bytes().len();

    // sanity check
    assert!(from_reader::<RootType, _>(make_reader(ttlv_bytes()), &no_response_size_limit()).is_ok());

    // limit the read buffer to several insufficient lengths
    for max_readable_bytes in [0, 1, 2, 10] {
        let res = from_reader::<RootType, _>(
            make_reader(ttlv_bytes()),
            &reject_if_response_larger_than(max_readable_bytes),
        );

        assert_matches!(res, Err(Error::ResponseSizeExceedsLimit(len)) if len == full_input_byte_len);
    }
}

#[test]
fn test_io_error_unexpected_eof_with_reader() {
    use fixtures::simple::*;

    for max_readable_bytes in [0, 1, 2, 10] {
        let res = from_reader::<RootType, _>(
            make_limited_reader(ttlv_bytes(), max_readable_bytes),
            &Config::default(),
        );

        assert_matches!(res, Err(Error::IoError(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof);
    }
}

#[test]
#[rustfmt::skip]
fn test_io_error_unexpected_eof_with_slice() {
    use fixtures::simple::*;

    let full_ttlv_byte_len = ttlv_bytes().len();

    for cutoff_bytes_at in 0..full_ttlv_byte_len-1 {
        assert_matches!(from_slice::<RootType>(&ttlv_bytes()[0..=cutoff_bytes_at]), Err(Error::IoError(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof);
    }

    assert!(from_slice::<RootType>(&ttlv_bytes()[0..full_ttlv_byte_len]).is_ok());
}

#[test]
fn test_malformed_ttlv() {
    use fixtures::malformed_ttlv::*;

    assert_matches!(
        from_slice::<RootType>(&ttlv_bytes_with_invalid_type()),
        Err(Error::MalformedTtlv{
            error: MalformedTtlvError::InvalidType(ty),
            location: ErrorLocation{ offset: Some(4) }
        })
        if ty == invalid_type()
    );

    assert_matches!(
        from_slice::<RootType>(&ttlv_bytes_with_wrong_root_type()),
        Err(Error::MalformedTtlv{
            error: MalformedTtlvError::UnexpectedType{
                expected: TtlvType::Structure,
                actual
            },
            location: ErrorLocation{ offset: Some(4) }
        })
        if actual == wrong_root_type()
    );

    assert_matches!(
        from_slice::<RootType>(&ttlv_bytes_with_length_overflow()),
        Err(Error::IoError(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof
    );

    assert_matches!(
        from_slice::<RootType>(&ttlv_bytes_with_wrong_value_length()),
        Err(Error::MalformedTtlv {
            error: MalformedTtlvError::InvalidLength {
                expected: 4,
                actual: 5,
                r#type: TtlvType::Integer
            },
            location: ErrorLocation { offset: Some(16) }
        })
    );

    assert_matches!(
        from_slice::<FlexibleRootType<bool>>(&ttlv_bytes_with_wrong_boolean_value()),
        Err(Error::MalformedTtlv {
            error: MalformedTtlvError::InvalidValue,
            location: ErrorLocation { offset: Some(24) }
        })
    );
    // would be useful to know the tag name, Rust or TTLV type here, and is it safe
    // to reveal the incorrect value?
}

#[test]
fn test_incorrect_serde_configuration_mismatched_types() {
    use fixtures::malformed_ttlv::*;
    use serde_derive::Deserialize;

    // $rust_type should be the Rust type that the $expected_ttlv_type should deserialize into, e.g. TTLV type
    // TtlvInteger deserializes into Rust type i32. $actual_ttlv_type is then an unexpected different TTLV type whose
    // numeric TTLV type code is written into the TTLV bytes instead of the expected TTLV type. On deserialization
    // the Serde Derive generated deserializer code will invoke Serde with the $rust_type which will lead to the code
    // for that type trying to deserialize the TTLV bytes at that point using the corresponding TTLV type deserializer,
    // but this will fail because the deserializer checks if the numeric TTLV type code encountered in the bytes stream
    // matches its expectation.
    macro_rules! test_rust_ttlv_type_mismatch {
        ($rust_type:ty, $expected_ttlv_type:path, $actual_tlv_value:expr) => {
            assert_matches!(
                from_slice::<$rust_type>(&ttlv_bytes_with_custom_tlv(&$actual_tlv_value)),
                Err(Error::SerdeError {
                    error: SerdeError::UnexpectedType {
                        expected: $expected_ttlv_type,
                        actual,
                    },
                    location: ErrorLocation { offset: Some(12) }
                }) if actual == $actual_tlv_value.ttlv_type()
            );
        };
    }

    // Dummy values to serialize into the byte stream to set it up ready for testing if deserializing behaves as
    // expected
    let a_int = TtlvInteger(1);
    let a_longint = TtlvLongInteger(1);
    let a_bigint = TtlvBigInteger(vec![1]);
    let a_enum = TtlvEnumeration(1);
    let a_bool = TtlvBoolean(true);
    let a_string = TtlvTextString("blah".to_string());
    let a_bytes = TtlvByteString(vec![1]);
    let a_datetime = TtlvDateTime(1);

    // GOOD: i32 <-- from TTLV Integer
    from_slice::<FlexibleRootType<i32>>(&ttlv_bytes_with_custom_tlv(&a_int)).unwrap();
    // BAD: attempt and fail to deserialize TTLV types that can't (or we won't) fit into the Rust i32 type
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i32>, TtlvType::Integer, a_longint);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i32>, TtlvType::Integer, a_bigint);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i32>, TtlvType::Integer, a_enum);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i32>, TtlvType::Integer, a_bool);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i32>, TtlvType::Integer, a_string);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i32>, TtlvType::Integer, a_bytes);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i32>, TtlvType::Integer, a_datetime);

    // GOOD: i64 <-- from TTLV Long Integer or TTLV Date Time (both are 64-bit values)
    from_slice::<FlexibleRootType<i64>>(&ttlv_bytes_with_custom_tlv(&a_longint)).unwrap();
    from_slice::<FlexibleRootType<i64>>(&ttlv_bytes_with_custom_tlv(&a_datetime)).unwrap();
    // BAD: attempt and fail to deserialize TTLV types that can't (or we won't) fit into the Rust i64 type
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i64>, TtlvType::LongInteger, a_int);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i64>, TtlvType::LongInteger, a_bigint);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i64>, TtlvType::LongInteger, a_enum);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i64>, TtlvType::LongInteger, a_bool);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i64>, TtlvType::LongInteger, a_string);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i64>, TtlvType::LongInteger, a_bytes);

    #[derive(Debug, Deserialize)]
    #[serde(rename = "0xBBBBBB")]
    enum DummyEnum {
        #[serde(rename = "0x00000001")]
        SomeValue,
    }
    // GOOD: enum <-- from TTLV Enumeration or TTLV Integer (both are 32-bit values)
    from_slice::<FlexibleRootType<DummyEnum>>(&ttlv_bytes_with_custom_tlv(&a_enum)).unwrap();
    from_slice::<FlexibleRootType<DummyEnum>>(&ttlv_bytes_with_custom_tlv(&a_int)).unwrap();
    // BAD: attempt and fail to deserialize TTLV types that can't (or we won't) fit into the Rust enum type
    test_rust_ttlv_type_mismatch!(FlexibleRootType<DummyEnum>, TtlvType::Enumeration, a_longint);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<DummyEnum>, TtlvType::Enumeration, a_bigint);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<DummyEnum>, TtlvType::Enumeration, a_bool);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<DummyEnum>, TtlvType::Enumeration, a_string);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<DummyEnum>, TtlvType::Enumeration, a_bytes);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<DummyEnum>, TtlvType::Enumeration, a_datetime);
}

#[test]
fn test_incorrect_serde_configuration_invalid_tags() {
    use fixtures::malformed_ttlv::*;
    use serde_derive::Deserialize;

    macro_rules! test_invalid_tag {
        ($rust_type:ty, $actual_tlv_value:expr) => {
            assert_matches!(
                from_slice::<$rust_type>(&ttlv_bytes_with_custom_tlv(&$actual_tlv_value)),
                Err(Error::SerdeError {
                    error: SerdeError::InvalidTag(_),
                    location: ErrorLocation { offset: Some(0) }
                })
            );
        };
    }

    #[derive(Debug, Deserialize)]
    struct UntaggedRoot {}
    test_invalid_tag!(UntaggedRoot, TtlvInteger(1));

    #[derive(Debug, Deserialize)]
    #[serde(rename = "This is not hex")]
    struct NonHexTaggedRoot {}
    test_invalid_tag!(NonHexTaggedRoot, TtlvInteger(1));
}
