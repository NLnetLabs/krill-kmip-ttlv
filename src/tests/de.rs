// TOOD: do "use ... as fix" instead of "use ... ::*", then refer to xxx to make it clear what comes from the fixtures.

use crate::error::{ErrorKind, MalformedTtlvError, SerdeError};
use crate::tests::fixtures;
use crate::tests::helpers::{make_limited_reader, make_reader, no_response_size_limit, reject_if_response_larger_than};
use crate::types::{
    ByteOffset, SerializableTtlvType, TtlvBigInteger, TtlvBoolean, TtlvByteString, TtlvDateTime, TtlvEnumeration,
    TtlvInteger, TtlvLongInteger, TtlvTag, TtlvTextString, TtlvType,
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
    for max_readable_bytes in &[0, 1, 2, 10] {
        let res = from_reader::<RootType, _>(
            make_reader(ttlv_bytes()),
            &reject_if_response_larger_than(*max_readable_bytes),
        );

        assert_matches!(res.unwrap_err().kind(), ErrorKind::ResponseSizeExceedsLimit(len) if len == &full_input_byte_len);
    }
}

#[test]
fn test_io_error_unexpected_eof_with_reader() {
    use fixtures::simple::*;

    for max_readable_bytes in &[0, 1, 2, 10] {
        let err = from_reader::<RootType, _>(
            make_limited_reader(ttlv_bytes(), *max_readable_bytes),
            &Config::default(),
        )
        .unwrap_err();

        assert_matches!(err.kind(), ErrorKind::IoError(io_error) if io_error.kind() == std::io::ErrorKind::UnexpectedEof);
    }
}

#[test]
#[rustfmt::skip]
fn test_io_error_unexpected_eof_with_slice() {
    use fixtures::simple::*;

    let full_ttlv_byte_len = ttlv_bytes().len();

    for cutoff_bytes_at in 0..full_ttlv_byte_len-1 {
        let err = from_slice::<RootType>(&ttlv_bytes()[0..=cutoff_bytes_at]).unwrap_err();
        assert_matches!(err.kind(), ErrorKind::IoError(io_error) if io_error.kind() == std::io::ErrorKind::UnexpectedEof);
    }

    assert!(from_slice::<RootType>(&ttlv_bytes()[0..full_ttlv_byte_len]).is_ok());
}

#[test]
fn test_malformed_ttlv_invalid_root_type() {
    use fixtures::malformed_ttlv::*;

    let err = from_slice::<RootType>(&ttlv_bytes_with_invalid_root_type()).unwrap_err();
    assert_matches!(err.kind(), ErrorKind::MalformedTtlv(MalformedTtlvError::InvalidType(ty)) if *ty == invalid_root_type());
    assert_eq!(err.location().offset(), Some(ByteOffset(3)));
    assert_eq!(err.location().parent_tags(), &[]);
    assert_eq!(err.location().tag(), Some(root_tag()));
    assert_eq!(err.location().r#type(), None);
}

#[test]
fn test_malformed_ttlv_wrong_root_type() {
    use fixtures::malformed_ttlv::*;

    let err = from_slice::<RootType>(&ttlv_bytes_with_wrong_root_type()).unwrap_err();
    assert_matches!(err.kind(), ErrorKind::MalformedTtlv(MalformedTtlvError::UnexpectedType{
        expected: TtlvType::Structure,
        actual
    }) if *actual == wrong_root_type());
    assert_eq!(err.location().offset(), Some(ByteOffset(4)));
    assert_eq!(err.location().parent_tags(), &[]);
    assert_eq!(err.location().tag(), Some(root_tag()));
    assert_eq!(err.location().r#type(), Some(wrong_root_type()));
}

#[test]
fn test_malformed_ttlv_length_overflow() {
    use fixtures::malformed_ttlv::*;

    let err = from_slice::<RootType>(&ttlv_bytes_with_length_overflow()).unwrap_err();
    assert_matches!(err.kind(), ErrorKind::IoError(io_error) if io_error.kind() == std::io::ErrorKind::UnexpectedEof);
    // TOOD: test the values of err.location()?
}

#[test]
fn test_malformed_ttlv_wrong_value_length() {
    use fixtures::malformed_ttlv::*;

    let err = from_slice::<RootType>(&ttlv_bytes_with_wrong_value_length()).unwrap_err();
    assert_matches!(
        err.kind(),
        ErrorKind::MalformedTtlv(MalformedTtlvError::InvalidLength {
            expected: 4,
            actual: 5,
            r#type: TtlvType::Integer
        })
    );
    assert_eq!(err.location().offset(), Some(ByteOffset(16)));
    assert_eq!(err.location().parent_tags(), &[root_tag()]);
    assert_eq!(err.location().tag(), Some(inner_tag()));
    assert_eq!(err.location().r#type(), Some(TtlvType::Integer));
}

#[test]
fn test_malformed_ttlv_invalid_boolean_value() {
    use fixtures::malformed_ttlv::*;

    let err = from_slice::<FlexibleRootType<bool>>(&ttlv_bytes_with_wrong_boolean_value()).unwrap_err();
    assert_matches!(
        err.kind(),
        ErrorKind::MalformedTtlv(MalformedTtlvError::InvalidValue {
            r#type: TtlvType::Boolean
        })
    );
    assert_eq!(err.location().offset(), Some(ByteOffset(24)));
    assert_eq!(err.location().parent_tags(), &[root_tag()]);
    assert_eq!(err.location().tag(), Some(inner_tag()));
    assert_eq!(err.location().r#type(), Some(TtlvType::Boolean));
}

#[test]
fn test_malformed_ttlv_invalid_utf8() {
    use fixtures::malformed_ttlv::*;

    // First do a quick sanity check that valid UTF-8 can be deserialized correctly.
    let r = from_slice::<FlexibleRootType<String>>(&ttlv_bytes_with_valid_utf8()).unwrap();
    assert_eq!(r.a, "κόσμε");

    // Now verify that invalid UTF-8 bytes cause the expected error
    let err = from_slice::<FlexibleRootType<String>>(&ttlv_bytes_with_invalid_utf8()).unwrap_err();
    assert_matches!(
        err.kind(),
        ErrorKind::MalformedTtlv(MalformedTtlvError::InvalidValue {
            r#type: TtlvType::TextString
        })
    );
    assert_eq!(err.location().offset(), Some(ByteOffset(17)));
    assert_eq!(err.location().parent_tags(), &[root_tag()]);
    assert_eq!(err.location().tag(), Some(inner_tag()));
    assert_eq!(err.location().r#type(), Some(TtlvType::TextString));
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
            let err = from_slice::<$rust_type>(&ttlv_bytes_with_custom_tlv(&$actual_tlv_value)).unwrap_err();
            assert_matches!(err.kind(), ErrorKind::SerdeError(SerdeError::UnexpectedType {
                expected: $expected_ttlv_type,
                actual,
            }) if *actual == $actual_tlv_value.ttlv_type());
            assert_eq!(err.location().offset(), Some(ByteOffset(12)));
            assert_eq!(err.location().parent_tags(), &[root_tag()]);
            assert_eq!(err.location().tag(), Some(inner_tag()));
            assert_eq!(err.location().r#type(), Some($actual_tlv_value.ttlv_type()));
        };
    }

    // Dummy values to serialize into the byte stream to set it up ready for testing if deserializing behaves as
    // expected
    let some_int = TtlvInteger(1);
    let some_longint = TtlvLongInteger(1);
    let some_bigint = TtlvBigInteger(vec![1]);
    let some_enum = TtlvEnumeration(1);
    let some_out_of_range_enum = TtlvEnumeration(2);
    let some_bool = TtlvBoolean(true);
    let some_string = TtlvTextString("blah".to_string());
    let some_bytes = TtlvByteString(vec![1]);
    let some_datetime = TtlvDateTime(1);

    // GOOD: i32 <-- from TTLV Integer
    from_slice::<FlexibleRootType<i32>>(&ttlv_bytes_with_custom_tlv(&some_int)).unwrap();
    // BAD: attempt and fail to deserialize TTLV types that can't (or we won't) fit into the Rust i32 type
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i32>, TtlvType::Integer, some_longint);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i32>, TtlvType::Integer, some_bigint);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i32>, TtlvType::Integer, some_enum);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i32>, TtlvType::Integer, some_bool);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i32>, TtlvType::Integer, some_string);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i32>, TtlvType::Integer, some_bytes);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i32>, TtlvType::Integer, some_datetime);

    // GOOD: i64 <-- from TTLV Long Integer or TTLV Date Time (both are 64-bit values)
    from_slice::<FlexibleRootType<i64>>(&ttlv_bytes_with_custom_tlv(&some_longint)).unwrap();
    from_slice::<FlexibleRootType<i64>>(&ttlv_bytes_with_custom_tlv(&some_datetime)).unwrap();
    // BAD: attempt and fail to deserialize TTLV types that can't (or we won't) fit into the Rust i64 type
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i64>, TtlvType::LongInteger, some_int);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i64>, TtlvType::LongInteger, some_bigint);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i64>, TtlvType::LongInteger, some_enum);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i64>, TtlvType::LongInteger, some_bool);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i64>, TtlvType::LongInteger, some_string);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<i64>, TtlvType::LongInteger, some_bytes);

    #[derive(Debug, Deserialize)]
    #[serde(rename = "0xBBBBBB")]
    enum DummyEnum {
        #[serde(rename = "0x00000001")]
        SomeValue,
    }
    // GOOD: enum <-- from TTLV Enumeration or TTLV Integer (both are 32-bit values)
    from_slice::<FlexibleRootType<DummyEnum>>(&ttlv_bytes_with_custom_tlv(&some_enum)).unwrap();
    from_slice::<FlexibleRootType<DummyEnum>>(&ttlv_bytes_with_custom_tlv(&some_int)).unwrap();
    // BAD: attempt and fail to deserialize TTLV types that can't (or we won't) fit into the Rust enum type
    test_rust_ttlv_type_mismatch!(FlexibleRootType<DummyEnum>, TtlvType::Enumeration, some_longint);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<DummyEnum>, TtlvType::Enumeration, some_bigint);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<DummyEnum>, TtlvType::Enumeration, some_bool);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<DummyEnum>, TtlvType::Enumeration, some_string);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<DummyEnum>, TtlvType::Enumeration, some_bytes);
    test_rust_ttlv_type_mismatch!(FlexibleRootType<DummyEnum>, TtlvType::Enumeration, some_datetime);

    // BAD: attempt to deserialize an enum variant that is not in the valid value range
    // Note: This test is brittle as it depends on the exact error message text produced by Serde Derive.
    let err =
        from_slice::<FlexibleRootType<DummyEnum>>(&ttlv_bytes_with_custom_tlv(&some_out_of_range_enum)).unwrap_err();
    assert_matches!(err.kind(), ErrorKind::SerdeError(SerdeError::Other(msg)) if msg == "unknown variant `0x00000002`, expected `0x00000001`");
    assert_eq!(err.location().offset(), Some(ByteOffset(24)));

    // BAD: attempt to deserialize into an enum instead of a struct. Valid TTLV always starts with a Structure so
    // cannot be deserialized into an enum. Serde Derive will invoke `fn deserialize_enum()` which will fail when the
    // internal state machine of the deserializer detects that it expected to be informed that a tag is to be
    // deserialized but is instead informed that a value is being deserialized.
    let err = from_slice::<DummyEnum>(&ttlv_bytes_with_custom_tlv(&some_int)).unwrap_err();
    dbg!(err);
}

#[test]
fn test_incorrect_serde_configuration_invalid_tags() {
    use fixtures::malformed_ttlv::*;
    use serde_derive::Deserialize;

    macro_rules! test_invalid_tag {
        ($rust_type:ty, $actual_tlv_value:expr) => {
            let err = from_slice::<$rust_type>(&ttlv_bytes_with_custom_tlv(&$actual_tlv_value)).unwrap_err();
            assert_matches!(err.kind(), ErrorKind::SerdeError(SerdeError::InvalidTag(_)));
            assert_eq!(err.location().offset(), Some(ByteOffset(0)));
            assert_eq!(err.location().parent_tags(), &[]);
            assert_eq!(err.location().tag(), None);
            assert_eq!(err.location().r#type(), None);
        };
    }

    #[derive(Debug, Deserialize)]
    struct UntaggedRoot {}
    test_invalid_tag!(UntaggedRoot, TtlvInteger(1));

    #[derive(Debug, Deserialize)]
    #[serde(rename = "This is not hex")]
    struct NonHexTaggedRoot {}
    test_invalid_tag!(NonHexTaggedRoot, TtlvInteger(1));

    #[derive(Debug, Deserialize)]
    #[serde(rename = "0xBBBBBB")]
    enum DummyEnum {
        #[serde(rename = "if malformed variant matcher syntax")]
        SomeValue,
    }

    let err = from_slice::<FlexibleRootType<DummyEnum>>(&ttlv_bytes_with_custom_tlv(&TtlvEnumeration(1))).unwrap_err();
    assert_matches!(err.kind(), ErrorKind::SerdeError(SerdeError::InvalidVariantMatcherSyntax(msg)) if msg == "if malformed variant matcher syntax");
    assert_eq!(err.location().offset(), Some(ByteOffset(12)));
    assert_eq!(err.location().parent_tags(), &[root_tag()]);
    assert_eq!(err.location().tag(), Some(inner_tag()));
    assert_eq!(err.location().r#type(), Some(TtlvType::Enumeration));
}

#[test]
fn test_mismatched_serde_configuration() {
    use fixtures::simple::*;
    use serde_derive::Deserialize;

    let root_tag = TtlvTag::from(*b"\xAA\xAA\xAA");

    // Attempt to deserialize a byte stream that contains a tag which we have not specified but we have configured
    // Serde derive to fail hard on the presence of unknown fields in the byte stream.
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[serde(rename = "0xAAAAAA")]
    struct MissingFieldRoot {
        #[serde(rename = "0xBBBBBB")]
        a: i32, // field b is missing
    }
    let err = from_slice::<MissingFieldRoot>(&ttlv_bytes()).unwrap_err();
    assert_matches!(err.kind(), ErrorKind::SerdeError(SerdeError::Other(msg)) if msg == "unknown field `0xCCCCCC`, expected `0xBBBBBB`");
    assert_eq!(err.location().offset(), Some(ByteOffset(28)));
    assert_eq!(err.location().parent_tags(), &[root_tag]);
    assert_eq!(err.location().tag(), Some(root_tag)); // TODO: Shouldn't really be root_tag here as then parent_tags is wrong
    assert_eq!(err.location().r#type(), Some(TtlvType::Structure));

    // Do the same again but this time without `#[serde(deny_unknown_fields)]` and see that we successfully ignore the
    // extra field in the byte stream and complete the deserialization.
    #[derive(Debug, Deserialize)]
    #[serde(rename = "0xAAAAAA")]
    struct IgnoredMissingFieldRoot {
        #[serde(rename = "0xBBBBBB")]
        a: i32, // field b is missing
    }
    from_slice::<IgnoredMissingFieldRoot>(&ttlv_bytes()).unwrap();

    // Fields specified in the Rust struct are required to exist in the byte stream unless marked as `Option`.
    #[derive(Debug, Deserialize)]
    #[serde(rename = "0xAAAAAA")]
    struct ExtraFieldRoot {
        #[serde(rename = "0xBBBBBB")]
        a: i32,
        #[serde(rename = "0xCCCCCC")]
        b: i32,
        // Field c doesn't match any field in the TTLV byte sequence
        #[serde(rename = "0xDDDDDD")]
        c: i32,
    }
    let err = from_slice::<ExtraFieldRoot>(&ttlv_bytes()).unwrap_err();
    assert_matches!(err.kind(), ErrorKind::SerdeError(SerdeError::Other(msg)) if msg == "missing field `0xDDDDDD`");
    assert_eq!(err.location().offset(), Some(ByteOffset(40)));
    assert_eq!(err.location().parent_tags(), &[root_tag]);
    assert_eq!(err.location().tag(), Some(root_tag)); // TODO: Shouldn't really be root_tag here as then parent_tags is wrong
    assert_eq!(err.location().r#type(), Some(TtlvType::Structure));
}
