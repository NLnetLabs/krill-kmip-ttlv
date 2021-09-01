use crate::error::{Error, ErrorLocation, MalformedTtlvError, SerdeError};
use crate::tests::fixtures;
use crate::tests::util::{make_limited_reader, make_reader, no_response_size_limit, reject_if_response_larger_than};
use crate::types::TtlvType;
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
        from_slice::<RootType>(&ttlv_bytes_with_invalid_integer_length()),
        Err(Error::MalformedTtlv {
            error: MalformedTtlvError::InvalidLength {
                expected: 4,
                actual: 5,
                r#type: TtlvType::Integer
            },
            location: ErrorLocation { offset: Some(16) }
        })
    );
}

#[test]
fn test_incorrect_serde_configuration() {
    use fixtures::malformed_ttlv::*;

    // use the invalid value length fixtures as we don't get as far as deserializing the value but instead fail before
    // that due to the TTLV type encountered not matching the Rust type being deserialized into.
    assert_matches!(
        from_slice::<FlexibleRootType<i64>>(&ttlv_bytes_with_invalid_integer_length()),
        Err(Error::SerdeError {
            error: SerdeError::UnexpectedType {
                expected: TtlvType::LongInteger,
                actual: TtlvType::Integer
            },
            location: ErrorLocation { offset: Some(12) }
        })
    );

    assert_matches!(
        from_slice::<FlexibleRootType<bool>>(&ttlv_bytes_with_invalid_integer_length()),
        Err(Error::SerdeError {
            error: SerdeError::UnexpectedType {
                expected: TtlvType::Boolean,
                actual: TtlvType::Integer
            },
            location: ErrorLocation { offset: Some(12) }
        })
    );

    assert_matches!(
        from_slice::<FlexibleRootType<String>>(&ttlv_bytes_with_invalid_integer_length()),
        Err(Error::SerdeError {
            error: SerdeError::UnexpectedType {
                expected: TtlvType::TextString,
                actual: TtlvType::Integer
            },
            location: ErrorLocation { offset: Some(12) }
        })
    );

    assert_matches!(
        from_slice::<ByteStringRootType>(&ttlv_bytes_with_invalid_integer_length()),
        Err(Error::SerdeError {
            error: SerdeError::UnexpectedType {
                expected: TtlvType::ByteString,
                actual: TtlvType::Integer
            },
            location: ErrorLocation { offset: Some(12) }
        })
    );
}
