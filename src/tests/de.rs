use crate::error::Error;
use crate::tests::fixtures;
use crate::{from_reader, from_slice, Config};

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

    fn no_response_size_limit() -> Config {
        Config::default()
    }

    fn reject_if_response_larger_than(max_bytes: u32) -> Config {
        Config::default().with_max_bytes(max_bytes)
    }

    fn make_reader() -> impl std::io::Read {
        std::io::Cursor::new(ttlv_bytes())
    }

    // sanity check
    assert!(from_reader::<RootType, _>(make_reader(), &no_response_size_limit()).is_ok());

    // limit the read buffer to several insufficient lengths
    for max_readable_bytes in [0, 1, 2, 10] {
        let res = from_reader::<RootType, _>(make_reader(), &reject_if_response_larger_than(max_readable_bytes));

        // Verify the error type
        assert!(matches!(res, Err(Error::InvalidLength(_))));

        // Verify the error message
        assert_eq!(
            format!("{}", res.unwrap_err()),
            format!(
                "Invalid item length: The TTLV response length ({}) is greater than the maximum supported ({})",
                full_input_byte_len, max_readable_bytes
            )
        );
    }
}

#[test]
fn test_io_error_unexpected_eof_with_reader() {
    use fixtures::simple::*;
    use std::io::Read; // for .take()

    fn make_limited_reader(max_bytes: u64) -> impl std::io::Read {
        std::io::Cursor::new(ttlv_bytes()).take(max_bytes)
    }

    for max_readable_bytes in [0, 1, 2, 10] {
        let res = from_reader::<RootType, _>(make_limited_reader(max_readable_bytes), &Config::default());
        assert!(matches!(res, Err(Error::IoError(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof));
    }
}

fn assert_err_msg(
    err: Error,
    err_desc: &'static str,
    expected_bytes_consumed: usize,
    buf_len: usize,
    expected_ctx: &'static str,
) {
    assert!(matches!(err, Error::DeserializeError { .. }));
    assert_eq!(
        format!("{}", err),
        format!(
            "{} at position {}/{} with context: {}",
            err_desc, expected_bytes_consumed, buf_len, expected_ctx
        )
    );
}

#[test]
#[rustfmt::skip]
fn test_io_error_unexpected_eof_with_slice() {
    use fixtures::simple::*;

    fn assert_err_msg_with_forced_eof(cutoff_at_byte: usize, expected_bytes_consumed: usize, expected_ctx: &'static str) {
        let err_desc = "Deserialization error: IO error (UnexpectedEof: failed to fill whole buffer)";
        let res = from_slice::<RootType>(&ttlv_bytes()[0..cutoff_at_byte]);
        assert_err_msg(res.unwrap_err(), err_desc, expected_bytes_consumed, cutoff_at_byte, expected_ctx);
    }

    assert_err_msg_with_forced_eof(0, 0, "^>><<$");                     //  0 bytes read, 0 bytes left

    // Read successive bytes until the entire TTLV 3-byte tag is read
    assert_err_msg_with_forced_eof( 1,  0, "^>>AA<<$");                 //  0 bytes read, 1 byte left
    assert_err_msg_with_forced_eof( 2,  0, "^>>AA<<AA$");               //  0 bytes read, 1 byte next, 1 byte after
    assert_err_msg_with_forced_eof( 3,  3, "^AAAAAA>><<$");             //  3 bytes read, 0 bytes left

    // Read the 1-byte TTLV type byte too
    assert_err_msg_with_forced_eof( 4,  4, "^AAAAAA01>><<$");           //  4 bytes read, 0 bytes left

    // Read successive bytes until the 4-byte TTLV length is also read
    assert_err_msg_with_forced_eof( 5,  4, "^AAAAAA01>>00<<$");         //  4 bytes read, 1 byte left
    assert_err_msg_with_forced_eof( 6,  4, "^AAAAAA01>>00<<00$");       //  4 bytes read, 1 byte next, 1 byte after
    assert_err_msg_with_forced_eof( 7,  4, "^AAAAAA01>>00<<0000$");     //  4 bytes read, 1 byte next, 2 bytes after

    // We can't read the entire TTLV length value as the deserializer will then notice that there are not enough bytes
    // available to contain the structure of the specified length and so we get a different error than we are testing
    // for here.
}

#[test]
fn test_malformed_ttlv() {
    use fixtures::malformed_ttlv::*;

    let ttlv_bytes = ttlv_bytes_with_invalid_type();
    let res = from_slice::<RootType>(&ttlv_bytes);
    assert_err_msg(
        res.unwrap_err(),
        "Deserialization error: No known ItemType has u8 value 0",
        4,
        ttlv_bytes.len(),
        "^AAAAAA00>>00<<000020$",
    );

    let ttlv_bytes = ttlv_bytes_with_wrong_root_type();
    let res = from_slice::<RootType>(&ttlv_bytes);
    assert_err_msg(
        res.unwrap_err(),
        "Deserialization error: Wanted type 'Structure' but found 'Integer'",
        4,
        ttlv_bytes.len(),
        "^AAAAAA02>>00<<000020$",
    );

    let ttlv_bytes = ttlv_bytes_with_length_overflow();
    let res = from_slice::<RootType>(&ttlv_bytes);
    assert_err_msg(
        res.unwrap_err(),
        "Deserialization error: Structure overflow: length 33 (0x00000021) puts end at byte 41 but buffer ends at byte 40",
        8,
        ttlv_bytes.len(),
        "^AAAAAA0100000021>>BB<<BBBB02000000040000000100000000CCCCCC02000000040000000200000000..$",
    );

    let ttlv_bytes = ttlv_bytes_with_invalid_integer_length();
    let res = from_slice::<FlexibleRootType<i32>>(&ttlv_bytes);
    assert_err_msg(
        res.unwrap_err(),
        "Deserialization error: Invalid item length: Item length is 5 but for type TtlvInteger it should be 4",
        16,
        ttlv_bytes.len(),
        "^AAAAAA0100000010BBBBBB0200000005>>00<<00000100000000$",
    );

    let ttlv_bytes = ttlv_bytes_with_invalid_long_integer_length();
    let res = from_slice::<FlexibleRootType<i64>>(&ttlv_bytes);
    assert_err_msg(
        res.unwrap_err(),
        "Deserialization error: Invalid item length: Item length is 5 but for type TtlvLongInteger it should be 8",
        16,
        ttlv_bytes.len(),
        "^AAAAAA0100000010BBBBBB0300000005>>00<<00000100000000$",
    );
}

#[test]
fn test_incorrect_serde_configuration() {
    use fixtures::malformed_ttlv::*;

    // use the invalid value length fixtures as we don't get as far as deserializing the value but instead fail before
    // that due to the TTLV type encountered not matching the Rust type being deserialized into.
    let ttlv_bytes = ttlv_bytes_with_invalid_long_integer_length();
    let res = from_slice::<FlexibleRootType<i32>>(&ttlv_bytes);
    assert_err_msg(
        res.unwrap_err(),
        "Deserialization error: Unexpected item type: TTLV type to deserialize into a i32 should be Integer (0x02) but found LongInteger (0x03)",
        12,
        ttlv_bytes.len(),
        "^AAAAAA0100000010BBBBBB03>>00<<0000050000000100000000$",
    );

    let ttlv_bytes = ttlv_bytes_with_invalid_integer_length();
    let res = from_slice::<FlexibleRootType<i64>>(&ttlv_bytes);
    assert_err_msg(
        res.unwrap_err(),
        "Deserialization error: Unexpected item type: TTLV type to deserialize into a i64 should be LongInteger (0x03) but found Integer (0x02)",
        12,
        ttlv_bytes.len(),
        "^AAAAAA0100000010BBBBBB02>>00<<0000050000000100000000$",
    );

    let ttlv_bytes = ttlv_bytes_with_invalid_integer_length();
    let res = from_slice::<FlexibleRootType<bool>>(&ttlv_bytes);
    assert_err_msg(
        res.unwrap_err(),
        "Deserialization error: Unexpected item type: TTLV type to deserialize into a bool should be Boolean (0x06) but found Integer (0x02)",
        12,
        ttlv_bytes.len(),
        "^AAAAAA0100000010BBBBBB02>>00<<0000050000000100000000$",
    );

    let ttlv_bytes = ttlv_bytes_with_invalid_integer_length();
    let res = from_slice::<FlexibleRootType<String>>(&ttlv_bytes);
    assert_err_msg(
        res.unwrap_err(),
        "Deserialization error: Unexpected item type: TTLV type to deserialize into a String should be TextString (0x07) but found Integer (0x02)",
        12,
        ttlv_bytes.len(),
        "^AAAAAA0100000010BBBBBB02>>00<<0000050000000100000000$",
    );

    let ttlv_bytes = ttlv_bytes_with_invalid_integer_length();
    let res = from_slice::<ByteStringRootType>(&ttlv_bytes);
    assert_err_msg(
        res.unwrap_err(),
        "Deserialization error: Unexpected item type: TTLV type to deserialize into a Vec<u8> should be ByteString (0x08) but found Integer (0x02)",
        12,
        ttlv_bytes.len(),
        "^AAAAAA0100000010BBBBBB02>>00<<0000050000000100000000$",
    );
}
