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

fn assert_err_msg(err: Error, err_desc: &'static str, expected_bytes_consumed: usize, buf_len: usize, expected_ctx: &'static str) {
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

    assert_err_msg_with_forced_eof(0, 0, "^>><<$");                                                 //  0 bytes read, 0 bytes left

    // Read successive bytes until the entire TTLV 3-byte tag is read
    assert_err_msg_with_forced_eof( 1,  0, "^>>AA<<$");                                             //  0 bytes read, 1 byte left
    assert_err_msg_with_forced_eof( 2,  0, "^>>AA<<AA$");                                           //  0 bytes read, 1 byte next, 1 byte after
    assert_err_msg_with_forced_eof( 3,  3, "^AAAAAA>><<$");                                         //  3 bytes read, 0 bytes left

    // Read the 1-byte TTLV type byte too
    assert_err_msg_with_forced_eof( 4,  4, "^AAAAAA01>><<$");                                       //  4 bytes read, 0 bytes left

    // Read successive bytes until the 4-byte TTLV length is also read
    assert_err_msg_with_forced_eof( 5,  4, "^AAAAAA01>>00<<$");                                     //  4 bytes read, 1 byte left
    assert_err_msg_with_forced_eof( 6,  4, "^AAAAAA01>>00<<00$");                                   //  4 bytes read, 1 byte next, 1 byte after
    assert_err_msg_with_forced_eof( 7,  4, "^AAAAAA01>>00<<0000$");                                 //  4 bytes read, 1 byte next, 2 bytes after
    assert_err_msg_with_forced_eof( 8,  8, "^AAAAAA0100000020>><<$");                               //  8 bytes read, 0 bytes left

    // Read successive bytes until the entire next TTLV 3-byte tag is read
    assert_err_msg_with_forced_eof( 9,  8, "^AAAAAA0100000020>>BB<<$");                             //  8 bytes read, 1 byte next
    assert_err_msg_with_forced_eof(10,  8, "^AAAAAA0100000020>>BB<<BB$");                           //  8 bytes read, 1 byte next, 1 byte after
    assert_err_msg_with_forced_eof(11, 11, "^AAAAAA0100000020BBBBBB>><<$");                         // 11 bytes read, 0 bytes left

    // Read the 1-byte TTLV type byte too
    assert_err_msg_with_forced_eof(12, 12, "^AAAAAA0100000020BBBBBB02>><<$");                       // 12 bytes read, 0 bytes left

    // Read successive bytes until the 4-byte TTLV length is also read
    assert_err_msg_with_forced_eof(13, 12, "^AAAAAA0100000020BBBBBB02>>00<<$");                     // 12 bytes read, 1 byte next
    assert_err_msg_with_forced_eof(14, 12, "^AAAAAA0100000020BBBBBB02>>00<<00$");                   // 12 bytes read, 1 byte next, 1 byte after
    assert_err_msg_with_forced_eof(15, 12, "^AAAAAA0100000020BBBBBB02>>00<<0000$");                 // 12 bytes read, 1 byte next, 2 bytes after
    assert_err_msg_with_forced_eof(16, 16, "^AAAAAA0100000020BBBBBB0200000004>><<$");               // 16 bytes read, 0 bytes left

    // Read successive bytes until the 4-byte TTLV value is also read
    assert_err_msg_with_forced_eof(17, 16, "^AAAAAA0100000020BBBBBB0200000004>>00<<$");             // 16 bytes read, 1 byte next
    assert_err_msg_with_forced_eof(18, 16, "^AAAAAA0100000020BBBBBB0200000004>>00<<00$");           // 16 bytes read, 1 byte next, 1 byte after
    assert_err_msg_with_forced_eof(19, 16, "^AAAAAA0100000020BBBBBB0200000004>>00<<0000$");         // 16 bytes read, 1 byte next, 2 bytes after
    assert_err_msg_with_forced_eof(20, 20, "^AAAAAA0100000020BBBBBB020000000400000001>><<$");       // 20 bytes read, 0 bytes left

    // Read successive bytes until the 4-byte TTLV value padding is also read
    assert_err_msg_with_forced_eof(21, 20, "^AAAAAA0100000020BBBBBB020000000400000001>>00<<$");     // 20 bytes read, 1 byte next
    assert_err_msg_with_forced_eof(22, 20, "^AAAAAA0100000020BBBBBB020000000400000001>>00<<00$");   // 20 bytes read, 1 byte next, 1 byte after
    assert_err_msg_with_forced_eof(23, 20, "^AAAAAA0100000020BBBBBB020000000400000001>>00<<0000$"); // 20 bytes read, 1 byte next, 2 bytes after
    assert_err_msg_with_forced_eof(24, 24, "..00000020BBBBBB02000000040000000100000000>><<$");      // 24 bytes read, 0 bytes left
    //                                      ^^ sliding window no longer stretches back to the start of the buffer
}

#[test]
fn test_malformed_ttlv() {
    use fixtures::malformed_ttlv::*;

    let ttlv_bytes = ttlv_bytes_with_invalid_type();
    let res = from_slice::<RootType>(&ttlv_bytes);
    assert_err_msg(res.unwrap_err(), "Deserialization error: No known ItemType has u8 value 0", 4, ttlv_bytes.len(), "^AAAAAA00>>00<<000020$");

    let ttlv_bytes = ttlv_bytes_with_wrong_root_type();
    let res = from_slice::<RootType>(&ttlv_bytes);
    assert_err_msg(res.unwrap_err(), "Deserialization error: Wanted type 'Structure' but found 'Integer'", 4, ttlv_bytes.len(), "^AAAAAA02>>00<<000020$");
}
