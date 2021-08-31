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

    fn with_full_read_buffer() -> Config {
        Config::default()
    }

    fn with_limited_read_buffer(max_bytes: u32) -> Config {
        Config::default().with_max_bytes(max_bytes)
    }

    fn make_full_reader() -> impl std::io::Read {
        std::io::Cursor::new(ttlv_bytes())
    }

    // sanity check
    assert!(from_reader::<RootType, _>(make_full_reader(), &with_full_read_buffer()).is_ok());

    // limit the read buffer to several insufficient lengths
    for insufficient_length in [0, 1, 2, 10] {
        let res = from_reader::<RootType, _>(make_full_reader(), &with_limited_read_buffer(insufficient_length));

        // Verify the error type
        assert!(matches!(res, Err(Error::InvalidLength(_))));

        // Verify the error message
        assert_eq!(
            format!("{}", res.unwrap_err()),
            format!(
                "Invalid Item Length: The TTLV response length ({}) is greater than the maximum supported ({})",
                full_input_byte_len, insufficient_length
            )
        );
    }
}

// #[test]
// fn test_io_error_unexpected_eof() {
//     use fixtures::simple::*;

//     fn make_limited_reader(max_bytes: u64) -> impl std::io::Read {
//         std::io::Cursor::new(ttlv_bytes()).take(max_bytes)
//     }
// }
