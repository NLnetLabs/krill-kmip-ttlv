use pretty_assertions::{assert_eq, assert_ne};

use std::{convert::TryFrom, io::Cursor, str::FromStr};

use crate::types::{
    Error, SerializableTtlvType, TtlvBigInteger, TtlvBoolean, TtlvByteString, TtlvDateTime, TtlvEnumeration,
    TtlvInteger, TtlvLongInteger, TtlvTag, TtlvTextString, TtlvType,
};

use assert_matches::assert_matches;

#[test]
fn test_item_tag() {
    // KMIP v1.0 spec: 9.1.1.1 Item Tag
    // "An Item Tag is a three-byte binary unsigned integer, transmitted big endian, which contains a number that
    //  designates the specific Protocol Field or Object that the TTLV object represents. To ease debugging, and
    //  to ensure that malformed messages are detected more easily, all tags SHALL contain either the value 42
    //  in hex or the value 54 in hex as the high order (first) byte. Tags defined by this specification contain hex
    //  42 in the first byte. Extensions, which are permitted, but are not defined in this specification, contain the
    //  value 54 hex in the first byte. A list of defined Item Tags is in Section 9.1.3.1"

    // Note: we do NOT enforce the 42 or 54 rules as those are specific to KMIP usage of TTLV, not to TTLV itself.

    assert!(TtlvTag::from_str("").is_err());
    assert!(TtlvTag::from_str("    ").is_err());
    assert!(TtlvTag::from_str("XYZ").is_err());

    #[allow(non_snake_case)]
    let ZERO_TAG = TtlvTag::from([0x00u8, 0x00u8, 0x00u8]);

    #[allow(non_snake_case)]
    let ONE_TAG = TtlvTag::from([0x00u8, 0x00u8, 0x01u8]);

    assert_eq!(ZERO_TAG, TtlvTag::from_str("0").unwrap());
    assert_eq!(ZERO_TAG, TtlvTag::from_str("000").unwrap());
    assert_eq!(ZERO_TAG, TtlvTag::from_str("0x0").unwrap());
    assert_eq!(ONE_TAG, TtlvTag::from_str("1").unwrap());
    assert_eq!(ONE_TAG, TtlvTag::from_str("001").unwrap());
    assert_eq!(ONE_TAG, TtlvTag::from_str("0x1").unwrap());

    assert_eq!(
        TtlvTag::from([0x42u8, 0x00u8, 0xAAu8]),
        TtlvTag::from_str("0x4200AA").unwrap()
    );
    assert_eq!(ZERO_TAG, ZERO_TAG);
    assert_ne!(ONE_TAG, ZERO_TAG);
}

#[test]
fn test_item_type() {
    // Quoting: http://docs.oasis-open.org/kmip/spec/v1.0/cs01/kmip-spec-1.0-cs-01.pdf Section 9.1.1.2 Item Type
    //
    //     An Item Type is a byte containing a coded value that indicates the data type of the data object. The
    //     allowed values are:
    //
    //         Data Type    | Coded Value in Hex
    //         -------------|-------------------
    //         Structure    | 01
    //         Integer      | 02
    //         Long Integer | 03
    //         Big Integer  | 04
    //         Enumeration  | 05
    //         Boolean      | 06
    //         Text String  | 07
    //         Byte String  | 08
    //         Date-Time    | 09
    //         Interval     | 0A
    //
    //         Table 191: Allowed Item Type Values

    assert_matches!(TtlvType::try_from(0x00), Err(Error::InvalidTtlvType(0x00)));
    assert_matches!(TtlvType::try_from(0x01), Ok(TtlvType::Structure));
    assert_matches!(TtlvType::try_from(0x02), Ok(TtlvType::Integer));
    assert_matches!(TtlvType::try_from(0x03), Ok(TtlvType::LongInteger));
    assert_matches!(TtlvType::try_from(0x04), Ok(TtlvType::BigInteger));
    assert_matches!(TtlvType::try_from(0x05), Ok(TtlvType::Enumeration));
    assert_matches!(TtlvType::try_from(0x06), Ok(TtlvType::Boolean));
    assert_matches!(TtlvType::try_from(0x07), Ok(TtlvType::TextString));
    assert_matches!(TtlvType::try_from(0x08), Ok(TtlvType::ByteString));
    assert_matches!(TtlvType::try_from(0x09), Ok(TtlvType::DateTime));

    // Interval is not yet implemented
    assert_matches!(TtlvType::try_from(0x0A), Err(Error::UnsupportedTtlvType(0x0A)));

    // All other values are invalid
    for i in 0x0B..0xFF {
        assert_matches!(TtlvType::try_from(i), Err(Error::InvalidTtlvType(n)) if n == i);
    }
}

fn spec_ttlv_to_vec_tlv(s: &str) -> Vec<u8> {
    // strip out the example fake item tag, spacing and separators
    hex::decode(s.replace("42 00 20 | ", "").replace(" ", "").replace("|", "")).unwrap()
}

#[test]
fn test_spec_ttlv_integer() {
    // Quoting: http://docs.oasis-open.org/kmip/spec/v1.0/cs01/kmip-spec-1.0-cs-01.pdf 9.1.2 Examples
    //   These examples are assumed to be encoding a Protocol Object whose tag is 420020. The examples are
    //   shown as a sequence of bytes in hexadecimal notation:
    //
    //   - An Integer containing the decimal value 8:
    //     42 00 20 | 02 | 00 00 00 04 | 00 00 00 08 00 00 00 00
    let spec_tlv_bytes = spec_ttlv_to_vec_tlv("42 00 20 | 02 | 00 00 00 04 | 00 00 00 08 00 00 00 00");

    // Test serialization
    let mut serialized_tlv_bytes = Vec::new();
    assert!(TtlvInteger(8).write(&mut serialized_tlv_bytes).is_ok());
    assert_eq!(spec_tlv_bytes, serialized_tlv_bytes);

    // Test deserialization
    let mut readable_spec_lv_bytes = Cursor::new(&spec_tlv_bytes[1..]);
    let v = TtlvInteger::read(&mut readable_spec_lv_bytes);
    assert!(v.is_ok());
    assert_eq!(8, *(v.unwrap()));
}

#[test]
fn test_spec_ttlv_long_integer() {
    //   - A Long Integer containing the decimal value 123456789000000000:
    //     42 00 20 | 03 | 00 00 00 08 | 01 B6 9B 4B A5 74 92 00
    let spec_tlv_bytes = spec_ttlv_to_vec_tlv("42 00 20 | 03 | 00 00 00 08 | 01 B6 9B 4B A5 74 92 00");

    // Test serialization
    let mut serialized_tlv_bytes = Vec::new();
    assert!(TtlvLongInteger(123456789000000000)
        .write(&mut serialized_tlv_bytes)
        .is_ok());
    assert_eq!(spec_tlv_bytes, serialized_tlv_bytes);

    // Test deserialization
    let mut readable_spec_lv_bytes = Cursor::new(&spec_tlv_bytes[1..]);
    let v = TtlvLongInteger::read(&mut readable_spec_lv_bytes);
    assert!(v.is_ok());
    assert_eq!(123456789000000000, *(v.unwrap()));
}

#[test]
fn test_spec_ttlv_big_integer() {
    //   - A Big Integer containing the decimal value 1234567890000000000000000000:
    //     42 00 20 | 04 | 00 00 00 10 | 00 00 00 00 03 FD 35 EB 6B C2 DF 46 18 08
    //     00 00
    let spec_tlv_bytes =
        spec_ttlv_to_vec_tlv("42 00 20 | 04 | 00 00 00 10 | 00 00 00 00 03 FD 35 EB 6B C2 DF 46 18 08 00 00");
    let big_int = num_bigint::BigInt::parse_bytes(b"1234567890000000000000000000", 10).unwrap();

    // Test serialization
    let mut serialized_tlv_bytes = Vec::new();
    assert!(TtlvBigInteger(big_int.to_signed_bytes_be())
        .write(&mut serialized_tlv_bytes)
        .is_ok());
    assert_eq!(spec_tlv_bytes, serialized_tlv_bytes);

    // Test deserialization
    let mut readable_spec_lv_bytes = Cursor::new(&spec_tlv_bytes[1..]);
    let v = TtlvBigInteger::read(&mut readable_spec_lv_bytes);
    assert!(v.is_ok());
    assert_eq!(big_int, num_bigint::BigInt::from_signed_bytes_be(&(*(v.unwrap()))));
}

#[test]
fn test_spec_ttlv_enumeration() {
    //   - An Enumeration with value 255:
    //     42 00 20 | 05 | 00 00 00 04 | 00 00 00 FF 00 00 00 00
    let mut actual = Vec::new();
    let expected = spec_ttlv_to_vec_tlv("42 00 20 | 05 | 00 00 00 04 | 00 00 00 FF 00 00 00 00");
    TtlvEnumeration(255).write(&mut actual).unwrap();
    assert_eq!(expected, actual);
}

#[test]
fn test_spec_ttlv_boolean() {
    //   - A Boolean with the value True:
    //     42 00 20 | 06 | 00 00 00 08 | 00 00 00 00 00 00 00 01
    let mut actual = Vec::new();
    let expected = spec_ttlv_to_vec_tlv("42 00 20 | 06 | 00 00 00 08 | 00 00 00 00 00 00 00 01");
    TtlvBoolean(true).write(&mut actual).unwrap();
    assert_eq!(expected, actual);
}

#[test]
fn test_spec_ttlv_text_string() {
    //   - A Text String with the value "Hello World":
    //     42 00 20 | 07 | 00 00 00 0B | 48 65 6C 6C 6F 20 57 6F 72 6C 64 00 00 00
    //     00 00
    let mut actual = Vec::new();
    let expected =
        spec_ttlv_to_vec_tlv("42 00 20 | 07 | 00 00 00 0B | 48 65 6C 6C 6F 20 57 6F 72 6C 64 00 00 00 00 00");
    TtlvTextString("Hello World".to_string()).write(&mut actual).unwrap();
    assert_eq!(expected, actual);
}

#[test]
fn test_spec_ttlv_byte_string() {
    //   - A Byte String with the value { 0x01, 0x02, 0x03 }:
    //     42 00 20 | 08 | 00 00 00 03 | 01 02 03 00 00 00 00 00
    let mut actual = Vec::new();
    let expected = spec_ttlv_to_vec_tlv("42 00 20 | 08 | 00 00 00 03 | 01 02 03 00 00 00 00 00");
    TtlvByteString(vec![0x01u8, 0x02u8, 0x03u8]).write(&mut actual).unwrap();
    assert_eq!(expected, actual);
}

#[test]
fn test_spec_ttlv_date_time() {
    use chrono::TimeZone;

    //   - A Date-Time, containing the value for Friday, March 14, 2008, 11:56:40 GMT:
    //     42 00 20 | 09 | 00 00 00 08 | 00 00 00 00 47 DA 67 F8
    let mut actual = Vec::new();
    let expected = spec_ttlv_to_vec_tlv("42 00 20 | 09 | 00 00 00 08 | 00 00 00 00 47 DA 67 F8");
    let dt = chrono::Utc
        .datetime_from_str("Friday, March 14, 2008, 11:56:40 GMT", "%A, %B %d, %Y, %H:%M:%S GMT")
        .unwrap();
    let dt_i64 = dt.timestamp();
    let expected_i64 = i64::from_be_bytes(*b"\x00\x00\x00\x00\x47\xDA\x67\xF8");
    assert_eq!(expected_i64, dt_i64);
    TtlvDateTime(dt_i64).write(&mut actual).unwrap();
    assert_eq!(expected, actual);
}

#[test]
#[should_panic]
fn test_spec_ttlv_interval() {
    //   - An Interval, containing the value for 10 days:
    //     42 00 20 | 0A | 00 00 00 04 | 00 0D 2F 00 00 00 00 00
    // NOT IMPLEMENTED YET
    todo!()
}

#[test]
#[should_panic]
fn test_spec_ttlv_structure() {
    //   - A Structure containing an Enumeration, value 254, followed by an Integer, value 255, having tags
    //   - 420004 and 420005 respectively:
    //     42 00 20 | 01 | 00 00 00 20 | 42 00 04 | 05 | 00 00 00 04 | 00 00 00 FE
    //     00 00 00 00 | 42 00 05 | 02 | 00 00 00 04 | 00 00 00 FF 00 00 00 00
    panic!("NOT IN SCOPE FOR THIS MODULE");
}
