use serde_derive::Deserialize;

use crate::types::{SerializableTtlvType, TtlvType};

#[derive(Debug, Deserialize)]
#[serde(rename = "0xAAAAAA")]
pub(crate) struct RootType {
    #[serde(rename = "0xBBBBBB")]
    a: i32,
    #[serde(rename = "0xCCCCCC")]
    b: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "0xAAAAAA")]
pub(crate) struct FlexibleRootType<T> {
    #[serde(rename = "0xCCCCCC")]
    a: T,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "0xAAAAAA")]
pub(crate) struct ByteStringRootType {
    #[serde(rename = "0xBBBBBB")]
    #[serde(with = "serde_bytes")]
    a: Vec<u8>,
}

pub(crate) fn ttlv_bytes_with_invalid_type() -> Vec<u8> {
    let test_data = format!("AAAAAA  {:02X}  00000020", invalid_type());
    hex::decode(test_data.replace(" ", "")).unwrap()
}

pub(crate) fn invalid_type() -> u8 {
    0
}

pub(crate) fn ttlv_bytes_with_wrong_root_type() -> Vec<u8> {
    let test_data = format!("AAAAAA  {:02X}  00000020", wrong_root_type() as u8);
    hex::decode(test_data.replace(" ", "")).unwrap()
}

pub(crate) fn wrong_root_type() -> TtlvType {
    TtlvType::Integer
}

pub(crate) fn ttlv_bytes_with_length_overflow() -> Vec<u8> {
    let struct_hdr = "AAAAAA  01  00000021";
    let raw_ints = [
        "BBBBBB  02  00000004  00000001  00000000",
        "CCCCCC  02  00000004  00000002  00000000",
    ];
    let mut test_data = String::new();
    test_data.push_str(struct_hdr);
    test_data.push_str(&raw_ints.join(""));
    hex::decode(test_data.replace(" ", "")).unwrap()
}

pub(crate) fn ttlv_bytes_with_wrong_value_length() -> Vec<u8> {
    let struct_hdr = "AAAAAA  01  00000021";
    let raw_ints = [
        "BBBBBB  02  00000005  00000001  00000000", // 00000005 should be 0000004
    ];
    let mut test_data = String::new();
    test_data.push_str(struct_hdr);
    test_data.push_str(&raw_ints.join(""));
    hex::decode(test_data.replace(" ", "")).unwrap()
}

pub(crate) fn ttlv_bytes_with_wrong_boolean_value() -> Vec<u8> {
    let struct_hdr = "AAAAAA  01  00000010";
    let raw_ints = [
        "BBBBBB  06  00000008  00000000  00000002", // Type 00000006 boolean should only have values of 0 or 1
    ];
    let mut test_data = String::new();
    test_data.push_str(struct_hdr);
    test_data.push_str(&raw_ints.join(""));
    hex::decode(test_data.replace(" ", "")).unwrap()
}

pub(crate) fn ttlv_bytes_with_custom_tlv<T>(ttlv_type: &T) -> Vec<u8>
where
    T: SerializableTtlvType,
{
    let struct_hdr = "AAAAAA  01  00000010";
    let value_tag = "BBBBBB";
    let mut test_data = String::new();
    test_data.push_str(struct_hdr);
    test_data.push_str(value_tag);
    let mut buf = hex::decode(test_data.replace(" ", "")).unwrap();
    ttlv_type.write(&mut buf).unwrap();
    buf
}
