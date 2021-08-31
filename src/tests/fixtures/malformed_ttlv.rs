use serde_derive::Deserialize;

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
    #[serde(rename = "0xBBBBBB")]
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
    let test_data = "AAAAAA  00  00000020";
    hex::decode(test_data.replace(" ", "")).unwrap()
}

pub(crate) fn ttlv_bytes_with_wrong_root_type() -> Vec<u8> {
    let test_data = "AAAAAA  02  00000020";
    hex::decode(test_data.replace(" ", "")).unwrap()
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

pub(crate) fn ttlv_bytes_with_invalid_integer_length() -> Vec<u8> {
    let struct_hdr = "AAAAAA  01  00000010";
    let raw_ints = [
        "BBBBBB  02  00000005  00000001  00000000", // integers must have 4 bytes of value padded to 8 bytes in total, not 5 bytes of value!
    ];
    let mut test_data = String::new();
    test_data.push_str(struct_hdr);
    test_data.push_str(&raw_ints.join(""));

    hex::decode(test_data.replace(" ", "")).unwrap()
}

pub(crate) fn ttlv_bytes_with_invalid_long_integer_length() -> Vec<u8> {
    let struct_hdr = "AAAAAA  01  00000010";
    let raw_ints = [
        "BBBBBB  03  00000005  00000001  00000000", // long integers must be 8 bytes long, not 5!
    ];
    let mut test_data = String::new();
    test_data.push_str(struct_hdr);
    test_data.push_str(&raw_ints.join(""));

    hex::decode(test_data.replace(" ", "")).unwrap()
}
