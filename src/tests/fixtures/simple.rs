use serde_derive::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename = "0xAAAAAA")]
pub(crate) struct RootType {
    #[serde(rename = "0xBBBBBB")]
    a: i32,
    #[serde(rename = "0xCCCCCC")]
    b: i32,
}

pub(crate) fn ttlv_bytes() -> Vec<u8> {
    // Each of the child TTLV integer items below is 16 bytes, so 32 in total which is 0x20 in hexadecimal.
    // 01 means we are defining a structure.
    let struct_hdr = "AAAAAA  01  00000020";
    let raw_ints = [
        "BBBBBB  02  00000004  00000001  00000000",
        "CCCCCC  02  00000004  00000002  00000000",
    ];
    let mut test_data = String::new();
    test_data.push_str(struct_hdr);
    test_data.push_str(&raw_ints.join(""));

    hex::decode(test_data.replace(" ", "")).unwrap()
}
