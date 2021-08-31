use serde_derive::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename = "0xAAAAAA")]
pub(crate) struct RootType { }

pub(crate) fn ttlv_bytes_with_invalid_type() -> Vec<u8> {
    let test_data = "AAAAAA  00  00000020";
    hex::decode(test_data.replace(" ", "")).unwrap()
}

pub(crate) fn ttlv_bytes_with_wrong_root_type() -> Vec<u8> {
    let test_data = "AAAAAA  02  00000020";
    hex::decode(test_data.replace(" ", "")).unwrap()
}
