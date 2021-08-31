use serde_derive::Deserialize;

// ============================================================================================================
// 1. Setup some test data structures that will exercise the is_variant_applicable() logic
//    by marking some enum fields with #[serde(rename(deserialize = "if ..."))].
// ============================================================================================================
use serde_derive::Serialize;

#[derive(Deserialize, Serialize, PartialEq, Debug)]
#[serde(rename = "0x420042")]
pub(crate) enum KeyFormatType {
    #[serde(rename = "0x00000001")]
    Raw,

    #[serde(rename = "0x00000002")]
    Opaque,

    #[serde(rename = "0x00000007")]
    TransparentSymmetricKey,
}

// Note: Transparent is needed on serialization otherwise the unit type enum variants will cause TTLV
// structs to be written when the intent is that only a value is written thus we must make the newtype
// wrapper "transparent" so that the serializer sees through it to the inner type and ignores the outer
// wrapper.
#[derive(Deserialize, Serialize, PartialEq, Debug)]
#[serde(rename = "0x420043")]
pub(crate) enum KeyMaterial {
    #[serde(rename(deserialize = "if 0x420042 in [0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000006]"))] // Raw, Opaque, PKCS1, PKCS8 or ECPrivateKey
    #[serde(rename(serialize = "Transparent"))]
    Bytes(i32),

    #[serde(rename(deserialize = "if 0x420042 == 0x00000007"))]
    #[serde(rename(serialize = "Transparent"))]
    TransparentSymmetricKey(String),
}

#[derive(Deserialize, Serialize, PartialEq, Debug)]
#[serde(rename = "0x123456")]
pub(crate) struct SomeKey {
    pub key_format_type: KeyFormatType, // the value encountered when deserializing this field
    pub key_material: KeyMaterial,      // determines the variant to deserialize into this field
}

pub(crate) mod some_transparent_key {
    pub fn ttlv_bytes() -> Vec<u8> {
        let test_data = concat!(
            "123456 01 00000020",
            "  420042 05 00000004 00000007 00000000", // enum variant 0x00000007 TransparentSymmetricKey
            "  420043 07 00000004 426C6168 00000000"  // string value "Blah"
        );

        hex::decode(test_data.replace(" ", "")).unwrap()
    }
}

pub(crate) mod some_raw_key {
    pub fn ttlv_bytes() -> Vec<u8> {
        let test_data = concat!(
            "123456 01 00000020",
            "  420042 05 00000004 00000001 00000000", // enum variant 0x00000001
            "  420043 02 00000004 000000FF 00000000"  // integer value 0xFF
        );

        hex::decode(test_data.replace(" ", "")).unwrap()
    }
}

pub(crate) mod some_opaque_key {
    pub fn ttlv_bytes() -> Vec<u8> {
        let test_data = concat!(
            "123456 01 00000020",
            "  420042 05 00000004 00000002 00000000", // enum variant 0x00000002
            "  420043 02 00000004 000000F0 00000000"  // integer value 0xF0
        );

        hex::decode(test_data.replace(" ", "")).unwrap()
    }
}

pub(crate) mod some_unknown_key_type {
    pub fn ttlv_bytes() -> Vec<u8> {
        let test_data = concat!(
            "123456 01 00000020",
            "  420042 05 00000004 00000099 00000000", // enum variant 0x00000099 is not defined
            "  420043 02 00000004 000000F0 00000000"  // integer value 0xF0
        );

        hex::decode(test_data.replace(" ", "")).unwrap()
    }
}
