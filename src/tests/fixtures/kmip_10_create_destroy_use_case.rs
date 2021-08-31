use serde_derive::Deserialize;

// Define the types needed to describe the response represented by the use case test data below. Note that these
// are richly structured to make it easy to interact with the response objects and fields, unlike the similar
// types defined for serialization tests which attempt to minimize boilerplate and verbosity to make it quick
// and easy to compose a rich request hierarchy that is easy to read at a glance.
//
// Notice also how unlike the Serialize counterpart structures for serialization where the #[serde(rename)] is
// on the struct definitions, the Deserialize structure needs the #[serde(rename)] on the fields that use those
// types instead.
#[derive(Debug, Deserialize)]
#[serde(rename = "0x42007B")]
pub(crate) struct ResponseMessage {
    pub header: ResponseHeader,
    pub items: Vec<BatchItem>,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "0x42007A")]
pub(crate) struct ResponseHeader {
    pub ver: ProtocolVersion,
    #[serde(rename = "0x420092")] pub timestamp: i64,
    #[serde(rename = "0x42000D")] pub item_count: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "0x420069")]
pub(crate) struct ProtocolVersion {
    #[serde(rename = "0x42006A")] pub major: i32,
    #[serde(rename = "0x42006B")] pub minor: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "0x42000F")]
pub(crate) struct BatchItem {
    pub operation: Operation,
    pub status: ResultStatus,
    pub payload: ResponsePayload,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename = "0x42005C")]
pub(crate) enum Operation {
    #[serde(rename = "0x00000001")]
    Create,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename = "0x42007F")]
pub(crate) enum ResultStatus {
    #[serde(rename = "0x00000000")]
    Success,
}

#[derive(Debug, Deserialize)]
pub(crate) enum ResponsePayload {
    #[serde(rename = "if 0x42005C==0x00000001")]
    Create(CreateResponsePayload),
    Other(SomeOtherResponsePayload),
}

#[derive(Debug, Deserialize)]
#[serde(rename = "0x42007C")]
pub(crate) struct CreateResponsePayload {
    #[serde(rename = "0x420057")] pub object_type: ObjectType,
    #[serde(rename = "0x420094")] pub unique_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SomeOtherResponsePayload {
    dummy_field: i32,
}

#[derive(Debug, Deserialize, PartialEq)]
pub(crate) enum ObjectType {
    #[serde(rename = "0x00000002")]
    SymmetricKey,
}

pub(crate) fn ttlv_bytes() -> Vec<u8> {
    // Attempt to parse correctly the binary response TTLV for KMIP specification v1.0 use case 3.1.1 Create /
    // Destroy as the use case definition includes the binary output and the corresponding deserialized structure.
    // See: http://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.pdf
    let use_case_input = concat!(
        "42007B01000000C042007A0100000048420069010000002042006A0200000004000000010000000042006B0200000",
        "00400000000000000004200920900000008000000004AFBE7C242000D0200000004000000010000000042000F0100",
        "00006842005C0500000004000000010000000042007F0500000004000000000000000042007C01000000404200570",
        "5000000040000000200000000420094070000002466633838333364652D373064322D346563652D623036332D6665",
        "6465336133633539666500000000"
    );
    hex::decode(use_case_input).unwrap()
}