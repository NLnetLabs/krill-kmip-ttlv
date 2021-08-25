[![CI](https://github.com/NLnetLabs/kmip-ttlv/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/NLnetLabs/kmip-ttlv/actions/workflows/ci.yml)

# kmip-ttlv - A library for (de)serializing KMIP TTLV

[KMIP](http://docs.oasis-open.org/kmip/spec/v1.0/kmip-spec-1.0.html):
> The OASIS Key Management Interoperability Protocol specifications which define message formats for the manipulation of cryptographic material on a key management server.

[TTLV](http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581260):
> A building block of the KMIP specifications which defines how to encode and decode structured data to/from a binary form as a sequence of Tag-Type-Length-Value (aka TTLV) items.

### Welcome

This crate offers a **partial implementation** of KMIP v1.0 **TTLV** (de)serialization functionality for use primarily by the [Krill](https://nlnetlabs.nl/projects/rpki/krill/) project. The interface offered is based on the popular Rust [Serde](https://serde.rs/) (de)serialization framework for decorating arbitrary high level Rust "business object" structs with attributes that guide the (de)serialization process.

### Scope

The primary responsibilities of this crate are handling the need to write the length _before_ knowing how long the _value_ will be, translating Rust types to/from TTLV types, guiding creation of correct request structures and offering useful diagnostic messages if response structures cannot be parsed.

This crate is one of potentially several crates that will be implemented to add the ability to Krill to interact with KMIP compliant servers. The current thinking is that the work consists of separate chunks for TTLV (de)serialization, KMIP business object definitions, client request/response API and the TCP+TLS client.

Note: The scope is limited to TTLV-over-TLS. Support for HTTPS instead of TLS and/or XML and/or JSON instead of TTLV binary encoding are not planned at this time as all KMIP server implementations are required to support TTLV-over-TLS.

### Status

This is a work-in-progress. The interface offered by this library is expected to change and **no guarantee** of interface stability is made at this time. The intention is publish this crate in the near future to https://crates.io/ to be depended on by Krill like any other Rust crate dependency. See the https://github.com/NLnetLabs/kmip/ repository for an implementation of a KMIP TTLV client that uses this crate as the core building block and also includes a sample TTLV over TLS client.

Not all TTLV types are supported:

| TTLV Type | TTLV Type Code | Supported? |
|---|---|---|
| Structure | 0x01 | ✔️ |
| Integer | 0x02 | ✔️ |
| Long Integer | 0x03 | ✔️ |
| Big Integer | 0x04 | ✔️ |
| Enumeration | 0x05 | ✔️ |
| Boolean | 0x06 | ✔️ |
| Text String | 0x07 | ✔️ |
| Byte String | 0x08 | ✔️ |
| Date Time | 0x09 | ✔️ |
| Interval | 0x0A | |

### Design goals

- Offer a strongly typed interface that prevents incorrect composition of low-level building blocks in ways that have no correct meaning in the a higher level KMIP interface specification. Leverage the Rust compile time capabilities to prevent writing of incorrect requests where possible, so that incorrect usage of the protocol at runtime is minimized.
- It should be possible to compose a high level KMIP request structure succinctly and in such a way that the written code is clearly relatable to the KMIP specifications.
- It should be possible for the results of deserialization to be interacted with without needing to know the KMIP specifications in detail, i.e. it should be in terms of Rust types, not TTLV types and the objects interacted with should have clearly named fields and only have response fields relevant to the request that was submitted.
- TTLV tag codes should be defined near to the type definition that they tag. 

### Example code

Based on the [KMIP v1.0 specification use case defined in section 3.1.1 Create / Destroy](http://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822053).

The examples below assume the client code has already defined Rust `structs` that `#[derive(Serialize)]` or `#[derive(Deserialize)]` as appropriate to tell the Serde based (de)serializer which tag codes should be used for each data structure.

_(subject to change)_

**Request building:**

```rust
let req = RequestMessage(
    RequestHeader(
        ProtocolVersion(
            ProtocolVersionMajor(1),
            ProtocolVersionMinor(0)),
        BatchCount(1),
    ),
    vec![BatchItem(
        Operation::Create,
        RequestPayload::Create(
            ObjectType::SymmetricKey,
            TemplateAttribute(vec![
                Attribute::CryptographicAlgorithm(CryptographicAlgorithm::AES),
                Attribute::CryptographicLength(128),
                Attribute::CryptographicUsageMask(0x0000_000C), // This can be made more user friendly
            ]),
        ),
    )],
);
```

In the example above one cannot for example accidentally add a second Operation::Delete to the request or provide completely wrong arguments as it will fail to compile.

**Response processing:**

```rust
let r: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

assert_eq!(r.header.ver.major, 1);
assert_eq!(r.header.ver.minor, 0);
assert_eq!(r.header.timestamp, 0x000000004AFBE7C2); // This can be made more user friendly
assert_eq!(r.header.item_count, 1);

assert_eq!(r.items.len(), 1);

let item = &r.items[0];
assert_eq!(item.operation, Operation::Create);
assert_eq!(item.status, ResultStatus::Success);
assert_eq!(item.payload.object_type, ObjectType::SymmetricKey);
assert_eq!(&item.payload.unique_id, "fc8833de-70d2-4ece-b063-fede3a3c59fe");
```

Likewise rather than process and/or index into an arbitrary sequence of TTLV response key/value pairs, this strongly typed approach makes it clear which fields are available and makes them immediately usable as Rust types.

### Re-use of existing metadata

The current approach makes heavy use of `#[serde(rename = "0xNNNNNN")]` to inform the (de)serializer of the TTLV tag that should be read from or written to the data stream for the current type, and infers the TTLV type to serialize to based on the Rust type being serialized. In certain special cases the Serde name is further (ab)used by including additional hints in the name for use by the deserializer.