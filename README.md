[![CI](https://github.com/NLnetLabs/kmip-ttlv/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/NLnetLabs/kmip-ttlv/actions/workflows/ci.yml)
[![Crate](https://img.shields.io/crates/v/kmip-ttlv)](crates.io/crates/kmip-ttlv)
[![Docs](https://img.shields.io/docsrs/kmip-ttlv)](https://docs.rs/kmip-ttlv/)

# kmip-ttlv - A library for (de)serializing KMIP TTLV

[KMIP](http://docs.oasis-open.org/kmip/spec/v1.0/kmip-spec-1.0.html):
> The OASIS Key Management Interoperability Protocol specifications which define message formats for the manipulation
> of cryptographic material on a key management server.

[TTLV](http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581260):
> A building block of the KMIP specifications which defines how to encode and decode structured data to/from a binary
> form as a sequence of Tag-Type-Length-Value (aka TTLV) items.

### Welcome

This crate offers a **partial implementation** of KMIP v1.0 **TTLV** (de)serialization functionality for use by the [`kmip-protocol`](https://crates.io/crates/kmip-protocol) crate. If you are looking to add KMIP support to your
product you should use the [`kmip-protocol`](https://crates.io/crates/kmip-protocol) crate instead. TTLV is defined
within, but is independent of, KMIP, so in theory it could also be used to (de)serialize data for applications
other than KMIP.

### Purpose

This crate provides low-level (de)serialization of Rust primitives (e.g. i32) from/to the equivalent KMIP TTLV byte
representation. It offers both a [Serde Derive](https://serde.rs/derive.html) based single `to_/from_` call style
[API](https://docs.rs/kmip-ttlv/) for (de)serialization of entire Rust type hierarchies (which is most easily driven
using Serde Derive attributes) and a lower-level API for (de)serializing one TTLV field (tag, type, length or value) at
a time for complete control.

The scope is limited at present to the binary TTLV protocol. Support for XML or JSON representation as defined in later
KMIP specifications is not in scope.

### Documentation

Full API documentation can be seen at https://docs.rs/kmip-ttlv/.

### Status

This crate is offered on as-is basis with no stability, quality or correctness guarantees. Use it at your own risk.

See https://github.com/NLnetLabs/kmip-ttlv/blob/main/src/tests/ for various automated tests of the low-level and high level (Serde based) APIs. Limited manual testing has been performed successfully against PyKMIP and Kryptus Cloud HSM servers.

Issue reports, feature requests, and contributions can be submitted to our
[GitHub repository](https://github.com/NLnetLabs/kmip-ttlv/).

The capabilities of this crate and the TTLV and Rust data types supported are those that were needed to provide a
foundation for the [`kmip-protocol`](https://crates.io/crates/kmip-protocol) crate. As such this crate does not yet
support every possible TTLV or Rust type.

Not all TTLV types are supported:

| TTLV Type | TTLV Type Code | Supported? |
|---|---|---|
| Structure | 0x01 | ✅ |
| Integer | 0x02 | ✅ |
| Long Integer | 0x03 | ✅ |
| Big Integer | 0x04 | ✅ _(serialization is only supported with the low-level API, not with Serde)_
| Enumeration | 0x05 | ✅ |
| Boolean | 0x06 | ✅ |
| Text String | 0x07 | ✅ |
| Byte String | 0x08 | ✅ |
| Date Time | 0x09 | ✅ |
| Interval | 0x0A | ❌ |

### Design goals

- Offer a strongly typed interface that prevents incorrect composition of low-level building blocks in ways that have
  no correct meaning in the a higher level KMIP interface specification. Leverage the Rust compile time capabilities to
  prevent writing of incorrect requests where possible, so that incorrect usage of the protocol at runtime is
  minimized.
- Support composition of high level KMIP request structures succinctly and in such a way that the written code is
  clearly relatable to the KMIP specifications.
- Using deserialized data shouldnot require knowledge of the KMIP specifications in detail, i.e. it should be in terms
  of Rust types, not TTLV types and the objects interacted with should have clearly named fields and only have response
  fields relevant to the request that was submitted.
- TTLV tag codes should be defined near to the type definition that they tag. 

### Example code

_Based on the [KMIP v1.0 specification use case defined in section 3.1.1 Create / Destroy](http://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html#_Toc262822053)._

The examples below assume the client code has already defined Rust `structs` that `#[derive(Serialize)]` or `#[derive(Deserialize)]` as appropriate to tell the Serde based (de)serializer which tag codes should be used for each data structure.

_(subject to change)_

**Request building:**

```rust
// serialize the request
let req = RequestMessage(
    RequestHeader(
        request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
        Option::<MaximumResponseSize>::None,
        Option::<Authentication>::None,
        BatchCount(1),
    ),
    vec![BatchItem(
        Operation::Create,
        Option::<UniqueBatchItemID>::None,
        RequestPayload::Create(
            ObjectType::SymmetricKey,
            TemplateAttribute::named(
                "Template1".into(),
                vec![
                    Attribute::CryptographicAlgorithm(CryptographicAlgorithm::AES),
                    Attribute::CryptographicLength(128),
                    Attribute::CryptographicUsageMask(
                        CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
                    ),
                ],
            ),
        ),
    )],
);

let ttlv_wire: Vec<u8> = to_vec(&req).unwrap();
// now write the `ttlv_wire` request bytes to an open TLS connection to the server
```

**Response processing:**

```rust
// read the `ttlv_wire` response bytes from an open TLS connection to the server:
let ttlv_wire: Vec<u8> = ...;

// deserialize the response
let res: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

assert_eq!(res.header.protocol_version.major, 1);
assert_eq!(res.header.protocol_version.minor, 0);
assert_eq!(res.header.timestamp, 0x4AFBE7C5);
assert_eq!(res.header.batch_count, 1);
assert_eq!(res.batch_items.len(), 1);

let item = &res.batch_items[0];
assert!(matches!(item.result_status, ResultStatus::Success));
assert!(matches!(item.operation, Some(Operation::Create)));
assert!(matches!(&item.payload, Some(ResponsePayload::Create(_))));

if let Some(ResponsePayload::Create(payload)) = item.payload.as_ref() {
    assert!(matches!(payload.object_type, ObjectType::SymmetricKey));
    assert_eq!(&payload.unique_identifier, KEY_ID);
} 
```

**Working with timestamps:**

Timestamps are stored in TTLV `Date-Time` format which is converted to a 64-bit integer which has no real world meaning until you interpret it correctly and in the context of the correct timezone. Working with the 64-bit integer values directly is probably not practical. This crate does NOT currently provide a way to work more easily with these values but doing so is fairly easy with crates already available in the Rust ecosystem.

For example, for the example above which is based on an official KMIP use case, the use case description states that the `0x4AFBE7C5` value is equivalent to `Thu Nov 12 11:47:32 CET 2009`. Below we use the [chrono](https://crates.io/crates/chrono/) crate to demonstrate that this is true and to show how you can work with `Date-Time` values in your application.

```rust
let one_hour_in_seconds = 3600;
let cet_tz = chrono::offset::FixedOffset::east(one_hour_in_seconds);
let cet_ts = cet_tz.timestamp(res.header.timestamp);
assert_eq!(cet_ts, cet_tz.ymd(2009,11,12).and_hms(11,47,32)
assert_eq!(cet_ts.format("%a %b %e %T %Z %Y").to_string(), "Thu Nov 12 11:47:32 +01:00 2009");
```