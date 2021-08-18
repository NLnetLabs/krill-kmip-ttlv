//! A crate to de/serialize Rust data types from/to bytes in the KMIP TTLV format.
//!
//! # Usage
//!
//! Assuming that you have already defined your Rust types with the required attributes (more on this below):
//!
//! ```ignore
//! use krill_kmip_ttlv::{Config, from_reader, to_vec};
//!
//! // Create a defensive deserializer configuration
//! let config = Config::new().with_max_bytes(1024);
//!
//! // Serialize a struct to a byte vec
//! let bytes = to_vec(&my_struct)?;
//!
//! // Deserialize the byte vec back to a struct
//! let my_other_struct: MyStruct = from_reader(&mut reader, &config)?;
//! ```
//!
//! Note that this crate does **NOT** send or receive data, it only (de)serializes it.
//!
//! # Tagged vs named data types
//!
//! Unlike formats like JSON which use named fields, TTLV uses tagged fields where tags are numeric values which KMIP
//! expresses in hexadecimal notation, e.g. see the [TTLV Encoding / Defined Values] section of the [KMIP 1.0 specification].
//!
//! This crate implements (de)serialization in terms of [Serde] with the intention that you describe your types for
//! Serde using [Serde's derive attributes]. In addition to deriving the `Serialize` and/or `Deserialize` traits you
//! must also map each Rust type to/from a TTLV "tag" value by telling Serde Derive to rename your type to its hex tag
//! value.
//!
//! [KMIP 1.0 specification]: https://docs.oasis-open.org/kmip/spec/v1.0/kmip-spec-1.0.html
//! [TTLV Encoding / Defined Values]: https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581263
//! [Serde]: https://serde.rs/
//! [Serde's derive attributes]: https://serde.rs/attributes.html
//!
//! ```
//! use serde_derive::Serialize;
//!
//! #[derive(Serialize)]
//! #[serde(rename = "0x123456")]
//! struct MyTtlv { }
//!
//! println!("{:0X?}", krill_kmip_ttlv::to_vec(&MyTtlv {}));
//!
//! // prints:
//! // Ok([12, 34, 56, 1, 0, 0, 0, 0])
//! ```
//!
//! You can see the TTLV byte format here: a 3 byte "tag", a 1 byte "type" (type code 1 means a TTLV Structure) and
//! a 4 byte "length". There is no "value" part in this case because the struct doesn't have any fields so the value
//! length is zero.
//!
//! # Choosing tag values
//!
//! When implementing one of the KMIP specifications the tag value to use for each KMIP object is defined by the spec.
//! The KMIP specifications reserve tag value range 0x420000 - 0x42FFFF for official KMIP tags and reserve tag value
//! range 0x540000 - 0x54FFFF for custom extensions. If using TTLV as a serialization format for your own data you are
//! free to choose your own tag values anywhere in the range 0x000000 - 0xFFFFFF.
//!
//! # Unsupported data types
//!
//! The following Rust types **CANNOT** be _serialized_ to TTLV as TTLV has no concept of unsigned
//! integers, floating point, character or 'missing' values : `u8`, `u16`, `f32`, `f64`, `char`, `()`, `None` _(but see
//! below for a special note about `None`)_.
//!
//! The following Rust types **CANNOT** be _deserialized_ into from TTLV: `()`, `u8`, `u16`, `u32`, `u64`,
//! `i8`, `i16`, `f32`, `f64`, `char`, `str`, map, `&[u8]`, `()`.
//! `char`,
//!
//! The following TTLV types **CANNOT** _yet_ be (de)serialized: Big Integer (0x04), Interval (0x0A). If you need
//! support for these the crate can be extended to support them, PRs are welcome!
//!
//! The following Rust types **CANNOT** be deserialized into as this crate is opinionated and prefers to
//! deserialize only into named fields, not nameless groups of values: unit struct, tuple struct, tuple. If you need
//! support for more Rust types the crate can be extended to support them, PRs are welcome!
//!
//! The rationale for this is that when serializing the meaningful type name is obvious to the programmer because only
//! tagged types can be serialized and tags can only be "hung off" Rust structs and enums which always have names. When
//! deserializing the field being accessed in the data type that was deserialized into only has a name if we require it
//! to have one. You could deserialize a named (via tag value) set of TTLV Structure fields into a Rust tuple where in
//! each individual value has no name, the TTLV tag value got lost in translation. This is just plain unhelpful and thus
//! not supported.
//!
//! # Getting involved
//!
//! The capabilities of this crate and the TTLV and Rust data types supported are those that were needed to provide a
//! foundation for the `krill-kmip-protocol` crate. This crate does not yet support every possible TTLV or Rust type. If
//! you wish to extend the crate yourself PRs are welcome!
//!
//! # Data types treated specially
//!
//! - The Rust 'struct' type by default serializes to a TTLV Structure but by using the `Transparent:` name prefix it is
//! possible to serialize the member fields of the struct without creating a TTLV Structure wrapper in the byte stream.
//!
//! - The Rust `Some` type is handled as if it were only the value inside the Option, the `Some` wrapper is ignored.
//!
//! - The Rust `None` type should be handled by placing the `#[serde(skip_serializing_if = "Option::is_none")]` attribute
//! on the `Option` to be serialized. When deserializing if an `Option` value is not present in the bytes being
//! deserialized this will result in the `Option` field having value `None`.
//!
//! - The Rust 'Vec' type can be used to (de)serialize to one or more TTLV items. To serialize a `Vec` of bytes to a TTLV
//! Byte String however you should annotate the field with the Serde derive attribute `#[serde(with = "serde_bytes")]`.
//!
//! - The Rust `enum` type is serialized differently depending on the type of the variant being serialized. For unit
//! variants a `#[serde(rename = "0xNNNNNNNN")]` attribute should be used to cause this crate to serialize the value as
//! a TTLV Enumeration. A tuple or struct variant will be serialized to a TTLV Structure.
//!
//! - In order to _deserialize_ into a Rust `enum` you must guide this crate to the correct variant to deserialize into.
//! To support the KMIP specifications this crate supports choosing the variant based on the value of a TTLV Enumeration
//! that was encountered earlier in the deserialization process. To handle this case each `enum` variant to be selected
//! between must be specially renamed with Serde derive using one of several supported special syntaxes:
//!   - `#[serde(rename = "if 0xNNNNNN==0xMMMMMMMM")]` syntax will cause this crate to look for a previously encountered
//!     TTLV Enumeration with tag value 0xNNNNNN and to select this `enum` variant if that Enumeration had value
//!     0xMMMMMMMM.
//!   - `#[serde(rename = "if 0xNNNNNN in [0xAAAAAAAA, 0xBBBBBBBB, ..]")]` is like the previous syntax but can match
//!     against more than one possible value.
//!   - `#[serde(rename = "if 0xNNNNNN >= 0xMMMMMMMM")]` can be used to select the variant if a previously seen value
//!     for the specified tag was at least the given value.
//!   - `#[serde(rename = "if 0xNNNNNN==Textual Content")]` syntax will cause this crate to look for a previously
//!     encountered TTLV Text String with tag value 0xNNNNNN and to select this `enum` variant if that Text String had
//!     value `Textual Content`.
//!   - `#[serde(rename = "if type==XXX")]` syntax (where `XXX` is a camel case TTLV type name without spaces such as
//!     `LongInteger`) will cause this crate to select the enum variant if the TTLV type encountered while deserializing
//!     has the specified type.
//!
//! # Supported data types
//!
//! The following data type mappings are supported by this crate:
//!
//! | TTLV data type      | Serializes from     | Deserializes to     |
//! |---------------------|---------------------|---------------------|
//! | Structure (0x01)    | `SomeStruct { .. }`, `SomeStruct( .. )`, tuple variant | `SomeStruct { .. }` |
//! | Integer (0x02)      | `i8`, `i16`, `i32`  | `i32`               |
//! | Long Integer (0x03) | `i64`               | `i64`               |
//! | Big Integer (0x04)  | **UNSUPPORTED**     | **UNSUPPORTED**     |
//! | Enumeration (0x05)  | `u32`               | See above           |
//! | Boolean (0x06)      | `bool`              | `bool`              |
//! | Text String (0x07)  | `str``              | `String`            |
//! | Byte String (0x08)  | `&[u8]`             | `Vec<u8>`           |
//! | Date Time (0x09)    | `u64`               | `i64`               |
//! | Interval (0x0A)     | **UNSUPPORTED**     | **UNSUPPORTED**     |
//!
//! # Examples
//!
//! For detailed examples of how to annotate your data types with Serde derive attributes look at the tests in the
//! source repository for this crate at the end of the `de.rs` and `ser.rs` source code files.
//!
//! For much richer examples see the code and tests in the source repository for the `kmip-ttlv-protocol` crate.
//!
//! # Diagnostics
//!
//! If your crate provides a [log] implementation then this crate will log at debug and trace level, if those levels
//! are enabled. At debug level every byte array is dumped in hex form pre-deserialization and post-serialization, along
//! with a human readable tree of the TTLV tree it represents. The latter is a best effort in the case of invalid or
//! incomplete TTLV. Trace level logs far too much about the internal logic of this crate and will likely be reduced as
//! the crate matures in favour of better error return values.
//!
//! # Error handling
//!
//! Deserialization will be aborted by Serde if your type specification is too inflexible to handle the bytes being
//! deserialized so some you may need, as with any Serde based deserializer, to explicitly account for known unknowns,
//! i.e. in the case of KMIP vendors are permitted to extend the response TTLV arbitrarily at certain points which can
//! be "ignored" by guiding Serde to deserialize the unknown bytes as just that: bytes.
//!
//! This crate does not try to be clone free or to support no_std scenarios, memory is allocated to serialize and
//! deserialize into. In particular when deserializing bytes received from an untrusted source this could cause
//! allocation of a large amount of memory at which point Rust will panic if the allocation fails. Rust is continually
//! becoming more robust in such cases so it may be possible to improve this in future. For now, when deserializing you
//! are strongly advised to use a `Config` object that specifies a maximum byte length to deserialize.
//!
//! If serialization or deserialization fails this crate tries to return sufficient contextual information to aid
//! diagnosing where the problem in the TTLV byte stream is and why. Error reporting is a work in-progres and should get
//! better as the crate matures.
//!
//! [log]: http://crates.io/crates/log

pub mod de;
pub mod error;
pub mod ser;
mod types;

pub use de::{from_reader, from_slice, Config};
pub use ser::{to_vec, to_writer};
