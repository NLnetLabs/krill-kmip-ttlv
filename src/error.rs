//! When serializing or deserializing TTLV data goes wrong.

use std::{fmt::Debug, fmt::Display, num::ParseIntError};

use crate::types::{ItemTag, ItemType};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    // TODO: use named struct fields
    DeserializeError { ctx: String, pos: usize, msg: String },
    IoError(std::io::Error),
    InsufficientBytes,
    InvalidTag(String),
    InvalidType(String),
    InvalidLength(String),
    InvalidUtf8(String),
    UnableToDetermineTtlvStructureLength,
    ParseError(ItemTag),
    UnexpectedTtlvTag(ItemTag, String),
    UnexpectedTtlvType(ItemType, u8),
    UnexpectedType(String),
    UnsupportedType(&'static str),
    Other(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<ParseIntError> for Error {
    fn from(e: ParseIntError) -> Self {
        Error::Other(format!("Parse error: {}", e))
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::DeserializeError { ctx, pos, msg } => f.write_fmt(format_args!(
                "Deserialization error: {} at position {} with context {:?}",
                ctx, pos, msg
            )),
            Error::IoError(err) => f.write_fmt(format_args!("IO error: {:?}", err)),
            Error::InsufficientBytes => f.write_str("Insufficient bytes"),
            Error::InvalidTag(err) => f.write_fmt(format_args!("Invalid Item Tag: {}", err)),
            Error::InvalidType(err) => f.write_fmt(format_args!("Invalid Item Type: {}", err)),
            Error::InvalidLength(err) => f.write_fmt(format_args!("Invalid Item Length: {}", err)),
            Error::InvalidUtf8(err) => f.write_fmt(format_args!("Invalid UTF-8: {}", err)),
            Error::UnableToDetermineTtlvStructureLength => {
                f.write_str("The length of one or more TTLV structures could not be determined.")
            }
            Error::ParseError(item_tag) => f.write_fmt(format_args!("Failed to parse TTLV tag '{:#0X?}'", item_tag)),
            Error::UnexpectedTtlvTag(item_tag, found) => f.write_fmt(format_args!(
                "Unexpected TTLV tag: expected={}, found={}",
                item_tag, found
            )),
            Error::UnexpectedTtlvType(item_type, found) => {
                f.write_fmt(format_args!("Unexpected TTLV type '{:?}' failed: {}", item_type, found))
            }
            Error::UnexpectedType(item_type) => f.write_fmt(format_args!("Unexpected item type '{:?}'", item_type)),
            Error::UnsupportedType(rust_type) => f.write_fmt(format_args!(
                "Serialization to TTLV from Rust type {} is not supported",
                rust_type
            )),
            Error::Other(err) => f.write_fmt(format_args!("Other error: {}", err)),
        }
    }
}
