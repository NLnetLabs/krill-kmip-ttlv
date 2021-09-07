//! When serializing or deserializing TTLV data goes wrong.

use std::{fmt::Debug, fmt::Display};

use crate::types::{TtlvTag, TtlvType};

pub type Result<T> = std::result::Result<T, Error>;

pub type ByteOffset = u64;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FieldType {
    Tag,
    Type,
    Length,
    Value,
    TypeAndLengthAndValue,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum MalformedTtlvError {
    InvalidType(u8),
    InvalidLength {
        expected: u32,
        actual: u32,
        r#type: TtlvType,
    },
    InvalidValue, // we deliberately don't include the invalid bytes as they could be sensitive
    UnexpectedTtlvField {
        expected: FieldType,
        actual: FieldType,
    },
    UnexpectedType {
        expected: TtlvType,
        actual: TtlvType,
    },
    UnsupportedType(u8),
    Overflow {
        field_end: ByteOffset,
    },
    UnknownStructureLength,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum SerdeError {
    InvalidVariant(&'static str),
    InvalidVariantMacherSyntax(String),
    InvalidTag(String), // a tag should be numeric i.e. 0xNNNNNN but we get it from the Rust type name via Serde so it can be any string
    UnexpectedTag { expected: TtlvTag, actual: TtlvTag },
    UnexpectedType { expected: TtlvType, actual: TtlvType },
    UnsupportedRustType(&'static str),
    MissingField, // todo: add more metadata here?
    MissingIdentifier,
    Other(String),
}

#[derive(Debug, Default)]
pub struct ErrorLocation {
    pub offset: Option<ByteOffset>,
    pub parent_tags: Vec<TtlvTag>,
    pub tag: Option<TtlvTag>,
    pub r#type: Option<TtlvType>,
}

impl From<ByteOffset> for ErrorLocation {
    fn from(offset: ByteOffset) -> Self {
        ErrorLocation {
            offset: Some(offset),
            ..Default::default()
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    IoError(std::io::Error),
    ResponseSizeExceedsLimit(usize),
    MalformedTtlv {
        error: MalformedTtlvError,
        location: ErrorLocation,
    },
    SerdeError {
        error: SerdeError,
        location: ErrorLocation,
    },
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IoError(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IoError(err) => f.write_fmt(format_args!("IO error ({:?}: {})", err.kind(), err)),
            Error::ResponseSizeExceedsLimit(size) => {
                f.write_fmt(format_args!("Response size {} exceeds the configured limit", size))
            }
            Error::MalformedTtlv { error, location } => f.write_fmt(format_args!(
                "Malformed TTLV at offset {:?}: {:?}",
                location.offset, error
            )),
            Error::SerdeError { error, location } => {
                f.write_fmt(format_args!("Serde error at offset {:?}: {:?}", location.offset, error))
            }
        }
    }
}

impl Error {
    pub(crate) fn set_tag_location(&mut self, parent_tags: Vec<TtlvTag>) {
        match self {
            Error::MalformedTtlv { location, .. } => {
                if location.parent_tags.is_empty() {
                    location.parent_tags = parent_tags
                }
            }
            Error::SerdeError { location, .. } => {
                if location.parent_tags.is_empty() {
                    location.parent_tags = parent_tags
                }
            }
            _ => {}
        }
    }
}
