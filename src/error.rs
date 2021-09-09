//! When serializing or deserializing TTLV data goes wrong.

use std::{convert::TryFrom, fmt::Debug, fmt::Display};

use crate::types::{self, ByteOffset, FieldType, TtlvTag, TtlvType};

pub type Result<T> = std::result::Result<T, Error>;

/// (De)serialization failure due to writing/reading byte values that do not conform to the TTLV specification.
#[derive(Debug)]
#[non_exhaustive]
pub enum MalformedTtlvError {
    /// The value in the TTLV type byte is not one of the known valid values.
    InvalidType(u8),

    /// The value in the TTLV length bytes are invalid for the type being read/written.
    InvalidLength {
        expected: u32,
        actual: u32,
        r#type: TtlvType,
    },

    /// The value in the TTLV value bytes is not valid for the type being read/written.
    InvalidValue {
        r#type: TtlvType,
    },

    /// A TTLV value being read/written is too large for the TTLV Structure that contains it.
    Overflow {
        field_end: ByteOffset,
    },

    /// The TTLV field being read/written is out of sequence (e.g. TLVV, VLTL, etc.).
    UnexpectedTtlvField {
        expected: FieldType,
        actual: FieldType,
    },

    /// The TTLV type being read/written is not correct at this location.
    ///
    /// For example, all TTLV sequences must start with a TTLV Structure.
    UnexpectedType {
        expected: TtlvType,
        actual: TtlvType,
    },

    /// The TTLV type byte value being read/written is valid but not supported.
    UnsupportedType(u8),

    /// The length of the TTLV Structure being read/written could not be determined.
    ///
    /// For example this can occur when TTLV serialization failed for some reason to return and rewrite the length
    /// bytes of a TTLV structure once its length was known and this was detected during serialization or later during
    /// deserialization.
    UnknownStructureLength,
}

impl MalformedTtlvError {
    pub fn overflow<T>(field_end: T) -> Self
    where
        ByteOffset: From<T>,
    {
        Self::Overflow {
            field_end: field_end.into(),
        }
    }
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

#[derive(Clone, Debug, Default)]
pub struct ErrorLocation {
    offset: Option<ByteOffset>,
    parent_tags: Vec<TtlvTag>,
    tag: Option<TtlvTag>,
    r#type: Option<TtlvType>,
}

impl From<ByteOffset> for ErrorLocation {
    fn from(offset: ByteOffset) -> Self {
        Self {
            offset: Some(offset),
            ..Default::default()
        }
    }
}

impl From<u8> for ErrorLocation {
    fn from(offset: u8) -> Self {
        Self::from(ByteOffset(offset.into()))
    }
}

impl From<u16> for ErrorLocation {
    fn from(offset: u16) -> Self {
        Self::from(ByteOffset(offset.into()))
    }
}

impl From<u32> for ErrorLocation {
    fn from(offset: u32) -> Self {
        Self::from(ByteOffset(offset.into()))
    }
}

impl From<u64> for ErrorLocation {
    fn from(offset: u64) -> Self {
        Self::from(ByteOffset(offset))
    }
}

impl From<usize> for ErrorLocation {
    fn from(value: usize) -> ErrorLocation {
        match ByteOffset::try_from(value) {
            Ok(offset) => ErrorLocation::from(offset),
            Err(_) => ErrorLocation::unknown(),
        }
    }
}

impl<T> From<std::io::Cursor<T>> for ErrorLocation {
    fn from(cursor: std::io::Cursor<T>) -> Self {
        Self {
            offset: Some(cursor.position().into()),
            ..Default::default()
        }
    }
}

impl<T> From<&std::io::Cursor<T>> for ErrorLocation {
    fn from(cursor: &std::io::Cursor<T>) -> Self {
        Self {
            offset: Some(cursor.position().into()),
            ..Default::default()
        }
    }
}

impl<T> From<&mut std::io::Cursor<T>> for ErrorLocation {
    fn from(cursor: &mut std::io::Cursor<T>) -> Self {
        Self {
            offset: Some(cursor.position().into()),
            ..Default::default()
        }
    }
}

impl Display for ErrorLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_unknown() {
            return f.write_str("Unknown");
        }

        let mut sep_str = "";

        #[rustfmt::skip]
        let mut sep = || { let s = sep_str; sep_str = ", "; s };

        if let Some(offset) = self.offset {
            f.write_fmt(format_args!("{}pos: {} bytes", sep(), *offset))?;
        }
        if !self.parent_tags.is_empty() {
            let mut iter = self.parent_tags.iter();
            f.write_fmt(format_args!("{}parent tags: {}", sep(), iter.next().unwrap()))?;
            for tag in iter {
                f.write_fmt(format_args!(" > {}", tag))?
            }
        }
        if let Some(tag) = self.tag {
            f.write_fmt(format_args!("{}tag: {}", sep(), tag))?;
        }
        if let Some(r#type) = self.r#type {
            f.write_fmt(format_args!("{}type: {}", sep(), r#type))?;
        }

        Ok(())
    }
}

impl ErrorLocation {
    pub(crate) fn at(offset: ByteOffset) -> Self {
        Self {
            offset: Some(offset),
            ..Default::default()
        }
    }

    // Use `at()` instead. Don't use this if you actually have a relevant byte offset and/or TTLV location for the error.
    pub(crate) fn unknown() -> Self {
        Self::default()
    }

    pub(crate) fn with_offset(mut self, offset: ByteOffset) -> Self {
        let _ = self.offset.get_or_insert(offset);
        self
    }

    pub(crate) fn with_parent_tags(mut self, parent_tags: &[TtlvTag]) -> Self {
        if self.parent_tags.is_empty() {
            self.parent_tags.extend(parent_tags);
        }
        self
    }

    pub(crate) fn with_tag(mut self, tag: TtlvTag) -> Self {
        let _ = self.tag.get_or_insert(tag);
        self
    }

    pub(crate) fn with_type(mut self, r#type: TtlvType) -> Self {
        let _ = self.r#type.get_or_insert(r#type);
        self
    }

    pub(crate) fn merge(mut self, loc: ErrorLocation) -> Self {
        if let Some(offset) = loc.offset {
            self = self.with_offset(offset);
        }
        self = self.with_parent_tags(&loc.parent_tags);
        if let Some(tag) = loc.tag {
            self = self.with_tag(tag);
        }
        if let Some(r#type) = loc.r#type {
            self = self.with_type(r#type);
        }
        self
    }

    pub fn is_unknown(&self) -> bool {
        matches!(
            (self.offset, self.parent_tags.is_empty(), self.tag, self.r#type),
            (None, true, None, None)
        )
    }

    pub fn offset(&self) -> Option<ByteOffset> {
        self.offset
    }

    pub fn parent_tags(&self) -> &[TtlvTag] {
        &self.parent_tags
    }

    pub fn tag(&self) -> Option<TtlvTag> {
        self.tag
    }

    pub fn r#type(&self) -> Option<TtlvType> {
        self.r#type
    }
}

// Errors raised by the inner guts of the (de)serialization process may occur in code that has no notion of the context
// of or position within those bytes and so no way to indicate the location of the bytes relevant to the error, either
// as a byte position or in terms of TTLV tag sequence.
#[derive(Debug)]
#[non_exhaustive]
pub enum ErrorKind {
    IoError(std::io::Error),
    ResponseSizeExceedsLimit(usize),
    MalformedTtlv(MalformedTtlvError),
    SerdeError(SerdeError),
}

impl From<std::io::Error> for ErrorKind {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<types::Error> for ErrorKind {
    fn from(err: types::Error) -> Self {
        match err {
            types::Error::IoError(e) => Self::IoError(e),
            types::Error::UnexpectedTtlvField { expected, actual } => {
                Self::MalformedTtlv(MalformedTtlvError::UnexpectedTtlvField { expected, actual })
            }
            types::Error::InvalidTtlvTag(v) => Self::SerdeError(SerdeError::InvalidTag(v)),
            types::Error::UnsupportedTtlvType(v) => Self::MalformedTtlv(MalformedTtlvError::UnsupportedType(v)),
            types::Error::InvalidTtlvType(v) => Self::MalformedTtlv(MalformedTtlvError::InvalidType(v)),
            types::Error::InvalidTtlvValueLength {
                expected,
                actual,
                r#type,
            } => Self::MalformedTtlv(MalformedTtlvError::InvalidLength {
                expected,
                actual,
                r#type,
            }),
            types::Error::InvalidTtlvValue(r#type) => Self::MalformedTtlv(MalformedTtlvError::InvalidValue { r#type }),
            types::Error::InvalidStateMachineOperation => Self::SerdeError(SerdeError::Other(
                "Internal error: invalid state machine operaiton".into(),
            )),
        }
    }
}

impl From<MalformedTtlvError> for ErrorKind {
    fn from(err: MalformedTtlvError) -> Self {
        Self::MalformedTtlv(err)
    }
}

impl From<SerdeError> for ErrorKind {
    fn from(err: SerdeError) -> Self {
        Self::SerdeError(err)
    }
}

// Actual errors are ones we expose to the client of the library and should indicate where in the (de)serialization
// process the problem occured so that if it's a problem with the data it can be investigated further.
#[derive(Debug)]
#[non_exhaustive]
pub struct Error {
    kind: ErrorKind,
    location: ErrorLocation,
}

impl Error {
    pub fn new(kind: ErrorKind, location: ErrorLocation) -> Self {
        Self { kind, location }
    }

    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    pub fn location(&self) -> &ErrorLocation {
        &self.location
    }

    pub fn into_inner(self) -> (ErrorKind, ErrorLocation) {
        (self.kind, self.location)
    }
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            ErrorKind::IoError(error) => f.write_fmt(format_args!(
                "IO error {:?}: {} (at {})",
                error.kind(),
                error,
                self.location
            )),
            ErrorKind::ResponseSizeExceedsLimit(size) => {
                f.write_fmt(format_args!("Response size {} exceeds the configured limit", size))
            }
            ErrorKind::MalformedTtlv(error) => {
                f.write_fmt(format_args!("Malformed TTLV: {:?} (at {})", error, self.location))
            }
            ErrorKind::SerdeError(error) => {
                f.write_fmt(format_args!("Serde error : {:?} (at {})", error, self.location))
            }
        }
    }
}

impl Error {
    pub(crate) fn pinpoint<T, L>(error: T, location: L) -> Self
    where
        ErrorKind: From<T>,
        ErrorLocation: From<L>,
    {
        Self {
            kind: error.into(),
            location: location.into(),
        }
    }

    pub(crate) fn pinpoint_with_tag<T, L>(error: T, location: L, tag: TtlvTag) -> Self
    where
        ErrorKind: From<T>,
        ErrorLocation: From<L>,
    {
        Self {
            kind: error.into(),
            location: ErrorLocation::from(location).with_tag(tag),
        }
    }

    pub(crate) fn pinpoint_with_tag_and_type<T, L>(error: T, location: L, tag: TtlvTag, r#type: TtlvType) -> Self
    where
        ErrorKind: From<T>,
        ErrorLocation: From<L>,
    {
        Self {
            kind: error.into(),
            location: ErrorLocation::from(location).with_tag(tag).with_type(r#type),
        }
    }
}
