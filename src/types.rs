use std::{
    convert::TryFrom,
    fmt::{Debug, Display},
    io::{Read, Write},
    ops::Deref,
    str::FromStr,
};

// --- FieldType ------------------------------------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FieldType {
    Tag,
    Type,
    Length,
    Value,
    LengthAndValue,        // used when deserializing
    TypeAndLengthAndValue, // used when serializing
}

impl Default for FieldType {
    fn default() -> Self {
        Self::Tag
    }
}

impl Display for FieldType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FieldType::Tag => f.write_str("Tag"),
            FieldType::Type => f.write_str("Type"),
            FieldType::Length => f.write_str("Length"),
            FieldType::Value => f.write_str("Value"),
            FieldType::LengthAndValue => f.write_str("LengthAndValue"),
            FieldType::TypeAndLengthAndValue => f.write_str("TypeAndLengthAndValue"),
        }
    }
}

// --- ByteOffset -----------------------------------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ByteOffset(pub u64);

impl std::ops::Deref for ByteOffset {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&u64> for ByteOffset {
    fn from(v: &u64) -> Self {
        ByteOffset(*v)
    }
}

impl From<u64> for ByteOffset {
    fn from(v: u64) -> Self {
        ByteOffset(v)
    }
}

impl TryFrom<usize> for ByteOffset {
    type Error = ();

    fn try_from(value: usize) -> std::result::Result<Self, Self::Error> {
        if value < (u64::MAX as usize) {
            Ok(ByteOffset(value as u64))
        } else {
            Err(())
        }
    }
}

impl<T> From<&std::io::Cursor<T>> for ByteOffset {
    fn from(cursor: &std::io::Cursor<T>) -> Self {
        ByteOffset(cursor.position())
    }
}

impl<T> From<std::io::Cursor<T>> for ByteOffset {
    fn from(cursor: std::io::Cursor<T>) -> Self {
        ByteOffset(cursor.position())
    }
}

#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    IoError(std::io::Error),
    InvalidTtlvTag(String),
    UnexpectedTtlvField {
        expected: FieldType,
        actual: FieldType,
    },
    UnsupportedTtlvType(u8),
    InvalidTtlvType(u8),
    InvalidTtlvValueLength {
        expected: u32,
        actual: u32,
        r#type: TtlvType,
    },
    InvalidTtlvValue(TtlvType),
    InvalidStateMachineOperation,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IoError(e)
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

// --- TtlvTag --------------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TtlvTag(u32);

impl TtlvTag {
    pub fn read<T: Read>(src: &mut T) -> Result<Self> {
        let mut raw_item_tag = [0u8; 3];
        src.read_exact(&mut raw_item_tag)?;
        Ok(TtlvTag::from(raw_item_tag))
    }

    pub fn write<T: Write>(&self, dst: &mut T) -> Result<()> {
        dst.write_all(&<[u8; 3]>::from(self)).map_err(Error::IoError)
    }
}

impl Debug for TtlvTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("0x{:0X}", &self.0))
    }
}

impl Deref for TtlvTag {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for TtlvTag {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let v =
            u32::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|_| Error::InvalidTtlvTag(s.to_string()))?;
        Ok(TtlvTag(v))
    }
}

impl std::fmt::Display for TtlvTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:06X}", self)
    }
}

impl std::fmt::UpperHex for TtlvTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:X}", self.0)
    }
}

impl From<TtlvTag> for [u8; 3] {
    fn from(tag: TtlvTag) -> Self {
        <[u8; 3]>::from(&tag)
    }
}

impl From<&TtlvTag> for [u8; 3] {
    fn from(tag: &TtlvTag) -> Self {
        let b: [u8; 4] = tag.to_be_bytes();
        [b[1], b[2], b[3]]
    }
}

impl From<[u8; 3]> for TtlvTag {
    fn from(b: [u8; 3]) -> Self {
        TtlvTag(u32::from_be_bytes([0x00u8, b[0], b[1], b[2]]))
    }
}

/// --- TtlvType ------------------------------------------------------------------------------------------------------

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TtlvType {
    Structure = 0x01,
    Integer = 0x02,
    LongInteger = 0x03,
    BigInteger = 0x04,
    Enumeration = 0x05,
    Boolean = 0x06,
    TextString = 0x07,
    ByteString = 0x08,
    DateTime = 0x09,
    // Interval = 0x0A,
}

impl TtlvType {
    pub fn read<T: Read>(src: &mut T) -> Result<Self> {
        let mut raw_item_type = [0u8; 1];
        src.read_exact(&mut raw_item_type)?;
        TtlvType::try_from(raw_item_type[0])
    }

    pub fn write<T: Write>(&self, dst: &mut T) -> Result<()> {
        dst.write_all(&[*self as u8]).map_err(Error::IoError)
    }
}

impl std::fmt::Display for TtlvType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TtlvType::Structure => f.write_str("Structure (0x01)"),
            TtlvType::Integer => f.write_str("Integer (0x02)"),
            TtlvType::LongInteger => f.write_str("LongInteger (0x03)"),
            TtlvType::BigInteger => f.write_str("BigInteger (0x04)"),
            TtlvType::Enumeration => f.write_str("Enumeration (0x05)"),
            TtlvType::Boolean => f.write_str("Boolean (0x06)"),
            TtlvType::TextString => f.write_str("TextString (0x07)"),
            TtlvType::ByteString => f.write_str("ByteString (0x08)"),
            TtlvType::DateTime => f.write_str("DateTime (0x09)"),
        }
    }
}

impl TryFrom<u8> for TtlvType {
    type Error = Error;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(TtlvType::Structure),
            0x02 => Ok(TtlvType::Integer),
            0x03 => Ok(TtlvType::LongInteger),
            0x04 => Ok(TtlvType::BigInteger),
            0x05 => Ok(TtlvType::Enumeration),
            0x06 => Ok(TtlvType::Boolean),
            0x07 => Ok(TtlvType::TextString),
            0x08 => Ok(TtlvType::ByteString),
            0x09 => Ok(TtlvType::DateTime),
            // 0x0A => Ok(TtlvType::Interval),
            0x0A => Err(Error::UnsupportedTtlvType(0x0A)),
            _ => Err(Error::InvalidTtlvType(value)),
        }
    }
}

impl From<TtlvType> for [u8; 1] {
    fn from(item_type: TtlvType) -> Self {
        [item_type as u8]
    }
}

// --- SerializableTtlvType -------------------------------------------------------------------------------------------

// KMIP v1.0 spec: 9.1.1.3 Item Length
// ===================================
// An Item Length is a 32-bit binary integer, transmitted big-endian, containing the number of bytes in the
// Item Value. The allowed values are:
//
//   Data Type    | Length
//   -------------|----------------------
//   Structure    | Varies, multiple of 8
//   Integer      | 4
//   Long Integer | 8
//   Big Integer  | Varies, multiple of 8
//   Enumeration  | 4
//   Boolean      | 8
//   Text String  | Varies
//   Byte String  | Varies
//   Date-Time    | 8
//   Interval     | 4
//
//   Table 192: Allowed Item Length Values
//
// If the Item Type is Structure, then the Item Length is the total length of all of the sub-items contained in
// the structure, including any padding. If the Item Type is Integer, Enumeration, Text String, Byte String, or
// Interval, then the Item Length is the number of bytes excluding the padding bytes. Text Strings and Byte
// Strings SHALL be padded with the minimal number of bytes following the Item Value to obtain a multiple
// of eight bytes. Integers, Enumerations, and Intervals SHALL be padded with four bytes following the Item
// Value.
//
pub trait SerializableTtlvType: Sized + Deref {
    const TTLV_TYPE: TtlvType;

    fn ttlv_type(&self) -> TtlvType {
        Self::TTLV_TYPE
    }

    fn calc_pad_bytes(value_len: u32) -> u32 {
        // pad to the next higher multiple of eight
        let remainder = value_len % 8;

        if remainder == 0 {
            // already on the alignment boundary, no need to add pad bytes to reach the boundary
            0
        } else {
            // for a shorter value, say 6 bytes, this calculates 8-(6%8) = 8-6 = 2, i.e. after having read 6 bytes the
            // next pad boundary is 2 bytes away.
            // for a longer value, say 10 bytes, this calcualtes 8-(10%8) = 8-2 = 6, i.e. after having read 10 bytes the
            // next pad boundary is 6 bytes away.
            8 - remainder
        }
    }

    fn read_pad_bytes<T: Read>(src: &mut T, value_len: u32) -> Result<()> {
        let num_pad_bytes = Self::calc_pad_bytes(value_len) as usize;
        if num_pad_bytes > 0 {
            let mut dst = [0u8; 8];
            src.read_exact(&mut dst[..num_pad_bytes])?;
        }
        Ok(())
    }

    fn write_pad_bytes<T: Write>(dst: &mut T, value_len: u32) -> Result<()> {
        let num_pad_bytes = Self::calc_pad_bytes(value_len) as usize;
        if num_pad_bytes > 0 {
            const PADDING_BYTES: [u8; 8] = [0; 8];
            dst.write_all(&PADDING_BYTES[..num_pad_bytes])?;
        }
        Ok(())
    }

    fn read<T: Read>(src: &mut T) -> Result<Self> {
        // The TTLV T_ype has already been read by the caller in order to determine which Primitive struct to use so
        // we only have to read the L_ength and and the V_alue.
        let mut value_len = [0u8; 4];
        src.read_exact(&mut value_len)?; // read L_ength
        let value_len = u32::from_be_bytes(value_len);
        let v = Self::read_value(src, value_len)?; // read V_alue
        Self::read_pad_bytes(src, value_len)?; // read 8-byte alignment padding bytes
        Ok(v)
    }

    // Writes the TLV part of TTLV, i.e. the type, length and value. It doesn't write the preceeding tag as that is
    // not part of the primitive value but is part of the callers context and only they can know which tag value to
    // write.
    fn write<T: Write>(&self, dst: &mut T) -> Result<()> {
        dst.write_all(&[Self::TTLV_TYPE as u8])?; // write T_ype
        let value_len = self.write_length_and_value(dst)?; // write L_ength and V_alue
        Self::write_pad_bytes(dst, value_len) // Write 8-byte alignment padding bytes
    }

    fn read_value<T: Read>(src: &mut T, value_len: u32) -> Result<Self>;

    fn write_length_and_value<T: Write>(&self, dst: &mut T) -> Result<u32>;
}

// E.g. simple_primitive!(MyType, ItemType::Integer, i32, 4) would define a new Rust struct called MyType which wraps an
// i32 value and implements the SerializableTtlvType trait to define how to read/write from/to a sequence of 4
// big-endian encoded bytes prefixed by a TTLV item type byte of value ItemType::Integer.
macro_rules! define_fixed_value_length_serializable_ttlv_type {
    ($NEW_TYPE_NAME:ident, $TTLV_ITEM_TYPE:expr, $RUST_TYPE:ty, $TTLV_VALUE_LEN:literal) => {
        #[derive(Clone, Debug)]
        pub struct $NEW_TYPE_NAME(pub $RUST_TYPE);
        impl $NEW_TYPE_NAME {
            const TTLV_FIXED_VALUE_LENGTH: u32 = $TTLV_VALUE_LEN;
        }
        impl Deref for $NEW_TYPE_NAME {
            type Target = $RUST_TYPE;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
        impl SerializableTtlvType for $NEW_TYPE_NAME {
            const TTLV_TYPE: TtlvType = $TTLV_ITEM_TYPE;

            fn read_value<T: Read>(src: &mut T, value_len: u32) -> Result<Self> {
                if value_len != Self::TTLV_FIXED_VALUE_LENGTH {
                    Err(Error::InvalidTtlvValueLength {
                        expected: Self::TTLV_FIXED_VALUE_LENGTH,
                        actual: value_len,
                        r#type: Self::TTLV_TYPE,
                    })
                } else {
                    let mut dst = [0u8; Self::TTLV_FIXED_VALUE_LENGTH as usize];
                    src.read_exact(&mut dst)?;
                    let v: $RUST_TYPE = <$RUST_TYPE>::from_be_bytes(dst);
                    Ok($NEW_TYPE_NAME(v))
                }
            }

            fn write_length_and_value<T: Write>(&self, dst: &mut T) -> Result<u32> {
                dst.write_all(&Self::TTLV_FIXED_VALUE_LENGTH.to_be_bytes())?; // Write L_ength
                dst.write_all(&self.0.to_be_bytes())?; // Write V_alue
                Ok(Self::TTLV_FIXED_VALUE_LENGTH)
            }
        }
    };
}

// --- TtlvInteger ----------------------------------------------------------------------------------------------------

// KMIP v1.0 spec: 9.1.1.4 Item Value: Integer
// ===========================================
// "Integers are encoded as four-byte long (32 bit) binary signed numbers in 2's complement notation,
//  transmitted big-endian."
define_fixed_value_length_serializable_ttlv_type!(TtlvInteger, TtlvType::Integer, i32, 4);

// --- TtlvLongInteger ------------------------------------------------------------------------------------------------

// KMIP v1.0 spec: 9.1.1.4 Item Value: Long Integer
// ================================================
// "Long Integers are encoded as eight-byte long (64 bit) binary signed numbers in 2's complement
//  notation, transmitted big-endian."
define_fixed_value_length_serializable_ttlv_type!(TtlvLongInteger, TtlvType::LongInteger, i64, 8);

// --- TtlvBigInteger -------------------------------------------------------------------------------------------------

// KMIP v1.0 spec: 9.1.1.4 Item Value: Big Integer
// ===============================================
// "Big Integers are encoded as a sequence of eight-bit bytes, in two's complement notation,
//  transmitted big-endian. If the length of the sequence is not a multiple of eight bytes, then Big
//  Integers SHALL be padded with the minimal number of leading sign-extended bytes to make the
//  length a multiple of eight bytes. These padding bytes are part of the Item Value and SHALL be
//  counted in the Item Length."
#[derive(Clone, Debug)]
pub struct TtlvBigInteger(pub Vec<u8>);
impl Deref for TtlvBigInteger {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl SerializableTtlvType for TtlvBigInteger {
    const TTLV_TYPE: TtlvType = TtlvType::BigInteger;

    fn read_value<T: Read>(src: &mut T, value_len: u32) -> Result<Self> {
        let mut dst = vec![0; value_len as usize];
        src.read_exact(&mut dst)?;
        Ok(TtlvBigInteger(dst))
    }

    fn write_length_and_value<T: Write>(&self, dst: &mut T) -> Result<u32> {
        let v = self.0.as_slice();
        let v_len = v.len() as u32;
        let num_pad_bytes = Self::calc_pad_bytes(v_len);
        let v_len = v_len + num_pad_bytes;
        dst.write_all(&v_len.to_be_bytes())?; // Write L_ength
                                              // Write pad bytes out as leading sign extending bytes, i.e. if the sign is positive then pad with zeros
                                              // otherwise pad with ones.
        let pad_byte = if v_len > 0 && v[0] & 0b1000_0000 == 0b1000_0000 {
            0b1111_1111
        } else {
            0b0000_0000
        };
        for _ in 1..=num_pad_bytes {
            dst.write_all(&[pad_byte])?;
        }
        dst.write_all(v)?; // Write V_alue
        Ok(v_len)
    }
}

// --- TtlvEnumeration ------------------------------------------------------------------------------------------------

// KMIP v1.0 spec: 9.1.1.4 Item Value: Enumeration
// ===============================================
// "Enumerations are encoded as four-byte long (32 bit) binary unsigned numbers transmitted big-
//  endian. Extensions, which are permitted, but are not defined in this specification, contain the
//  value 8 hex in the first nibble of the first byte."
define_fixed_value_length_serializable_ttlv_type!(TtlvEnumeration, TtlvType::Enumeration, u32, 4);

// --- TtlvBoolean ----------------------------------------------------------------------------------------------------

// KMIP v1.0 spec: 9.1.1.4 Item Value: Boolean
// ===========================================
// "Booleans are encoded as an eight-byte value that SHALL either contain the hex value
//  0000000000000000, indicating the Boolean value False, or the hex value 0000000000000001,
//  transmitted big-endian, indicating the Boolean value True."
// Boolean cannot be implemented using the define_fixed_value_length_serializable_ttlv_type! macro because it has
// special value verification rules.
#[derive(Clone, Debug)]
pub struct TtlvBoolean(pub bool);
impl TtlvBoolean {
    const TTLV_FIXED_VALUE_LENGTH: u32 = 8;
}
impl Deref for TtlvBoolean {
    type Target = bool;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl SerializableTtlvType for TtlvBoolean {
    const TTLV_TYPE: TtlvType = TtlvType::Boolean;

    fn read_value<T: Read>(src: &mut T, value_len: u32) -> Result<Self> {
        if value_len != Self::TTLV_FIXED_VALUE_LENGTH {
            Err(Error::InvalidTtlvValueLength {
                expected: Self::TTLV_FIXED_VALUE_LENGTH,
                actual: value_len,
                r#type: Self::TTLV_TYPE,
            })
        } else {
            let mut dst = [0u8; Self::TTLV_FIXED_VALUE_LENGTH as usize];
            src.read_exact(&mut dst)?;
            match u64::from_be_bytes(dst) {
                0 => Ok(TtlvBoolean(false)),
                1 => Ok(TtlvBoolean(true)),
                _ => Err(Error::InvalidTtlvValue(Self::TTLV_TYPE)),
            }
        }
    }

    fn write_length_and_value<T: Write>(&self, dst: &mut T) -> Result<u32> {
        let v = match self.0 {
            true => 1u64,
            false => 0u64,
        };
        dst.write_all(&Self::TTLV_FIXED_VALUE_LENGTH.to_be_bytes())?; // Write L_ength
        dst.write_all(&v.to_be_bytes())?; // Write V_alue
        Ok(Self::TTLV_FIXED_VALUE_LENGTH)
    }
}

// --- TtlvTextString -------------------------------------------------------------------------------------------------

// KMIP v1.0 spec: 9.1.1.4 Item Value: Text String
// ===============================================
// "Text Strings are sequences of bytes that encode character values according to the UTF-8
//  encoding standard. There SHALL NOT be null-termination at the end of such strings."
// TextString cannot be implemented using the define_fixed_value_length_serializable_ttlv_type! macro because it has a
// dynamic length.
#[derive(Clone, Debug)]
pub struct TtlvTextString(pub String);
impl Deref for TtlvTextString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl SerializableTtlvType for TtlvTextString {
    const TTLV_TYPE: TtlvType = TtlvType::TextString;

    fn read_value<T: Read>(src: &mut T, value_len: u32) -> Result<Self> {
        // Read the UTF-8 bytes, without knowing if they are valid UTF-8
        let mut dst = vec![0; value_len as usize];
        src.read_exact(&mut dst)?;

        // Use the bytes as-is as the internal buffer for a String, verifying that the bytes are indeed valid
        // UTF-8
        let new_str = String::from_utf8(dst).map_err(|_| Error::InvalidTtlvValue(Self::TTLV_TYPE))?;

        Ok(TtlvTextString(new_str))
    }

    fn write_length_and_value<T: Write>(&self, dst: &mut T) -> Result<u32> {
        let v = self.0.as_bytes();
        let v_len = v.len() as u32;
        dst.write_all(&v_len.to_be_bytes())?; // Write L_ength
        dst.write_all(v)?; // Write V_alue
        Ok(v_len)
    }
}

// --- TtlvByteString -------------------------------------------------------------------------------------------------

// KMIP v1.0 spec: 9.1.1.4 Item Value: Byte String
// ===============================================
// "Byte Strings are sequences of bytes containing individual unspecified eight-bit binary values, and are interpreted
//  in the same sequence order."
// ByteString cannot be implemented using the define_fixed_value_length_serializable_ttlv_type! macro because it has a
// dynamic length.
#[derive(Clone, Debug)]
pub struct TtlvByteString(pub Vec<u8>);
impl Deref for TtlvByteString {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl SerializableTtlvType for TtlvByteString {
    const TTLV_TYPE: TtlvType = TtlvType::ByteString;

    fn read_value<T: Read>(src: &mut T, value_len: u32) -> Result<Self> {
        // Read the UTF-8 bytes, without knowing if they are valid UTF-8
        let mut dst = vec![0; value_len as usize];
        src.read_exact(&mut dst)?;
        Ok(TtlvByteString(dst))
    }

    fn write_length_and_value<T: Write>(&self, dst: &mut T) -> Result<u32> {
        let v = self.0.as_slice();
        let v_len = v.len() as u32;
        dst.write_all(&v_len.to_be_bytes())?; // Write L_ength
        dst.write_all(v)?; // Write V_alue
        Ok(v_len)
    }
}

// --- TtlvDateTime ---------------------------------------------------------------------------------------------------

// KMIP v1.0 spec: 9.1.1.4 Item Value: Date Time
// =============================================
// "Date-Time values are POSIX Time values encoded as Long Integers. POSIX Time, as described
//  in IEEE Standard 1003.1 [IEEE1003-1], is the number of seconds since the Epoch (1970 Jan 1,
//  00:00:00 UTC), not counting leap seconds."
define_fixed_value_length_serializable_ttlv_type!(TtlvDateTime, TtlvType::DateTime, i64, 8);

// --- TtlvInterval ---------------------------------------------------------------------------------------------------

// KMIP v1.0 spec: 9.1.1.4 Item Value: Interval
// ============================================
// "Intervals are encoded as four-byte long (32 bit) binary unsigned numbers, transmitted big-endian.
//  They have a resolution of one second."
#[allow(dead_code)]
pub type TtlvInterval = TtlvEnumeration;

// --- TtlvStateMachine ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TtlvStateMachineMode {
    Deserializing,
    Serializing,
}

pub struct TtlvStateMachine {
    mode: TtlvStateMachineMode,
    expected_next_field_type: FieldType,
    ignore_next_tag: bool,
}

impl TtlvStateMachine {
    pub fn new(mode: TtlvStateMachineMode) -> Self {
        Self {
            mode,
            expected_next_field_type: FieldType::default(),
            ignore_next_tag: false,
        }
    }

    pub fn advance(&mut self, next_field_type: FieldType) -> std::result::Result<bool, Error> {
        use TtlvStateMachineMode as Mode;

        let next_expected_next_field_type = match (self.mode, self.expected_next_field_type, next_field_type) {
            // First, the normal cases: expect a certain field type to be written next and that is what is indicated
            (_, FieldType::Tag, FieldType::Tag) => FieldType::Type,
            (_, FieldType::Type, FieldType::Type) => FieldType::Length,
            (Mode::Serializing, FieldType::Type, FieldType::TypeAndLengthAndValue) => FieldType::Tag,
            (_, FieldType::Length, FieldType::Length) => FieldType::Value,
            (Mode::Deserializing, FieldType::Length, FieldType::LengthAndValue) => FieldType::Tag,
            (_, FieldType::Value, FieldType::Value) => FieldType::Tag,

            // In the leaf case a V always follows TTL, but higher in the TTLV structure hierarchy the first item in
            // a structure can be another TTLV item (i.e. we see a tag being written instead of a value)
            (_, FieldType::Value, FieldType::Tag) => FieldType::Type,

            // Special case: we've been explicitly asked after writing a tag to ignore a subsequent attempt to write
            // another tag. Normally attempting to write TT would be an error, but in this case the second T should be
            // silently ignored. This supports use cases like the KMIP Attribute Value which is of the form XTLV where
            // X is constant tag value and not the normal tag associated with the item being serialized.
            (Mode::Serializing, FieldType::Type, FieldType::Tag) if self.ignore_next_tag => {
                self.ignore_next_tag = false;
                FieldType::Type
            }

            // Error, don't permit invalid things like TTVL etc.
            (_, expected, actual) => {
                return Err(Error::UnexpectedTtlvField { expected, actual });
            }
        };

        // Advance the state machine if needed
        if self.mode == Mode::Deserializing || next_expected_next_field_type != self.expected_next_field_type {
            self.expected_next_field_type = next_expected_next_field_type;
            Ok(true)
        } else {
            // It was permitted to stay in the current state. Signalling this allows calling code to know that it should
            // NOT write out the next field, which normally would be an error and we would abort but in this case it is
            // going to be okay as long as the caller respects this return value.
            Ok(false)
        }
    }

    pub fn ignore_next_tag(&mut self) -> std::result::Result<(), Error> {
        if matches!(self.mode, TtlvStateMachineMode::Serializing) {
            self.ignore_next_tag = true;
            Ok(())
        } else {
            Err(Error::InvalidStateMachineOperation)
        }
    }

    pub fn reset(&mut self) {
        self.expected_next_field_type = FieldType::default();
        self.ignore_next_tag = false;
    }
}

// --- Tests ----------------------------------------------------------------------------------------------------------

#[cfg(test)]
mod test {
    use chrono::TimeZone;
    #[allow(unused_imports)]
    use pretty_assertions::{assert_eq, assert_ne};

    use std::{io::Cursor, str::FromStr};

    use crate::types::{SerializableTtlvType, TtlvTag, TtlvType};

    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn test_item_tag() {
        // KMIP v1.0 spec: 9.1.1.1 Item Tag
        // "An Item Tag is a three-byte binary unsigned integer, transmitted big endian, which contains a number that
        //  designates the specific Protocol Field or Object that the TTLV object represents. To ease debugging, and
        //  to ensure that malformed messages are detected more easily, all tags SHALL contain either the value 42
        //  in hex or the value 54 in hex as the high order (first) byte. Tags defined by this specification contain hex
        //  42 in the first byte. Extensions, which are permitted, but are not defined in this specification, contain the
        //  value 54 hex in the first byte. A list of defined Item Tags is in Section 9.1.3.1"

        // Note: we do NOT enforce the 42 or 54 rules as those are specific to KMIP usage of TTLV, not to TTLV itself.

        assert!(TtlvTag::from_str("").is_err());
        assert!(TtlvTag::from_str("    ").is_err());
        assert!(TtlvTag::from_str("XYZ").is_err());

        #[allow(non_snake_case)]
        let ZERO_TAG = TtlvTag::from([0x00u8, 0x00u8, 0x00u8]);

        #[allow(non_snake_case)]
        let ONE_TAG = TtlvTag::from([0x00u8, 0x00u8, 0x01u8]);

        assert_eq!(ZERO_TAG, TtlvTag::from_str("0").unwrap());
        assert_eq!(ZERO_TAG, TtlvTag::from_str("000").unwrap());
        assert_eq!(ZERO_TAG, TtlvTag::from_str("0x0").unwrap());
        assert_eq!(ONE_TAG, TtlvTag::from_str("1").unwrap());
        assert_eq!(ONE_TAG, TtlvTag::from_str("001").unwrap());
        assert_eq!(ONE_TAG, TtlvTag::from_str("0x1").unwrap());

        assert_eq!(
            TtlvTag::from([0x42u8, 0x00u8, 0xAAu8]),
            TtlvTag::from_str("0x4200AA").unwrap()
        );
        assert_eq!(ZERO_TAG, ZERO_TAG);
        assert_ne!(ONE_TAG, ZERO_TAG);
    }

    #[test]
    fn test_item_type() {
        // Quoting: http://docs.oasis-open.org/kmip/spec/v1.0/cs01/kmip-spec-1.0-cs-01.pdf Section 9.1.1.2 Item Type
        //
        //     An Item Type is a byte containing a coded value that indicates the data type of the data object. The
        //     allowed values are:
        //
        //         Data Type    | Coded Value in Hex
        //         -------------|-------------------
        //         Structure    | 01
        //         Integer      | 02
        //         Long Integer | 03
        //         Big Integer  | 04
        //         Enumeration  | 05
        //         Boolean      | 06
        //         Text String  | 07
        //         Byte String  | 08
        //         Date-Time    | 09
        //         Interval     | 0A
        //
        //         Table 191: Allowed Item Type Values

        assert_matches!(TtlvType::try_from(0x00), Err(Error::InvalidTtlvType(0x00)));
        assert_matches!(TtlvType::try_from(0x01), Ok(TtlvType::Structure));
        assert_matches!(TtlvType::try_from(0x02), Ok(TtlvType::Integer));
        assert_matches!(TtlvType::try_from(0x03), Ok(TtlvType::LongInteger));
        assert_matches!(TtlvType::try_from(0x04), Ok(TtlvType::BigInteger));
        assert_matches!(TtlvType::try_from(0x05), Ok(TtlvType::Enumeration));
        assert_matches!(TtlvType::try_from(0x06), Ok(TtlvType::Boolean));
        assert_matches!(TtlvType::try_from(0x07), Ok(TtlvType::TextString));
        assert_matches!(TtlvType::try_from(0x08), Ok(TtlvType::ByteString));
        assert_matches!(TtlvType::try_from(0x09), Ok(TtlvType::DateTime));

        // Interval is not yet implemented
        assert_matches!(TtlvType::try_from(0x0A), Err(Error::UnsupportedTtlvType(0x0A)));

        // All other values are invalid
        for i in 0x0B..0xFF {
            assert_matches!(TtlvType::try_from(i), Err(Error::InvalidTtlvType(n)) if n == i);
        }
    }

    fn spec_ttlv_to_vec_tlv(s: &str) -> Vec<u8> {
        // strip out the example fake item tag, spacing and separators
        hex::decode(s.replace("42 00 20 | ", "").replace(" ", "").replace("|", "")).unwrap()
    }

    #[test]
    fn test_spec_ttlv_integer() {
        // Quoting: http://docs.oasis-open.org/kmip/spec/v1.0/cs01/kmip-spec-1.0-cs-01.pdf 9.1.2 Examples
        //   These examples are assumed to be encoding a Protocol Object whose tag is 420020. The examples are
        //   shown as a sequence of bytes in hexadecimal notation:
        //
        //   - An Integer containing the decimal value 8:
        //     42 00 20 | 02 | 00 00 00 04 | 00 00 00 08 00 00 00 00
        let spec_tlv_bytes = spec_ttlv_to_vec_tlv("42 00 20 | 02 | 00 00 00 04 | 00 00 00 08 00 00 00 00");

        // Test serialization
        let mut serialized_tlv_bytes = Vec::new();
        assert!(TtlvInteger(8).write(&mut serialized_tlv_bytes).is_ok());
        assert_eq!(spec_tlv_bytes, serialized_tlv_bytes);

        // Test deserialization
        let mut readable_spec_lv_bytes = Cursor::new(&spec_tlv_bytes[1..]);
        let v = TtlvInteger::read(&mut readable_spec_lv_bytes);
        assert!(v.is_ok());
        assert_eq!(8, *(v.unwrap()));
    }

    #[test]
    fn test_spec_ttlv_long_integer() {
        //   - A Long Integer containing the decimal value 123456789000000000:
        //     42 00 20 | 03 | 00 00 00 08 | 01 B6 9B 4B A5 74 92 00
        let spec_tlv_bytes = spec_ttlv_to_vec_tlv("42 00 20 | 03 | 00 00 00 08 | 01 B6 9B 4B A5 74 92 00");

        // Test serialization
        let mut serialized_tlv_bytes = Vec::new();
        assert!(TtlvLongInteger(123456789000000000)
            .write(&mut serialized_tlv_bytes)
            .is_ok());
        assert_eq!(spec_tlv_bytes, serialized_tlv_bytes);

        // Test deserialization
        let mut readable_spec_lv_bytes = Cursor::new(&spec_tlv_bytes[1..]);
        let v = TtlvLongInteger::read(&mut readable_spec_lv_bytes);
        assert!(v.is_ok());
        assert_eq!(123456789000000000, *(v.unwrap()));
    }

    #[test]
    fn test_spec_ttlv_big_integer() {
        //   - A Big Integer containing the decimal value 1234567890000000000000000000:
        //     42 00 20 | 04 | 00 00 00 10 | 00 00 00 00 03 FD 35 EB 6B C2 DF 46 18 08
        //     00 00
        let spec_tlv_bytes =
            spec_ttlv_to_vec_tlv("42 00 20 | 04 | 00 00 00 10 | 00 00 00 00 03 FD 35 EB 6B C2 DF 46 18 08 00 00");
        let big_int = num_bigint::BigInt::parse_bytes(b"1234567890000000000000000000", 10).unwrap();

        // Test serialization
        let mut serialized_tlv_bytes = Vec::new();
        assert!(TtlvBigInteger(big_int.to_signed_bytes_be())
            .write(&mut serialized_tlv_bytes)
            .is_ok());
        assert_eq!(spec_tlv_bytes, serialized_tlv_bytes);

        // Test deserialization
        let mut readable_spec_lv_bytes = Cursor::new(&spec_tlv_bytes[1..]);
        let v = TtlvBigInteger::read(&mut readable_spec_lv_bytes);
        assert!(v.is_ok());
        assert_eq!(big_int, num_bigint::BigInt::from_signed_bytes_be(&(*(v.unwrap()))));
    }

    #[test]
    fn test_spec_ttlv_enumeration() {
        //   - An Enumeration with value 255:
        //     42 00 20 | 05 | 00 00 00 04 | 00 00 00 FF 00 00 00 00
        let mut actual = Vec::new();
        let expected = spec_ttlv_to_vec_tlv("42 00 20 | 05 | 00 00 00 04 | 00 00 00 FF 00 00 00 00");
        TtlvEnumeration(255).write(&mut actual).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_spec_ttlv_boolean() {
        //   - A Boolean with the value True:
        //     42 00 20 | 06 | 00 00 00 08 | 00 00 00 00 00 00 00 01
        let mut actual = Vec::new();
        let expected = spec_ttlv_to_vec_tlv("42 00 20 | 06 | 00 00 00 08 | 00 00 00 00 00 00 00 01");
        TtlvBoolean(true).write(&mut actual).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_spec_ttlv_text_string() {
        //   - A Text String with the value "Hello World":
        //     42 00 20 | 07 | 00 00 00 0B | 48 65 6C 6C 6F 20 57 6F 72 6C 64 00 00 00
        //     00 00
        let mut actual = Vec::new();
        let expected =
            spec_ttlv_to_vec_tlv("42 00 20 | 07 | 00 00 00 0B | 48 65 6C 6C 6F 20 57 6F 72 6C 64 00 00 00 00 00");
        TtlvTextString("Hello World".to_string()).write(&mut actual).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_spec_ttlv_byte_string() {
        //   - A Byte String with the value { 0x01, 0x02, 0x03 }:
        //     42 00 20 | 08 | 00 00 00 03 | 01 02 03 00 00 00 00 00
        let mut actual = Vec::new();
        let expected = spec_ttlv_to_vec_tlv("42 00 20 | 08 | 00 00 00 03 | 01 02 03 00 00 00 00 00");
        TtlvByteString(vec![0x01u8, 0x02u8, 0x03u8]).write(&mut actual).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_spec_ttlv_date_time() {
        //   - A Date-Time, containing the value for Friday, March 14, 2008, 11:56:40 GMT:
        //     42 00 20 | 09 | 00 00 00 08 | 00 00 00 00 47 DA 67 F8
        let mut actual = Vec::new();
        let expected = spec_ttlv_to_vec_tlv("42 00 20 | 09 | 00 00 00 08 | 00 00 00 00 47 DA 67 F8");
        let dt = chrono::Utc
            .datetime_from_str("Friday, March 14, 2008, 11:56:40 GMT", "%A, %B %d, %Y, %H:%M:%S GMT")
            .unwrap();
        let dt_i64 = dt.timestamp();
        let expected_i64 = i64::from_be_bytes(*b"\x00\x00\x00\x00\x47\xDA\x67\xF8");
        assert_eq!(expected_i64, dt_i64);
        TtlvDateTime(dt_i64).write(&mut actual).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    #[should_panic]
    fn test_spec_ttlv_interval() {
        //   - An Interval, containing the value for 10 days:
        //     42 00 20 | 0A | 00 00 00 04 | 00 0D 2F 00 00 00 00 00
        // NOT IMPLEMENTED YET
        todo!()
    }

    #[test]
    #[should_panic]
    fn test_spec_ttlv_structure() {
        //   - A Structure containing an Enumeration, value 254, followed by an Integer, value 255, having tags
        //   - 420004 and 420005 respectively:
        //     42 00 20 | 01 | 00 00 00 20 | 42 00 04 | 05 | 00 00 00 04 | 00 00 00 FE
        //     00 00 00 00 | 42 00 05 | 02 | 00 00 00 04 | 00 00 00 FF 00 00 00 00
        panic!("NOT IN SCOPE FOR THIS MODULE");
    }
}
