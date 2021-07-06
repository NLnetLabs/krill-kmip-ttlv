use std::{
    convert::TryFrom,
    io::{Read, Write},
    ops::Deref,
    str::FromStr,
};

use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ItemTag(u32);

impl Deref for ItemTag {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for ItemTag {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let v = u32::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|err| Error::InvalidTag(format!("Invalid Item Tag '{}': {}", s, err.to_string())))?;
        Ok(ItemTag(v))
    }
}

impl std::fmt::Display for ItemTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode_upper(<[u8; 3]>::from(self)))
    }
}

impl From<ItemTag> for [u8; 3] {
    fn from(tag: ItemTag) -> Self {
        <[u8; 3]>::from(&tag)
    }
}

impl From<&ItemTag> for [u8; 3] {
    fn from(tag: &ItemTag) -> Self {
        let b: [u8; 4] = tag.to_be_bytes();
        [b[1], b[2], b[3]]
    }
}

impl TryFrom<&[u8]> for ItemTag {
    type Error = Error;

    fn try_from(b: &[u8]) -> std::result::Result<Self, Self::Error> {
        fn strip_leading_zeros(b: &[u8]) -> &[u8] {
            b.iter().position(|&x| x != 0).map_or(b, |p| &b[p..])
        }

        let b = strip_leading_zeros(b);

        if b.len() != 3 {
            Err(Error::InvalidTag(format!(
                "'An Item Tag is a three-byte binary unsigned integer' but '{:?}' is {} bytes in length",
                b,
                b.len()
            )))
        } else {
            Ok(ItemTag(u32::from_be_bytes([0u8, b[0], b[1], b[2]])))
        }
    }
}

impl From<[u8; 3]> for ItemTag {
    fn from(b: [u8; 3]) -> Self {
        ItemTag(u32::from_be_bytes([0x00u8, b[0], b[1], b[2]]))
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ItemType {
    Structure = 0x01,
    Integer = 0x02,
    LongInteger = 0x03,
    // BigInteger = 0x04,
    Enumeration = 0x05,
    Boolean = 0x06,
    TextString = 0x07,
    // ByteString = 0x08,
    DateTime = 0x09,
    // Interval = 0x0A,
}

impl TryFrom<u8> for ItemType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(ItemType::Structure),
            0x02 => Ok(ItemType::Integer),
            0x03 => Ok(ItemType::LongInteger),
            // 0x04 => Ok(ItemType::BigInteger),
            0x05 => Ok(ItemType::Enumeration),
            0x06 => Ok(ItemType::Boolean),
            0x07 => Ok(ItemType::TextString),
            // 0x08 => Ok(ItemType::ByteString),
            0x09 => Ok(ItemType::DateTime),
            // 0x0A => Ok(ItemType::Interval),
            _ => Err(Error::Other(format!("No known ItemType has u8 value {}", value))),
        }
    }
}

impl FromStr for ItemType {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let v = u8::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|err| Error::InvalidType(format!("Cannot parse hexadecimal item type value '{}': {}", s, err)))?;
        ItemType::try_from(v)
    }
}

impl From<ItemType> for [u8; 1] {
    fn from(item_type: ItemType) -> Self {
        [item_type as u8]
    }
}

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
    const TTLV_TYPE: ItemType;

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
macro_rules! define_serializable_ttlv_type {
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
            const TTLV_TYPE: ItemType = $TTLV_ITEM_TYPE;

            fn read_value<T: Read>(src: &mut T, value_len: u32) -> Result<Self> {
                if value_len != Self::TTLV_FIXED_VALUE_LENGTH {
                    Err(Error::InvalidLength(format!(
                        "Item length is {} but for type {} it should be {}",
                        value_len,
                        stringify!($NEW_TYPE_NAME),
                        Self::TTLV_FIXED_VALUE_LENGTH
                    )))
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

// KMIP v1.0 spec: 9.1.1.4 Item Value
// ==================================
// "Integers are encoded as four-byte long (32 bit) binary signed numbers in 2's complement notation,
//  transmitted big-endian."
define_serializable_ttlv_type!(TtlvInteger, ItemType::Integer, i32, 4);

// KMIP v1.0 spec: 9.1.1.4 Item Value
// ==================================
// "Long Integers are encoded as eight-byte long (64 bit) binary signed numbers in 2's complement
//  notation, transmitted big-endian."
define_serializable_ttlv_type!(TtlvLongInteger, ItemType::LongInteger, i64, 8);

// KMIP v1.0 spec: 9.1.1.4 Item Value
// ==================================
// "Big Integers are encoded as a sequence of eight-bit bytes, in two's complement notation,
//  transmitted big-endian. If the length of the sequence is not a multiple of eight bytes, then Big
//  Integers SHALL be padded with the minimal number of leading sign-extended bytes to make the
//  length a multiple of eight bytes. These padding bytes are part of the Item Value and SHALL be
//  counted in the Item Length."
// #[derive(Clone, Debug)]
// struct BigInteger(Vec<u8>);

// KMIP v1.0 spec: 9.1.1.4 Item Value
// ==================================
// "Enumerations are encoded as four-byte long (32 bit) binary unsigned numbers transmitted big-
//  endian. Extensions, which are permitted, but are not defined in this specification, contain the
//  value 8 hex in the first nibble of the first byte."
define_serializable_ttlv_type!(TtlvEnumeration, ItemType::Enumeration, u32, 4);

// KMIP v1.0 spec: 9.1.1.4 Item Value
// ==================================
// "Booleans are encoded as an eight-byte value that SHALL either contain the hex value
//  0000000000000000, indicating the Boolean value False, or the hex value 0000000000000001,
//  transmitted big-endian, indicating the Boolean value True."
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
    const TTLV_TYPE: ItemType = ItemType::Boolean;

    fn read_value<T: Read>(src: &mut T, value_len: u32) -> Result<Self> {
        if value_len != Self::TTLV_FIXED_VALUE_LENGTH {
            Err(Error::InvalidLength(format!(
                "Item length is {} but for type TtlvBoolean it should be {}",
                value_len,
                Self::TTLV_FIXED_VALUE_LENGTH
            )))
        } else {
            let mut dst = [0u8; Self::TTLV_FIXED_VALUE_LENGTH as usize];
            src.read_exact(&mut dst)?;
            match u64::from_be_bytes(dst) {
                0 => Ok(TtlvBoolean(false)),
                1 => Ok(TtlvBoolean(true)),
                n => Err(Error::Other(format!(
                    "TtlvBoolean value must be 0 or 1 but found {}",
                    n
                ))),
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

// KMIP v1.0 spec: 9.1.1.4 Item Value
// ==================================
// "Text Strings are sequences of bytes that encode character values according to the UTF-8
//  encoding standard. There SHALL NOT be null-termination at the end of such strings."
#[derive(Clone, Debug)]
pub struct TtlvTextString(pub String);
impl Deref for TtlvTextString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl SerializableTtlvType for TtlvTextString {
    const TTLV_TYPE: ItemType = ItemType::TextString;

    fn read_value<T: Read>(src: &mut T, value_len: u32) -> Result<Self> {
        // Read the UTF-8 bytes, without knowing if they are valid UTF-8
        let mut dst = vec![0; value_len as usize];
        src.read_exact(&mut dst)?;

        // Use the bytes as-is as the internal buffer for a String, verifying that the bytes are indeed valid
        // UTF-8
        let new_str = String::from_utf8(dst).map_err(|err| Error::InvalidUtf8(err.to_string()))?;

        Ok(TtlvTextString(new_str))
    }

    fn write_length_and_value<T: Write>(&self, dst: &mut T) -> Result<u32> {
        let v = self.0.as_bytes();
        let v_len = v.len() as u32;
        dst.write_all(&v_len.to_be_bytes())?; // Write L_ength
        dst.write_all(&v)?; // Write V_alue
        Ok(v_len)
    }
}

// KMIP v1.0 spec: 9.1.1.4 Item Value
// ==================================
// "Date-Time values are POSIX Time values encoded as Long Integers. POSIX Time, as described
//  in IEEE Standard 1003.1 [IEEE1003-1], is the number of seconds since the Epoch (1970 Jan 1,
//  00:00:00 UTC), not counting leap seconds."
#[allow(dead_code)]
pub type TtlvDateTime = TtlvLongInteger;

// KMIP v1.0 spec: 9.1.1.4 Item Value
// ==================================
// "Intervals are encoded as four-byte long (32 bit) binary unsigned numbers, transmitted big-endian.
//  They have a resolution of one second."
#[allow(dead_code)]
pub type TtlvInterval = TtlvEnumeration;

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::types::{ItemTag, ItemType, SerializableTtlvType};

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

        assert!(ItemTag::from_str("").is_err());
        assert!(ItemTag::from_str("    ").is_err());
        assert!(ItemTag::from_str("XYZ").is_err());
        assert!(ItemType::from_str("-1").is_err());

        #[allow(non_snake_case)]
        let ZERO_TAG = ItemTag::from([0x00u8, 0x00u8, 0x00u8]);

        #[allow(non_snake_case)]
        let ONE_TAG = ItemTag::from([0x00u8, 0x00u8, 0x01u8]);

        assert_eq!(ZERO_TAG, ItemTag::from_str("0").unwrap());
        assert_eq!(ZERO_TAG, ItemTag::from_str("000").unwrap());
        assert_eq!(ZERO_TAG, ItemTag::from_str("0x0").unwrap());
        assert_eq!(ONE_TAG, ItemTag::from_str("1").unwrap());
        assert_eq!(ONE_TAG, ItemTag::from_str("001").unwrap());
        assert_eq!(ONE_TAG, ItemTag::from_str("0x1").unwrap());

        assert_eq!(
            ItemTag::from([0x42u8, 0x00u8, 0xAAu8]),
            ItemTag::from_str("0x4200AA").unwrap()
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

        assert!(ItemType::from_str("").is_err());
        assert!(ItemType::from_str("    ").is_err());
        assert!(ItemType::from_str("XYZ").is_err());

        assert!(ItemType::from_str("-1").is_err());
        assert!(ItemType::from_str("0").is_err());
        assert!(matches!(ItemType::from_str("0x01").unwrap(), ItemType::Structure));
        assert!(matches!(ItemType::from_str("0x02").unwrap(), ItemType::Integer));
        assert!(matches!(ItemType::from_str("0x03").unwrap(), ItemType::LongInteger));
        assert!(matches!(ItemType::from_str("0x05").unwrap(), ItemType::Enumeration));
        assert!(matches!(ItemType::from_str("0x06").unwrap(), ItemType::Boolean));
        assert!(matches!(ItemType::from_str("0x07").unwrap(), ItemType::TextString));
        assert!(matches!(ItemType::from_str("0x09").unwrap(), ItemType::DateTime));

        assert_eq!(ItemType::from_str("0x01").unwrap(), ItemType::try_from(0x01).unwrap());
        assert_eq!(ItemType::from_str("0x02").unwrap(), ItemType::try_from(0x02).unwrap());
        assert_eq!(ItemType::from_str("0x03").unwrap(), ItemType::try_from(0x03).unwrap());
        assert_eq!(ItemType::from_str("0x05").unwrap(), ItemType::try_from(0x05).unwrap());
        assert_eq!(ItemType::from_str("0x06").unwrap(), ItemType::try_from(0x06).unwrap());
        assert_eq!(ItemType::from_str("0x07").unwrap(), ItemType::try_from(0x07).unwrap());
        assert_eq!(ItemType::from_str("0x09").unwrap(), ItemType::try_from(0x09).unwrap());

        // Big Integer is not yet implemented
        assert!(ItemType::from_str("0x04").is_err());
        // assert_eq!(ItemType::from_str("0x04").unwrap(), ItemType::try_from(0x04).unwrap());

        // Byte String is not yet implemented
        assert!(ItemType::from_str("0x08").is_err());
        // assert_eq!(ItemType::from_str("0x08").unwrap(), ItemType::try_from(0x08).unwrap());

        // Interval is not yet implemented
        assert!(ItemType::from_str("0x0A").is_err());
        // assert_eq!(ItemType::from_str("0x02").unwrap(), ItemType::try_from(0x0A).unwrap());
    }

    #[test]
    fn test_spec_value_type_examples() {
        fn example(s: &str) -> Vec<u8> {
            // strip out the example fake item tag, spacing and separators
            hex::decode(s.replace("42 00 20 | ", "").replace(" ", "").replace("|", "")).unwrap()
        }

        // Quoting: http://docs.oasis-open.org/kmip/spec/v1.0/cs01/kmip-spec-1.0-cs-01.pdf 9.1.2 Examples
        //   These examples are assumed to be encoding a Protocol Object whose tag is 420020. The examples are
        //   shown as a sequence of bytes in hexadecimal notation:
        //
        //   - An Integer containing the decimal value 8:
        //     42 00 20 | 02 | 00 00 00 04 | 00 00 00 08 00 00 00 00
        let mut actual = Vec::new();
        let expected = example("42 00 20 | 02 | 00 00 00 04 | 00 00 00 08 00 00 00 00");
        TtlvInteger(8).write(&mut actual).unwrap();
        assert_eq!(expected, actual);

        //   - A Long Integer containing the decimal value 123456789000000000:
        //     42 00 20 | 03 | 00 00 00 08 | 01 B6 9B 4B A5 74 92 00
        let mut actual = Vec::new();
        let expected = example("42 00 20 | 03 | 00 00 00 08 | 01 B6 9B 4B A5 74 92 00");
        TtlvLongInteger(123456789000000000).write(&mut actual).unwrap();
        assert_eq!(expected, actual);

        //   - A Big Integer containing the decimal value 1234567890000000000000000000:
        //     42 00 20 | 04 | 00 00 00 10 | 00 00 00 00 03 FD 35 EB 6B C2 DF 46 18 08
        //     00 00
        // NOT IMPLEMENTED YET

        //   - An Enumeration with value 255:
        //     42 00 20 | 05 | 00 00 00 04 | 00 00 00 FF 00 00 00 00
        let mut actual = Vec::new();
        let expected = example("42 00 20 | 05 | 00 00 00 04 | 00 00 00 FF 00 00 00 00");
        TtlvEnumeration(255).write(&mut actual).unwrap();
        assert_eq!(expected, actual);

        //   - A Boolean with the value True:
        //     42 00 20 | 06 | 00 00 00 08 | 00 00 00 00 00 00 00 01
        let mut actual = Vec::new();
        let expected = example("42 00 20 | 06 | 00 00 00 08 | 00 00 00 00 00 00 00 01");
        TtlvBoolean(true).write(&mut actual).unwrap();
        assert_eq!(expected, actual);

        //   - A Text String with the value "Hello World":
        //     42 00 20 | 07 | 00 00 00 0B | 48 65 6C 6C 6F 20 57 6F 72 6C 64 00 00 00
        //     00 00
        let mut actual = Vec::new();
        let expected = example("42 00 20 | 07 | 00 00 00 0B | 48 65 6C 6C 6F 20 57 6F 72 6C 64 00 00 00 00 00");
        TtlvTextString("Hello World".to_string()).write(&mut actual).unwrap();
        assert_eq!(expected, actual);

        //   - A Byte String with the value { 0x01, 0x02, 0x03 }:
        //     42 00 20 | 08 | 00 00 00 03 | 01 02 03 00 00 00 00 00
        // NOT IMPLEMENTED YET

        //   - A Date-Time, containing the value for Friday, March 14, 2008, 11:56:40 GMT:
        //     42 00 20 | 09 | 00 00 00 08 | 00 00 00 00 47 DA 67 F8
        // TODO

        //   - An Interval, containing the value for 10 days:
        //     42 00 20 | 0A | 00 00 00 04 | 00 0D 2F 00 00 00 00 00
        // NOT IMPLEMENTED YET

        //   - A Structure containing an Enumeration, value 254, followed by an Integer, value 255, having tags
        //   - 420004 and 420005 respectively:
        //     42 00 20 | 01 | 00 00 00 20 | 42 00 04 | 05 | 00 00 00 04 | 00 00 00 FE
        //     00 00 00 00 | 42 00 05 | 02 | 00 00 00 04 | 00 00 00 FF 00 00 00 00
        // NOT IN SCOPE FOR THIS MODULE
    }
}
