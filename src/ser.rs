//! Serialize a Rust data structure into TTLV data.

use std::{io::Write, str::FromStr};

use serde::{
    ser::{self, Impossible, SerializeTupleStruct},
    Serialize,
};
use types::{TtlvBoolean, TtlvEnumeration, TtlvInteger, TtlvLongInteger, TtlvTextString};

use crate::{
    error::{Error, ErrorLocation, MalformedTtlvError, Result, SerdeError},
    types::{
        self, ByteOffset, FieldType, SerializableTtlvType, TtlvByteString, TtlvDateTime, TtlvStateMachine,
        TtlvStateMachineMode, TtlvTag, TtlvType,
    },
};

// --- Public interface ------------------------------------------------------------------------------------------------

pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut ser = TtlvSerializer::new();
    value.serialize(&mut ser)?;
    ser.into_vec()
}

pub fn to_writer<T, W>(value: &T, mut writer: W) -> Result<()>
where
    T: Serialize,
    W: Write,
{
    let vec = to_vec(value)?;
    let res = writer
        .write_all(&vec)
        .map_err(|err| pinpoint!(err, ErrorLocation::unknown()))?;
    Ok(res)
}

impl serde::ser::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        pinpoint!(SerdeError::Other(msg.to_string()), ErrorLocation::unknown())
    }
}

// --- Private implementation details ----------------------------------------------------------------------------------

impl From<&mut TtlvSerializer> for ErrorLocation {
    fn from(ser: &mut TtlvSerializer) -> Self {
        use std::convert::TryFrom;
        match u64::try_from(ser.dst.len()) {
            Ok(offset) => ErrorLocation::from(ByteOffset::from(offset)),
            Err(_) => ErrorLocation::unknown(),
        }
    }
}

pub struct TtlvSerializer {
    /// The destination buffer to serialize TTLV bytes into. If we want to write to something else in future we will need
    /// a way to be able to write to an earlier position in the output so that we can rewrite an items length value once
    /// we know how long it is (with padding rules per TTLV type taken into account). Currently this is done simply by
    /// indexing directly into the output buffer. An alternate approach could be to require the Seek trait to be
    /// implemented.
    dst: Vec<u8>,

    /// A push/pop stack of indexes into the `dst` buffer to the points at which TTLV value byte lengths must be returned
    /// to and overwritten once the length of the value being written, and any padding to ignore, is known.
    bookmarks: Vec<usize>,

    state: TtlvStateMachine,
}

impl Default for TtlvSerializer {
    fn default() -> Self {
        Self {
            dst: Default::default(),
            bookmarks: Default::default(),
            state: TtlvStateMachine::new(TtlvStateMachineMode::Serializing),
        }
    }
}

impl TtlvSerializer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn into_vec(mut self) -> Result<Vec<u8>> {
        self.finalize()?;
        Ok(self.dst)
    }

    /// Write the item tag (a "three-byte binary unsigned integer, transmitted big-endian"). The caller is
    /// responsible for ensuring that the given tag value is big-endian encoded, i.e.
    /// assert_eq!(0x42007B_u32.to_be_bytes(), [00, 0x42, 0x00, 0x7B]); This will advance the buffer write position
    /// by 3 bytes.
    fn write_tag(&mut self, item_tag: TtlvTag, set_ignore_next_tag: bool) -> Result<()> {
        if self.advance_state_machine(FieldType::Tag)? {
            if set_ignore_next_tag {
                let loc = self.location();
                self.state.ignore_next_tag().map_err(|err| pinpoint!(err, loc))?;
            }
            item_tag.write(&mut self.dst).map_err(|err| pinpoint!(err, self))?;
        }
        Ok(())
    }

    /// Write the TTLV item type ("a byte containing a coded value"). This will advance the buffer write position by
    /// 1 byte.
    fn write_type(&mut self, item_type: TtlvType) -> Result<()> {
        if self.advance_state_machine(FieldType::Type)? {
            item_type.write(&mut self.dst).map_err(|err| pinpoint!(err, self))?;
        }
        Ok(())
    }

    /// Push a dummy 0x000000 4-byte TTLV item length. After writing the value bytes we'll come back later and replace
    /// the dummy bytes with the correct item length. Adds a bookmark at the current buffer write location so that
    /// fn rewite_len() knows where to come back to.
    fn write_zero_len(&mut self) -> Result<()> {
        if self.advance_state_machine(FieldType::Length)? {
            self.dst
                .write_all(&[0u8, 0u8, 0u8, 0u8])
                .map_err(|err| pinpoint!(err, self.location()))?;
            self.bookmarks.push(self.dst.len());
        }
        Ok(())
    }

    /// Replace the most recent dummy 0x00000000 4-byte TTLV item length written by the last call to fn write_zero_len()
    /// with the actual TTLV item length value. Assumes that the most recently bookmarked location in the write buffer
    /// is the start of the 4 bytes to overwrite.
    fn rewrite_len(&mut self) -> Result<()> {
        if let Some(v_start_pos) = self.bookmarks.pop() {
            // the bookmark is the position just after the L in TTLV, i.e. the start of the value V. Calculate the length of
            // V by comparing the bookmarked position to our current position in the write buffer, then write that length
            // into the bookmarked L position.
            let len_to_write: u32 = (self.dst.len() - v_start_pos) as u32;
            let bytes_to_overwrite = &mut self.dst.as_mut_slice()[v_start_pos - 4..v_start_pos];
            bytes_to_overwrite.copy_from_slice(&len_to_write.to_be_bytes());
        }
        Ok(())
    }

    /// To be called at the end of serializing the stream of TTLV bytes. Makes sure that we didn't forget to rewrite the
    /// last dummy TTLV length value and verifies afterwards that there are no bookmarks left.
    fn finalize(&mut self) -> Result<()> {
        if !self.bookmarks.is_empty() {
            // This shouldn't happen.
            Err(pinpoint!(MalformedTtlvError::UnknownStructureLength, self))
        } else {
            Ok(())
        }
    }

    fn location(&self) -> ErrorLocation {
        ErrorLocation::from(self.dst.len())
    }

    fn advance_state_machine(&mut self, next_state: FieldType) -> Result<bool> {
        self.state.advance(next_state).map_err(|err| pinpoint!(err, self))
    }
}

impl serde::ser::Serializer for &mut TtlvSerializer {
    type Ok = ();
    type Error = Error;

    // =======================================================
    // RUST TYPES FOR WHICH SERIALIZATION TO TTLV IS SUPPORTED
    // =======================================================
    type SerializeSeq = Self;
    type SerializeStruct = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;

    /// This fn is called at the start of serializing a Rust tuple struct, e.g. struct SomeStruct(type, type, type). The
    /// struct contents will be written out as a tree of TTLV structures (TTLV type 0x01) with each field in the Rust
    /// structure being represented as a TTLV tag, type, len and value byte sequence. Inner structs or other supported
    /// complex Rust types that can be serialized by this Serializer will be rendered as inner TTLV structure sequences
    /// in the created TTLV byte sequence. The TTLV tag value to write is taken from the name argument passed to this fn.
    /// When using #[derive(Serialize)] you should use #[serde(rename = "0xAABBCC")] to cause the name argument value
    /// received here to be the TTLV tag value to use when serializing the structure to the write buffer.
    fn serialize_tuple_struct(self, name: &'static str, _len: usize) -> Result<Self::SerializeTupleStruct> {
        let item_tag = TtlvTag::from_str(name).map_err(|err| pinpoint!(err, self.location()))?;
        self.write_tag(item_tag, false)?;
        self.write_type(TtlvType::Structure)?;
        self.write_zero_len()?;
        // SerializeTupleStruct will write out the tuple fields then call rewrite_len()
        Ok(self)
    }

    /// Serialize a Rust bool value into the TTLV write buffer as TTLV type 0x06 (Boolean).
    fn serialize_bool(self, v: bool) -> Result<()> {
        if self.advance_state_machine(FieldType::TypeAndLengthAndValue)? {
            TtlvBoolean(v)
                .write(&mut self.dst)
                .map_err(|err| pinpoint!(err, self))?;
        }
        Ok(())
    }

    /// Serialize a Rust integer value into the TTLV write buffer as TTLV type 0x02 (Integer).
    fn serialize_i8(self, v: i8) -> Result<()> {
        self.serialize_i32(v as i32)
    }

    /// Serialize a Rust integer value into the TTLV write buffer as TTLV type 0x02 (Integer).
    fn serialize_i16(self, v: i16) -> Result<()> {
        self.serialize_i32(v as i32)
    }

    /// Serialize a Rust integer value into the TTLV write buffer as TTLV type 0x02 (Integer).
    fn serialize_i32(self, v: i32) -> Result<()> {
        if self.advance_state_machine(FieldType::TypeAndLengthAndValue)? {
            TtlvInteger(v)
                .write(&mut self.dst)
                .map_err(|err| pinpoint!(err, self))?;
        }
        Ok(())
    }

    /// Serialize a Rust unsigned 32-bit integer value into the TTLV write buffer as TTLV type 0x05 (Enumeration).
    fn serialize_u32(self, v: u32) -> Result<()> {
        if self.advance_state_machine(FieldType::TypeAndLengthAndValue)? {
            TtlvEnumeration(v)
                .write(&mut self.dst)
                .map_err(|err| pinpoint!(err, self))?;
        }
        Ok(())
    }

    /// Serialize a Rust integer value into the TTLV write buffer as TTLV type 0x03 (Long Integer).
    fn serialize_i64(self, v: i64) -> Result<()> {
        if self.advance_state_machine(FieldType::TypeAndLengthAndValue)? {
            TtlvLongInteger(v)
                .write(&mut self.dst)
                .map_err(|err| pinpoint!(err, self))?;
        }
        Ok(())
    }

    /// Serialize a Rust unsigned 64-bit integer value into the TTLV write buffer as TTLV type 0x09 (DateTime).
    ///
    /// TTLV DateTime values are serialized as a signed 64-bit value but as we need to ensure that we serialize the
    /// correct TTLV type we can't handle these in serialize_i64 as that is already used for TTLV type 0x03
    /// (Long Integer).
    fn serialize_u64(self, v: u64) -> Result<()> {
        if self.advance_state_machine(FieldType::TypeAndLengthAndValue)? {
            TtlvDateTime(v as i64)
                .write(&mut self.dst)
                .map_err(|err| pinpoint!(err, self))?;
        }
        Ok(())
    }

    /// Serialize a Rust str value into the TTLV write buffer as TTLV type 0x07 (Text String).
    fn serialize_str(self, v: &str) -> Result<()> {
        if self.advance_state_machine(FieldType::TypeAndLengthAndValue)? {
            TtlvTextString(v.to_string())
                .write(&mut self.dst)
                .map_err(|err| pinpoint!(err, self))?;
        }
        Ok(())
    }

    /// Use #[serde(with = "serde_bytes")] to direct Serde to this serializer function for type Vec<u8>.
    fn serialize_bytes(self, v: &[u8]) -> Result<()> {
        if self.advance_state_machine(FieldType::TypeAndLengthAndValue)? {
            TtlvByteString(v.to_vec())
                .write(&mut self.dst)
                .map_err(|err| pinpoint!(err, self))?;
        }
        Ok(())
    }

    /// Serialize a unit enum variant.
    ///
    /// We can't serialize based on the discriminant as Serde doesn't make that available to us. We also can't serialize
    /// based on the variant index as most KMIP enumerations start at one rather than zero, and we can't work based on
    /// that assumption either as some start at other numbers entirely (e.g. the KMIP spec 1.0 section 9.1.3.2.19 Link
    /// Type Enumeration defines an enumeration that starts at 0x00000101). And we can't serialize based on the variant
    /// name if that name is a string, e.g. "Query", as TTLV requires an enumeration to be serialized as a 32-bit
    /// unsigned integer and we only have a string which might not be (correctly) convertable to an integer. And we also
    /// can't serialize using serde_repr which would give us access to the discriminant, but would invoke our
    /// `fn serialize_u32()` function with ONLY the discriminant, we wouldn't be able to write out the TTLV tag as we
    /// wouldn't know what it was.
    ///
    /// Therefore we require the tag AND the discriminant to be communicated to us. The tag should be passed via the
    /// enum name and the discriminant via the variant name. When using serde-derive both should be overridden using the
    /// `#[serde(rename = "0xAABBCC")]` syntax, e.g.
    ///
    /// ```ignore
    /// #[derive(Serialize)]
    /// #[serde(rename = "0x42005C")]
    /// enum MyEnum {
    ///     #[serde(rename = "0x000000001")] // The discriminant has to be defined here.
    ///     SomeVariant // = 1,                 Any discriminant value assigned here will be ignored
    /// }
    /// ```
    fn serialize_unit_variant(self, name: &'static str, _variant_index: u32, variant: &'static str) -> Result<()> {
        // Don't write the tag if we just wrote a tag. This can happen in situations like this:
        //
        //   Tag: Template-Attribute (0x420091), Type: Structure (0x01), Data:
        //     Tag: Attribute (0x420008), Type: Structure (0x01), Data:
        //       Tag: Attribute Name (0x42000A), Type: Text String (0x07), Data: Cryptographic Algorithm
        //       Tag: Attribute Value (0x42000B), Type: Enumeration (0x05), Data: 0x00000003 (AES)
        //
        // Here we've just written out the tag 0x42000B and we're about to write the enum value 0x00000003. However, the
        // input to Serde that we are processing looked like this:
        //
        //   #[derive(Clone, Copy, Debug, Deserialize, Serialize, Display, PartialEq, Eq)]
        //   #[serde(rename = "0x420028")]
        //   #[non_exhaustive]
        //   #[allow(non_camel_case_types)]
        //   pub enum CryptographicAlgorithm {
        //       #[serde(rename = "0x00000001")]
        //       ...
        //
        // This type has its own tag, 0x4200028, and we would normally write this out as a full TTLV. In the case of a
        // KMIP Attribute Value however the tag is always the same, 0x420000B, and the type of the data is inferred by
        // the deserializer by looking at the Data of the preceeding Attribute Name.
        //
        // So in this case we should skip writing out the tag and only write the type, length and value.

        let item_tag = TtlvTag::from_str(name).map_err(|err| pinpoint!(err, self.location()))?;
        self.write_tag(item_tag, false)?;

        let variant = u32::from_str_radix(variant.trim_start_matches("0x"), 16)
            .map_err(|_| pinpoint!(SerdeError::InvalidVariant(variant), self.location()))?;
        variant.serialize(self)
    }

    /// Serialize a struct SomeEnumVariant(a, b, c) to the TTLV write buffer as a TTLV Structure with fields a, b and c.
    fn serialize_tuple_variant(
        self,
        name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        // The Override name prefix has no meaning in the case of a tuple variant, it only applies to a single inner
        // tagged value whose tag should be overriden. See serialize_newtype_variant().
        let name = name.strip_prefix("Override:").unwrap_or(name);
        let item_tag = TtlvTag::from_str(name).map_err(|err| pinpoint!(err, self.location()))?;
        self.write_tag(item_tag, false)?;
        self.write_type(TtlvType::Structure)?;
        self.write_zero_len()?;
        // SerializeTupleVariant will write out the tuple fields then call rewrite_len()
        Ok(self)
    }

    fn serialize_newtype_variant<T: ?Sized>(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<()>
    where
        T: Serialize,
    {
        // If the Override name prefix is present use the tag of this enum when writing the next item instead of that
        // items own tag.
        let (name, set_ignore_next_tag) = if let Some(name) = name.strip_prefix("Override:") {
            (name, true)
        } else {
            (name, false)
        };

        // If the variant name is "Transparent" serialize the inner value directly, don't wrap it in a TTLV Structure.
        if variant == "Transparent" {
            let item_tag = TtlvTag::from_str(name).map_err(|err| pinpoint!(err, self.location()))?;
            self.write_tag(item_tag, set_ignore_next_tag)?;
            value.serialize(self)
        } else {
            let mut ser = self.serialize_tuple_variant(name, variant_index, variant, 1)?;
            ser.serialize_field(value)?;
            ser.end()
        }
    }

    /// Serialize a struct SomeStruct(type) to the TTLV write buffer as if it were the naked type without the enclosing
    /// "newtype" SomeStruct wrapper.
    ///
    /// We don't use `#[serde(transparent)]` on the structs because then the serialization process would go straight to
    /// functions such as `serialize_i32()` which serialize the V in TTLV but we also need to serialize the TTL part as
    /// well.
    fn serialize_newtype_struct<T: ?Sized>(self, name: &'static str, value: &T) -> Result<()>
    where
        T: Serialize,
    {
        if let Some(name) = name.strip_prefix("Transparent:") {
            let item_tag = TtlvTag::from_str(name).map_err(|err| pinpoint!(err, self.location()))?;
            self.write_tag(item_tag, false)?;
            value.serialize(self)
        } else {
            let mut ser = self.serialize_tuple_struct(name, 1)?;
            ser.serialize_field(value)?;
            ser.end()
        }
    }

    /// Serializing Rust brace structs to TTLV.
    ///
    /// Use of newtype and tuple structs is preferred as it leads to less verbose (yet still well named) Rust
    /// hierarchical data structures because the field names do not need to be expressed. Usually this would be less
    /// readable but because wrapper types must be used around primitive types (in order to give them a Serde "name"
    /// which will be used as the TTLV "tag") then the unnamed primitive value is still wrapped in a named wrapper type.
    ///
    /// One use case for brace structs however is to avoid having to define separately a tuple struct for a type sent in
    /// a request and a brace struct for the same type when received in a response. For structs with many fields this
    /// can lead to a lot of duplication. If instead a single brace struct is defined but helper functions on the struct
    /// are used to streamline the request construction this can be a way to achieve the best of both worlds: simple
    /// requests based on anonymous fields that are self-evident from their type names, and responses with helpfully
    /// named member fields for cases where there is no need to explicitly name the field type in order to use it.
    fn serialize_struct(self, name: &'static str, _len: usize) -> Result<Self::SerializeStruct> {
        let item_tag = TtlvTag::from_str(name).map_err(|err| pinpoint!(err, self.location()))?;
        self.write_tag(item_tag, false)?;
        self.write_type(TtlvType::Structure)?;
        self.write_zero_len()?;
        // SerializeStruct will write out the tuple fields then call rewrite_len()
        Ok(self)
    }

    /// Dispatch serialization of a Rust sequence type such as Vec to the implementation of SerializeSeq that we
    /// provide.
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq> {
        Ok(self)
    }

    /// Serialize a `Some(value)` as if it were plain `value`.
    fn serialize_some<T: ?Sized>(self, value: &T) -> Result<()>
    where
        T: Serialize,
    {
        value.serialize(self)
    }

    // ==============================================================
    // RUST TYPES FOR WHICH SERIALIZATION TO TTLV IS _NOT_ SUPPORTED!
    // ==============================================================

    type SerializeMap = Impossible<(), Self::Error>;
    type SerializeStructVariant = Impossible<(), Self::Error>;
    type SerializeTuple = Impossible<(), Self::Error>;

    fn serialize_u8(self, _v: u8) -> Result<()> {
        Err(pinpoint!(SerdeError::UnsupportedRustType("u8"), self))
    }

    fn serialize_u16(self, _v: u16) -> Result<()> {
        Err(pinpoint!(SerdeError::UnsupportedRustType("u16"), self))
    }

    fn serialize_f32(self, _v: f32) -> Result<()> {
        Err(pinpoint!(SerdeError::UnsupportedRustType("f32"), self))
    }

    fn serialize_f64(self, _v: f64) -> Result<()> {
        Err(pinpoint!(SerdeError::UnsupportedRustType("f64"), self))
    }

    fn serialize_char(self, _v: char) -> Result<()> {
        Err(pinpoint!(SerdeError::UnsupportedRustType("char"), self))
    }

    /// Serializing `None` values, e.g. Option::<TypeName>::None, is not supported.
    ///
    /// TTLV doesn't support the notion of a serialized value that indicates the absence of a value.
    ///
    /// ### Using Serde to "skip" a missing value
    ///
    /// The correct way to omit None values is to not attempt to serialize them at all, e.g. using the
    /// `#[serde(skip_serializing_if = "Option::is_none")]` Serde derive field attribute. Note that at the time of
    /// writing it seems that Serde derive only handles this attribute correctly when used on Rust brace struct field
    /// members (which we do not support), or on tuple struct fields (i.e. there must be more than one field). Also,
    /// note that not serializing a None struct field value will still result in the struct itself being serialized as
    /// a TTLV "Structure" unless you also mark the struct as "transparent" (using the rename attribute like so:
    /// `[#serde(rename = "Transparent:0xAABBCC"))]`. Using the attribute on newtype structs still causes Serde derive
    /// to invoke `serialize_none()` which will result in an unsupported error.
    ///
    /// ### Rationale
    ///
    /// As we have already serialized the item tag to the output by the time we process the `Option` value, serializing
    /// nothing here would still result in something having been serialized. We could in theory remove the already
    /// serialized bytes from the stream but is not necessarily safe, e.g. if the already serialized bytes were a TTLV
    /// Structure "header" (i.e. 0xAABBCC 0x00000001 0x00000000) removing the header might be incorrect if there are
    /// other structure items that will be serialized to the stream after this "none". Removing the Structure "header"
    /// bytes would also break the current logic which at the end of a structure goes back to the start and replaces the
    /// zero length value in the TTLV Structure "header" with the actual length as the bytes to replace would no longer
    /// exist.
    fn serialize_none(self) -> Result<()> {
        Err(pinpoint!(SerdeError::UnsupportedRustType("None"), self))
    }

    fn serialize_unit(self) -> Result<()> {
        Err(pinpoint!(SerdeError::UnsupportedRustType("unit"), self))
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        Err(pinpoint!(SerdeError::UnsupportedRustType("unit struct"), self))
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple> {
        Err(pinpoint!(SerdeError::UnsupportedRustType("tuple"), self))
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        Err(pinpoint!(SerdeError::UnsupportedRustType("map"), self))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        Err(pinpoint!(SerdeError::UnsupportedRustType("struct variant"), self))
    }
}

// =======================================
// SERIALIZATION OF RUST SEQUENCES TO TTLV
// =======================================
impl ser::SerializeSeq for &mut TtlvSerializer {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T: ?Sized>(&mut self, value: &T) -> Result<()>
    where
        T: Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

// =====================================
// SERIALIZATION OF RUST STRUCTS TO TTLV
// =====================================
impl ser::SerializeStruct for &mut TtlvSerializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: ?Sized>(&mut self, _key: &'static str, value: &T) -> Result<()>
    where
        T: Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        // This fn is called at the end of serializing a Struct.
        self.rewrite_len()
    }
}

// ===========================================
// SERIALIZATION OF RUST TUPLE STRUCTS TO TTLV
// ===========================================
impl ser::SerializeTupleStruct for &mut TtlvSerializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: ?Sized>(&mut self, value: &T) -> Result<()>
    where
        T: Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        // This fn is called at the end of serializing a Struct.
        self.rewrite_len()
    }
}

// ============================================
// SERIALIZATION OF RUST TUPLE VARIANTS TO TTLV
// ============================================
impl ser::SerializeTupleVariant for &mut TtlvSerializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: ?Sized>(&mut self, value: &T) -> Result<()>
    where
        T: Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<Self::Ok> {
        // This fn is called at the end of serializing a tuple variant.
        // TODO: go back to the length byte pos in the vec and write in our distance from that point
        // Either we need to receive back from ... from where? we get no values passed to us, so instead we need to
        // store the position to go back to in the vec, but we'll need to do that for each level of struct nesting, push
        // them on and pop them off.
        self.rewrite_len()
    }
}

#[cfg(test)]
mod test {
    #[allow(unused_imports)]
    use pretty_assertions::{assert_eq, assert_ne};

    use serde_derive::Serialize;

    use crate::ser::to_vec;

    #[test]
    fn test_kmip_10_create_destroy_use_case_create_request_serialization() {
        // Define the types used by the test below. Note that these are structured so as to be easy to compose with minimal
        // boilerplate overhead. For example tuple structs are heavily used rather than structs with named fields. If this
        // were for deserialization instead of serialization these types should instead be verbose with named fields to make
        // it easy to interact with the response objects.
        #[derive(Serialize)]
        #[serde(rename = "0x420078")]
        struct RequestMessage(RequestHeader, Vec<BatchItem>);

        #[derive(Serialize)]
        #[serde(rename = "0x420077")]
        struct RequestHeader(ProtocolVersion, BatchCount);

        #[derive(Serialize)]
        #[serde(rename = "Transparent:0x42006B")]
        struct ProtocolVersionMinor(i32);

        #[derive(Serialize)]
        #[serde(rename = "Transparent:0x42006A")]
        struct ProtocolVersionMajor(i32);

        #[derive(Serialize)]
        #[serde(rename = "0x420069")]
        struct ProtocolVersion(ProtocolVersionMajor, ProtocolVersionMinor);

        #[derive(Serialize)]
        #[serde(rename = "Transparent:0x42000D")]
        struct BatchCount(i32);

        #[derive(Serialize)]
        #[serde(rename = "0x42000F")]
        struct BatchItem(Operation, RequestPayload);

        #[derive(Serialize)]
        #[serde(rename = "0x42005C")]
        enum Operation {
            #[serde(rename = "0x00000001")]
            Create,
        }

        #[derive(Serialize)]
        #[serde(rename = "0x420079")]
        struct RequestPayload(ObjectType, TemplateAttribute);

        #[derive(Serialize)]
        #[serde(rename = "0x420057")]
        enum ObjectType {
            #[serde(rename = "0x00000002")]
            SymmetricKey,
        }

        #[derive(Serialize)]
        #[serde(rename = "0x420091")]
        struct TemplateAttribute(Vec<Attribute>);

        #[derive(Serialize)]
        #[serde(rename = "0x420008")]
        struct Attribute(AttributeName, AttributeValue);

        #[derive(Serialize)]
        #[serde(rename = "Transparent:0x42000A")]
        struct AttributeName(&'static str);

        #[derive(Serialize)]
        #[serde(rename = "Override:0x42000B")]
        enum AttributeValue {
            #[serde(rename = "Transparent")]
            CryptographicAlgorithm(CryptographicAlgorithm),

            #[serde(rename = "Transparent")]
            Integer(i32),
        }

        impl Attribute {
            #[allow(non_snake_case)]
            fn CryptographicAlgorithm(value: CryptographicAlgorithm) -> Self {
                Attribute(
                    AttributeName("Cryptographic Algorithm"),
                    AttributeValue::CryptographicAlgorithm(value),
                )
            }

            #[allow(non_snake_case)]
            fn CryptographicLength(value: i32) -> Self {
                Attribute(AttributeName("Cryptographic Length"), AttributeValue::Integer(value))
            }

            #[allow(non_snake_case)]
            fn CryptographicUsageMask(value: i32) -> Self {
                Attribute(
                    AttributeName("Cryptographic Usage Mask"),
                    AttributeValue::Integer(value),
                )
            }
        }

        #[derive(Serialize)]
        #[serde(rename = "420028")]
        enum CryptographicAlgorithm {
            #[serde(rename = "0x00000003")]
            AES,
        }

        // Attempt to generate correct binary TTLV for KMIP specification v1.0 use case 3.1.1 Create / Destroy as the\
        // use case definition includes the input structure and the corresponding expected binary output.
        // See: http://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.html

        let use_case_input = RequestMessage(
            RequestHeader(
                ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0)),
                BatchCount(1),
            ),
            vec![BatchItem(
                Operation::Create,
                RequestPayload(
                    ObjectType::SymmetricKey,
                    TemplateAttribute(vec![
                        Attribute::CryptographicAlgorithm(CryptographicAlgorithm::AES),
                        Attribute::CryptographicLength(128),
                        Attribute::CryptographicUsageMask(0x0000_000C),
                    ]),
                ),
            )],
        );

        let use_case_output = concat!(
            "42007801000001204200770100000038420069010000002042006A0200000004000000010000000042006B0200000",
            "004000000000000000042000D0200000004000000010000000042000F01000000D842005C05000000040000000100",
            "00000042007901000000C04200570500000004000000020000000042009101000000A8420008010000003042000A0",
            "70000001743727970746F6772617068696320416C676F726974686D0042000B050000000400000003000000004200",
            "08010000003042000A070000001443727970746F67726170686963204C656E6774680000000042000B02000000040",
            "000008000000000420008010000003042000A070000001843727970746F67726170686963205573616765204D6173",
            "6B42000B02000000040000000C00000000"
        );

        assert_eq!(
            use_case_output,
            hex::encode_upper(to_vec(&use_case_input).unwrap()),
            "expected hex (left) differs to the generated hex (right)"
        );
    }

    // The rule for how Rust structs are by default mapped to TTLV is: a struct will be serialized as a Structure,
    // UNLESS it has been marked as "transparent". To use a Rust struct as a container to hang a Serde attribute off
    // without actually serializing it as a TTLV Structure one must mark the struct as "transparent". Option types
    // are also transparent in the sense that either the entire value SHOULD NOT be serialized if it is None, or if
    // Some then only its inner value will be serialized.

    #[test]
    fn test_structure_members_must_be_tagged() {
        // The following cannot be serialized as valid TTLV because a Rust struct is serialized as a TTLV Structure and
        // a TTLV Structure must contain complete TTLV items (i.e. a full Tag+Type+Length+Value). This doesn't work for
        // primitive types as they are passed by Serde Derive to serializer functions that only take a value as an
        // argument, e.g. `serialize_i32(self, value)`, and so the serializer has no name from which to create the tag
        // (for the initial T in TTLV) for the item. We also cannot handle a None value inside a struct because a None
        // value should not be serialized at all yet by the time serialize_none() is invoked, the outer struct TTL part
        // has already been serialized to the byte stream and not serializing the V part doesn't remove the alraedy
        // serialized TTL part.
        #[derive(Serialize)]
        #[serde(rename = "0xAABBCC")]
        struct SomeStruct(i32);
        let to_encode = SomeStruct(3);
        assert!(to_vec(&to_encode).is_err()); // Error: attempt to serialize malformed TTLTLV.
    }

    #[test]
    fn test_a_transparent_struct_can_be_used_to_tag_a_primitive_value() {
        // If we instead mark the struct as transparent we can then serialize the inner value using the Serde "name" of
        // the struct as the TTLV tag, instead of creating a containing TTLV Structure with that tag as happens
        // otherwise.
        #[derive(Serialize)]
        #[serde(rename = "Transparent:0xAABBCC")]
        struct SomeStruct(i32);
        let to_encode = SomeStruct(3);
        assert_eq!(
            "AABBCC02000000040000000300000000",
            hex::encode_upper(to_vec(&to_encode).unwrap()),
            "expected hex (left) differs to the generated hex (right)"
        );
    }

    #[test]
    fn test_ttlv_has_no_concept_of_values_that_denote_absence() {
        #[derive(Serialize)]
        #[serde(rename = "0xAABBCC")]
        struct SomeStruct(Option<i32>);
        let to_encode = SomeStruct(None);
        assert!(to_vec(&to_encode).is_err()); // Error: serializing None is not supported.
    }

    #[test]
    fn test_optional_values_that_are_present_are_serialized_as_the_value_directly() {
        #[derive(Serialize)]
        #[serde(rename = "Transparent:0xAABBCC")]
        struct SomeStruct(Option<i32>);
        let to_encode = SomeStruct(Some(3));
        assert_eq!(
            "AABBCC02000000040000000300000000",
            hex::encode_upper(to_vec(&to_encode).unwrap()),
            "expected hex (left) differs to the generated hex (right)"
        );
    }

    #[test]
    fn test_serde_derive_doesnt_skip_an_inner_none_inside_a_newtype() {
        // One would expect the following to work, but Serde Derive ignores the skip directive in this case and still
        // attempts to serialize the None. What would it mean for a Structure expected to have a single field for that
        // field to be missing anyway?
        #[derive(Serialize)]
        #[serde(rename = "Transparent:0xAABBCC")]
        struct TransparentItemWithConditionallySerializedOptionalField(
            #[serde(skip_serializing_if = "Option::is_none")] Option<i32>,
        );
        let transparent_conditional_with_none = TransparentItemWithConditionallySerializedOptionalField(None);
        assert!(to_vec(&transparent_conditional_with_none).is_err()); // Error: serializing None is not supported.
    }

    #[test]
    fn test_transparent_is_only_for_newtypes_not_for_tuples() {
        // Serde Derive will correctly ignore the None field if it is not the only field, but then in this case
        // "Transparent:0xNNNNNNN" isn't supported because it is intended only for the case of a single inner field.
        #[derive(Serialize)]
        #[serde(rename = "Transparent:0xAABBCC")]
        struct TransparentTupleWithConditionallySerializedOptionalField(
            i32,
            #[serde(skip_serializing_if = "Option::is_none")] Option<i32>,
        );
        let transparent_tuple_conditional_with_none = TransparentTupleWithConditionallySerializedOptionalField(1, None);
        assert!(to_vec(&transparent_tuple_conditional_with_none).is_err()); // Error: "Transparent" is not supported here.
    }

    #[test]
    fn test_serde_derive_can_skip_optional_none_values_in_a_tuple() {
        // We can use Serde Derive to skip serialization of a None value if it is not the only inner value in the type
        // being serialized:
        #[derive(Serialize)]
        #[serde(rename = "Transparent:0x123456")]
        struct SomeTaggedValue(i32);

        #[derive(Serialize)]
        #[serde(rename = "0xAABBCC")]
        struct TupleWithConditionallySerializedOptionalField(
            SomeTaggedValue,
            #[serde(skip_serializing_if = "Option::is_none")] Option<SomeTaggedValue>,
        );
        let tuple_conditional_with_none = TupleWithConditionallySerializedOptionalField(SomeTaggedValue(3), None);
        assert_eq!(
            "AABBCC010000001012345602000000040000000300000000",
            hex::encode_upper(to_vec(&tuple_conditional_with_none).unwrap()),
            "expected hex (left) differs to the generated hex (right)"
        );
    }
}
