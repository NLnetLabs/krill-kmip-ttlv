//! Deserialize TTLV data to a Rust data structure.
//!
//! # Basic usage
//!
//! ```
//! #[derive(Deserialize)]
//! #[serde(rename = "0xAABBCC")]
//! struct User {
//!     #[serde(rename = "0xDDEEFF")]
//!     some_field: i32
//! }
//! 
//! let res: User = from_slice(bytes)?;
//! ```
//!
//! The bytes in the slice are encoded according to the KMIP 1.0 TTLV encoding rules. In this example the data
//! represents a single TTLV structure whose "tag" code is 0xAABBCC, and the structure contains a single integer field
//! whose "tag" code is 0xDDEEFF.
//!
//! In TTLV format both the outer structure and the inner field are represented as TTLV "items" which have the byte form
//! when represented using hexadecimal as follows:
//!
//! ```
//!      TA TA TA TY LE LE LE LE VA VA VA VA VA VA VA VA VA VA VA VA
//! e.g. AA BB CC 01 00 00 00 12 DD EE FF 02 00 00 00 04 00 00 00 01
//!
//! i.e.                         TA TA TA TY LE LE LE LE VA VA VA VA
//!                              DD EE FF 02 00 00 00 04 00 00 00 01
//! ```
//!
//! Where:
//!   - TA denotes 3 "tag" code bytes, e.g. the outer struct tag code is 0xAABBCC
//!   - TY denotes 1 "type" code byte, e.g. the outer struct has tyoe 0x01 denoting a TTLV structure
//!   - LE denotes 4 "length" bytes, e.g. the outer struct has 12 value bytes
//!   - VA denotes a variable number of "value" bytes, in this case they define another TTLV item representing a type 0x2
//!     TTLV 32-bit (4 byte) integer field with value 0x00000001.
//!
//! # How it works
//!
//! Behind the scenes this will do something like this:
//!
//! ```
//!    --> struct User::deserialize( TtlvDeserializer::from_slice(bytes) )
//!         --> TtlvDeserializer::deserialize_struct()
//!             --> visitor.visit_map(TtlvStructureFieldAccess::new(cursor.clone()))
//! ```
//! 
//! The map visitor will now look for keys matching the field names (or serde renames) in the User structure, and will
//! invoke deserializer functions corresponding to the Rust type of the corresponding User structure field values, or
//! `deserialize_any` if the `Deserializer` doesn't support the particular type.
//! 
//! - User struct keys are processed by `fn deserialize_identifier()`. Serde expects one of the `visit_str` family of
//!   functions to be invoked with the same text as either the field name in the User struct or the
//!   `#[serde(rename = "xxx")]` "xxx" value defined by the user on the User struct field.
//! 
//! - Primitive fields are handled by `fn deserialize_any()`, including the non-primitive case of a complex enum
//!   variant.
//! 
//! - Simple structures that wrap just a single value are handled by `fn deserialize_newtype_struct()` which in turn
//!   will invoke any of the other handlers.
//! 
//! - Enums over single values are handled by `fn deserialize_enum()` which in turn uses either `TtlvEnumVariantAccess`
//!   or `TtlvEnumOneVariantAccess` to invoke any of the other handlers, both structs are only partially implemented.
//!   `TtlvEnumVariantAccess` keeps a record in the parent `TtlvStructureFieldAccess` of which enum tags have which
//!   values. These are then looked up when deciding which enum variant to populate in cases where
//!   `#[serde(rename = "if A==B")]` are defined.
//! 
//! - Structures are handled by `fn deserialize_struct()` which recurses into `self` as `MapAccess`.
//! 
//! - Sequences (i.e. `Vec<_>`) are handled by `fn deserialize_seq()` with the assistance of `self` as `SeqAccess`.
//!
//! # Real world application
//!
//! Its unlikely that you'll need to define a single hierarchy of TTLV data types to represent your data format /
//! communication protocol. In the case of KMIP for example the request and response hierarchies consist of a common
//! outer wrapper, a header followed by one or more batch items each with a common payload wrapper and a variable inner
//! payload.
//!
//! When deserializing, the structure to expect in the payload depends on the "Operation" enum field value in the
//! payload wrapper. Given an enum type as input, Serde cannot know which of the variants it is supposed to use to
//! populate the users data structure as it knows know about the "Operation" value.
//!
//! The solution is to teach it about the "Operation" value like so:
//!
//! ```
//! #[derive(Deserialize)]
//! struct BatchItem {
//!     #[serde(rename = "0x42005C")]
//!     operation: Operation,
//!     #[serde(rename = "0x42007C")]
//!     payload: ResponsePayload,
//! }
//! 
//! #[derive(Deserialize)]
//! enum Operation {
//!     #[serde(rename = "0x00000001")]
//!     Create,
//! }
//! 
//! #[derive(Deserialize)]
//! enum ResponsePayload {
//!      #[serde(rename = "if 0x42005C==0x00000001")]
//!      Create(CreateResponsePayload),
//!      Other(SomeOtherResponsePayload),
//! }
//! 
//! #[derive(Deserialize)]
//! struct CreateResponsePayload {
//!     // ... some fields ...
//! }
//! ```
//!
//! The link between the "Operation" enum and the payload enum variant is established using the
//! special `#[serde(rename = "if 0x42005C==0x00000001")]` syntax.
use std::{
    cell::{RefCell, RefMut},
    cmp::Ordering,
    collections::HashMap,
    convert::TryFrom,
    io::{Cursor, Read},
    rc::Rc,
    str::FromStr,
};

use serde::{
    de::{EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor},
    Deserialize, Deserializer,
};

use crate::{
    error::Error,
    error::Result,
    types::{ItemTag, ItemType},
    types::{SerializableTtlvType, TtlvDateTime, TtlvEnumeration, TtlvInteger, TtlvLongInteger, TtlvTextString},
};

// --- Public interface ------------------------------------------------------------------------------------------------

pub fn from_slice<'de, T>(bytes: &'de [u8]) -> Result<T>
where
    T: Deserialize<'de>,
{
    let mut deserializer = TtlvDeserializer::from_slice(bytes);
    T::deserialize(&mut deserializer)
}

// --- Private implementation details ----------------------------------------------------------------------------------

impl serde::de::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Self::Other(format!("Serde deserialization error: {}", msg))
    }
}

//======================================================================================================================
// ROOT DESERIALIZER
//======================================================================================================================

struct TtlvDeserializer<'de> {
    src: Cursor<&'de [u8]>,
}

impl<'de> TtlvDeserializer<'de> {
    pub fn from_slice(bytes: &'de [u8]) -> Self {
        Self {
            src: Cursor::new(bytes),
        }
    }
}

/// Here we implement the Serde Deserializer trait functions that we need to support. The more of the interface that we
/// implement and the richer the implementation then the more flexibly the client can use serde to transpose the data
/// into their own desired layout.
impl<'de> Deserializer<'de> for &mut TtlvDeserializer<'de> {
    type Error = Error;

    // The client is expected to invoke the serializer on a Rust struct. The entrypoint for deserialization is thus one
    // of the serde struct deserializer functions. To make the most readable and obvious client interface I would
    // expect the client to use named struct fields, i.e. not to use a tuple or unit struct. As such we implement only
    // deserialize_struct() for now. Instruct serde about the types that we do not support deserialization to:
    serde::forward_to_deserialize_any! {
        bool u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 char str map string seq bytes byte_buf option unit newtype_struct
        ignored_any unit_struct tuple_struct tuple enum identifier
    }

    /// If the caller defines something like this:
    ///
    /// ```ignore
    /// #[derive(Deserialize)]
    /// #[serde(rename = "0xAABBCC")]
    /// struct MyType {
    ///     some_num: i32
    /// }
    /// ```
    ///
    /// Then we will be invoked as deserialize_struct(self, "0xAABBCC", ["some_num"], visitor). Notice that we lose any
    /// knowledge of the struct name, but that has no meaning for us anyway as it is a name the client chooses that is
    /// most meaningful to their domain. We need to know the TTLV tag value, the 0xAABBCC, so that we can check that the
    /// TTLV tree or subtree that we are currently processing is for the same tag as specified by the client and thus we
    /// are putting the right data into the target struct, not by accident putting some arbitrary integer value into
    /// some_num but instead only the integer value that was transmitted over the wire as belonging to TTLV tag
    /// 0xAABBCC.
    ///
    /// We can use the given count of field names (but not their values as they have no meaning to us) to know how many
    /// TTLV structure fields we should publish to the visitor in order to finish populating the client struct.
    fn deserialize_struct<V>(self, name: &'static str, fields: &'static [&'static str], visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // Serde documentation says that:
        //
        //     "The implementation supports two possible ways that a struct may be represented by a data format: as a
        //      seq like in Bincode, and as a map like in JSON."
        //
        //     Source: https://serde.rs/deserialize-struct.html
        //
        // The SeqAccess trait expects a sequence of elements, while the MapAccess trait expects a sequence of element
        // key value pairs. TTLV structs are a sequence of tagged (i.e. keyed) values and thus match the MapAccess
        // approach.

        visitor.visit_map(TtlvStructureFieldAccess::new(
            self.src.clone(),
            fields,
            ItemTag::from_str(name).ok(),
        ))
    }

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::DeserializeError)
    }
}

//======================================================================================================================
// HELPER FUNCTIONS
//======================================================================================================================

fn read_item_tag(src: &mut Cursor<&[u8]>) -> Result<ItemTag> {
    let mut raw_item_tag = [0u8; 3];
    src.read_exact(&mut raw_item_tag)?;
    let item_tag = ItemTag::from(raw_item_tag);
    Ok(item_tag)
}

fn read_raw_item_type(src: &mut Cursor<&[u8]>) -> Result<u8> {
    let mut raw_item_type = [0u8; 1];
    src.read_exact(&mut raw_item_type)?;
    Ok(raw_item_type[0])
}

fn read_value_length(src: &mut Cursor<&[u8]>) -> Result<u32> {
    let mut value_length = [0u8; 4];
    src.read_exact(&mut value_length)?;
    Ok(u32::from_be_bytes(value_length))
}

//======================================================================================================================
// STRUCTURE FIELD ACCESS DESERIALIZATION HELPER
//======================================================================================================================

struct TtlvStructureFieldAccess<'de> {
    src: Cursor<&'de [u8]>,
    fields: &'static [&'static str],
    read_field_count: usize,
    expected_tag: Option<ItemTag>,
    end_pos: Option<u64>,
    struct_start_pos: Option<u64>,
    item_type: Option<u8>,
    enum_tag_positions: Rc<RefCell<HashMap<ItemTag, String>>>,
}

impl<'de> TtlvStructureFieldAccess<'de> {
    fn new(src: Cursor<&'de [u8]>, fields: &'static [&'static str], expected_tag: Option<ItemTag>) -> Self {
        Self {
            src,
            fields,
            read_field_count: 0,
            expected_tag,
            end_pos: None,
            struct_start_pos: None,
            item_type: None,
            enum_tag_positions: Rc::new(RefCell::new(HashMap::new())),
        }
    }
}

impl<'de> MapAccess<'de> for TtlvStructureFieldAccess<'de> {
    type Error = Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: serde::de::DeserializeSeed<'de>,
    {
        if self.end_pos.is_some() {
            // We're already initialized so we must have just read a key and a value. Bump the count of fields read.
            self.read_field_count += 1;
        } else {
            // We haven't read the structure header yet. Verify that we indeed that the next bytes in the buffer define
            // a TTLV structure and find out how long the structure is so that we don't attempt to read structure fields
            // beyond the end of the TTLV structure value bytes.
            let item_tag = read_item_tag(&mut self.src)?;
            if let Some(expected_tag) = self.expected_tag {
                if item_tag != expected_tag {
                    return Err(Error::UnexpectedTtlvTag(expected_tag, item_tag.to_string()));
                }
            }

            let item_type = read_raw_item_type(&mut self.src)?;
            if item_type != (ItemType::Structure as u8) {
                return Err(Error::UnexpectedTtlvType(ItemType::Structure, item_type));
            }

            // Note: it's unclear from the KMIP v1.0 spec if the value length is an unsigned integer, or a KMIP Integer,
            // or a 2's complement integer... assuming for now that's it a big endian u32.
            let value_length = read_value_length(&mut self.src)?;

            // Remember the end position of this structure so that when reading subsequent keys we can check that we
            // haven't reached the end of the structure.
            self.end_pos = Some(self.src.position() + (value_length as u64));
        }

        // Have we already read the expected number of fields?
        if self.read_field_count >= self.fields.len() {
            return Ok(None);
        }

        // Have we reached the end of the structure value?
        if self.src.position() > self.end_pos.unwrap() {
            return Ok(None);
        }

        self.struct_start_pos = Some(self.src.position());
        self.item_type = None;

        seed.deserialize(self).map(Some)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value>
    where
        V: serde::de::DeserializeSeed<'de>,
    {
        // sanity checks
        if self.end_pos.is_none() {
            return Err(Error::DeserializeError);
        }

        if self.read_field_count >= self.fields.len() {
            return Err(Error::DeserializeError);
        }

        if self.src.position() > self.end_pos.unwrap() {
            return Err(Error::DeserializeError);
        }

        self.item_type = Some(read_raw_item_type(&mut self.src)?);

        seed.deserialize(self)
    }
}

impl<'de> SeqAccess<'de> for TtlvStructureFieldAccess<'de> {
    type Error = Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        // sanity checks
        if self.end_pos.is_none() {
            return Err(Error::DeserializeError);
        }

        match self.src.position().cmp(&self.end_pos.unwrap()) {
            Ordering::Less => {
                // We're not done yet, keep going...
            }
            Ordering::Equal => {
                // This is the end of the structure that contains this sequence
                return Ok(None);
            }
            Ordering::Greater => {
                // We ran off the end of the buffer, this shouldn't be possible!
                return Err(Error::DeserializeError);
            }
        }

        seed.deserialize(self).map(Some)
    }
}

struct TtlvEnumVariantAccess<'de> {
    src: Cursor<&'de [u8]>,
    enum_tag_positions: Rc<RefCell<HashMap<ItemTag, String>>>,
}

impl<'de> TtlvEnumVariantAccess<'de> {
    fn new(src: Cursor<&'de [u8]>, enum_tag_positions: Rc<RefCell<HashMap<ItemTag, String>>>) -> Self {
        Self {
            src,
            enum_tag_positions,
        }
    }
}

impl<'de> EnumAccess<'de> for TtlvEnumVariantAccess<'de> {
    type Error = Error;
    type Variant = Self;

    fn variant_seed<V>(mut self, seed: V) -> Result<(V::Value, Self::Variant)>
    where
        V: serde::de::DeserializeSeed<'de>,
    {
        let val = seed.deserialize(&mut self)?;
        Ok((val, self))
    }
}

impl<'de> VariantAccess<'de> for TtlvEnumVariantAccess<'de> {
    type Error = Error;

    fn unit_variant(self) -> Result<()> {
        Ok(())
    }

    fn newtype_variant_seed<T>(self, _seed: T) -> Result<T::Value>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        unimplemented!()
    }

    fn tuple_variant<V>(self, _len: usize, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn struct_variant<V>(self, _fields: &'static [&'static str], _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
}

impl<'de> Deserializer<'de> for &mut TtlvEnumVariantAccess<'de> {
    type Error = Error;

    serde::forward_to_deserialize_any! {
        bool u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 char str string bytes byte_buf map option unit
        ignored_any unit_struct tuple_struct tuple enum newtype_struct seq struct
    }

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.src.set_position(self.src.position() - 4);
        let item_tag = read_item_tag(&mut self.src)?;
        let item_type = read_raw_item_type(&mut self.src)?;
        if item_type != (ItemType::Enumeration as u8) {
            return Err(Error::DeserializeError);
        }
        let v = TtlvEnumeration::read(&mut self.src)?;
        let n = format!("0x{}", hex::encode_upper(v.to_be_bytes()));
        let mut map: RefMut<_> = self.enum_tag_positions.borrow_mut();
        map.insert(item_tag, n.clone());
        visitor.visit_string(n)
    }
}

///

struct TtlvEnumOneVariantAccess<'de> {
    src: Cursor<&'de [u8]>,
    one_variant: &'static str,
}

impl<'de> TtlvEnumOneVariantAccess<'de> {
    fn new(src: Cursor<&'de [u8]>, one_variant: &'static str) -> Self {
        Self { src, one_variant }
    }
}

impl<'de> EnumAccess<'de> for TtlvEnumOneVariantAccess<'de> {
    type Error = Error;
    type Variant = Self;

    fn variant_seed<V>(mut self, seed: V) -> Result<(V::Value, Self::Variant)>
    where
        V: serde::de::DeserializeSeed<'de>,
    {
        let val = seed.deserialize(&mut self)?;
        Ok((val, self))
    }
}

impl<'de> VariantAccess<'de> for TtlvEnumOneVariantAccess<'de> {
    type Error = Error;

    fn unit_variant(self) -> Result<()> {
        //Ok(())
        unimplemented!()
    }

    fn newtype_variant_seed<T>(mut self, seed: T) -> Result<T::Value>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        seed.deserialize(&mut self)
    }

    fn tuple_variant<V>(self, _len: usize, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn struct_variant<V>(self, _fields: &'static [&'static str], _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
}

impl<'de> Deserializer<'de> for &mut TtlvEnumOneVariantAccess<'de> {
    type Error = Error;

    serde::forward_to_deserialize_any! {
        bool u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 char str string bytes byte_buf map option unit
        ignored_any unit_struct tuple_struct tuple enum newtype_struct seq
    }

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_str(self.one_variant)
    }

    fn deserialize_struct<V>(self, name: &'static str, fields: &'static [&'static str], visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_map(TtlvStructureFieldAccess::new(
            self.src.clone(),
            fields,
            ItemTag::from_str(name).ok(),
        ))
    }
}

///

impl<'de> Deserializer<'de> for &mut TtlvStructureFieldAccess<'de> {
    type Error = Error;

    serde::forward_to_deserialize_any! {
        bool u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 char str string bytes byte_buf map option unit
        ignored_any unit_struct tuple_struct tuple
    }

    /// Invoked to deserialize struct field keys.
    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // Expect the next bytes in the buffer to be the start of a TTLV.
        let item_tag = read_item_tag(&mut self.src)?;

        let expected_tag_str = self.fields.get(self.read_field_count).ok_or(Error::DeserializeError)?;
        let expected_tag = ItemTag::from_str(expected_tag_str)?;
        if item_tag != expected_tag {
            return Err(Error::UnexpectedTtlvTag(expected_tag, item_tag.to_string()));
        }

        visitor.visit_str(expected_tag_str)
    }

    fn deserialize_struct<V>(self, name: &'static str, fields: &'static [&'static str], visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let mut inner_cursor = self.src.clone();
        inner_cursor.set_position(self.struct_start_pos.unwrap());

        let r = visitor.visit_map(TtlvStructureFieldAccess::new(
            inner_cursor,
            fields,
            ItemTag::from_str(name).ok(),
        ))?;

        // Reset our cursor as we let the field accessor modify the underlying buffer using its own cursor and so ours
        // no longer reflects the correct read position. We know however that we finished processing the struct and so
        // the next read position must be after the struct. Find out where the end of the struct is and skip it.
        self.src.set_position(self.struct_start_pos.unwrap() + 4);
        let len_to_skip = read_value_length(&mut self.src)? as u64;
        self.src.set_position(self.src.position() + len_to_skip);
        Ok(r)
    }

    // e.g.
    //    #[derive(Debug, Deserialize)]
    //    #[serde(rename = "0x42000D")]
    //    struct BatchCount(i32);
    fn deserialize_newtype_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // Assume we have been called from deserialize_value_seed() and that the item tag has already been read.
        visitor.visit_newtype_struct(self)
    }

    // e.g.
    //   #[serde(rename = "0x42000F")]
    //   items: Vec<BatchItem>,
    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_seq(self)
    }

    fn deserialize_enum<V>(self, _name: &'static str, variants: &'static [&'static str], visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // are we really deserializing an enum, or is an enum being used as a way to select one of many structs into
        // which to deserialize and the next value in the data is actually a TTLV structure?
        match self.item_type {
            Some(item_type) if item_type == (ItemType::Enumeration as u8) => {
                let r = visitor.visit_enum(TtlvEnumVariantAccess::new(
                    self.src.clone(),
                    self.enum_tag_positions.clone(),
                ))?;
                // Skip the enum value length and value fields as we just processed them.
                self.src.set_position(self.src.position() + 12);
                Ok(r)
            }
            Some(item_type) if item_type == (ItemType::Structure as u8) => {
                // IDEA: if _variants[n] is of the form "0xA==0xB" find 0xA in the byte stream (going backwards from
                // our current position) and assume it is the tag of an Enumeration TTLV, read out its value and see if
                // it matches 0xB. For the _variants[n] entry that satisfies this test, cause an EnumAccess instance to
                // call visitor.string(str) from its `fn deserialize_identifier()`. E.g. if 0xA were found, the str
                // value would be the whole of "0xA==0xB" thereby causing Serde to pick that enum variant. An example of
                // this could be selecting the right Response Payload enum variant based on the previous Operation enum
                // value.
                for v in variants {
                    if let Some((enum_tag, enum_val)) = v.strip_prefix("if ").unwrap_or("").split_once("==") {
                        if let Some(val) = self.enum_tag_positions.borrow().get(&ItemTag::from_str(enum_tag)?) {
                            if val == enum_val {
                                // Use this variant

                                // if we are going to treat this as a structure we need to walk back to the start of the
                                // tag
                                let mut inner_src = self.src.clone();
                                inner_src.set_position(self.struct_start_pos.unwrap());
                                let r = visitor.visit_enum(TtlvEnumOneVariantAccess::new(inner_src, v))?;
                                // Skip the enum value length and value fields as we just processed them.
                                self.src.set_position(self.src.position() + 12);
                                return Ok(r);
                            }
                        }
                    }
                }

                Err(Error::DeserializeError)
            }
            Some(item_type) => Err(Error::UnexpectedTtlvType(ItemType::Enumeration, item_type)),
            None => Err(Error::DeserializeError),
        }
    }

    /// Invoked to deserialize struct field values.
    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        match ItemType::try_from(self.item_type.unwrap())? {
            ItemType::Integer => {
                let v = TtlvInteger::read(&mut self.src)?;
                visitor.visit_i32(*v)
            }
            ItemType::LongInteger => {
                let v = TtlvLongInteger::read(&mut self.src)?;
                visitor.visit_i64(*v)
            }
            ItemType::Enumeration => {
                let r = visitor.visit_enum(TtlvEnumVariantAccess::new(
                    self.src.clone(),
                    self.enum_tag_positions.clone(),
                ))?;
                // Skip the enum value length and value fields as we just processed them.
                self.src.set_position(self.src.position() + 12);
                Ok(r)
            }
            ItemType::Boolean => {
                unimplemented!()
            }
            ItemType::TextString => {
                let v = TtlvTextString::read(&mut self.src)?;
                visitor.visit_string(v.0)
            }
            ItemType::DateTime => {
                let v = TtlvDateTime::read(&mut self.src)?;
                visitor.visit_i64(*v)
            }
            ItemType::Structure => Err(Error::DeserializeError),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::de::from_slice;

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
    struct ResponseMessage {
        #[serde(rename = "0x42007A")]
        header: ResponseHeader,
        #[serde(rename = "0x42000F")]
        items: Vec<BatchItem>,
    }

    #[derive(Debug, Deserialize)]
    struct ResponseHeader {
        #[serde(rename = "0x420069")]
        ver: ProtocolVersion,
        #[serde(rename = "0x420092")]
        timestamp: i64,
        #[serde(rename = "0x42000D")]
        item_count: i32,
    }

    #[derive(Debug, Deserialize)]
    struct ProtocolVersion {
        #[serde(rename = "0x42006A")]
        major: i32,
        #[serde(rename = "0x42006B")]
        minor: i32,
    }

    #[derive(Debug, Deserialize)]
    struct BatchItem {
        #[serde(rename = "0x42005C")]
        operation: Operation,
        #[serde(rename = "0x42007F")]
        status: ResultStatus,
        #[serde(rename = "0x42007C")]
        payload: ResponsePayload,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    enum Operation {
        #[serde(rename = "0x00000001")]
        Create,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    enum ResultStatus {
        #[serde(rename = "0x00000000")]
        Success,
    }

    #[derive(Debug, Deserialize)]
    enum ResponsePayload {
        #[serde(rename = "if 0x42005C==0x00000001")]
        Create(CreateResponsePayload),
        Other(SomeOtherResponsePayload),
    }

    #[derive(Debug, Deserialize)]
    struct CreateResponsePayload {
        #[serde(rename = "0x420057")]
        object_type: ObjectType,
        #[serde(rename = "0x420094")]
        unique_id: String,
    }

    #[derive(Debug, Deserialize)]
    struct SomeOtherResponsePayload {
        dummy_field: i32,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    enum ObjectType {
        #[serde(rename = "0x00000002")]
        SymmetricKey,
    }

    #[test]
    fn simple_test() {
        // Each of the child TTLV integer items below is 16 bytes, so 32 in total which is 0x20 in hexadecimal.
        // 01 means we are defining a structure.
        let struct_hdr = "AAAAAA  01  00000020";

        // Define the child TTLV integer items. 02 means we are defining an integer. Each integer is 32-bit thus has a
        // 4-byte value length, but must be padded with zeros to an 8-byte length.
        //   TAG     TYPE  LEN       INTVAL    PADDING
        let raw_ints = [
            "BBBBBB  02  00000004  00000001  00000000",
            "CCCCCC  02  00000004  00000002  00000000",
        ];

        // Combine the struct header and payload items together
        let mut test_data = String::new();
        test_data.push_str(struct_hdr);
        test_data.push_str(&raw_ints.join(""));

        // Now define a Rust structure to hold this data
        #[derive(Debug, Deserialize)]
        #[serde(rename = "0xAAAAAA")]
        struct MyIntContainer {
            #[serde(rename = "0xBBBBBB")]
            a: i32,
            #[serde(rename = "0xCCCCCC")]
            b: i32,
        }

        // Now attempt to deserialize the hex byte string into the MyIntContainer
        let ttlv_wire = hex::decode(test_data.replace(" ", "")).unwrap();
        let r: MyIntContainer = from_slice(ttlv_wire.as_ref()).unwrap();
        dbg!(r);
    }

    #[test]
    fn test_kmip_10_create_destroy_use_case_create_response_deserialization() {
        // Attempt to parse correctly the binary response TTLV for KMIP specification v1.0 use case 3.1.1 Create /
        // Destroy as the use case definition includes the binary output and the corresponding deserialized structure.
        // See: http://docs.oasis-open.org/kmip/usecases/v1.0/cs01/kmip-usecases-1.0-cs-01.pdf

        let use_case_input = "42007B01000000C042007A0100000048420069010000002042006A0200000004000000010000000042006B020000000400000000000000004200920900000008000000004AFBE7C242000D0200000004000000010000000042000F010000006842005C0500000004000000010000000042007F0500000004000000000000000042007C010000004042005705000000040000000200000000420094070000002466633838333364652D373064322D346563652D623036332D66656465336133633539666500000000";
        let ttlv_wire = hex::decode(use_case_input).unwrap();
        let r: ResponseMessage = from_slice(ttlv_wire.as_ref()).unwrap();

        assert_eq!(r.header.ver.major, 1);
        assert_eq!(r.header.ver.minor, 0);
        assert_eq!(r.header.timestamp, 0x000000004AFBE7C2); // This can be made more user friendly
        assert_eq!(r.header.item_count, 1);

        assert_eq!(r.items.len(), 1);

        let item = &r.items[0];
        assert_eq!(item.operation, Operation::Create);
        assert_eq!(item.status, ResultStatus::Success);
        if let ResponsePayload::Create(payload) = &item.payload {
            assert_eq!(payload.object_type, ObjectType::SymmetricKey);
            assert_eq!(&payload.unique_id, "fc8833de-70d2-4ece-b063-fede3a3c59fe");
        } else {
            panic!("Wrong payload");
        }
    }
}
