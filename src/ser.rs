//! Serialize a Rust data structure into TTLV data.

use std::{io::Write, str::FromStr};

use serde::{
    ser::{self, Impossible},
    Serialize,
};
use types::{TtlvBoolean, TtlvEnumeration, TtlvInteger, TtlvLongInteger, TtlvTextString};

use crate::{
    error::{Error, Result},
    types::{self, ItemTag, ItemType, SerializableTtlvType, TtlvDateTime},
};

// --- Public interface ------------------------------------------------------------------------------------------------

pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut ser = Serializer::new();
    value.serialize(&mut ser)?;
    ser.into_vec()
}

impl std::error::Error for Error {}

impl serde::ser::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Self::Other(format!("Serde serialization error: {}", msg))
    }
}

// --- Private implementation details ----------------------------------------------------------------------------------

#[derive(Default)]
pub struct Serializer {
    /// The destination buffer to serialize TTLV bytes into. If we want to write to something else in future we will need
    /// a way to be able to write to an earlier position in the output so that we can rewrite an items length value once
    /// we know how long it is (with padding rules per TTLV type taken into account). Currently this is done simply by
    /// indexing directly into the output buffer. An alternate approach could be to require the Seek trait to be
    /// implemented.
    dst: Vec<u8>,

    /// A push/pop stack of indexes into the `dst` buffer to the points at which TTLV value byte lengths must be returned
    /// to and overwritten once the length of the value being written, and any padding to ignore, is known.
    bookmarks: Vec<usize>,

    in_tag_header: bool,

    in_enum: bool,
}

impl Serializer {
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
    fn write_tag(&mut self, item_tag: ItemTag) -> Result<()> {
        if self.in_tag_header {
            self.write_type(ItemType::Structure)?;
            self.write_zero_len()?;
        }
        self.dst.write_all(&<[u8; 3]>::from(item_tag))?;
        self.in_tag_header = true;
        self.in_enum = false;
        Ok(())
    }

    /// Write the TTLV item type ("a byte containing a coded value"). This will advance the buffer write position by
    /// 1 byte.
    fn write_type(&mut self, item_type: ItemType) -> Result<()> {
        self.dst.write_all(&[item_type as u8])?;
        Ok(())
    }

    /// Push a dummy 0x000000 4-byte TTLV item length. After writing the value bytes we'll come back later and replace
    /// the dummy bytes with the correct item length. Adds a bookmark at the current buffer write location so that
    /// fn rewite_len() knows where to come back to.
    fn write_zero_len(&mut self) -> Result<()> {
        self.dst.write_all(&[0u8, 0u8, 0u8, 0u8])?;
        self.in_tag_header = false;
        self.bookmarks.push(self.dst.len());
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
        while !self.bookmarks.is_empty() {
            self.rewrite_len()?;
        }
        Ok(())
    }
}

impl serde::ser::Serializer for &mut Serializer {
    type Ok = ();
    type Error = Error;

    // =======================================================
    // RUST TYPES FOR WHICH SERIALIZATION TO TTLV IS SUPPORTED
    // =======================================================
    type SerializeSeq = Self;
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
        self.write_tag(ItemTag::from_str(name)?)?;
        Ok(self)
    }

    /// Serialize a Rust bool value into the TTLV write buffer as TTLV type 0x06 (Boolean).
    fn serialize_bool(self, v: bool) -> Result<()> {
        TtlvBoolean(v).write(&mut self.dst)?;
        self.in_tag_header = false;
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
        TtlvInteger(v).write(&mut self.dst)?;
        self.in_tag_header = false;
        Ok(())
    }

    /// Serialize a Rust unsigned 32-bit integer value into the TTLV write buffer as TTLV type 0x05 (Enumeration).
    fn serialize_u32(self, v: u32) -> Result<()> {
        TtlvEnumeration(v).write(&mut self.dst)?;
        self.in_tag_header = false;
        Ok(())
    }

    /// Serialize a Rust integer value into the TTLV write buffer as TTLV type 0x03 (Long Integer).
    fn serialize_i64(self, v: i64) -> Result<()> {
        TtlvLongInteger(v).write(&mut self.dst)?;
        self.in_tag_header = false;
        Ok(())
    }

    /// Serialize a Rust unsigned 64-bit integer value into the TTLV write buffer as TTLV type 0x09 (DateTime).
    ///
    /// TTLV DateTime values are serialized as a signed 64-bit value but as we need to ensure that we serialize the
    /// correct TTLV type we can't handle these in serialize_i64 as that is already used for TTLV type 0x03
    /// (Long Integer).
    fn serialize_u64(self, v: u64) -> Result<()> {
        TtlvDateTime(v as i64).write(&mut self.dst)?;
        self.in_tag_header = false;
        Ok(())
    }

    /// Serialize a Rust str value into the TTLV write buffer as TTLV type 0x07 (Text String).
    fn serialize_str(self, v: &str) -> Result<()> {
        TtlvTextString(v.to_string()).write(&mut self.dst)?;
        self.in_tag_header = false;
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
        if !self.in_enum {
            // Quick hack to permit an enum to be used as a child of the AttributeValue tag with the value being written
            // serialized TTLV Enumeration but without the value having its own tag and type.
            self.write_tag(ItemTag::from_str(name)?)?;
        }
        let variant = u32::from_str_radix(variant.trim_start_matches("0x"), 16)?;
        TtlvEnumeration(variant).write(&mut self.dst)?;
        self.in_tag_header = false;
        Ok(())
    }

    /// Serialize a struct SomeStruct(type) to the TTLV write buffer as if it were the naked type without the enclosing
    /// "newtype" SomeStruct wrapper.
    fn serialize_newtype_struct<T: ?Sized>(self, name: &'static str, value: &T) -> Result<()>
    where
        T: Serialize,
    {
        self.write_tag(ItemTag::from_str(name)?)?;
        value.serialize(self)?;
        Ok(())
    }

    /// Serialize a struct SomeStruct(a, b, c) to the TTLV write buffer as if it were the naked type without the
    /// enclosing SomeStruct "tuple" wrapper.
    fn serialize_tuple_variant(
        self,
        name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        self.write_tag(ItemTag::from_str(name)?)?;
        Ok(self)
    }

    fn serialize_newtype_variant<T: ?Sized>(
        self,
        name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<()>
    where
        T: Serialize,
    {
        self.write_tag(ItemTag::from_str(name)?)?;
        self.in_enum = true;
        value.serialize(self)?;
        Ok(())
    }

    /// Dispatch serialization of a Rust sequence type such as Vec to the implementation of SerializeSeq that we
    /// provide.
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq> {
        // When we have an enum containing an enum in Rust (e.g. a KMIP attribute with an Enumeration value) that is
        // expressed in TTLV as a single enum tag and for that case we earlier set self.in_enum = true. However, if the
        // enum instead contains (e.g. a vec) then it represents the dynamic payload scenario where one of several
        // structures are possible and are used via a Rust enum but in that case we want to serialize a TTLV Structure
        // so disable the special enum in enum behaviour.
        self.in_enum = false;
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
    type SerializeStruct = Impossible<(), Self::Error>;
    type SerializeStructVariant = Impossible<(), Self::Error>;
    type SerializeTuple = Impossible<(), Self::Error>;

    fn serialize_u8(self, _v: u8) -> Result<()> {
        Err(Self::Error::UnsupportedType("u8"))
    }

    fn serialize_u16(self, _v: u16) -> Result<()> {
        Err(Self::Error::UnsupportedType("u16"))
    }

    fn serialize_f32(self, _v: f32) -> Result<()> {
        Err(Self::Error::UnsupportedType("f32"))
    }

    fn serialize_f64(self, _v: f64) -> Result<()> {
        Err(Self::Error::UnsupportedType("f64"))
    }

    fn serialize_char(self, _v: char) -> Result<()> {
        Err(Self::Error::UnsupportedType("char"))
    }

    fn serialize_bytes(self, _v: &[u8]) -> Result<()> {
        Err(Self::Error::UnsupportedType("&[u8]"))
    }

    /// Serializing `None` values, e.g. Option::<TypeName>::None, is not supported as we have already serialized the
    /// item tag to the output by the time we process the `Option` value. The correct way to omit None values is to not
    /// attempt to serialize them at all, e.g. using the `#[serde(skip_serializing_if = "Option::is_none")]` Serde
    /// derive field attribute.
    fn serialize_none(self) -> Result<()> {
        Err(Self::Error::UnsupportedType("None"))
    }

    fn serialize_unit(self) -> Result<()> {
        Err(Self::Error::UnsupportedType("unit"))
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        Err(Self::Error::UnsupportedType("unit struct"))
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple> {
        Err(Self::Error::UnsupportedType("tuple"))
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        Err(Self::Error::UnsupportedType("map"))
    }

    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeStruct> {
        Err(Self::Error::UnsupportedType("struct"))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        Err(Self::Error::UnsupportedType("struct variant"))
    }
}

// =======================================
// SERIALIZATION OF RUST SEQUENCES TO TTLV
// =======================================
impl ser::SerializeSeq for &mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T: ?Sized>(&mut self, value: &T) -> Result<()>
    where
        T: Serialize,
    {
        value.serialize(&mut **self)?;
        Ok(())
    }

    fn end(self) -> Result<()> {
        if self.in_tag_header {
            // We emited a tag then started an empty sequence and thus never wrote a type or length to the byte stream.
            // If another tag were to be written this would be caught by write_tag(), but if this sequence is the last
            // TTLV item to be written this will not be caught in time to correctly calculate the length of the parent
            // structure. As a sequence can only be contained by a structure so assume this should be an empty
            // structure.
            self.write_type(ItemType::Structure)?;
            self.write_zero_len()?;
        }
        Ok(())
    }
}

// ===========================================
// SERIALIZATION OF RUST TUPLE STRUCTS TO TTLV
// ===========================================
impl ser::SerializeTupleStruct for &mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: ?Sized>(&mut self, value: &T) -> Result<()>
    where
        T: Serialize,
    {
        value.serialize(&mut **self)?;
        Ok(())
    }

    fn end(self) -> Result<()> {
        // This fn is called at the end of serializing a Struct.
        // TODO: go back to the length byte pos in the vec and write in our distance from that point
        // Either we need to receive back from ... from where? we get no values passed to us, so instead we need to
        // store the position to go back to in the vec, but we'll need to do that for each level of struct nesting, push
        // them on and pop them off.
        self.rewrite_len()?;
        Ok(())
    }
}

// ============================================
// SERIALIZATION OF RUST TUPLE VARIANTS TO TTLV
// ============================================
impl ser::SerializeTupleVariant for &mut Serializer {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: ?Sized>(&mut self, value: &T) -> Result<()>
    where
        T: Serialize,
    {
        value.serialize(&mut **self)?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok> {
        // This fn is called at the end of serializing a tuple variant.
        // TODO: go back to the length byte pos in the vec and write in our distance from that point
        // Either we need to receive back from ... from where? we get no values passed to us, so instead we need to
        // store the position to go back to in the vec, but we'll need to do that for each level of struct nesting, push
        // them on and pop them off.
        self.rewrite_len()?;
        Ok(())
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
        #[serde(rename = "0x42006B")]
        struct ProtocolVersionMinor(i32);

        #[derive(Serialize)]
        #[serde(rename = "0x42006A")]
        struct ProtocolVersionMajor(i32);

        #[derive(Serialize)]
        #[serde(rename = "0x420069")]
        struct ProtocolVersion(ProtocolVersionMajor, ProtocolVersionMinor);

        #[derive(Serialize)]
        #[serde(rename = "0x42000D")]
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
        #[serde(rename = "0x42000A")]
        struct AttributeName(&'static str);

        #[derive(Serialize)]
        #[serde(rename = "0x42000B")]
        enum AttributeValue {
            CryptographicAlgorithm(CryptographicAlgorithm),
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

        let use_case_output = "42007801000001204200770100000038420069010000002042006A0200000004000000010000000042006B0200000004000000000000000042000D0200000004000000010000000042000F01000000D842005C0500000004000000010000000042007901000000C04200570500000004000000020000000042009101000000A8420008010000003042000A070000001743727970746F6772617068696320416C676F726974686D0042000B05000000040000000300000000420008010000003042000A070000001443727970746F67726170686963204C656E6774680000000042000B02000000040000008000000000420008010000003042000A070000001843727970746F67726170686963205573616765204D61736B42000B02000000040000000C00000000";

        assert_eq!(use_case_output, hex::encode_upper(to_vec(&use_case_input).unwrap()));
    }

    #[test]
    fn test_some_option_ttlv_item() {
        #[derive(Serialize)]
        #[serde(rename = "0xAABBCC")]
        struct ItemWithOptionalField(Option<i32>);
        let with_some = ItemWithOptionalField(Some(3));

        #[derive(Serialize)]
        #[serde(rename = "0xAABBCC")]
        struct ItemWithoutOptionalField(i32);
        let without_some = ItemWithoutOptionalField(3);

        let encoded_with_some = hex::encode_upper(to_vec(&with_some).unwrap());
        let encoded_without_some = hex::encode_upper(to_vec(&without_some).unwrap());

        assert_eq!(encoded_with_some, encoded_without_some);
    }
}
