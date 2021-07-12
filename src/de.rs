use std::{
    cell::{RefCell, RefMut},
    cmp::Ordering,
    collections::HashMap,
    convert::TryFrom,
    io::{Cursor, Read},
    ops::Deref,
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
    types::{ItemTag, ItemType, TtlvByteString},
    types::{
        SerializableTtlvType, TtlvBoolean, TtlvDateTime, TtlvEnumeration, TtlvInteger, TtlvLongInteger, TtlvTextString,
    },
};

// --- Public interface ------------------------------------------------------------------------------------------------

pub fn from_slice<'de, T>(bytes: &'de [u8]) -> Result<T>
where
    T: Deserialize<'de>,
{
    let cursor = &mut Cursor::new(bytes);
    let mut deserializer = TtlvDeserializer::from_slice(cursor);
    T::deserialize(&mut deserializer)
}

// --- Private implementation details ----------------------------------------------------------------------------------

impl serde::de::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Self::Other(format!("Serde deserialization error: {}", msg))
    }
}

trait ContextualErrorSupport {
    const WINDOW_SIZE: usize = 20;

    fn pos(&self) -> usize;
    fn buf(&self) -> &[u8];
    fn ctx(&self) -> String {
        let pos = self.pos();
        let buf_len = self.buf().len();
        let start = if pos > Self::WINDOW_SIZE {
            pos - Self::WINDOW_SIZE
        } else {
            0
        };
        let mut end = start + (2 * Self::WINDOW_SIZE);
        if end >= buf_len {
            end = buf_len - 1
        }

        let mut ctx = String::new();
        if start < pos {
            let range = start..pos;
            if range.len() > Self::WINDOW_SIZE {
                ctx.push_str("..")
            }
            ctx.push_str(&hex::encode_upper(self.buf()[range].to_vec()));
        }
        if pos < end {
            ctx.push_str(&format!(
                " >>{}<< ",
                &hex::encode_upper(self.buf()[pos..pos + 1].to_vec())
            ));
        } else {
            ctx.push_str(" >>{}<<");
        }
        if (pos + 1) < end {
            let range = (pos + 1)..end;
            let add_ellipsis = range.len() > Self::WINDOW_SIZE;
            ctx.push_str(&hex::encode_upper(self.buf()[range].to_vec()));
            if add_ellipsis {
                ctx.push_str("..")
            }
        }
        ctx
    }
    fn unknown_error(&self, fn_name: &str) -> Error {
        Error::DeserializeError {
            ctx: self.ctx(),
            pos: self.pos(),
            msg: format!("{}: internal error", fn_name),
        }
    }
    fn error(&self, fn_name: &str, msg: &str) -> Error {
        Error::DeserializeError {
            ctx: self.ctx(),
            pos: self.pos(),
            msg: format!("{}: internal error: {}", fn_name, msg),
        }
    }
}

struct TtlvDeserializer<'de: 'c, 'c> {
    src: &'c mut Cursor<&'de [u8]>,

    // for container/group types (map, seq)
    #[allow(dead_code)]
    group_start: u64,
    group_tag: Option<ItemTag>,
    group_type: Option<ItemType>,
    group_end: Option<u64>,
    group_fields: &'static [&'static str], // optional field handling: expected fields to compare to actual fields
    group_item_count: usize,               // optional field handling: index into the group_fields array

    // for the current field being parsed
    item_start: u64, // optional field handling: point to return to if field is missing
    item_tag: Option<ItemTag>,
    item_type: Option<ItemType>,
    item_unexpected: bool, // optional field handling: is this tag wrong for the expected field (and thus is missing?)
    item_identifier: Option<String>,

    // lookup maps
    tag_value_store: Rc<RefCell<HashMap<ItemTag, String>>>,
}

impl<'de: 'c, 'c> TtlvDeserializer<'de, 'c> {
    pub fn from_slice(cursor: &'c mut Cursor<&'de [u8]>) -> Self {
        Self {
            src: cursor,
            group_start: 0,
            group_tag: None,
            group_type: None,
            group_end: None,
            group_fields: &[],
            group_item_count: 0,
            item_start: 0,
            item_tag: None,
            item_type: None,
            item_unexpected: false,
            item_identifier: None,
            tag_value_store: Rc::new(RefCell::new(HashMap::new())),
        }
    }

    pub fn from_cursor(
        src: &'c mut Cursor<&'de [u8]>,
        group_tag: ItemTag,
        group_type: ItemType,
        group_end: u64,
        group_fields: &'static [&'static str],
        unit_enum_store: Rc<RefCell<HashMap<ItemTag, String>>>,
    ) -> Self {
        let group_start = src.position();
        let group_tag = Some(group_tag);
        let group_type = Some(group_type);
        let group_end = Some(group_end);

        Self {
            src,
            group_start,
            group_tag,
            group_type,
            group_end,
            group_fields,
            group_item_count: 0,
            item_start: group_start,
            item_tag: None,
            item_type: None,
            item_unexpected: false,
            item_identifier: None,
            tag_value_store: unit_enum_store,
        }
    }

    fn read_tag(&mut self) -> Result<ItemTag> {
        let mut raw_item_tag = [0u8; 3];
        self.src.read_exact(&mut raw_item_tag)?;
        let item_tag = ItemTag::from(raw_item_tag);
        Ok(item_tag)
    }

    fn read_type(&mut self) -> Result<ItemType> {
        let mut raw_item_type = [0u8; 1];
        self.src.read_exact(&mut raw_item_type)?;
        let item_type = ItemType::try_from(raw_item_type[0])?;
        Ok(item_type)
    }

    fn read_length(&mut self) -> Result<u32> {
        let mut value_length = [0u8; 4];
        self.src.read_exact(&mut value_length)?;
        Ok(u32::from_be_bytes(value_length))
    }

    /// Returns Ok(true) if there is data available, Ok(false) if the end of the group has been reached or Err()
    /// otherwise.
    fn read_item_key(&mut self, caller_fn_name: &'static str) -> Result<bool> {
        match self.pos().cmp(&(self.group_end.unwrap() as usize)) {
            Ordering::Less => {}
            Ordering::Equal => return Ok(false),
            Ordering::Greater => {
                return Err(self.error(
                    caller_fn_name,
                    &format!("buffer overrun: {} > {}", self.pos(), self.group_end.unwrap()),
                ))
            }
        }

        self.item_start = self.pos() as u64;
        self.item_tag = Some(self.read_tag()?);
        self.item_type = Some(self.read_type()?);

        self.group_item_count += 1;

        self.item_unexpected = if self.group_fields.is_empty() {
            false
        } else {
            let field_index = self.group_item_count - 1;
            let expected_tag_str = self.group_fields.get(field_index).ok_or_else(|| {
                self.error(
                    caller_fn_name,
                    &format!(
                        "expected field index is out of bounds {} >= {}",
                        field_index,
                        self.group_fields.len()
                    ),
                )
            })?;
            let actual_tag_str = &self.item_tag.unwrap().to_string();

            let item_unexpected = actual_tag_str != expected_tag_str;
            self.item_identifier = Some(expected_tag_str.to_string());

            item_unexpected
        };

        Ok(true)
    }

    fn get_start_tag_type(&mut self) -> Result<(u64, ItemTag, ItemType)> {
        let (group_start, group_tag, group_type) = if self.pos() == 0 {
            // When invoked by Serde via from_slice() there is no prior call to next_key_seed() that reads the tag and
            // type as we are not visiting a map at that point. Thus we need to read the opening tag and type here.
            let group_start = self.src.position();
            let group_tag = self.read_tag()?;
            let group_type = self.read_type()?;
            (group_start, group_tag, group_type)
        } else {
            // When invoked while visiting a map the opening tag and type of the struct header will have already been
            // read by next_key_seed() so we don't need to read them here.
            (self.src.position() - 4, self.item_tag.unwrap(), self.item_type.unwrap())
        };
        Ok((group_start, group_tag, group_type))
    }

    fn prepare_to_descend(
        &mut self,
        caller_fn_name: &'static str,
        name: &'static str,
    ) -> Result<(u64, ItemTag, ItemType, u64)> {
        let (group_start, group_tag, group_type) = self
            .get_start_tag_type()
            .map_err(|err| self.error(caller_fn_name, &err.to_string()))?;

        let group_len = self.read_length()?;
        let group_end = (self.pos() + (group_len as usize)) as u64;

        let wanted_tag =
            ItemTag::from_str(name).map_err(|_| self.error(caller_fn_name, &format!("'{}' is not a tag", name)))?;

        if group_tag != wanted_tag {
            return Err(self.error(
                caller_fn_name,
                &format!("Wanted tag '{}' but found '{}'", wanted_tag, group_tag),
            ));
        }

        if group_type != ItemType::Structure {
            return Err(self.error(
                caller_fn_name,
                &format!("Wanted type '{:?}' but found '{:?}'", ItemType::Structure, group_type),
            ));
        }

        Ok((group_start, group_tag, group_type, group_end))
    }

    fn is_variant_applicable(&self, variant: &'static str) -> Result<bool> {
        // TODO: this is horrible code.
        if let Some((wanted_tag, wanted_val)) = variant.strip_prefix("if ").and_then(|v| v.split_once("==")) {
            // Have we earlier seen a TTLV tag 'wanted_tag' and if so was its value 'wanted_val'? If so then this is
            // the variant name to announce to Serde that we are deserializing into.
            if let Some(seen_enum_val) = self.tag_value_store.borrow().get(&ItemTag::from_str(wanted_tag)?) {
                if *seen_enum_val == wanted_val {
                    return Ok(true);
                }
            }
        } else if let Some((wanted_tag, wanted_val)) = variant.strip_prefix("if ").and_then(|v| v.split_once(">=")) {
            if let Some(seen_enum_val) = self.tag_value_store.borrow().get(&ItemTag::from_str(wanted_tag)?) {
                if ItemTag::from_str(&seen_enum_val)?.deref() >= ItemTag::from_str(wanted_val)?.deref() {
                    return Ok(true);
                }
            }
        } else if let Some((wanted_tag, wanted_values)) = variant.strip_prefix("if ").unwrap_or("").split_once(" in ") {
            let wanted_values = wanted_values.strip_prefix("[").and_then(|v| v.strip_suffix("]"));
            if let Some(wanted_values) = wanted_values {
                if let Some(seen_enum_val) = self.tag_value_store.borrow().get(&ItemTag::from_str(wanted_tag)?) {
                    for wanted_value in wanted_values.split(",") {
                        if *seen_enum_val == wanted_value {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        Ok(false)
    }
}

impl<'de: 'c, 'c> ContextualErrorSupport for TtlvDeserializer<'de, 'c> {
    fn pos(&self) -> usize {
        self.src.position() as usize
    }

    fn buf(&self) -> &[u8] {
        self.src.get_ref()
    }
}

impl<'de: 'c, 'c> Deserializer<'de> for &mut TtlvDeserializer<'de, 'c> {
    type Error = Error;

    /// Deserialize the bytes at the current cursor position to a Rust structure.
    ///
    /// The use of a Rust structure by the caller is assumed to signify that the TTLV item should be of TTLV type
    /// "Structure". E.g. given something like:
    ///
    /// ```ignore
    /// #[derive(Deserialize)]
    /// #[serde(rename = "0x012345")]
    /// struct MyStruct {
    ///    a: i32,
    ///    b: MyOtherStruct,
    /// }
    /// ```
    ///
    /// This function will be invoked with the `name` parameter set to `0x012345` (or `MyStruct` if `rename` were not
    /// used), with the `fields` parameter set to `['a', 'b']`. Serde requires that we delegate to either `visit_map()`
    /// or `visit_seq()`. These delegates are responsible for issuing key/value pairs that correspond to the struct
    /// fields (e.g. `a` and `b` in the example above) being processed by Serde.
    ///
    /// For keys serde invokes `deserialize_identifier()` to parse out the field name from the byte stream and pass it
    /// to `visit_str()`.
    ///
    /// For values serde invokes the corresponding trait function in this impl, e.g. `deserialize_i32()`, to
    /// parse out the TTLV value and pass it to the corresponding visit function such as `visit_i32()`. For
    /// complex types such as a struct or vec the `deserialize_struct` (i.e. recursion) or `deserialize_seq` will be
    /// invoked.
    ///
    /// We have to be careful to handle correctly the fact that the Rust structure fields are "children" in the TTLV
    /// byte stream of a TTLV structure, e.g. for the example above the byte stream might contain TTLV bytes like so:
    ///
    /// ```text
    ///   TTLVVVVVVVVVVVVVVVVVV <- the TTLV representation of 'MyStruct'
    ///      TTLVVTTLVVVVVVVVVV <- the TTLV representation of 'a' and 'b' within 'MyStruct'
    /// ```
    ///
    /// Furthermore, field order in TTLV matters. We remember the given fields and if we encounter a field other than
    /// the one that we expect we flag it as unexpected. We can't immediately reject it because it could be that the
    /// caller wrapped the type to deserialize to in a Rust `Option` indicating that the TTLV item is optional. If when
    /// Serde asks us to process the value we will raise an error if we are not asked to process an `Option`.
    fn deserialize_struct<V>(self, name: &'static str, fields: &'static [&'static str], visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let (_, group_tag, group_type, group_end) = self.prepare_to_descend("deserialize_struct", name)?;

        let mut struct_cursor = self.src.clone();

        let descendent_parser = TtlvDeserializer::from_cursor(
            &mut struct_cursor,
            group_tag,
            group_type,
            group_end,
            fields,
            self.tag_value_store.clone(),
        );

        let r = visitor.visit_map(descendent_parser)?; // jumps to impl MapAccess below

        // The descendant parser cursor advanced but ours did not. Skip the tag that we just read.
        self.src.set_position(struct_cursor.position());

        Ok(r)
    }

    /// Deserialize the bytes at the current cursor position to a Rust struct with a single field.
    fn deserialize_newtype_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self) // jumps to to the appropriate deserializer fn such as deserialize_string()
    }

    /// Deserialize the bytes at the current cursor position to a Rust vector.
    ///
    /// The use of a Rust vector by the caller is assumed to signify that the next items in the TTLV byte stream will
    /// represent an instance of "MAY be repeated" in the KMIP 1.0 spec. E.g. for [section 4.24 Query of the KMIP 1.0 spec](https://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581232)
    /// for the Query operation response, one could represent the response like so:
    ///
    /// ```ignore
    /// struct QueryResponsePayload {     // OBJECT       REQUIRED
    ///    operations: Vec<Operation>,    // Operation    No, MAY be repeated
    ///    object_types: Vec<ObjectType>, // Object Type  No, MAY be repeated
    ///    ...
    /// }
    /// ```
    ///
    /// _(the inline comments quote the relevant parts of the KMIP 1.0 spec)_
    ///
    /// The KMIP 1.0 spec does not define the terminating conditions for a field that "MAY be repeated. This
    /// deserializer assumes that the sequence is limited by the L_ength of the TTLV item that contains it and that to
    /// be considered part of a "MAY be repeated" sequence the TTLV item must have the same tag and type as the previous
    /// items. Otherwise two adjacent "MAY be repeated" sequences within the same parent TTLV "Structure" would not have
    /// a clear boundary indicating when one sequence ends and the other starts. For example, checking the tag and type
    /// are needed to know whether the next TTLV item in the QueryResponsePayload example above is another item in the
    /// operations vector or is the first item in the object_types vector.
    ///
    /// When deserializing a structure the initial TTL is a sort of header for the structure, with the structure field
    /// values following the header as individual TTLV Items. When deserializing a sequence however the initial TTL is
    /// not separate to but rather belongs to the first item in the sequence.
    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let seq_start = self.item_start;
        let seq_tag = self.item_tag.unwrap();
        let seq_type = self.item_type.unwrap();
        let seq_end = self.group_end.unwrap();

        // We just read the tag, type and length but each item in the sequence needs to be read in its entirety as a
        // whole TTLV item so rewind the cursor that we give to the SeqAccess impl back to the start of the TTLV item.
        let mut seq_cursor = self.src.clone();
        seq_cursor.set_position(seq_start);

        let descendent_parser = TtlvDeserializer::from_cursor(
            &mut seq_cursor,
            seq_tag,
            seq_type,
            seq_end,
            &[],
            self.tag_value_store.clone(),
        );

        let r = visitor.visit_seq(descendent_parser)?; // jumps to impl SeqAccess below

        // The descendant parser cursor advanced but ours did not. Skip the tag that we just read.
        self.src.set_position(seq_cursor.position());

        Ok(r)
    }

    /// Deserialize the bytes at the current cursor position to a Rust Option.
    ///
    /// The TTLV format has no explicit support for optional items, though a client and server may agree that it is okay
    /// for a particular point in the TTLV byte stream to optionally contain a particular TTLV item. For example the
    /// KMIP 1.0 spec labels some response fields as NOT required i.e. optional. To handle such cases the caller can use
    /// the Rust Option type in the datatype being deserialized into. As TTLV has no explicit mechanism to indicate a
    /// NULL or missing value, the caller MUST treat missing fields that deserialize to an `Option` as `None`. For
    /// example:
    ///
    /// ```ignore
    /// #[derive(Deserialize)]
    /// #[serde(rename = "0x42000F")]
    /// pub struct BatchItem {
    ///     #[serde(default)]
    ///     pub operation: Option<Operation>,
    ///     ...
    /// }
    /// ```
    ///
    /// Here we see a KMIP BatchItem response structure with an optional field and the use of `#[serde(default)]` to set
    /// the member field to `None` if the corresponding TTLV item is not found while deserializing.
    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // The tag has already been read, now we are handling the value. How can we know that this item is NOT the one
        // that was intended to fill the Option and thus the item is missing and the Option should be

        // Is this the field we expected at this point?
        if self.item_unexpected {
            // This isn't the item that the caller expected but they indicated that the expected item was optional.
            // Report back that the optional item was not found and rewind the read cursor so that we will visit this
            // TTLV tag again.
            self.src.set_position(self.item_start);
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }

    /// Deserialize the bytes at the current cursor position to a Rust unit-like enum variant or struct enum variant.
    ///
    /// # Unit-like enum variants
    ///
    /// Rust enum variants can be unit-like or can have data attached to them. The unit-like form should be used when
    /// the TTLV bytes being deserialized are of type "Enumeration". Serde will use the deserialized unsigned 32-bit
    /// value to select a variant with matching name. By using the serde-derive rename feature we can associate each
    /// enum variant with a single TTLV "Enumeration" value. For example one could define the first few values of the
    /// KMIP "Operation" Enumeration like so:
    ///
    /// ```ignore
    /// #[derive(Deserialize, Serialize, Display)]
    /// #[serde(rename = "0x42005C")]
    /// #[non_exhaustive]
    /// pub enum Operation {
    ///     #[serde(rename = "0x00000001")]
    ///     Create,
    ///
    ///     #[serde(rename = "0x00000002")]
    ///     CreateKeyPair,
    ///
    ///     #[serde(rename = "0x00000003")]
    ///     Register,
    /// ```
    ///
    /// These enum variants are referred to as unit-like as they have no associated data, i.e. the variants have the
    /// form `Create` rather than `Create(...some associated data...)`.
    ///
    /// The TTLV byte sequence `42005C05000000040000000200000000` will be deserialized as tag `0x42005C`, type 0x05
    /// (Enumeration), value length 4 (bytes) and a 4-byte 0x00000002 value with 4 bytes of padding. Serde will be
    /// notified that the callers identifier with name "0x00000002" should have the value `Operation::CreateKeyPair`.
    ///
    /// # Struct enum variants
    ///
    /// By using an enum with struct variants the caller signals to the deserializer that it expects the TTLV byte
    /// stream to contain a TTLV "Structure" item that can be deserialized into one of the variant structs, but which
    /// one? For this to work we must also give the deserializer a way of determining from the data deserialized so far
    /// which of the variants is represented by the TTLV byte stream. We do this by using a serde "name" with a special
    /// syntax of the form `if A==B`.
    ///
    /// Let's see this in action using the variable KMIP response payload structure layout as an example where the
    /// payload structure to deserialize is indicated by the KMIP Operation enum value that appears earlier in the TTLV
    /// byte stream:
    ///
    /// First we define a struct that contains the variable payload as a member field:
    ///
    /// ```ignore
    /// #[derive(Deserialize)]
    /// #[serde(rename = "0x42000F")]
    /// pub struct BatchItem {
    ///     pub operation: Option<Operation>,
    ///     pub payload: Option<ResponsePayload>,
    /// }
    /// ```
    ///
    /// Then we define the variable payload type as an enum whose variants have different Rust structures attached to
    /// them. We also signal to the deserializer how each variant is selected by some other value in the TTLV byte
    /// stream:
    ///
    /// ```ignore
    /// #[derive(Deserialize)]
    /// #[serde(rename = "0x42007C")]
    /// #[non_exhaustive]
    /// pub enum ResponsePayload {
    ///     #[serde(rename = "if 0x42005C==0x00000001")]
    ///     Create(CreateResponsePayload),
    ///
    ///     #[serde(rename = "if 0x42005C==0x00000002")]
    ///     CreateKeyPair(CreateKeyPairResponsePayload),
    ///
    ///     #[serde(rename = "if 0x42005C==0x00000003")]
    ///     Register(RegisterResponsePayload),
    /// }
    /// ```
    ///
    /// Where `CreateResponsePayload`, `CreateKeyPairResponsePayload` and `RegisterResponsePayload` are Rust structs
    /// defined elsewhere.
    ///
    /// The special name syntax `if A==B` is used here to select the correct variant by matching against the value of
    /// another tag, "Operation" in this case, seen earlier in the TTLV byte stream. A TTLV byte sequence of the form
    /// `42000F01LLLLLLLL42005C0500000004000000020000000042007C01LLLLLLLLV...` would be deserialized as operation code
    /// 0x00000002 indicating that the payload is of type `CreateKeyPairResponsePayload`.
    ///
    /// The if syntax currently only supports matching against the value of earlier seen enum or string TTLV items that
    /// are looked up by their tag.
    fn deserialize_enum<V>(self, name: &'static str, variants: &'static [&'static str], visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // We don't know which type of enum the caller is deserializing into nor without guidance do we even know which
        // variant to announce to Serde that we are populating. We assume that the caller knows whether to expect a
        // structure or a single integer value in the TTLV byte stream at this point and that they therefore correctly
        // specified a tuple/tuple-struct enum variant or a unit-like variant as the datatype being deserialized into.
        //
        // We can only do two things:
        //   1. Deserialize the type of TTLV item that we find at this point in the byte stream.
        //
        //   2. Announce to serde either the TTLV tag as the variant name, or if the enum name is in the special form
        //      "if A==B" attempt to see if the value of previously seen tag A is B and if so we then announce the
        //      "if A==B" variant name as the chosen variant.
        //
        // When matching against previously seen tag values the match we find is used to tell Serde which enum variant
        // to deserialie into. This is the only case where we support an enum within an enum in the Rust code structure,
        // as TTLV doesn't support such nesting of enum values, that is we match against the name (or rename) of the
        // variant in an outer enum but the TTLV enum value that we read is used to select the variant of an inner enum.
        //
        // The concrete KMIP use case for such nested enums is when the response includes an Attribute Value whose tag
        // cannot tell us which Rust enum variant to deserialize into as it is always the same (0x42000B) so instead we
        // want to use the Attribute Name tag (0x42000A) string value seen earlier to select the Rust variant to
        // deserialize into, but that variant is itself an enum (e.g. AttributeValue::State(State)) and the actual TTLV
        // enum value read selects the variant of this "inner" State enum that will be deserialized into (e.g.
        // State::PreActive).

        self.item_identifier = None;

        // Check each enum variant name to see if it is of the form "if enum_tag==enum_val" and if so extract
        // enum_tag and enum_value:
        for v in variants {
            if self.is_variant_applicable(v)? {
                self.item_identifier = Some(v.to_string());
                break;
            }
        }

        // 1: Deserialize according to the TTLV item type:
        match self.item_type {
            Some(ItemType::Enumeration) => {
                // 2: Read a TTLV enumeration from the byte stream and announce the read value as the enum variant name.
                //    If we are selecting an enum variant based on a special "if" string then item_identifier will be
                //    Some(xxx) where xxx will NOT match the TTLV value that is waiting to be read, instead that will
                //    match an inner enum variant so we read the TTLV value when we visit this function again deeper in
                //    the call hierarchy. This enables handling of cases such as `AttributeName` string field that
                //    indicates the enum variant represented by the `AttributeValue`.
                if self.item_identifier.is_none() {
                    let enum_val = TtlvEnumeration::read(self.src)?;
                    let enum_hex = format!("0x{}", hex::encode_upper(enum_val.to_be_bytes()));

                    // Insert or replace the last value seen for this enum in our enum value lookup table
                    {
                        let mut map: RefMut<_> = self.tag_value_store.borrow_mut();
                        map.insert(self.item_tag.unwrap(), enum_hex.clone());
                    }

                    self.item_identifier = Some(enum_hex);
                }

                visitor.visit_enum(&mut *self) // jumps to impl EnumAccess (ending at unit_variant()) below
            }
            Some(ItemType::Structure) => {
                // 2: Read a TTLV structure from the byte stream. This enables handling of cases such as
                //    `BatchItem.operation` enum field that indicates the enum variant and thus structure type of
                //    `BatchItem.payload` that this TTLV structure should be deserialized into.

                // If we couldn't work out the correct variant name to announce to serde, announce the enum tag as the
                // variant name and let Serde handle it in case the caller has used `#[serde(other)]` to mark one
                // variant as the default.
                if self.item_identifier.is_none() {
                    self.item_identifier = Some(self.item_tag.unwrap().to_string());
                }

                visitor.visit_enum(&mut *self) // jumps to impl EnumAccess below
            }
            Some(ItemType::ByteString) => {
                // Handle the KeyMaterial case where the KeyMaterial is an enum that can be either bytes or a structure.

                visitor.visit_enum(&mut *self) // jumps to impl EnumAccess below
            }
            Some(item_type) => Err(self.error(
                "deserialize_enum",
                &format!(
                    "TTLV item type '{:?}' for enum '{}' cannot be deserialized into an enum",
                    item_type, name
                ),
            )),
            None => Err(self.error(
                "deserialize_enum",
                &format!("TTLV item type for enum '{}' has not yet been read", name),
            )),
        }
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        if let Some(identifier) = &self.item_identifier {
            visitor.visit_str(identifier).map_err(|err: Self::Error| {
                self.error(
                    "deserialize_identifier",
                    &format!(
                        concat!(
                            "Serde was not expecting identifier '{}': {}. Tip: Ensure that the Rust type being ",
                            "deserialized into either has a member field with name '{}' or add attribute ",
                            r#"`#[serde(rename = "{}")]` to the field"#
                        ),
                        identifier, err, identifier, identifier
                    ),
                )
            })
        } else {
            Err(self.error("deserialize_identifier", "No identifier available!"))
        }
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let v = TtlvInteger::read(&mut self.src)?;
        visitor.visit_i32(*v)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        match self.item_type.unwrap() {
            ItemType::LongInteger => {
                let v = TtlvLongInteger::read(&mut self.src)?;
                visitor.visit_i64(*v)
            }
            ItemType::DateTime => {
                let v = TtlvDateTime::read(&mut self.src)?;
                visitor.visit_i64(*v)
            }
            _ => Err(self.error(
                "deserialize_i64",
                &format!(
                    "Cannot deserialize item type {:?} for tag {} as i64",
                    self.item_type.unwrap(),
                    self.item_tag.unwrap()
                ),
            )),
        }
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let v = TtlvBoolean::read(&mut self.src)?;
        visitor.visit_bool(*v)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let v = TtlvTextString::read(&mut self.src)?;
        let str = v.0;

        // Insert or replace the last value seen for this tag in our value lookup table
        {
            let mut map: RefMut<_> = self.tag_value_store.borrow_mut();
            map.insert(self.item_tag.unwrap(), str.clone());
        }

        visitor.visit_string(str)
    }

    /// Use #[serde(with = "serde_bytes")] to direct Serde to this deserializer function for type Vec<u8>.
    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let v = TtlvByteString::read(&mut self.src)?;
        visitor.visit_byte_buf(v.0)
    }

    // dummy implementations of unsupported types so that we can give back a more useful error message than when using
    // `forward_to_deserialize_any()` as the latter doesn't make available the type currently being deserialized into.

    fn deserialize_u8<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(self.error(
            "deserialize_u8",
            "Deserializing TTLV to the Rust u8 type is not supported.",
        ))
    }

    fn deserialize_u16<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(self.error(
            "deserialize_u16",
            "Deserializing TTLV to the Rust u16 type is not supported.",
        ))
    }

    fn deserialize_u32<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(self.error(
            "deserialize_u32",
            "Deserializing TTLV to the Rust u32 type is not supported.",
        ))
    }

    fn deserialize_u64<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(self.error(
            "deserialize_u64",
            "Deserializing TTLV to the Rust u64 type is not supported.",
        ))
    }

    fn deserialize_i8<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(self.error(
            "deserialize_i8",
            "Deserializing TTLV to the Rust i8 type is not supported.",
        ))
    }

    fn deserialize_i16<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(self.error(
            "deserialize_i16",
            "Deserializing TTLV to the Rust i16 type is not supported.",
        ))
    }

    fn deserialize_f32<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(self.error(
            "deserialize_f32",
            "Deserializing TTLV to the Rust f32 type is not supported.",
        ))
    }

    fn deserialize_f64<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(self.error(
            "deserialize_f64",
            "Deserializing TTLV to the Rust f64 type is not supported.",
        ))
    }

    fn deserialize_char<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(self.error(
            "deserialize_char",
            "Deserializing TTLV to the Rust char type is not supported.",
        ))
    }

    fn deserialize_str<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(self.error(
            "deserialize_str",
            "Deserializing TTLV to the Rust str type is not supported.",
        ))
    }

    fn deserialize_map<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(self.error(
            "deserialize_map",
            "Deserializing TTLV to Serde as a map is not supported.",
        ))
    }

    fn deserialize_bytes<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(self.error(
            "deserialize_bytes",
            "Deserializing TTLV to Serde as bytes is not supported.",
        ))
    }

    fn deserialize_unit<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(self.error(
            "deserialize_unit",
            "Deserializing TTLV to Serde as a unit is not supported.",
        ))
    }

    /// Deserialize the bytes at the current cursor location into .. anything.
    ///
    /// This function shouldn't be invoked when using Serde derive as deserialization is being guided by a strongly
    /// typed model to deserialize into.
    fn deserialize_ignored_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(self.error(
            "deserialize_ignored_any",
            "Deserializing TTLV to Serde as ignored any is not supported.",
        ))
    }

    fn deserialize_unit_struct<V>(self, _name: &'static str, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(self.error(
            "deserialize_unit_struct",
            "Deserializing TTLV to Serde as a unit struct is not supported.",
        ))
    }

    fn deserialize_tuple_struct<V>(self, _name: &'static str, _len: usize, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(self.error(
            "deserialize_tuple_struct",
            "Deserializing TTLV to Serde as a tuple struct is not supported.",
        ))
    }

    fn deserialize_tuple<V>(self, _len: usize, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(self.error(
            "deserialize_tuple",
            "Deserializing TTLV to Serde as a tuple is not supported.",
        ))
    }

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(self.error(
            "deserialize_any",
            &format!(
                "unsupported tag {} type {}",
                self.item_tag.unwrap(),
                self.item_type.unwrap() as u8
            ),
        ))
    }
}

// Deserialize structure members
impl<'de: 'c, 'c> MapAccess<'de> for TtlvDeserializer<'de, 'c> {
    type Error = Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: serde::de::DeserializeSeed<'de>,
    {
        if self.read_item_key("next_key_seed")? {
            seed.deserialize(self).map(Some) // jumps to deserialize_identifier() above
        } else {
            // The end of the group was reached
            Ok(None)
        }
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value>
    where
        V: serde::de::DeserializeSeed<'de>,
    {
        seed.deserialize(self) // jumps to deserialize_xxx() in impl Deserializer above
    }
}

// Deserialize a Vec of one type/tag
impl<'de: 'c, 'c> SeqAccess<'de> for TtlvDeserializer<'de, 'c> {
    type Error = Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        if !self.read_item_key("next_element_seed")? {
            // The end of the containing group was reached
            Ok(None)
        } else if self.item_tag != self.group_tag || self.item_type != self.group_type {
            // The next tag is not part of the sequence.
            // Walk the cursor back before the tag because we didn't consume it.
            self.src.set_position(self.item_start);
            Ok(None)
        } else {
            // The tag and type match that of the first item in the sequence, process this element.
            seed.deserialize(self).map(Some) // jumps to deserialize_identifier() above
        }
    }
}

// Deserialize an enum
impl<'de: 'c, 'c> EnumAccess<'de> for &mut TtlvDeserializer<'de, 'c> {
    type Error = Error;
    type Variant = Self;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant)>
    where
        V: serde::de::DeserializeSeed<'de>,
    {
        let val = seed.deserialize(&mut *self)?; // jumps to deserialize_identifier() above
        Ok((val, self)) // jumps to VariantAccess below
    }
}

// Deserialize a variant of an enum
impl<'de: 'c, 'c> VariantAccess<'de> for &mut TtlvDeserializer<'de, 'c> {
    type Error = Error;

    fn unit_variant(self) -> Result<()> {
        Ok(())
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        seed.deserialize(self)
    }

    fn tuple_variant<V>(self, _len: usize, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(self.error(
            "newtype_variant_seed",
            "Deserializing TTLV to the Rust enum tuple variant type is not supported.",
        ))
    }

    fn struct_variant<V>(self, _fields: &'static [&'static str], _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(self.error(
            "newtype_variant_seed",
            "Deserializing TTLV to the Rust enum struct variant type is not supported.",
        ))
    }
}

#[cfg(test)]
mod test {
    #[allow(unused_imports)]
    use pretty_assertions::{assert_eq, assert_ne};

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
    #[serde(rename = "0x42007B")]
    struct ResponseMessage {
        header: ResponseHeader,
        items: Vec<BatchItem>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename = "0x42007A")]
    struct ResponseHeader {
        ver: ProtocolVersion,
        #[serde(rename = "0x420092")]
        timestamp: i64,
        #[serde(rename = "0x42000D")]
        item_count: i32,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename = "0x420069")]
    struct ProtocolVersion {
        #[serde(rename = "0x42006A")]
        major: i32,
        #[serde(rename = "0x42006B")]
        minor: i32,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename = "0x42000F")]
    struct BatchItem {
        operation: Operation,
        status: ResultStatus,
        payload: ResponsePayload,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(rename = "0x42005C")]
    enum Operation {
        #[serde(rename = "0x00000001")]
        Create,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(rename = "0x42007F")]
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
    #[serde(rename = "0x42007C")]
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
