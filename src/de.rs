//! Deserialize TTLV bytes into Rust data types.

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
    de::{DeserializeOwned, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor},
    Deserialize, Deserializer,
};

use crate::{
    error::Error,
    error::Result,
    types::{ItemTag, ItemType, TtlvBigInteger, TtlvByteString},
    types::{
        SerializableTtlvType, TtlvBoolean, TtlvDateTime, TtlvEnumeration, TtlvInteger, TtlvLongInteger, TtlvTextString,
    },
};

// --- Public interface ------------------------------------------------------------------------------------------------

#[derive(Debug)]
pub struct Config {
    max_bytes: Option<u32>,
}

impl Default for Config {
    fn default() -> Self {
        Self { max_bytes: None }
    }
}

impl Config {
    fn max_bytes(&self) -> Option<u32> {
        self.max_bytes
    }
}

// Builder style interface
impl Config {
    pub fn with_max_bytes(self, max_bytes: u32) -> Self {
        Self {
            max_bytes: Some(max_bytes),
        }
    }
}

pub fn from_slice<'de, T>(bytes: &'de [u8]) -> Result<T>
where
    T: Deserialize<'de>,
{
    let cursor = &mut Cursor::new(bytes);
    let mut deserializer = TtlvDeserializer::from_slice(cursor);
    T::deserialize(&mut deserializer).map_err(|err| deserializer.error(err))
}

/// Read and deserialize bytes from the given reader.
///
/// Note: Also accepts a mut reference.
///
/// Attempting to process a stream whose initial TTL header length value is larger the config max_bytes, if any, will
/// result in`Error::InvalidLength`.
pub fn from_reader<T, R>(mut reader: R, config: &Config) -> Result<T>
where
    T: DeserializeOwned,
    R: Read,
{
    // When reading from a stream we don't know how many bytes to read until we've read the L of the first TTLV in
    // the response stream. As the current implementation jumps around in the response bytes while parsing (see
    // calls to set_position()), and requiring the caller to provider a Seek capable stream would be quite onerous,
    // and as we're not trying to be super efficient as HSMs are typically quite slow anywa, just read the bytes into a
    // Vec and then parse it from there. We can't just call read_to_end() because that can cause the response reading to
    // block if the server doesn't close the connection after writing the response bytes (e.g. PyKMIP behaves this way).
    // We know from the TTLV specification that the initial TTL bytes must be 8 bytes long (3-byte tag, 1-byte type,
    // 4-byte length) so we attempt read to this "magic header" from the given stream.
    let mut buf = vec![0; 8];
    reader.read_exact(&mut buf)?;

    let mut cursor = Cursor::new(&mut buf);
    let _tag = TtlvDeserializer::read_tag(&mut cursor)?;
    let _type = TtlvDeserializer::read_type(&mut cursor)?;
    let additional_len = TtlvDeserializer::read_length(&mut cursor)?;

    // The number of bytes to allocate is determined by the data being read. It could be a gazillion bytes and we'd
    // panic trying to allocate it. The caller is therefore advised to define an upper bound if the source cannot be
    // trusted.
    if let Some(max_bytes) = config.max_bytes() {
        if additional_len > max_bytes {
            return Err(Error::InvalidLength(format!(
                "The TTLV response length ({}) is greater than the maximum supported ({})",
                buf.len() + additional_len as usize,
                max_bytes
            )));
        }
    }

    // Warning: this will panic if it fails to allocate the requested amount of memory, at least until try_reserve() is
    // stabilized!
    buf.reserve(additional_len as usize);
    buf.resize(buf.capacity(), 0);
    reader.read_exact(&mut buf[8..])?;

    from_slice(&buf)
}

/// Interpret the given byte slice as TTLV as much as possible and render it to a String in human readable form.
pub fn to_string(bytes: &[u8]) -> String {
    let mut indent: usize = 0;
    let mut report = String::new();
    let mut struct_ends = Vec::<u64>::new();
    let mut cur_struct_end = Option::<u64>::None;
    let mut broken = false;
    let mut cursor = Cursor::new(bytes);

    /// Given a read cursor into a byte stream, attempt to read the next TTLV item and render its metadata and value in
    /// humand readable form to a result string. The TTLV item to process should have the form:
    ///   - T: 3 bytes of "tag"
    ///   - T: 1 byte of "type"
    ///   - L: 4 bytes of "length"
    ///   - V: L bytes of "value"
    /// On success returns the human readable string representation of the parsed TTLV item and if it was a "Structure"
    /// header also returns the byte length of the structure that follows. If the bytes in the stream at the cursor
    /// position are not valid TTLV an error will be returned.
    fn deserialize_ttlv_to_string(mut cursor: &mut Cursor<&[u8]>) -> Result<(String, Option<u64>)> {
        let tag = TtlvDeserializer::read_tag(&mut cursor)?;
        let typ = TtlvDeserializer::read_type(&mut cursor)?;
        let mut len = Option::<u64>::None;
        const EMPTY_STRING: String = String::new();

        #[rustfmt::skip]
        let data = match typ {
            ItemType::Structure   => { len = Some(TtlvDeserializer::read_length(cursor)? as u64); EMPTY_STRING }
            ItemType::Integer     => { format!(" {data:#08X} ({data})", data = TtlvInteger::read(cursor)?.deref()) }
            ItemType::LongInteger => { format!(" {data:#08X} ({data})", data = TtlvLongInteger::read(cursor)?.deref()) }
            ItemType::BigInteger  => { format!(" {data}", data = hex::encode_upper(&TtlvBigInteger::read(cursor)?.deref())) }
            ItemType::Enumeration => { format!(" {data:#08X} ({data})", data = TtlvEnumeration::read(cursor)?.deref()) }
            ItemType::Boolean     => { format!(" {data}", data = TtlvBoolean::read(cursor)?.deref()) }
            ItemType::TextString  => { format!(" {data}", data = TtlvTextString::read(cursor)?.deref()) }
            ItemType::ByteString  => { format!(" {data}", data = hex::encode_upper(&TtlvByteString::read(cursor)?.deref())) }
            ItemType::DateTime    => { format!(" {data:#08X}", data = TtlvDateTime::read(cursor)?.deref()) }
        };

        let fragment = format!("Tag: Unknown ({:#06X}), Type: {}, Data:{}\n", *tag, typ, data);

        Ok((fragment, len))
    }

    loop {
        // Handle walking off the end of the current structure and the entire input
        loop {
            let rel_pos = if let Some(end) = cur_struct_end {
                cursor.position().cmp(&end)
            } else {
                Ordering::Less
            };

            match rel_pos {
                Ordering::Less => {
                    // Keep processing the current TTLV structure items
                    break;
                }
                Ordering::Equal => {
                    // End of current (sub)structure reached, outdent and use end of parent structure as next struct end
                    if let Some(end) = struct_ends.pop() {
                        indent -= 2;
                        cur_struct_end = Some(end);
                    } else {
                        // No more parent structures, we have finished processing the TTLV bytes
                        return report;
                    }
                }
                Ordering::Greater => {
                    if !broken {
                        // Error, we shouldn't be able to move beyond the end of the current TTLV structure end position.
                        report.push_str("\nERROR: TTLV structure content exceeds the structure length.");
                        return report;
                    }
                }
            }
        }

        // Deserialize the next TTLV in the input to a human readable string
        match deserialize_ttlv_to_string(&mut cursor) {
            Ok((ttlv_string, possible_new_struct_len)) => {
                // Add (with correct indentation) the human readable result of deserialization to the "report" built up
                // so far.
                report.push_str(&format!(
                    "{:width$}{ttlv_string}",
                    "",
                    width = indent,
                    ttlv_string = &ttlv_string
                ));

                // Handle descent into an inner TTLV "Structure"
                if let Some(new_len) = possible_new_struct_len {
                    indent += 2;

                    if let Some(cur_end) = cur_struct_end {
                        // We have started processing a new child structure, remember the end of the parent structure we
                        // were processing so when we finish the child structure we can continue looking for the end of the
                        // current structure.
                        struct_ends.push(cur_end);
                    }

                    if new_len == 0 {
                        // This can happen if we are trying to dump out bytes that we were busy serializing when we hit
                        // an error before we were able to go back into the byte stream to rewrite the structure length
                        // once the length was known. Note: this can also be correct, it might actually be an empty
                        // structure, but we cannot distinguish between the two cases.
                        report.push_str("WARNING: TTLV structure length is zero\n");
                        broken = true;
                    } else {
                        cur_struct_end = Some(cursor.position() + new_len);
                    }
                }
            }
            Err(err) => {
                // Oops, we couldn't deserialize a TTLV from the input stream at the current cursor position
                report.push_str(&format!(
                    "ERROR: {} (cursor pos={}, end={:?})",
                    err,
                    cursor.position(),
                    cur_struct_end
                ));
                return report;
            }
        }
    }
}

// --- Private implementation details ----------------------------------------------------------------------------------

impl serde::de::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Self::Other(msg.to_string())
    }
}

trait ContextualErrorSupport {
    const WINDOW_SIZE: usize = 20;

    fn pos(&self) -> usize;

    fn buf(&self) -> &[u8];

    fn ctx(&self) -> String {
        let pos = self.pos();
        let buf_len = self.buf().len();

        if buf_len == 0 {
            return "^>><<$".to_string();
        }

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
        if start == 0 {
            ctx.push('^');
        }
        if start < pos {
            let range = start..pos;
            if start > 0 {
                ctx.push_str("..")
            }
            ctx.push_str(&hex::encode_upper(self.buf()[range].to_vec()));
        }
        if pos <= end {
            ctx.push_str(&format!(">>{:02X}<<", self.buf()[pos]));
        } else {
            ctx.push_str(">><<");
        }
        if (pos + 1) <= end {
            let range = (pos + 1)..=end;
            let range_len = end - pos;
            let add_ellipsis = range_len > Self::WINDOW_SIZE;
            ctx.push_str(&hex::encode_upper(self.buf()[range].to_vec()));
            if add_ellipsis {
                ctx.push_str("..")
            }
        }
        if end == (buf_len - 1) {
            ctx.push('$');
        }
        ctx
    }

    fn error(&self, msg: impl std::fmt::Display) -> Error {
        Error::DeserializeError {
            ctx: self.ctx(),
            pos: self.pos(),
            len: self.buf().len(),
            msg: msg.to_string(),
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
    group_homogenous: bool,                // sequence/map field handling: are all items in the group of the same type?

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
            group_homogenous: false,
            item_start: 0,
            item_tag: None,
            item_type: None,
            item_unexpected: false,
            item_identifier: None,
            tag_value_store: Rc::new(RefCell::new(HashMap::new())),
        }
    }

    fn from_cursor(
        src: &'c mut Cursor<&'de [u8]>,
        group_tag: ItemTag,
        group_type: ItemType,
        group_end: u64,
        group_fields: &'static [&'static str],
        group_homogenous: bool, // are all items in the group the same tag and type?
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
            group_homogenous,
            item_start: group_start,
            item_tag: None,
            item_type: None,
            item_unexpected: false,
            item_identifier: None,
            tag_value_store: unit_enum_store,
        }
    }

    /// Note: Also accepts a mut reference.
    fn read_tag<R>(mut src: R) -> Result<ItemTag>
    where
        R: Read,
    {
        let mut raw_item_tag = [0u8; 3];
        src.read_exact(&mut raw_item_tag)?;
        let item_tag = ItemTag::from(raw_item_tag);
        Ok(item_tag)
    }

    /// Note: Also accepts a mut reference.
    fn read_type<R>(mut src: R) -> Result<ItemType>
    where
        R: Read,
    {
        let mut raw_item_type = [0u8; 1];
        src.read_exact(&mut raw_item_type)?;
        let item_type = ItemType::try_from(raw_item_type[0])?;
        Ok(item_type)
    }

    /// Note: Also accepts a mut reference.
    fn read_length<R>(mut src: R) -> Result<u32>
    where
        R: Read,
    {
        let mut value_length = [0u8; 4];
        src.read_exact(&mut value_length)?;
        Ok(u32::from_be_bytes(value_length))
    }

    /// Returns Ok(true) if there is data available, Ok(false) if the end of the group has been reached or Err()
    /// otherwise.
    fn read_item_key(&mut self) -> Result<bool> {
        match self.pos().cmp(&(self.group_end.unwrap() as usize)) {
            Ordering::Less => {}
            Ordering::Equal => return Ok(false),
            Ordering::Greater => {
                return Err(Error::Other(format!(
                    "Buffer overrun: {} > {}",
                    self.pos(),
                    self.group_end.unwrap()
                )))
            }
        }

        self.item_start = self.pos() as u64;
        self.item_tag = Some(Self::read_tag(&mut self.src)?);
        self.item_type = Some(Self::read_type(&mut self.src)?);

        self.group_item_count += 1;

        self.item_unexpected = if self.group_fields.is_empty() {
            false
        } else {
            let field_index = self.group_item_count - 1;
            let expected_tag_str = self.group_fields.get(field_index).ok_or_else(|| {
                Error::Other(format!(
                    "Expected field index is out of bounds {} >= {}",
                    field_index,
                    self.group_fields.len()
                ))
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
            let group_tag = Self::read_tag(&mut self.src)?;
            let group_type = Self::read_type(&mut self.src)?;
            (group_start, group_tag, group_type)
        } else {
            // When invoked while visiting a map the opening tag and type of the struct header will have already been
            // read by next_key_seed() so we don't need to read them here.
            (self.src.position() - 4, self.item_tag.unwrap(), self.item_type.unwrap())
        };
        Ok((group_start, group_tag, group_type))
    }

    fn prepare_to_descend(&mut self, name: &'static str) -> Result<(u64, ItemTag, ItemType, u64)> {
        let wanted_tag = ItemTag::from_str(name).map_err(|err| Error::InvalidTag(err.to_string()))?;

        let (group_start, group_tag, group_type) = self.get_start_tag_type()?;

        if group_tag != wanted_tag {
            return Err(Error::Other(format!(
                "Wanted tag '{}' but found '{}'",
                wanted_tag, group_tag
            )));
        }

        if group_type != ItemType::Structure {
            return Err(Error::Other(format!(
                "Wanted type '{:?}' but found '{:?}'",
                ItemType::Structure,
                group_type
            )));
        }

        let group_len = Self::read_length(&mut self.src)?;
        let group_end = (self.pos() + (group_len as usize)) as u64;

        let buf_len = self.buf().len() as u64;
        if group_end > buf_len {
            return Err(Error::Other(format!(
                "Structure overflow: length {} (0x{:08X}) puts end at byte {} but buffer ends at byte {}",
                group_len, group_len, group_end, buf_len,
            )));
        }

        Ok((group_start, group_tag, group_type, group_end))
    }

    fn is_variant_applicable(&self, variant: &'static str) -> Result<bool> {
        // str::split_once() wasn't stablized until Rust 1.52.0 but as we want to be usable by Krill, and Krill
        // currently supports Rust >= 1.47.0, we use our own split_once() implementation.
        pub fn split_once<'a>(value: &'a str, delimiter: &str) -> Option<(&'a str, &'a str)> {
            value
                .find(delimiter)
                .map(|idx| (&value[..idx], &value[idx + delimiter.len()..]))
        }

        // TODO: this is horrible code.
        if let Some((wanted_tag, wanted_val)) = variant.strip_prefix("if ").and_then(|v| split_once(v, "==")) {
            let wanted_tag = wanted_tag.trim();
            let wanted_val = wanted_val.trim();

            // Have we earlier seen a TTLV tag 'wanted_tag' and if so was its value 'wanted_val'? If so then this is
            // the variant name to announce to Serde that we are deserializing into.
            if wanted_tag == "type" {
                // See if wanted_val is a literal string that matches the TTLV type we are currently deserializing
                // TODO: Add BigInteger and Interval when supported
                if matches!(
                    (wanted_val, self.item_type.unwrap()),
                    ("Structure", ItemType::Structure)
                        | ("Integer", ItemType::Integer)
                        | ("LongInteger", ItemType::LongInteger)
                        | ("Enumeration", ItemType::Enumeration)
                        | ("Boolean", ItemType::Boolean)
                        | ("TextString", ItemType::TextString)
                        | ("ByteString", ItemType::ByteString)
                        | ("DateTime", ItemType::DateTime)
                ) {
                    return Ok(true);
                }
            } else if let Some(seen_enum_val) = self.tag_value_store.borrow().get(&ItemTag::from_str(wanted_tag)?) {
                if *seen_enum_val == wanted_val {
                    return Ok(true);
                }
            }
        } else if let Some((wanted_tag, wanted_val)) = variant.strip_prefix("if ").and_then(|v| split_once(v, ">=")) {
            let wanted_tag = wanted_tag.trim();
            let wanted_val = wanted_val.trim();

            if let Some(seen_enum_val) = self.tag_value_store.borrow().get(&ItemTag::from_str(wanted_tag)?) {
                if ItemTag::from_str(seen_enum_val)?.deref() >= ItemTag::from_str(wanted_val)?.deref() {
                    return Ok(true);
                }
            }
        } else if let Some((wanted_tag, wanted_values)) = split_once(variant.strip_prefix("if ").unwrap_or(""), " in ")
        {
            let wanted_values = wanted_values.strip_prefix('[').and_then(|v| v.strip_suffix(']'));
            if let Some(wanted_values) = wanted_values {
                if let Some(seen_enum_val) = self.tag_value_store.borrow().get(&ItemTag::from_str(wanted_tag)?) {
                    for wanted_value in wanted_values.split(',') {
                        if *seen_enum_val == wanted_value.trim() {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    fn build_unexpected_type_error_msg(&self, rust_type_name: &'static str, expected_ttlv_type: ItemType) -> Error {
        let actual_ttlv_type = if self.item_type.is_some() {
            self.item_type.unwrap().to_string()
        } else {
            "None".to_string()
        };
        Error::UnexpectedType(format!(
            "TTLV type to deserialize into a {} should be {} but found {}",
            rust_type_name, expected_ttlv_type, actual_ttlv_type,
        ))
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

macro_rules! unsupported_type {
    ($deserialize:ident, $type:ident) => {
        fn $deserialize<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
            Err(Error::Other(
                concat!(
                    "Deserializing TTLV to the Rust ",
                    stringify!($type),
                    " type is not supported."
                )
                .into(),
            ))
        }
    };
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
        let (_, group_tag, group_type, group_end) = self.prepare_to_descend(name)?;

        let mut struct_cursor = self.src.clone();

        let descendent_parser = TtlvDeserializer::from_cursor(
            &mut struct_cursor,
            group_tag,
            group_type,
            group_end,
            fields,
            false, // struct member fields can have different tags and types
            self.tag_value_store.clone(),
        );

        let r = visitor.visit_map(descendent_parser); // jumps to impl MapAccess below

        // The descendant parser cursor advanced but ours did not. Skip the tag that we just read.
        self.src.set_position(struct_cursor.position());

        r
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
            true, // sequence fields must all have the same tag and type
            self.tag_value_store.clone(),
        );

        let r = visitor.visit_seq(descendent_parser); // jumps to impl SeqAccess below

        // The descendant parser cursor advanced but ours did not. Skip the tag that we just read.
        self.src.set_position(seq_cursor.position());

        r
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
            Some(_) => {
                // Handle cases such as a `BatchItem.operation` enum field that indicates the enum variant and thus
                // structure type of `BatchItem.payload` that this TTLV structure should be deserialized into, the
                // KeyMaterial case where the KeyMaterial is an enum that can be either bytes or a structure, or the
                // AttributeValue case where the value can be one of several predefined structure types or any primitive
                // type....

                // If we couldn't work out the correct variant name to announce to serde, announce the enum tag as the
                // variant name and let Serde handle it in case the caller has used `#[serde(other)]` to mark one
                // variant as the default.
                if self.item_identifier.is_none() {
                    self.item_identifier = Some(self.item_tag.unwrap().to_string());
                }

                visitor.visit_enum(&mut *self) // jumps to impl EnumAccess below
            }
            None => Err(Error::Other(format!(
                "TTLV item type for enum '{}' has not yet been read",
                name
            ))),
        }
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        if let Some(identifier) = &self.item_identifier {
            visitor.visit_str(identifier).map_err(|err: Self::Error| {
                Error::Other(format!(
                    concat!(
                        "Serde was not expecting identifier '{}': {}. Tip: Ensure that the Rust type being ",
                        "deserialized into either has a member field with name '{}' or add attribute ",
                        r#"`#[serde(rename = "{}")]` to the field"#
                    ),
                    identifier, err, identifier, identifier
                ))
            })
        } else {
            Err(Error::Other("No identifier available!".into()))
        }
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        if let Some(ItemType::Integer) = self.item_type {
            let v = TtlvInteger::read(&mut self.src)?;
            visitor.visit_i32(*v)
        } else {
            Err(self.build_unexpected_type_error_msg("i32", ItemType::Integer))
        }
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
            _ => Err(self.build_unexpected_type_error_msg("i64", ItemType::LongInteger)),
        }
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        if let Some(ItemType::Boolean) = self.item_type {
            let v = TtlvBoolean::read(&mut self.src)?;
            visitor.visit_bool(*v)
        } else {
            Err(self.build_unexpected_type_error_msg("bool", ItemType::Boolean))
        }
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        if let Some(ItemType::TextString) = self.item_type {
            let v = TtlvTextString::read(&mut self.src)?;
            let str = v.0;

            // Insert or replace the last value seen for this tag in our value lookup table
            {
                let mut map: RefMut<_> = self.tag_value_store.borrow_mut();
                map.insert(self.item_tag.unwrap(), str.clone());
            }

            visitor.visit_string(str)
        } else {
            Err(self.build_unexpected_type_error_msg("String", ItemType::TextString))
        }
    }

    /// Use #[serde(with = "serde_bytes")] to direct Serde to this deserializer function for type Vec<u8>.
    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        if let Some(ItemType::ByteString) = self.item_type {
            let v = TtlvByteString::read(&mut self.src)?;
            visitor.visit_byte_buf(v.0)
        } else {
            Err(self.build_unexpected_type_error_msg("Vec<u8>", ItemType::ByteString))
        }
    }

    // dummy implementations of unsupported types so that we can give back a more useful error message than when using
    // `forward_to_deserialize_any()` as the latter doesn't make available the type currently being deserialized into.

    unsupported_type!(deserialize_u8, u8);
    unsupported_type!(deserialize_u16, u16);
    unsupported_type!(deserialize_u32, u32);
    unsupported_type!(deserialize_u64, u64);
    unsupported_type!(deserialize_i8, i8);
    unsupported_type!(deserialize_i16, i16);
    unsupported_type!(deserialize_f32, f32);
    unsupported_type!(deserialize_f64, f64);
    unsupported_type!(deserialize_char, char);
    unsupported_type!(deserialize_str, str);
    unsupported_type!(deserialize_map, map);
    unsupported_type!(deserialize_bytes, bytes);
    unsupported_type!(deserialize_unit, unit);

    /// Deserialize the bytes at the current cursor location into .. anything.
    ///
    /// This function shouldn't be invoked when using Serde derive as deserialization is being guided by a strongly
    /// typed model to deserialize into.
    fn deserialize_ignored_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Other(
            "Deserializing TTLV to Serde as ignored any is not supported.".into(),
        ))
    }

    fn deserialize_unit_struct<V>(self, _name: &'static str, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Other(
            "Deserializing TTLV to Serde as a unit struct is not supported.".into(),
        ))
    }

    fn deserialize_tuple_struct<V>(self, _name: &'static str, _len: usize, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Other(
            "Deserializing TTLV to Serde as a tuple struct is not supported.".into(),
        ))
    }

    fn deserialize_tuple<V>(self, _len: usize, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Other(
            "Deserializing TTLV to Serde as a tuple is not supported.".into(),
        ))
    }

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Other(format!(
            "Unsupported tag {} type {}",
            self.item_tag.unwrap(),
            self.item_type.unwrap() as u8
        )))
    }
}

// Deserialize structure members
impl<'de: 'c, 'c> MapAccess<'de> for TtlvDeserializer<'de, 'c> {
    type Error = Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: serde::de::DeserializeSeed<'de>,
    {
        if self.read_item_key()? {
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
        if !self.read_item_key()? {
            // The end of the containing group was reached
            Ok(None)
        } else if self.group_homogenous && (self.item_tag != self.group_tag || self.item_type != self.group_type) {
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

    fn tuple_variant<V>(self, _len: usize, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // The caller has provided a Rust enum variant in tuple form, i.e. SomeEnum(a, b, c), and expects us to
        // deserialize the right number of items to match those fields.
        let seq_len = TtlvDeserializer::read_length(&mut self.src)?;
        let seq_start = self.pos() as u64;
        let seq_end = seq_start + (seq_len as u64);
        let seq_tag = TtlvDeserializer::read_tag(&mut self.src)?;
        let seq_type = TtlvDeserializer::read_type(&mut self.src)?;

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
            false, // don't require all fields in the sequence to be of the same tag and type
            self.tag_value_store.clone(),
        );

        let r = visitor.visit_seq(descendent_parser); // jumps to impl SeqAccess below

        // The descendant parser cursor advanced but ours did not. Skip the tag that we just read.
        self.src.set_position(seq_cursor.position());

        r
    }

    fn struct_variant<V>(self, _fields: &'static [&'static str], _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::Other(
            "Deserializing TTLV to the Rust enum struct variant type is not supported.".into(),
        ))
    }
}
