//! High-level Serde based deserialization of TTLV bytes to Rust data types.

use std::{
    cell::RefCell,
    cmp::Ordering,
    collections::HashMap,
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
    error::{ErrorKind, ErrorLocation, MalformedTtlvError, Result, SerdeError},
    types::{
        self, FieldType, SerializableTtlvType, TtlvBoolean, TtlvDateTime, TtlvEnumeration, TtlvInteger, TtlvLength,
        TtlvLongInteger, TtlvStateMachine, TtlvStateMachineMode, TtlvTextString,
    },
    types::{TtlvBigInteger, TtlvByteString, TtlvTag, TtlvType},
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
    T::deserialize(&mut deserializer)
}

/// Read and deserialize bytes from the given reader.
///
/// Note: Also accepts a mut reference.
///
/// Attempting to process a stream whose initial TTL header length value is larger the config max_bytes, if any, will
/// result in`Error::ResponseSizeExceedsLimit`.
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

    fn cur_pos(buf_len: u64) -> ErrorLocation {
        ErrorLocation::from(buf_len)
    }

    // Greedy closure capturing:
    // -------------------------
    // Note: In the read_xxx() calls below we take the cursor.position() _before_ the read because otherwise, in Rust
    // 2018 Edition, the closure captures the cursor causing compilation to fail due to multiple mutable borrows of fhe
    // cursor. Rust 2021 Edition implements so-called "Disjoint capture in closures" which may eliminate this problem.
    // See: https://doc.rust-lang.org/nightly/edition-guide/rust-2021/disjoint-capture-in-closures.html

    // Read the bytes of the first TTL (3 byte tag, 1 byte type, 4 byte len)
    let mut buf = vec![0; 8];
    let response_size;
    let tag;
    let r#type;
    {
        let mut state = TtlvStateMachine::new(TtlvStateMachineMode::Deserializing);
        reader.read_exact(&mut buf).map_err(|err| pinpoint!(err, cur_pos(0)))?;

        // Extract and verify the first T (tag)
        let mut cursor = Cursor::new(&mut buf);
        let buf_len = cursor.position();
        tag = TtlvDeserializer::read_tag(&mut cursor, Some(&mut state))
            .map_err(|err| pinpoint!(err, cur_pos(buf_len)))?;

        // Extract and verify the second T (type)
        let buf_len = cursor.position();
        r#type = TtlvDeserializer::read_type(&mut cursor, Some(&mut state))
            .map_err(|err| pinpoint!(err, cur_pos(buf_len), tag))?;

        // Extract and verify the L (value length)
        let buf_len = cursor.position();
        let additional_len = TtlvDeserializer::read_length(&mut cursor, Some(&mut state))
            .map_err(|err| pinpoint!(err, cur_pos(buf_len), tag, r#type))?;

        // ------------------------------------------------------------------------------------------
        // Now read the value bytes of the first TTLV item (i.e. the rest of the entire TTLV message)
        // ------------------------------------------------------------------------------------------

        // The number of bytes to allocate is determined by the data being read. It could be a gazillion bytes and we'd
        // panic trying to allocate it. The caller is therefore advised to define an upper bound if the source cannot be
        // trusted.
        let buf_len = cursor.position();
        response_size = buf_len + (additional_len as u64);
        if let Some(max_bytes) = config.max_bytes() {
            if response_size > (max_bytes as u64) {
                let error = ErrorKind::ResponseSizeExceedsLimit(response_size as usize);
                let location = ErrorLocation::from(cursor).with_tag(tag).with_type(r#type);
                return Err(Error::pinpoint(error, location));
            }
        }
    }

    // Warning: this will panic if it fails to allocate the requested amount of memory, at least until try_reserve() is
    // stabilized!
    buf.resize(response_size as usize, 0);
    reader
        .read_exact(&mut buf[8..])
        .map_err(|err| Error::pinpoint(err, ErrorLocation::from(buf.len()).with_tag(tag).with_type(r#type)))?;

    from_slice(&buf)
}

// --- Private implementation details ----------------------------------------------------------------------------------

// Required for impl Deserializer below to use this type, but I don't really want arbitrary strings leaking out of the
// deserializer as they could leak sensitive data
impl serde::de::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        pinpoint!(SerdeError::Other(msg.to_string()), ErrorLocation::unknown())
    }
}

impl<'de: 'c, 'c> From<&mut TtlvDeserializer<'de, 'c>> for ErrorLocation {
    fn from(de: &mut TtlvDeserializer) -> Self {
        de.location()
    }
}

impl<'de: 'c, 'c> From<&TtlvDeserializer<'de, 'c>> for ErrorLocation {
    fn from(de: &TtlvDeserializer) -> Self {
        de.location()
    }
}

trait ContextualErrorSupport {
    fn pos(&self) -> u64;
}

pub(crate) struct TtlvDeserializer<'de: 'c, 'c> {
    src: &'c mut Cursor<&'de [u8]>,

    state: Rc<RefCell<TtlvStateMachine>>,

    // for container/group types (map, seq)
    #[allow(dead_code)]
    group_start: u64,
    group_tag: Option<TtlvTag>,
    group_type: Option<TtlvType>,
    group_end: Option<u64>,
    group_fields: &'static [&'static str], // optional field handling: expected fields to compare to actual fields
    group_item_count: usize,               // optional field handling: index into the group_fields array
    group_homogenous: bool,                // sequence/map field handling: are all items in the group of the same type?

    // for the current field being parsed
    item_start: u64, // optional field handling: point to return to if field is missing
    item_tag: Option<TtlvTag>,
    item_type: Option<TtlvType>,
    item_unexpected: bool, // optional field handling: is this tag wrong for the expected field (and thus is missing?)
    item_identifier: Option<String>,

    // lookup maps
    tag_value_store: Rc<RefCell<HashMap<TtlvTag, String>>>,
    matcher_rule_handlers: [(&'static str, MatcherRuleHandlerFn<'de, 'c>); 3],

    // diagnostic support
    tag_path: Rc<RefCell<Vec<TtlvTag>>>,
}

type MatcherRuleHandlerFn<'de, 'c> =
    fn(&TtlvDeserializer<'de, 'c>, &str, &str) -> std::result::Result<bool, types::Error>;

impl<'de: 'c, 'c> TtlvDeserializer<'de, 'c> {
    // This is not a global read-only static array as they do not support lifetime specification which is required
    // by the Self::fn_name references which is in turn required because the handler functions can use arbitrary data
    // from the current instance of the deserializer. One could argue that the set of matcher fns is fixed and thus we
    // can concretely specify everything in advance, but I'm not convinced that's really more readable.
    fn init_matcher_rule_handlers() -> [(&'static str, MatcherRuleHandlerFn<'de, 'c>); 3] {
        [
            ("==", Self::handle_matcher_rule_eq),
            (">=", Self::handle_matcher_rule_ge),
            ("in", Self::handle_matcher_rule_in),
        ]
    }

    pub fn from_slice(cursor: &'c mut Cursor<&'de [u8]>) -> Self {
        Self {
            src: cursor,
            state: Rc::new(RefCell::new(TtlvStateMachine::new(TtlvStateMachineMode::Deserializing))),
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
            matcher_rule_handlers: Self::init_matcher_rule_handlers(),
            tag_path: Rc::new(RefCell::new(Vec::new())),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn from_cursor(
        src: &'c mut Cursor<&'de [u8]>,
        state: Rc<RefCell<TtlvStateMachine>>,
        group_tag: TtlvTag,
        group_type: TtlvType,
        group_end: u64,
        group_fields: &'static [&'static str],
        group_homogenous: bool, // are all items in the group the same tag and type?
        unit_enum_store: Rc<RefCell<HashMap<TtlvTag, String>>>,
        tag_path: Rc<RefCell<Vec<TtlvTag>>>,
    ) -> Self {
        let group_start = src.position();
        let group_tag = Some(group_tag);
        let group_type = Some(group_type);
        let group_end = Some(group_end);

        Self {
            src,
            state,
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
            matcher_rule_handlers: Self::init_matcher_rule_handlers(),
            tag_path,
        }
    }

    /// Read a 3-byte TTLV tag into an [TtlvTag].
    ///
    /// This function is not normally intended to be used directly. Instead use [from_slice] or [from_reader].
    ///
    /// Note: Also accepts a mut reference.
    ///
    /// # Errors
    ///
    /// If this function is unable to read 3 bytes from the given reader an [Error::IoError] will be returned.
    ///
    /// If the state machine is not in the expected state then [Error::UnexpectedTtlvField] will be returned.
    pub(crate) fn read_tag<R>(
        mut src: R,
        state: Option<&mut TtlvStateMachine>,
    ) -> std::result::Result<TtlvTag, types::Error>
    where
        R: Read,
    {
        if let Some(state) = state {
            state.advance(FieldType::Tag)?;
        }
        TtlvTag::read(&mut src)
    }

    /// Read a 1-byte TTLV type into an [ItemType]
    ///
    /// This function is not normally intended to be used directly. Instead use [from_slice] or [from_reader].
    ///
    /// Note: Also accepts a mut reference.
    ///
    /// # Errors
    ///
    /// If this function is unable to read 1 byte from the given reader an [Error::IoError] will be returned.
    ///
    /// If the read byte is not a valid value according to the KMIP 1.0 TTLV specification or is a type which
    /// we do not yet support an error will be returned.
    ///
    /// If the state machine is not in the expected state then [Error::UnexpectedTtlvField] will be returned.
    pub(crate) fn read_type<R>(
        mut src: R,
        state: Option<&mut TtlvStateMachine>,
    ) -> std::result::Result<TtlvType, types::Error>
    where
        R: Read,
    {
        if let Some(state) = state {
            state.advance(FieldType::Type)?;
        }
        TtlvType::read(&mut src)
    }

    /// Read a 4-byte TTLV length into a u32.
    ///
    /// This function is not normally intended to be used directly. Instead use [from_slice] or [from_reader].
    ///
    /// Note: Also accepts a mut reference.
    ///
    /// # Errors
    ///
    /// If this function is unable to read 4 bytes from the given reader an [Error::IoError] will be returned.
    ///
    /// If the state machine is not in the expected state then [Error::UnexpectedTtlvField] will be returned.
    pub(crate) fn read_length<R>(
        mut src: R,
        state: Option<&mut TtlvStateMachine>,
    ) -> std::result::Result<u32, types::Error>
    where
        R: Read,
    {
        if let Some(state) = state {
            state.advance(FieldType::Length)?;
        }
        TtlvLength::read(&mut src).map(|len| *len)
    }

    /// Read the next TTLV tag and type header and prepare for full deserialization.
    ///
    /// Returns Ok(true) if there is data available, Ok(false) if the end of the current group (TTLV sequence or
    /// structure) has been reached or an I/O error or `MalformedTtlvError` (e.g. if the tag or type are invalid or if
    /// the read cursor is past the last byte of the group).
    fn read_item_key(&mut self, use_group_fields: bool) -> Result<bool> {
        if let Some(group_end) = self.group_end {
            match self.pos().cmp(&group_end) {
                Ordering::Less => {
                    // More bytes to read
                }
                Ordering::Equal => {
                    // End of group reached
                    return Ok(false);
                }
                Ordering::Greater => {
                    // Error: Read cursor is beyond the end of the current TTLV group
                    let error = MalformedTtlvError::overflow(group_end);
                    let location = self.location();
                    return Err(Error::pinpoint(error, location));
                }
            }
        } else {
            unreachable!()
        }

        if use_group_fields {
            self.item_start = self.group_start;
            self.item_tag = self.group_tag;
            self.item_type = self.group_type;
        } else {
            self.item_start = self.pos() as u64;
            self.item_tag = None;
            self.item_type = None;

            let loc = self.location(); // See the note above about working around greedy closure capturing
            self.item_tag = Some(
                Self::read_tag(&mut self.src, Some(&mut self.state.borrow_mut()))
                    .map_err(|err| Error::pinpoint(err, loc))?,
            );

            let loc = self.location(); // See the note above about working around greedy closure capturing
            self.item_type = Some(
                Self::read_type(&mut self.src, Some(&mut self.state.borrow_mut()))
                    .map_err(|err| Error::pinpoint(err, loc))?,
            );
        }

        // As we are invoked for every field that Serde derive found on the target Rust struct we need to handle the
        // not just the case where the expected tag is present in the byte stream in the expected position in the
        // sequence, but also:
        //
        //   - `Option` fields: these represent fields that may optionally exist in the byte stream, i.e. for a Rust
        //     struct field with `#[serde(rename = "0x123456")]` is the next item tag in the byte stream 0x123456 or
        //     something else (because 0x123456 is correctly missing from the byte stream)? These should be
        //     deserialized as `Some` if present, `None` otherwise.
        //
        //   - Missing fields; tags that exist in the byte stream but do not have a corresponding field in the Rust
        //     struct. These should be ignored unless `#[serde(deny_unknown_fields)]` has been used.
        //
        //   - Extra fields: tags that exist in the Rust struct but not in the byte stream. These represent missing
        //     but required data which the absence of which should cause deserialization to fail.
        //
        // Serde derive expects that we announce the name of the field that we have encountered in the byte stream,
        // i.e. that `fn deserialize_identifier()` will invoke `visitor.visit_str()` with the *Rust* field name. Due to
        // our abuse of `#[serde(rename)]` we can't just announce the TTLV tag hex representation as the *Rust* field
        // name, the *Rust* field name may be something special like "if 0x123456 in ...". Serde derive will only
        // accept our deserialized value for the field if we announce the exact same name as the field was assigned in
        // the Rust struct via `#[serde(rename)])`.
        //
        // To know which Rust name to announce as the field identifier we rely on the fact that the KMIP TTLV
        // specification states that "All fields SHALL appear in the order specified" and that Serde derive earlier
        // gave us the set of field names in the group when processing of the group stated. We keep track of how many
        // items we have seen in the group and thus expect that for item N we can assume that Serde derive expects us
        // to announce the Nth group field name.
        //
        // We compare the Nth field name to the tag of the next TTLV item. If N >= M, where N is zero-based and M is
        // the number of fields that Serde derive communicated to us at the start of the group, we announce the TTLV
        // tag in hex form as the field name so that something useful appears in the Serde error message if any. By
        // default Serde will ignore the field value by invoking `fn deserialized_ignored_any()` and we will skip over
        // the bytes of the TTLV item in the stream as if it were not there. If however `#[serde(deny_unknown_fields)]`
        // is in use this scenario causes Serde derive to abort deserialization with an error.
        //
        // If the read tag doesn't match the expected tag, we record that the item is unexpected and continue. If the
        // field in the Rust struct is an `Option` Serde derive will then invoke `fn deserialize_option()` at which
        // point we detect the recorded unexpected flag and return `None` (because there was no item for that tag at
        // this point (which is the correct position in the Rust struct/TTLV Structure sequence for the item) in the
        // byte stream.

        self.group_item_count += 1;

        self.item_unexpected = if self.group_fields.is_empty() {
            // We have no idea which field is expected so this field cannot be unexpected, but we also cannot set the
            // item identifier to announce for this field (though we might establish an identifier subsequently, e.g.
            // in the case of selecting the appropriate Rust enum variant).
            false
        } else {
            let field_index = self.group_item_count - 1;
            let actual_tag_str = &self.item_tag.unwrap().to_string();
            let expected_tag_str = self
                .group_fields
                .get(field_index)
                .map_or_else(|| actual_tag_str.clone(), |v| v.to_string());
            self.item_identifier = Some(expected_tag_str.clone());
            actual_tag_str != &expected_tag_str
        };

        Ok(true)
    }

    fn get_start_tag_type(&mut self) -> Result<(u64, TtlvTag, TtlvType)> {
        let (group_start, group_tag, group_type) = if self.pos() == 0 {
            // When invoked by Serde via from_slice() there is no prior call to next_key_seed() that reads the tag and
            // type as we are not visiting a map at that point. Thus we need to read the opening tag and type here.
            let group_start = self.src.position();

            let loc = self.location(); // See the note above about working around greedy closure capturing
            let group_tag =
                Self::read_tag(&mut self.src, Some(&mut self.state.borrow_mut())).map_err(|err| pinpoint!(err, loc))?;
            self.item_tag = Some(group_tag);

            let loc = self.location(); // See the note above about working around greedy closure capturing
            let group_type = Self::read_type(&mut self.src, Some(&mut self.state.borrow_mut()))
                .map_err(|err| pinpoint!(err, loc))?;
            self.item_type = Some(group_type);

            (group_start, group_tag, group_type)
        } else {
            // When invoked while visiting a map the opening tag and type of the struct header will have already been
            // read by next_key_seed() so we don't need to read them here.
            (self.src.position() - 4, self.item_tag.unwrap(), self.item_type.unwrap())
        };
        Ok((group_start, group_tag, group_type))
    }

    fn prepare_to_descend(&mut self, name: &'static str) -> Result<(u64, TtlvTag, TtlvType, u64)> {
        let loc = self.location(); // See the note above about working around greedy closure capturing
        let wanted_tag = TtlvTag::from_str(name).map_err(|err| pinpoint!(err, loc))?;

        let (group_start, group_tag, group_type) = self.get_start_tag_type()?;

        if group_tag != wanted_tag {
            return Err(pinpoint!(
                SerdeError::UnexpectedTag {
                    expected: wanted_tag,
                    actual: group_tag
                },
                self
            ));
        }

        if group_type != TtlvType::Structure {
            return Err(pinpoint!(
                MalformedTtlvError::UnexpectedType {
                    expected: TtlvType::Structure,
                    actual: group_type
                },
                self
            ));
        }

        let loc = self.location(); // See the note above about working around greedy closure capturing
        let group_len =
            Self::read_length(&mut self.src, Some(&mut self.state.borrow_mut())).map_err(|err| pinpoint!(err, loc))?;
        let group_end = self.pos() + (group_len as u64);
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

        if let Some(rule) = variant.strip_prefix("if ") {
            for (op, handler_fn) in self.matcher_rule_handlers {
                if let Some((wanted_tag, wanted_val)) = split_once(rule, op) {
                    return handler_fn(self, wanted_tag.trim(), wanted_val.trim()).map_err(|err| pinpoint!(err, self));
                }
            }

            return Err(pinpoint!(SerdeError::InvalidVariantMatcherSyntax(variant.into()), self));
        }

        Ok(false)
    }

    fn handle_matcher_rule_eq(&self, wanted_tag: &str, wanted_val: &str) -> std::result::Result<bool, types::Error> {
        if wanted_tag == "type" {
            // See if wanted_val is a literal string that matches the TTLV type we are currently deserializing
            // TODO: Add BigInteger and Interval when supported
            if matches!(
                (wanted_val, self.item_type.unwrap()),
                ("Structure", TtlvType::Structure)
                    | ("Integer", TtlvType::Integer)
                    | ("LongInteger", TtlvType::LongInteger)
                    | ("Enumeration", TtlvType::Enumeration)
                    | ("Boolean", TtlvType::Boolean)
                    | ("TextString", TtlvType::TextString)
                    | ("ByteString", TtlvType::ByteString)
                    | ("DateTime", TtlvType::DateTime)
            ) {
                return Ok(true);
            }
        } else if let Ok(wanted_tag) = TtlvTag::from_str(wanted_tag) {
            if let Some(seen_enum_val) = self.lookup_tag_value(wanted_tag) {
                if seen_enum_val == wanted_val {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    fn handle_matcher_rule_ge(&self, wanted_tag: &str, wanted_val: &str) -> std::result::Result<bool, types::Error> {
        if let Some(seen_enum_val) = self.tag_value_store.borrow().get(&TtlvTag::from_str(wanted_tag)?) {
            if TtlvTag::from_str(seen_enum_val)?.deref() >= TtlvTag::from_str(wanted_val)?.deref() {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn handle_matcher_rule_in(&self, wanted_tag: &str, wanted_val: &str) -> std::result::Result<bool, types::Error> {
        let wanted_values = wanted_val.strip_prefix('[').and_then(|v| v.strip_suffix(']'));
        if let Some(wanted_values) = wanted_values {
            if let Some(seen_enum_val) = self.tag_value_store.borrow().get(&TtlvTag::from_str(wanted_tag)?) {
                for wanted_value in wanted_values.split(',') {
                    if *seen_enum_val == wanted_value.trim() {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    fn location(&self) -> ErrorLocation {
        let mut loc = ErrorLocation::at(self.src.position().into()).with_parent_tags(&self.tag_path.borrow());

        if let Some(tag) = self.item_tag {
            loc = loc.with_tag(tag);
        }

        if let Some(r#type) = self.item_type {
            loc = loc.with_type(r#type);
        }

        loc
    }

    fn remember_tag_value<T>(&self, tag: TtlvTag, value: T)
    where
        String: From<T>,
    {
        self.tag_value_store.borrow_mut().insert(tag, value.into());
    }

    fn lookup_tag_value(&self, tag: TtlvTag) -> Option<String> {
        self.tag_value_store.borrow().get(&tag).cloned()
    }

    fn seek_forward(&mut self, num_bytes_to_skip: u32) -> Result<u64> {
        use std::io::Seek;
        self.src
            .seek(std::io::SeekFrom::Current(num_bytes_to_skip as i64))
            .map_err(|err| pinpoint!(err, self))
    }
}

// TODO: remove this
impl<'de: 'c, 'c> ContextualErrorSupport for TtlvDeserializer<'de, 'c> {
    fn pos(&self) -> u64 {
        self.src.position()
    }
}

macro_rules! unsupported_type {
    ($deserialize:ident, $type:ident) => {
        fn $deserialize<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
            Err(pinpoint!(
                SerdeError::UnsupportedRustType(stringify!($type)),
                self
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

        self.tag_path.borrow_mut().push(group_tag);

        let descendent_parser = TtlvDeserializer::from_cursor(
            &mut struct_cursor,
            self.state.clone(),
            group_tag,
            group_type,
            group_end,
            fields,
            false, // struct member fields can have different tags and types
            self.tag_value_store.clone(),
            self.tag_path.clone(),
        );

        let r = visitor.visit_map(descendent_parser); // jumps to impl MapAccess below

        // The descendant parser cursor advanced but ours did not. Skip the tag that we just read.
        self.src.set_position(struct_cursor.position());

        match r {
            Ok(_) => {
                self.tag_path.borrow_mut().pop();
                r
            }
            Err(err) => {
                // Errors can be raised directly by Serde Derive, e.g. SerdeError::Other("missing field"), which
                // necessarily have ErrorLocation::is_unknown() as Serde Derive is not aware of our ErrorLocation type.
                // When that happens, this is the first opportunity after calling `visitor.visit_map()` that we have to
                // add the missing location data. However, if the error _was_ raised by our code and not by Serde
                // Derive it probably already has location details. Therefore we "merge" the current location into the
                // error so that only missing details are added if needed as the existing location details may more
                // point more accurately to the source of the problem than we are able to indicate here (we don't know
                // where in the `visit_map()` process the issue occured, on which field and at which byte, we just use
                // the current cursor position and hope that is good enough).
                let (kind, loc) = err.into_inner();
                let new_loc = loc.merge(self.location());
                Err(Error::new(kind, new_loc))
            }
        }
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
        let seq_tag = self.item_tag.unwrap();
        let seq_type = self.item_type.unwrap();
        let seq_end = self.group_end.unwrap();

        let mut seq_cursor = self.src.clone();

        let descendent_parser = TtlvDeserializer::from_cursor(
            &mut seq_cursor,
            self.state.clone(),
            seq_tag,
            seq_type,
            seq_end,
            &[],
            true, // sequence fields must all have the same tag and type
            self.tag_value_store.clone(),
            self.tag_path.clone(),
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
        // The tag and type have already been read, now we are handling the value. How can we know that this item is
        // NOT the one that was intended to fill the Option and thus the item is missing and the Option should be
        // populated with None. This can happen e.g. in the case of a KMIP response the response batch item structure
        // 0x42000F has several optional member fields including the operation code field 0x42005C. The operation code
        // field is only required to be present in the response if it was present in the request. The order of fields
        // in a KMIP structure is also required to match that of the spec and the operation code field is the first
        // item in the response batch item structure.
        //
        // Thus if we define a Rust struct for the response batch item TTLV structure the first member must be an
        // optional operation code, but the first batch item structure member field present in the TTLV response might
        // be another response batch item field such as result status 0x42007F. We handle this by detecting the
        // mismatch between Rust field name (i.e. TTLV tag) and the actual tag code found in the TTLV bytes. If they do
        // not match and the Rust field was of type Option then we respond as if the field value was read and the
        // Option should be set to None, but we reset the read cursor in the TTLV byte stream so that we will read this
        // "wrong" tag again as it should match one of the as yet unprocessed member fields in the Rust struct.
        //
        // Finally we have to reset the state machine as we just read a tag and type and the next TTLV fields should be
        // the length and value, but we are resetting the read cursor to point at the tag again.

        // Is this the field we expected at this point?
        if self.item_unexpected {
            // This isn't the item that the caller expected but they indicated that the expected item was optional.
            // Report back that the optional item was not found and rewind the read cursor so that we will visit this
            // TTLV tag again.
            self.src.set_position(self.item_start);
            // Reset the state machine to expect a tag as it's currently expecting a value but should expect a tag.
            self.state.borrow_mut().reset();
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
            Some(TtlvType::Enumeration) | Some(TtlvType::Integer) => {
                // 2: Read a TTLV enumeration from the byte stream and announce the read value as the enum variant name.
                //    If we are selecting an enum variant based on a special "if" string then item_identifier will be
                //    Some(xxx) where xxx will NOT match the TTLV value that is waiting to be read, instead that will
                //    match an inner enum variant so we read the TTLV value when we visit this function again deeper in
                //    the call hierarchy. This enables handling of cases such as `AttributeName` string field that
                //    indicates the enum variant represented by the `AttributeValue`.
                if self.item_identifier.is_none() {
                    let loc = self.location(); // See the note above about working around greedy closure capturing
                    self.state
                        .borrow_mut()
                        .advance(FieldType::LengthAndValue)
                        .map_err(|err| pinpoint!(err, loc.clone()))?;
                    let enum_val = TtlvEnumeration::read(self.src).map_err(|err| pinpoint!(err, loc))?;
                    let enum_hex = format!("0x{}", hex::encode_upper(enum_val.to_be_bytes()));

                    // Insert or replace the last value seen for this enum in our enum value lookup table
                    self.remember_tag_value(self.item_tag.unwrap(), &enum_hex);

                    self.item_identifier = Some(enum_hex);
                }

                visitor.visit_enum(&mut *self) // jumps to impl EnumAccess (ending at unit_variant()) below
            }
            Some(item_type) => {
                // "simple" enums, i.e. TTLV integer or TTLV enumeration values in the byte stream, are handled by the
                // case above.
                //
                // This case is for handling non-enum non-int TTLV types in the byte stream which are next to deserialize
                // because they match a "complex" enum variant, i.e. a tuple or struct variant that has an associated type
                // or types whose values are now attempintg to deserialize.
                //
                // As we can't read an enum/int value from the byte stream and use that as the item_identifier to announce
                // to serde we can't select the right variant. So instead we is_variant_applicable() to have been used
                // successfully above to grab a variant name to announce here. So if we get here and self.item_identifier
                // is not set then we can't announce a variant and Serde will fail to deserialize. That's fine, users
                // shouldn't be trying to deserialize non-TTLV-enums into Rust enums directly!

                // This logic can handle cases such as a previously seen `BatchItem.operation` enum field whose value was
                // e.g. 0x00000005 which we stored in the value_store map against the tag id of the `BatchItem.operation`
                // field and can now use that to select a variant by naming the variant
                // "if <prev_tag_id> == <this_variant_id>".

                // If we couldn't work out the correct variant name to announce to serde, don't bother going further as
                // that will result in `deserialize_identfier()` below calling `visitor.visit_str(identifier)` which will
                // then raise a `SerdeError::Other("unknown variant")` error. That isn't terrible, but it's better to
                // raise a `SerdeError::UnexpectedType` error here instead as really we are being asked to deserialize a
                // non-enum TTLV item into a Rust enum which is a type expectation mismatch.
                if self.item_identifier.is_none() {
                    let error = SerdeError::UnexpectedType {
                        expected: TtlvType::Enumeration,
                        actual: item_type,
                    };
                    Err(pinpoint!(error, self))
                } else {
                    visitor.visit_enum(&mut *self) // jumps to impl EnumAccess below
                }
            }
            None => {
                let error = SerdeError::Other(format!("TTLV item type for enum '{}' has not yet been read", name));
                Err(pinpoint!(error, self))
            }
        }
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        if let Some(identifier) = &self.item_identifier {
            visitor.visit_str(identifier)
        } else {
            Err(pinpoint!(SerdeError::MissingIdentifier, self))
        }
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let loc = self.location(); // See the note above about working around greedy closure capturing
        self.state
            .borrow_mut()
            .advance(FieldType::LengthAndValue)
            .map_err(|err| pinpoint!(err, loc))?;
        match self.item_type {
            Some(TtlvType::Integer) | None => {
                let v = TtlvInteger::read(&mut self.src).map_err(|err| pinpoint!(err, self))?;
                visitor.visit_i32(*v)
            }
            Some(other_type) => {
                let error = SerdeError::UnexpectedType {
                    expected: TtlvType::Integer,
                    actual: other_type,
                };
                Err(pinpoint!(error, self))
            }
        }
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let loc = self.location(); // See the note above about working around greedy closure capturing
        self.state
            .borrow_mut()
            .advance(FieldType::LengthAndValue)
            .map_err(|err| pinpoint!(err, loc))?;
        match self.item_type {
            Some(TtlvType::LongInteger) | None => {
                let v = TtlvLongInteger::read(&mut self.src).map_err(|err| pinpoint!(err, self))?;
                visitor.visit_i64(*v)
            }
            Some(TtlvType::DateTime) => {
                let v = TtlvDateTime::read(&mut self.src).map_err(|err| pinpoint!(err, self))?;
                visitor.visit_i64(*v)
            }
            Some(other_type) => {
                let error = SerdeError::UnexpectedType {
                    expected: TtlvType::LongInteger,
                    actual: other_type,
                };
                Err(pinpoint!(error, self))
            }
        }
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let loc = self.location(); // See the note above about working around greedy closure capturing
        self.state
            .borrow_mut()
            .advance(FieldType::LengthAndValue)
            .map_err(|err| pinpoint!(err, loc))?;
        match self.item_type {
            Some(TtlvType::Boolean) | None => {
                let v = TtlvBoolean::read(&mut self.src).map_err(|err| pinpoint!(err, self))?;
                visitor.visit_bool(*v)
            }
            Some(other_type) => {
                let error = SerdeError::UnexpectedType {
                    expected: TtlvType::Boolean,
                    actual: other_type,
                };
                Err(pinpoint!(error, self))
            }
        }
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let loc = self.location(); // See the note above about working around greedy closure capturing
        self.state
            .borrow_mut()
            .advance(FieldType::LengthAndValue)
            .map_err(|err| pinpoint!(err, loc))?;
        match self.item_type {
            Some(TtlvType::TextString) | None => {
                let str = TtlvTextString::read(&mut self.src).map_err(|err| pinpoint!(err, self.location()))?;

                // Insert or replace the last value seen for this tag in our value lookup table
                self.remember_tag_value(self.item_tag.unwrap(), str.0.clone());

                visitor.visit_string(str.0)
            }
            Some(other_type) => {
                let error = SerdeError::UnexpectedType {
                    expected: TtlvType::TextString,
                    actual: other_type,
                };
                Err(pinpoint!(error, self))
            }
        }
    }

    /// Use #[serde(with = "serde_bytes")] to direct Serde to this deserializer function for type Vec<u8>.
    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let loc = self.location(); // See the note above about working around greedy closure capturing
        self.state
            .borrow_mut()
            .advance(FieldType::LengthAndValue)
            .map_err(|err| pinpoint!(err, loc))?;
        match self.item_type {
            Some(TtlvType::ByteString) | Some(TtlvType::BigInteger) | None => {
                let v = TtlvByteString::read(&mut self.src).map_err(|err| pinpoint!(err, self))?;
                visitor.visit_byte_buf(v.0)
            }
            Some(other_type) => {
                let error = SerdeError::UnexpectedType {
                    expected: TtlvType::ByteString,
                    actual: other_type,
                };
                Err(pinpoint!(error, self))
            }
        }
    }

    /// Skip over the current TTLV item.
    ///
    /// When `#[serde(deny_unknown_fields)]` is not used this function is invoked by Serde derive to have us skip over
    /// a TTLV item for which no corresponding Rust struct field exists to deserialize it into.
    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // Skip over the TTLV item. We can't just read the length and skip it because the meaning of the length is TTLV
        // type dependent. For some types it is the entire byte size of the TTLV item, for others it is the length of
        // the TTLV item value excluding padding. For TTLV Structures skip the whole structure content. For other types
        // deserialize them but discard the deserialized value.

        if matches!(self.item_type.unwrap(), TtlvType::Structure) {
            // We're going to read the structure length and then skip it without reading the value
            // Reading the length advances the state machine past the length but not past the value
            // so we have to do that manually.

            // Use the TTLV item length to skip the structure.
            let num_bytes_to_skip = TtlvDeserializer::read_length(&mut self.src, Some(&mut self.state.borrow_mut()))
                .map_err(|err| pinpoint!(err, self.location()))?;

            // Skip the value bytes
            self.seek_forward(num_bytes_to_skip)?;

            // Tell the state machine that we're finished reading this TTLV item
            self.state.borrow_mut().reset();
        } else {
            // We're going to read the value length, read the value and discard the value, all without involving
            // the state machine, so tell it what we are about to do.
            // TODO: pass the state machine to the ::read() functions instead and have them update it.
            let loc = self.location(); // See the note above about working around greedy closure capturing
            self.state
                .borrow_mut()
                .advance(FieldType::LengthAndValue)
                .map_err(|err| pinpoint!(err, loc))?;

            match self.item_type.unwrap() {
                TtlvType::Structure => {
                    // We handled this case above
                    unreachable!()
                }
                TtlvType::Integer => {
                    TtlvInteger::read(&mut self.src).map_err(|err| pinpoint!(err, self))?;
                }
                TtlvType::LongInteger => {
                    TtlvLongInteger::read(&mut self.src).map_err(|err| pinpoint!(err, self))?;
                }
                TtlvType::BigInteger => {
                    TtlvBigInteger::read(&mut self.src).map_err(|err| pinpoint!(err, self))?;
                }
                TtlvType::Enumeration => {
                    TtlvEnumeration::read(&mut self.src).map_err(|err| pinpoint!(err, self))?;
                }
                TtlvType::Boolean => {
                    TtlvBoolean::read(&mut self.src).map_err(|err| pinpoint!(err, self))?;
                }
                TtlvType::TextString => {
                    TtlvTextString::read(&mut self.src).map_err(|err| pinpoint!(err, self))?;
                }
                TtlvType::ByteString => {
                    TtlvByteString::read(&mut self.src).map_err(|err| pinpoint!(err, self))?;
                }
                TtlvType::DateTime => {
                    TtlvDateTime::read(&mut self.src).map_err(|err| pinpoint!(err, self))?;
                }
            }
        }

        // Any visitor fn can be invoked here, they all internally return Ok(IgnoredAny).
        visitor.visit_none()
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

    fn deserialize_unit_struct<V>(self, _name: &'static str, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(pinpoint!(SerdeError::UnsupportedRustType("unit struct"), self))
    }

    fn deserialize_tuple_struct<V>(self, _name: &'static str, _len: usize, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(pinpoint!(SerdeError::UnsupportedRustType("tuple struct"), self))
    }

    fn deserialize_tuple<V>(self, _len: usize, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(pinpoint!(SerdeError::UnsupportedRustType("tuple"), self))
    }

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(pinpoint!(SerdeError::UnsupportedRustType("any"), self))
    }
}

// Deserialize structure members
impl<'de: 'c, 'c> MapAccess<'de> for TtlvDeserializer<'de, 'c> {
    type Error = Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: serde::de::DeserializeSeed<'de>,
    {
        if self.read_item_key(false)? {
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
        if !self.read_item_key(self.group_item_count == 0)? {
            // The end of the containing group was reached
            Ok(None)
        } else if self.group_homogenous && (self.item_tag != self.group_tag || self.item_type != self.group_type) {
            // The next tag is not part of the sequence.
            // Walk the cursor back before the tag because we didn't consume it.
            self.src.set_position(self.item_start);
            // And reset the state machine to expect a tag again
            self.state.borrow_mut().reset();
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
        let loc = self.location(); // See the note above about working around greedy closure capturing
        let seq_len = TtlvDeserializer::read_length(&mut self.src, Some(&mut self.state.borrow_mut()))
            .map_err(|err| pinpoint!(err, loc))?;
        let seq_start = self.pos() as u64;
        let seq_end = seq_start + (seq_len as u64);

        let loc = self.location(); // See the note above about working around greedy closure capturing
        let seq_tag = TtlvDeserializer::read_tag(&mut self.src, Some(&mut self.state.borrow_mut()))
            .map_err(|err| pinpoint!(err, loc))?;
        self.item_tag = Some(seq_tag);

        let loc = self.location(); // See the note above about working around greedy closure capturing
        let seq_type = TtlvDeserializer::read_type(&mut self.src, Some(&mut self.state.borrow_mut()))
            .map_err(|err| pinpoint!(err, loc))?;
        self.item_type = Some(seq_type);

        let mut seq_cursor = self.src.clone();

        let descendent_parser = TtlvDeserializer::from_cursor(
            &mut seq_cursor,
            self.state.clone(),
            seq_tag,
            seq_type,
            seq_end,
            &[],
            false, // don't require all fields in the sequence to be of the same tag and type
            self.tag_value_store.clone(),
            self.tag_path.clone(),
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
        Err(pinpoint!(SerdeError::UnsupportedRustType("struct variant"), self))
    }
}
