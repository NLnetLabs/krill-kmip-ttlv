//! Useful functionality separate but related to (de)serialization.
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt::Write;
use std::io::Cursor;
use std::ops::Deref;
use std::str::FromStr;

use crate::de::TtlvDeserializer;
use crate::error::ErrorKind;
use crate::types::{
    SerializableTtlvType, TtlvBigInteger, TtlvBoolean, TtlvByteString, TtlvDateTime, TtlvEnumeration, TtlvInteger,
    TtlvLongInteger, TtlvStateMachine, TtlvStateMachineMode, TtlvTag, TtlvTextString, TtlvType,
};

/// Facilities for pretty printing TTLV bytes to text format.
#[derive(Clone, Debug, Default)]
pub struct PrettyPrinter {
    tag_prefix: String,
    tag_map: HashMap<TtlvTag, &'static str>,
}

impl PrettyPrinter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the pretty printer's tag prefix.
    ///
    /// This can be used both to strip common tag prefixes from the output produced by [PrettyPrinter::to_diag_string()]
    /// to make it shorter, and to restore them when using [PrettyPrinter::from_diag_string()].
    pub fn with_tag_prefix(&mut self, tag_prefix: String) -> &Self {
        self.tag_prefix = tag_prefix;
        self
    }

    /// Set the pretty printer's tag map.
    ///
    /// The tag map is used to render a meaningful name for hexadecimal tag identifiers in pretty printed output by
    /// looking up the human friendly name associated with the tag in the given map.
    pub fn with_tag_map(&mut self, tag_map: HashMap<TtlvTag, &'static str>) -> &Self {
        self.tag_map = tag_map;
        self
    }

    /// Interpret the given byte slice as TTLV as much as possible and render it to a String in human readable form.
    ///
    /// An example string for a successful KMIP 1.0 create symmetric key response could look like this:
    ///
    /// ```text
    /// Tag: 0x42007B, Type: Structure (0x01), Data:
    ///   Tag: 0x42007A, Type: Structure (0x01), Data:
    ///     Tag: 0x420069, Type: Structure (0x01), Data:
    ///       Tag: 0x42006A, Type: Integer (0x02), Data: 0x000001 (1)
    ///       Tag: 0x42006B, Type: Integer (0x02), Data: 0x000000 (0)
    ///     Tag: 0x420092, Type: DateTime (0x09), Data: 0x4AFBE7C2
    ///     Tag: 0x42000D, Type: Integer (0x02), Data: 0x000001 (1)
    ///   Tag: 0x42000F, Type: Structure (0x01), Data:
    ///     Tag: 0x42005C, Type: Enumeration (0x05), Data: 0x000001 (1)
    ///     Tag: 0x42007F, Type: Enumeration (0x05), Data: 0x000000 (0)
    ///     Tag: 0x42007C, Type: Structure (0x01), Data:
    ///       Tag: 0x420057, Type: Enumeration (0x05), Data: 0x000002 (2)
    ///       Tag: 0x420094, Type: TextString (0x07), Data: fc8833de-70d2-4ece-b063-fede3a3c59fe
    /// ```
    ///
    /// If configured using [PrettyPrinter::with_tag_map()] the hexadecimal tag identifiers will be prefixed by their
    /// mapped human readable name.
    ///
    /// For a more compact form that omits sensitive details see [PrettyPrinter::to_diag_string()].
    pub fn to_string(&self, bytes: &[u8]) -> String {
        self.internal_to_string(bytes, false)
    }

    /// Interpret the given byte slice as TTLV as much as possible and render it to a String in compact diagnostic form.
    ///
    /// It will contain only the tags, types, the tags hierarchical relationship to one another, and enum values but no
    /// other values (to avoid including sensitive data in the report). The format is compact and not intended for end
    /// users to interpret but rather to be included in problem reports to the vendor of the application using this
    /// library.
    ///
    /// The [PrettyPrinter::with_tag_prefix()] configuration setting can be used to further compact the created
    /// diagnostic string by removing the specified prefix from the hex representation of all TTLV tags. For example if
    /// used with the KMIP protocol one could strip "4200" from all tags as all official KMIP 1.0 tags begin with 4200.
    ///
    /// An example diagnostic string for a successful KMIP 1.0 create symmetric key response could look like this:
    ///
    /// ```text
    /// 7B[7A[69[6Ai6Bi]92d0Di]0F[5Ce17Fe07C[57e294t]]]
    /// ```
    ///
    /// This is a compact and desensitized form of the same response shown in the [PrettyPrinter::to_string()] example. The `[` and
    /// `]` characters denote the start and end points of KMIP structures. The 4200 tag prefixes have been stripped in this
    /// example so each tag is two hex characters, e.g. `7B` is short for `0x42007B` which is the KMIP Response Message
    /// tag, and `7A` is the Response Header tag (0x42007A). Actual values are omitted except for their types (i - Integer,
    /// I - Big Integer, l - Long Integer, e - Enumeration, t - Text String, o - Byte String (o for Octal, etc).
    /// Enumeration values are included in hexadecimal form, e.g. `5Ce1` is tag 0x42005C Operation, `e` denotes that this
    /// is an Enumeration and its value `1` i.e. 0x00000001 indicates that it was a Create operation.
    ///
    /// Such diagnostic strings could be useful to generate for all TTLV requests and responses in order to store the last
    /// N in memory and be able to dump them out if a TTLV related problem occurs, and/or to log at debug or trace level.
    pub fn to_diag_string(&self, bytes: &[u8]) -> String {
        self.internal_to_string(bytes, true)
    }

    fn internal_to_string(&self, bytes: &[u8], diagnostic_report: bool) -> String {
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
        fn deserialize_ttlv_to_string(
            mut cursor: &mut Cursor<&[u8]>,
            diagnostic_report: bool,
            strip_tag_prefix: &str,
            tag_map: &HashMap<TtlvTag, &'static str>,
        ) -> std::result::Result<(String, Option<u64>), ErrorKind> {
            let mut sm = TtlvStateMachine::new(TtlvStateMachineMode::Deserializing);
            let tag = TtlvDeserializer::read_tag(&mut cursor, Some(&mut sm))?;
            let typ = TtlvDeserializer::read_type(&mut cursor, Some(&mut sm))?;
            let mut len = Option::<u64>::None;
            const EMPTY_STRING: String = String::new();

            let fragment = if !diagnostic_report {
                #[rustfmt::skip]
            let data = match typ {
                TtlvType::Structure   => { len = Some(TtlvDeserializer::read_length(cursor, Some(&mut sm))? as u64); EMPTY_STRING }
                TtlvType::Integer     => { format!(" {data:#08X} ({data})", data = TtlvInteger::read(cursor)?.deref()) }
                TtlvType::LongInteger => { format!(" {data:#08X} ({data})", data = TtlvLongInteger::read(cursor)?.deref()) }
                TtlvType::BigInteger  => { format!(" {data}", data = hex::encode_upper(&TtlvBigInteger::read(cursor)?.deref())) }
                TtlvType::Enumeration => { format!(" {data:#08X} ({data})", data = TtlvEnumeration::read(cursor)?.deref()) }
                TtlvType::Boolean     => { format!(" {data}", data = TtlvBoolean::read(cursor)?.deref()) }
                TtlvType::TextString  => { format!(" {data}", data = TtlvTextString::read(cursor)?.deref()) }
                TtlvType::ByteString  => { format!(" {data}", data = hex::encode_upper(&TtlvByteString::read(cursor)?.deref())) }
                TtlvType::DateTime    => { format!(" {data:#08X}", data = TtlvDateTime::read(cursor)?.deref()) }
            };

                if let Some(tag_name) = tag_map.get(&tag) {
                    format!("Tag: {} ({:#06X}), Type: {}, Data:{}\n", tag_name, *tag, typ, data)
                } else {
                    format!("Tag: {:#06X}, Type: {}, Data:{}\n", *tag, typ, data)
                }
            } else {
                #[rustfmt::skip]
            let data = match typ {
                TtlvType::Structure   => { len = Some(TtlvDeserializer::read_length(cursor, Some(&mut sm))? as u64); EMPTY_STRING }
                TtlvType::Integer     => { TtlvInteger::read(cursor)?; "i".to_string() }
                TtlvType::LongInteger => { TtlvLongInteger::read(cursor)?; "l".to_string() }
                TtlvType::BigInteger  => { TtlvBigInteger::read(cursor)?; "I".to_string() }
                TtlvType::Enumeration => { format!("e{data:X}:", data = TtlvEnumeration::read(cursor)?.deref()) }
                TtlvType::Boolean     => { TtlvBoolean::read(cursor)?; "b".to_string() }
                TtlvType::TextString  => { TtlvTextString::read(cursor)?; "t".to_string() }
                TtlvType::ByteString  => { TtlvByteString::read(cursor)?; "o".to_string() }
                TtlvType::DateTime    => { TtlvDateTime::read(cursor)?; "d".to_string() }
            };

                let tag = format!("{:06X}", *tag);
                let tag = tag.strip_prefix(&strip_tag_prefix).unwrap_or(&tag);
                format!("{}{}", tag, data)
            };

            Ok((fragment, len))
        }

        loop {
            // Handle walking off the end of the current structure and the entire input
            loop {
                let rel_pos = cur_struct_end.map_or(Ordering::Less, |end| cursor.position().cmp(&end));
                match rel_pos {
                    Ordering::Less => {
                        // Keep processing the current TTLV structure items
                        break;
                    }
                    Ordering::Equal => {
                        // End of current (sub)structure reached, outdent and use end of parent structure as next struct end
                        if let Some(end) = struct_ends.pop() {
                            if !diagnostic_report {
                                indent -= 2;
                            } else {
                                report.push(']');
                            }
                            cur_struct_end = Some(end);
                        } else {
                            // No more parent structures, we have finished processing the TTLV bytes
                            if diagnostic_report {
                                report.push(']');
                            }
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
            let pos = cursor.position();
            let res = deserialize_ttlv_to_string(&mut cursor, diagnostic_report, &self.tag_prefix, &self.tag_map)
                .map_err(|err| pinpoint!(err, pos));

            match res {
                Ok((ttlv_string, possible_new_struct_len)) => {
                    // Add (with correct indentation) the human readable result of deserialization to the "report" built up
                    // so far.
                    if !diagnostic_report {
                        let _ = write!(
                            report,
                            "{:width$}{ttlv_string}",
                            width = indent,
                            ttlv_string = &ttlv_string
                        );
                    } else {
                        report.push_str(&ttlv_string);
                    }

                    // Handle descent into an inner TTLV "Structure"
                    if let Some(new_len) = possible_new_struct_len {
                        if !diagnostic_report {
                            indent += 2;
                        } else {
                            report.push('[');
                        }

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
                            if !diagnostic_report {
                                report.push_str("WARNING: TTLV structure length is zero\n");
                            }
                            broken = true;
                        } else {
                            cur_struct_end = Some(cursor.position() + new_len);
                        }
                    }
                }
                Err(err) => {
                    // Oops, we couldn't deserialize a TTLV from the input stream at the current cursor position
                    if !diagnostic_report {
                        let _ = write!(
                            report,
                            "ERROR: {} (cursor pos={}, end={:?})",
                            err,
                            cursor.position(),
                            cur_struct_end
                        );
                    } else {
                        report.push_str("ERR");
                    }
                    return report;
                }
            }
        }
    }

    /// Render the given diag string in human readable form.
    ///
    /// This function can be used to render a String previously created by [PrettyPrinter::to_diag_string()] to a
    /// format similar to that produced by [PrettyPrinter::to_string()].
    ///
    /// For example for the following input string:
    ///
    /// ```text
    /// 78[77[69[6Ai6Bi]0C[23[24e1:25[99tA1t]]]0Di]0F[5Ce12:79[94t]]]
    /// ```
    ///
    /// The pretty output produced by this function when using a suitable `tag_map` would look like this:
    ///
    /// ```text
    /// Tag: Request Message (0x420078), Type: Structure (0x01), Data:
    ///   Tag: Request Header (0x420077), Type: Structure (0x01), Data:
    ///     Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
    ///       Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: <redacted>
    ///       Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: <redacted>
    ///     Tag: Authentication (0x42000C), Type: Structure (0x01), Data:
    ///       Tag: Credential (0x420023), Type: Structure (0x01), Data:
    ///         Tag: Credential Type (0x420024), Type: Enumeration (0x05), Data: 1
    ///         Tag: Credential Value (0x420025), Type: Structure (0x01), Data:
    ///           Tag: Username (0x420099), Type: TextString (0x07), Data: <redacted>
    ///           Tag: Password (0x4200A1), Type: TextString (0x07), Data: <redacted>
    ///     Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: <redacted>
    ///   Tag: Batch Item (0x42000F), Type: Structure (0x01), Data:
    ///     Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 12
    ///     Tag: Request Payload (0x420079), Type: Structure (0x01), Data:
    ///       Tag: Unique Identifier (0x420094), Type: TextString (0x07), Data: <redacted>
    /// ```
    ///
    /// Notice how the sensitive details are shown as `<redacted>` because [PrettyPrinter::to_diag_string()] omitted
    /// them from the string it produced that we used as input. This example also demonstrates use of a `tag_map` to
    /// give meaning to the hexadecimal tag identifiers.
    pub fn from_diag_string(&self, diag_str: &str) -> String {
        fn read_tag<'a>(s: &'a str, tag_prefix: &str) -> Option<(Option<TtlvTag>, Option<&'a str>)> {
            // if the next character is ']' it signals the end of a TTLV Structure
            if let Some(']') = s.chars().next() {
                return Some((None, Some(&s[1..])));
            }

            // read until the first non-capital hex character
            let (tag_str, opt_new_s) = if let Some(bracket_idx) = s.find(|c: char| !matches!(c, '0'..='9' | 'A'..='F'))
            {
                (s[..bracket_idx].to_string(), Some(&s[bracket_idx..]))
            } else if !s.is_empty() {
                (s.to_string(), None)
            } else {
                return None;
            };

            let tag_str = format!("0x{}{}", tag_prefix, tag_str);
            if let Ok(tag) = TtlvTag::from_str(&tag_str) {
                Some((Some(tag), opt_new_s))
            } else {
                None
            }
        }

        fn read_typ(s: &str) -> Option<(TtlvType, Option<&str>)> {
            let mut iter = s.chars();
            if let Some(c) = iter.next() {
                let new_s = if iter.next().is_some() { Some(&s[1..]) } else { None };
                match c {
                    '[' => Some((TtlvType::Structure, new_s)),
                    'i' => Some((TtlvType::Integer, new_s)),
                    'l' => Some((TtlvType::LongInteger, new_s)),
                    'I' => Some((TtlvType::BigInteger, new_s)),
                    'e' => Some((TtlvType::Enumeration, new_s)),
                    'b' => Some((TtlvType::Boolean, new_s)),
                    't' => Some((TtlvType::TextString, new_s)),
                    'o' => Some((TtlvType::ByteString, new_s)),
                    'd' => Some((TtlvType::DateTime, new_s)),
                    _ => None,
                }
            } else {
                None
            }
        }

        fn read_val<'a>(
            indent: &str,
            s: &'a str,
            typ: TtlvType,
            tag_map: &HashMap<TtlvTag, &'static str>,
            tag_prefix: &str,
        ) -> Option<(String, Option<&'a str>)> {
            // split_once isn't available until Rust 1.52
            pub fn split_once(s: &str, delimiter: char) -> Option<(&str, &str)> {
                let (start, end) = s.split_at(s.find(delimiter)?);
                Some((&start[..=(start.len() - 1)], &end[1..]))
            }

            match typ {
                TtlvType::Structure => {
                    // recurse
                    let indent = format!("  {}", indent);
                    let next = read_next(&indent, s, tag_map, tag_prefix);
                    if next.trim().is_empty() {
                        Some((String::new(), None))
                    } else {
                        Some((format!("\n{}", next), None))
                    }
                }
                TtlvType::Enumeration => {
                    // split at the enumeration value terminator ':' character
                    match split_once(s, ':') {
                        Some((before, "")) => Some((before.to_string(), None)),
                        Some((before, after)) => Some((before.to_string(), Some(after))),
                        None => None,
                    }
                }
                _ => {
                    // no value to read
                    Some(("<redacted>".into(), Some(s)))
                }
            }
        }

        fn read_next(in_indent: &str, s: &str, tag_map: &HashMap<TtlvTag, &'static str>, tag_prefix: &str) -> String {
            let mut out = String::new();
            let mut outer_s = s;
            let mut indent = in_indent;

            loop {
                if let Some((opt_tag, opt_new_s)) = read_tag(outer_s, tag_prefix) {
                    if let Some(tag) = opt_tag {
                        out.push_str(indent);
                        if let Some(tag_name) = tag_map.get(&tag) {
                            let _ = write!(out, "Tag: {} ({:#06X})", tag_name, *tag);
                        } else {
                            let _ = write!(out, "Tag: {:#06X}", *tag);
                        }
                        if let Some(s) = opt_new_s {
                            if let Some((typ, opt_new_s)) = read_typ(s) {
                                let _ = write!(out, ", Type: {}", typ);
                                if let Some(s) = opt_new_s {
                                    if let Some((val, opt_new_s)) = read_val(indent, s, typ, tag_map, tag_prefix) {
                                        let _ = writeln!(out, ", Data: {}", &val);
                                        if let Some(s) = opt_new_s {
                                            outer_s = s;
                                            continue;
                                        }
                                    }
                                }
                            }
                        }
                    } else if let Some(s) = opt_new_s {
                        // this is this the end of a structure
                        indent = &indent[2..];
                        outer_s = s;
                        continue;
                    }
                }

                break;
            }

            out
        }

        read_next("", diag_str, &self.tag_map, &self.tag_prefix)
            .trim_end()
            .to_string()
    }
}
