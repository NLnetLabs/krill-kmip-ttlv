//! Facilities for pretty printing TTLV bytes to text format.
use std::cmp::Ordering;
use std::io::Cursor;
use std::ops::Deref;

use crate::de::TtlvDeserializer;
use crate::error::ErrorKind;
use crate::types::{
    SerializableTtlvType, TtlvBigInteger, TtlvBoolean, TtlvByteString, TtlvDateTime, TtlvEnumeration, TtlvInteger,
    TtlvLongInteger, TtlvStateMachine, TtlvStateMachineMode, TtlvTextString, TtlvType,
};

#[derive(Clone, Debug, Default)]
pub struct PrettyPrinter {
    tag_prefix: String,

impl PrettyPrinter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the pretty printer's tag prefix.
    pub fn with_tag_prefix(&mut self, tag_prefix: String) -> &Self {
        self.tag_prefix = tag_prefix;
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
/// For a more compact form that omits sensitive details see [to_diag_string()].
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
/// The `strip_tag_prefix` string argument can be used to further compact the created diagnostic string by removing the
/// specified prefix from the hex representation of all TTLV tags. For example if used with the KMIP protocol one could
/// strip "4200" from all tags as all official KMIP tags begin with 4200.
///
/// An example diagnostic string for a successful KMIP 1.0 create symmetric key response could look like this:
///
/// ```text
/// 7B[7A[69[6Ai6Bi]92d0Di]0F[5Ce17Fe07C[57e294t]]]
/// ```
///
/// This is a compact and desensitized form of the same response shown in the [to_string()] example. The `[` and
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

            format!("Tag: {:#06X}, Type: {}, Data:{}\n", *tag, typ, data)
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
        let res = deserialize_ttlv_to_string(&mut cursor, diagnostic_report, &strip_tag_prefix)
            .map_err(|err| pinpoint!(err, pos));

        match res {
            Ok((ttlv_string, possible_new_struct_len)) => {
                // Add (with correct indentation) the human readable result of deserialization to the "report" built up
                // so far.
                if !diagnostic_report {
                    report.push_str(&format!(
                        "{:width$}{ttlv_string}",
                        "",
                        width = indent,
                        ttlv_string = &ttlv_string
                    ));
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
                    report.push_str(&format!(
                        "ERROR: {} (cursor pos={}, end={:?})",
                        err,
                        cursor.position(),
                        cur_struct_end
                    ));
                } else {
                    report.push_str("ERR");
                }
                return report;
            }
        }
    }
}
