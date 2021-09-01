use std::cmp::Ordering;
use std::io::Cursor;
use std::ops::Deref;

use crate::de::TtlvDeserializer;
use crate::error::Result;
use crate::types::{
    SerializableTtlvType, TtlvBigInteger, TtlvBoolean, TtlvByteString, TtlvDateTime, TtlvEnumeration, TtlvInteger,
    TtlvLongInteger, TtlvTextString, TtlvType,
};

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
            TtlvType::Structure   => { len = Some(TtlvDeserializer::read_length(cursor)? as u64); EMPTY_STRING }
            TtlvType::Integer     => { format!(" {data:#08X} ({data})", data = TtlvInteger::read(cursor)?.deref()) }
            TtlvType::LongInteger => { format!(" {data:#08X} ({data})", data = TtlvLongInteger::read(cursor)?.deref()) }
            TtlvType::BigInteger  => { format!(" {data}", data = hex::encode_upper(&TtlvBigInteger::read(cursor)?.deref())) }
            TtlvType::Enumeration => { format!(" {data:#08X} ({data})", data = TtlvEnumeration::read(cursor)?.deref()) }
            TtlvType::Boolean     => { format!(" {data}", data = TtlvBoolean::read(cursor)?.deref()) }
            TtlvType::TextString  => { format!(" {data}", data = TtlvTextString::read(cursor)?.deref()) }
            TtlvType::ByteString  => { format!(" {data}", data = hex::encode_upper(&TtlvByteString::read(cursor)?.deref())) }
            TtlvType::DateTime    => { format!(" {data:#08X}", data = TtlvDateTime::read(cursor)?.deref()) }
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
