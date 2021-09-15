use std::collections::HashMap;

#[allow(unused_imports)]
use pretty_assertions::{assert_eq, assert_ne};

use crate::{types::TtlvTag, PrettyPrinter};

#[test]
fn test_from_diag_string() {
    let mut pretty_printer = PrettyPrinter::default();
    pretty_printer.with_tag_prefix("4200".into());

    let diag_str = "78[77[69[6Ai6Bi]0C[23[24e1:25[99tA1t]]]0Di]0F[5Ce2:79[1F[08[0At0Be4:]08[0At0Bi]]65[08[0At0B[55t54e1:]]08[0At0Bi]]6E[08[0At0B[55t54e1:]]08[0At0Bi]]]]]";

    let expected_pretty_str = r#"Tag: 0x420078, Type: Structure (0x01), Data: 
  Tag: 0x420077, Type: Structure (0x01), Data: 
    Tag: 0x420069, Type: Structure (0x01), Data: 
      Tag: 0x42006A, Type: Integer (0x02), Data: <redacted>
      Tag: 0x42006B, Type: Integer (0x02), Data: <redacted>
    Tag: 0x42000C, Type: Structure (0x01), Data: 
      Tag: 0x420023, Type: Structure (0x01), Data: 
        Tag: 0x420024, Type: Enumeration (0x05), Data: 1
        Tag: 0x420025, Type: Structure (0x01), Data: 
          Tag: 0x420099, Type: TextString (0x07), Data: <redacted>
          Tag: 0x4200A1, Type: TextString (0x07), Data: <redacted>
    Tag: 0x42000D, Type: Integer (0x02), Data: <redacted>
  Tag: 0x42000F, Type: Structure (0x01), Data: 
    Tag: 0x42005C, Type: Enumeration (0x05), Data: 2
    Tag: 0x420079, Type: Structure (0x01), Data: 
      Tag: 0x42001F, Type: Structure (0x01), Data: 
        Tag: 0x420008, Type: Structure (0x01), Data: 
          Tag: 0x42000A, Type: TextString (0x07), Data: <redacted>
          Tag: 0x42000B, Type: Enumeration (0x05), Data: 4
        Tag: 0x420008, Type: Structure (0x01), Data: 
          Tag: 0x42000A, Type: TextString (0x07), Data: <redacted>
          Tag: 0x42000B, Type: Integer (0x02), Data: <redacted>
      Tag: 0x420065, Type: Structure (0x01), Data: 
        Tag: 0x420008, Type: Structure (0x01), Data: 
          Tag: 0x42000A, Type: TextString (0x07), Data: <redacted>
          Tag: 0x42000B, Type: Structure (0x01), Data: 
            Tag: 0x420055, Type: TextString (0x07), Data: <redacted>
            Tag: 0x420054, Type: Enumeration (0x05), Data: 1
        Tag: 0x420008, Type: Structure (0x01), Data: 
          Tag: 0x42000A, Type: TextString (0x07), Data: <redacted>
          Tag: 0x42000B, Type: Integer (0x02), Data: <redacted>
      Tag: 0x42006E, Type: Structure (0x01), Data: 
        Tag: 0x420008, Type: Structure (0x01), Data: 
          Tag: 0x42000A, Type: TextString (0x07), Data: <redacted>
          Tag: 0x42000B, Type: Structure (0x01), Data: 
            Tag: 0x420055, Type: TextString (0x07), Data: <redacted>
            Tag: 0x420054, Type: Enumeration (0x05), Data: 1
        Tag: 0x420008, Type: Structure (0x01), Data: 
          Tag: 0x42000A, Type: TextString (0x07), Data: <redacted>
          Tag: 0x42000B, Type: Integer (0x02), Data: <redacted>"#;
    assert_eq!(expected_pretty_str, pretty_printer.from_diag_string(diag_str));
}

#[test]
fn test_from_diag_string_with_tag_map() {
    let tag_map: HashMap<TtlvTag, &'static str> = vec![
        // KMIP 1.0: http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581263
        (b"\x42\x00\x08".into(), "Attribute"),
        (b"\x42\x00\x0A".into(), "Attribute Name"),
        (b"\x42\x00\x0B".into(), "Attribute Value"),
        (b"\x42\x00\x0C".into(), "Authentication"),
        (b"\x42\x00\x0D".into(), "Batch Count"),
        (b"\x42\x00\x0F".into(), "Batch Item"),
        (b"\x42\x00\x1F".into(), "Common Template-Attribute"),
        (b"\x42\x00\x23".into(), "Credential"),
        (b"\x42\x00\x24".into(), "Credential Type"),
        (b"\x42\x00\x25".into(), "Credential Value"),
        (b"\x42\x00\x54".into(), "Name Type"),
        (b"\x42\x00\x55".into(), "Name Value"),
        (b"\x42\x00\x5C".into(), "Operation"),
        (b"\x42\x00\x65".into(), "Private Key Template-Attribute"),
        (b"\x42\x00\x69".into(), "Protocol Version"),
        (b"\x42\x00\x6A".into(), "Protocol Version Major"),
        (b"\x42\x00\x6B".into(), "Protocol Version Minor"),
        (b"\x42\x00\x6E".into(), "Public Key Template-Attribute"),
        (b"\x42\x00\x77".into(), "Request Header"),
        (b"\x42\x00\x78".into(), "Request Message"),
        (b"\x42\x00\x79".into(), "Request Payload"),
        (b"\x42\x00\x99".into(), "Username"),
        (b"\x42\x00\xA1".into(), "Password"),
    ]
    .into_iter()
    .collect();

    let mut pretty_printer = PrettyPrinter::default();
    pretty_printer.with_tag_prefix("4200".into());
    pretty_printer.with_tag_map(tag_map);

    let diag_str = "78[77[69[6Ai6Bi]0C[23[24e1:25[99tA1t]]]0Di]0F[5Ce2:79[1F[08[0At0Be4:]08[0At0Bi]]65[08[0At0B[55t54e1:]]08[0At0Bi]]6E[08[0At0B[55t54e1:]]08[0At0Bi]]]]]";

    let expected_pretty_str = r#"Tag: Request Message (0x420078), Type: Structure (0x01), Data: 
  Tag: Request Header (0x420077), Type: Structure (0x01), Data: 
    Tag: Protocol Version (0x420069), Type: Structure (0x01), Data: 
      Tag: Protocol Version Major (0x42006A), Type: Integer (0x02), Data: <redacted>
      Tag: Protocol Version Minor (0x42006B), Type: Integer (0x02), Data: <redacted>
    Tag: Authentication (0x42000C), Type: Structure (0x01), Data: 
      Tag: Credential (0x420023), Type: Structure (0x01), Data: 
        Tag: Credential Type (0x420024), Type: Enumeration (0x05), Data: 1
        Tag: Credential Value (0x420025), Type: Structure (0x01), Data: 
          Tag: Username (0x420099), Type: TextString (0x07), Data: <redacted>
          Tag: Password (0x4200A1), Type: TextString (0x07), Data: <redacted>
    Tag: Batch Count (0x42000D), Type: Integer (0x02), Data: <redacted>
  Tag: Batch Item (0x42000F), Type: Structure (0x01), Data: 
    Tag: Operation (0x42005C), Type: Enumeration (0x05), Data: 2
    Tag: Request Payload (0x420079), Type: Structure (0x01), Data: 
      Tag: Common Template-Attribute (0x42001F), Type: Structure (0x01), Data: 
        Tag: Attribute (0x420008), Type: Structure (0x01), Data: 
          Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: <redacted>
          Tag: Attribute Value (0x42000B), Type: Enumeration (0x05), Data: 4
        Tag: Attribute (0x420008), Type: Structure (0x01), Data: 
          Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: <redacted>
          Tag: Attribute Value (0x42000B), Type: Integer (0x02), Data: <redacted>
      Tag: Private Key Template-Attribute (0x420065), Type: Structure (0x01), Data: 
        Tag: Attribute (0x420008), Type: Structure (0x01), Data: 
          Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: <redacted>
          Tag: Attribute Value (0x42000B), Type: Structure (0x01), Data: 
            Tag: Name Value (0x420055), Type: TextString (0x07), Data: <redacted>
            Tag: Name Type (0x420054), Type: Enumeration (0x05), Data: 1
        Tag: Attribute (0x420008), Type: Structure (0x01), Data: 
          Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: <redacted>
          Tag: Attribute Value (0x42000B), Type: Integer (0x02), Data: <redacted>
      Tag: Public Key Template-Attribute (0x42006E), Type: Structure (0x01), Data: 
        Tag: Attribute (0x420008), Type: Structure (0x01), Data: 
          Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: <redacted>
          Tag: Attribute Value (0x42000B), Type: Structure (0x01), Data: 
            Tag: Name Value (0x420055), Type: TextString (0x07), Data: <redacted>
            Tag: Name Type (0x420054), Type: Enumeration (0x05), Data: 1
        Tag: Attribute (0x420008), Type: Structure (0x01), Data: 
          Tag: Attribute Name (0x42000A), Type: TextString (0x07), Data: <redacted>
          Tag: Attribute Value (0x42000B), Type: Integer (0x02), Data: <redacted>"#;
    assert_eq!(expected_pretty_str, pretty_printer.from_diag_string(diag_str));
}
