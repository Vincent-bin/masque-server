//! Identical wire fixtures exercise CONNECT-UDP capsule handling on H2 and H3.

use masque::capsule::{CapsuleFrame, encoder};
use masque::varint;

pub fn ignored_capsules_then_datagram(payload: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    // Both large values exceed even the maximum UDP payload, not just a
    // configured small datagram limit. 0x21 and 0x40 are RFC 9297 GREASE types.
    // IP control types have no meaning on a CONNECT-UDP stream, even when
    // their values would be malformed for CONNECT-IP.
    for (kind, length) in [
        (0x20, 70_000),
        (0x21, 0),
        (0x40, 70_001),
        (1, 3),
        (2, 3),
        (3, 3),
        (varint::MAX_VALUE, 0),
    ] {
        encoder::encode(
            &CapsuleFrame::Unknown {
                capsule_type: kind,
                value: vec![0xff; length],
            },
            &mut wire,
        );
    }
    encoder::encode_datagram_context_zero(payload, &mut wire);
    wire
}

pub fn truncated_capsules() -> Vec<Vec<u8>> {
    let mut longest_type = Vec::new();
    varint::encode_to_vec(varint::MAX_VALUE, &mut longest_type).unwrap();
    let mut partial_length = longest_type.clone();
    partial_length.push(0xff);
    let mut huge_value = longest_type.clone();
    varint::encode_to_vec(varint::MAX_VALUE, &mut huge_value).unwrap();
    huge_value.push(0xaa);
    vec![
        vec![0xff],                // partial type
        longest_type,              // missing length
        partial_length,            // partial length
        huge_value,                // huge unknown value must still complete
        vec![0x40, 0x40, 2, 0xaa], // partial GREASE value
        vec![0, 2, 0],             // partial DATAGRAM value
    ]
}
