// QUIC variable-length integer encoding (RFC 9000, Section 16).
//
// Encoding uses the two most-significant bits of the first byte to indicate
// the length of the integer:
//   00 -> 1 byte  (6-bit value,  max 63)
//   01 -> 2 bytes (14-bit value, max 16_383)
//   10 -> 4 bytes (30-bit value, max 1_073_741_823)
//   11 -> 8 bytes (62-bit value, max 4_611_686_018_427_387_903)

use std::fmt;

/// Maximum value representable by a QUIC variable-length integer (2^62 - 1).
pub const MAX_VALUE: u64 = (1 << 62) - 1;

/// Error returned when decoding or encoding a varint fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Not enough bytes in the buffer to decode a complete varint.
    BufferTooShort,
    /// The value exceeds the 62-bit maximum.
    Overflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BufferTooShort => write!(f, "buffer too short for varint"),
            Error::Overflow => write!(f, "varint value exceeds 2^62 - 1"),
        }
    }
}

impl std::error::Error for Error {}

/// Decode a variable-length integer from `buf`.
///
/// Returns `(value, bytes_consumed)` on success.
pub fn decode(buf: &[u8]) -> Result<(u64, usize), Error> {
    if buf.is_empty() {
        return Err(Error::BufferTooShort);
    }

    let first = buf[0];
    let length = 1 << (first >> 6);

    if buf.len() < length {
        return Err(Error::BufferTooShort);
    }

    let value = match length {
        1 => u64::from(first & 0x3f),
        2 => {
            let val = u16::from_be_bytes([first & 0x3f, buf[1]]);
            u64::from(val)
        }
        4 => {
            let val =
                u32::from_be_bytes([first & 0x3f, buf[1], buf[2], buf[3]]);
            u64::from(val)
        }
        8 => u64::from_be_bytes([
            first & 0x3f,
            buf[1],
            buf[2],
            buf[3],
            buf[4],
            buf[5],
            buf[6],
            buf[7],
        ]),
        _ => unreachable!(),
    };

    Ok((value, length))
}

/// Return the number of bytes needed to encode `value`.
pub fn encoded_len(value: u64) -> Result<usize, Error> {
    if value <= 63 {
        Ok(1)
    } else if value <= 16_383 {
        Ok(2)
    } else if value <= 1_073_741_823 {
        Ok(4)
    } else if value <= MAX_VALUE {
        Ok(8)
    } else {
        Err(Error::Overflow)
    }
}

/// Encode `value` into `buf`.
///
/// Returns the number of bytes written.
/// `buf` must be large enough (use [`encoded_len`] to check).
pub fn encode(value: u64, buf: &mut [u8]) -> Result<usize, Error> {
    let len = encoded_len(value)?;
    if buf.len() < len {
        return Err(Error::BufferTooShort);
    }

    match len {
        1 => {
            buf[0] = value as u8;
        }
        2 => {
            let bytes = (value as u16).to_be_bytes();
            buf[0] = bytes[0] | 0x40;
            buf[1] = bytes[1];
        }
        4 => {
            let bytes = (value as u32).to_be_bytes();
            buf[0] = bytes[0] | 0x80;
            buf[1] = bytes[1];
            buf[2] = bytes[2];
            buf[3] = bytes[3];
        }
        8 => {
            let bytes = value.to_be_bytes();
            buf[0] = bytes[0] | 0xc0;
            buf[1] = bytes[1];
            buf[2] = bytes[2];
            buf[3] = bytes[3];
            buf[4] = bytes[4];
            buf[5] = bytes[5];
            buf[6] = bytes[6];
            buf[7] = bytes[7];
        }
        _ => unreachable!(),
    }

    Ok(len)
}

/// Encode `value` and append the bytes to `vec`.
pub fn encode_to_vec(value: u64, vec: &mut Vec<u8>) -> Result<usize, Error> {
    // Encode into a stack buffer and append, rather than `resize`-ing the vec
    // first: that zero-fills the tail only for `encode` to overwrite it.
    let mut scratch = [0u8; 8];
    let len = encode(value, &mut scratch)?;
    vec.extend_from_slice(&scratch[..len]);
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RFC 9000 Appendix A test vectors ──────────────────────────────

    #[test]
    fn rfc_test_vector_1byte() {
        // Value 37 encoded in 1 byte: 0x25
        let buf = [0x25];
        let (val, len) = decode(&buf).unwrap();
        assert_eq!(val, 37);
        assert_eq!(len, 1);
    }

    #[test]
    fn rfc_test_vector_2byte() {
        // Value 15293 encoded in 2 bytes: 0x7bbd
        let buf = [0x7b, 0xbd];
        let (val, len) = decode(&buf).unwrap();
        assert_eq!(val, 15293);
        assert_eq!(len, 2);
    }

    #[test]
    fn rfc_test_vector_4byte() {
        // Value 494878333 encoded in 4 bytes: 0x9d7f3e7d
        let buf = [0x9d, 0x7f, 0x3e, 0x7d];
        let (val, len) = decode(&buf).unwrap();
        assert_eq!(val, 494_878_333);
        assert_eq!(len, 4);
    }

    #[test]
    fn rfc_test_vector_8byte() {
        // Value 151288809941952652 encoded in 8 bytes: 0xc2197c5eff14e88c
        let buf = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
        let (val, len) = decode(&buf).unwrap();
        assert_eq!(val, 151_288_809_941_952_652);
        assert_eq!(len, 8);
    }

    // ── Boundary values ───────────────────────────────────────────────

    #[test]
    fn decode_zero() {
        let buf = [0x00];
        let (val, len) = decode(&buf).unwrap();
        assert_eq!(val, 0);
        assert_eq!(len, 1);
    }

    #[test]
    fn decode_max_1byte() {
        let buf = [0x3f]; // 63
        let (val, len) = decode(&buf).unwrap();
        assert_eq!(val, 63);
        assert_eq!(len, 1);
    }

    #[test]
    fn decode_min_2byte() {
        // 64 encoded as 2-byte: 0x4040
        let mut buf = [0u8; 2];
        encode(64, &mut buf).unwrap();
        let (val, len) = decode(&buf).unwrap();
        assert_eq!(val, 64);
        assert_eq!(len, 2);
    }

    #[test]
    fn decode_max_2byte() {
        let mut buf = [0u8; 2];
        encode(16_383, &mut buf).unwrap();
        let (val, len) = decode(&buf).unwrap();
        assert_eq!(val, 16_383);
        assert_eq!(len, 2);
    }

    #[test]
    fn decode_min_4byte() {
        let mut buf = [0u8; 4];
        encode(16_384, &mut buf).unwrap();
        let (val, len) = decode(&buf).unwrap();
        assert_eq!(val, 16_384);
        assert_eq!(len, 4);
    }

    #[test]
    fn decode_max_4byte() {
        let mut buf = [0u8; 4];
        encode(1_073_741_823, &mut buf).unwrap();
        let (val, len) = decode(&buf).unwrap();
        assert_eq!(val, 1_073_741_823);
        assert_eq!(len, 4);
    }

    #[test]
    fn decode_min_8byte() {
        let mut buf = [0u8; 8];
        encode(1_073_741_824, &mut buf).unwrap();
        let (val, len) = decode(&buf).unwrap();
        assert_eq!(val, 1_073_741_824);
        assert_eq!(len, 8);
    }

    #[test]
    fn decode_max_value() {
        let mut buf = [0u8; 8];
        encode(MAX_VALUE, &mut buf).unwrap();
        let (val, len) = decode(&buf).unwrap();
        assert_eq!(val, MAX_VALUE);
        assert_eq!(len, 8);
    }

    // ── Error cases ───────────────────────────────────────────────────

    #[test]
    fn decode_empty_buffer() {
        assert_eq!(decode(&[]), Err(Error::BufferTooShort));
    }

    #[test]
    fn decode_truncated_2byte() {
        // First byte says 2-byte encoding, but only 1 byte available
        let buf = [0x40];
        assert_eq!(decode(&buf), Err(Error::BufferTooShort));
    }

    #[test]
    fn decode_truncated_4byte() {
        let buf = [0x80, 0x00];
        assert_eq!(decode(&buf), Err(Error::BufferTooShort));
    }

    #[test]
    fn decode_truncated_8byte() {
        let buf = [0xc0, 0x00, 0x00, 0x00];
        assert_eq!(decode(&buf), Err(Error::BufferTooShort));
    }

    #[test]
    fn encode_overflow() {
        assert_eq!(encode(MAX_VALUE + 1, &mut [0u8; 8]), Err(Error::Overflow));
    }

    #[test]
    fn encode_buffer_too_short() {
        assert_eq!(encode(64, &mut [0u8; 1]), Err(Error::BufferTooShort));
    }

    // ── Round-trip ────────────────────────────────────────────────────

    #[test]
    fn roundtrip_all_lengths() {
        let test_values: &[u64] =
            &[0, 1, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824, MAX_VALUE];

        for &v in test_values {
            let mut buf = [0u8; 8];
            let written = encode(v, &mut buf).unwrap();
            let (decoded, consumed) = decode(&buf[..written]).unwrap();
            assert_eq!(decoded, v, "roundtrip failed for {v}");
            assert_eq!(written, consumed);
        }
    }

    // ── encoded_len ───────────────────────────────────────────────────

    #[test]
    fn encoded_len_boundaries() {
        assert_eq!(encoded_len(0).unwrap(), 1);
        assert_eq!(encoded_len(63).unwrap(), 1);
        assert_eq!(encoded_len(64).unwrap(), 2);
        assert_eq!(encoded_len(16_383).unwrap(), 2);
        assert_eq!(encoded_len(16_384).unwrap(), 4);
        assert_eq!(encoded_len(1_073_741_823).unwrap(), 4);
        assert_eq!(encoded_len(1_073_741_824).unwrap(), 8);
        assert_eq!(encoded_len(MAX_VALUE).unwrap(), 8);
        assert_eq!(encoded_len(MAX_VALUE + 1), Err(Error::Overflow));
    }

    // ── encode_to_vec ─────────────────────────────────────────────────

    #[test]
    fn encode_to_vec_appends() {
        let mut vec = vec![0xff];
        encode_to_vec(37, &mut vec).unwrap();
        assert_eq!(vec, vec![0xff, 0x25]);
    }

    // ── Decode with trailing data ─────────────────────────────────────

    #[test]
    fn decode_ignores_trailing_bytes() {
        let buf = [0x25, 0xaa, 0xbb]; // 37 in 1 byte, then junk
        let (val, len) = decode(&buf).unwrap();
        assert_eq!(val, 37);
        assert_eq!(len, 1);
    }
}
