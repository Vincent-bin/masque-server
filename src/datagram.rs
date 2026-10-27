// HTTP Datagram framing (RFC 9297).
//
// QUIC DATAGRAM payload layout:
//   [Quarter Stream ID (varint)] [Context ID (varint)] [Payload]
//
// Quarter Stream ID = stream_id / 4 (only client-initiated bidi streams).
// Context ID 0 = raw UDP/IP payload.

use crate::varint;

/// RFC 9297 Section 2.1: QUIC stream IDs have at most 62 bits.
pub const MAX_QUARTER_STREAM_ID: u64 = (1 << 60) - 1;

/// HTTP/3 application error for a missing or out-of-range Quarter Stream ID.
pub const H3_DATAGRAM_ERROR: u64 = 0x33;

/// Error from datagram parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatagramError {
    /// Buffer too short to decode the Context ID.
    TooShort,
    /// Buffer too short to decode the Quarter Stream ID.
    MissingQuarterStreamId,
    /// The Quarter Stream ID exceeds the legal 60-bit range.
    InvalidQuarterStreamId(u64),
    /// The stream ID is not a valid client-initiated bidirectional stream
    /// (must be divisible by 4 and fit in 62 bits).
    InvalidStreamId(u64),
}

impl std::fmt::Display for DatagramError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatagramError::TooShort => write!(f, "datagram too short"),
            DatagramError::MissingQuarterStreamId => {
                write!(f, "datagram has no complete quarter stream id")
            }
            DatagramError::InvalidQuarterStreamId(id) => {
                write!(f, "quarter stream id exceeds the legal maximum: {id}")
            }
            DatagramError::InvalidStreamId(id) => {
                write!(f, "invalid stream id for datagram: {id}")
            }
        }
    }
}

impl std::error::Error for DatagramError {}

impl DatagramError {
    /// RFC 9297 Section 2.1 requires a connection error for QSID failures.
    /// A malformed Context ID is a separate, tunnel-specific payload error.
    pub fn is_connection_error(&self) -> bool {
        matches!(
            self,
            Self::MissingQuarterStreamId | Self::InvalidQuarterStreamId(_)
        )
    }
}

/// A parsed HTTP Datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpDatagram {
    /// The HTTP/3 request stream this datagram belongs to.
    pub stream_id: u64,
    /// Context ID (0 = raw payload, non-zero = extension).
    pub context_id: u64,
    /// The payload bytes after the header.
    pub payload: Vec<u8>,
}

/// A borrowed HTTP Datagram view that avoids copying the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpDatagramRef<'a> {
    pub stream_id: u64,
    pub context_id: u64,
    pub payload: &'a [u8],
}

/// Decode an HTTP Datagram without allocating or copying its payload.
pub fn decode_ref(buf: &[u8]) -> Result<HttpDatagramRef<'_>, DatagramError> {
    let (qsid, qlen) = varint::decode(buf).map_err(|_| DatagramError::MissingQuarterStreamId)?;
    if qsid > MAX_QUARTER_STREAM_ID {
        return Err(DatagramError::InvalidQuarterStreamId(qsid));
    }
    let (context_id, clen) = varint::decode(&buf[qlen..]).map_err(|_| DatagramError::TooShort)?;

    Ok(HttpDatagramRef {
        stream_id: qsid * 4,
        context_id,
        payload: &buf[qlen + clen..],
    })
}

/// Decode an HTTP Datagram from a QUIC DATAGRAM frame payload.
pub fn decode(buf: &[u8]) -> Result<HttpDatagram, DatagramError> {
    let dgram = decode_ref(buf)?;

    Ok(HttpDatagram {
        stream_id: dgram.stream_id,
        context_id: dgram.context_id,
        payload: dgram.payload.to_vec(),
    })
}

/// Encode an HTTP Datagram into a QUIC DATAGRAM frame payload.
pub fn encode(dgram: &HttpDatagram) -> Result<Vec<u8>, DatagramError> {
    if !dgram.stream_id.is_multiple_of(4) || dgram.stream_id > varint::MAX_VALUE {
        return Err(DatagramError::InvalidStreamId(dgram.stream_id));
    }

    let qsid = dgram.stream_id / 4;
    let header_len = varint::encoded_len(qsid)
        .map_err(|_| DatagramError::InvalidStreamId(dgram.stream_id))?
        + varint::encoded_len(dgram.context_id).map_err(|_| DatagramError::TooShort)?;
    let mut buf = Vec::with_capacity(header_len + dgram.payload.len());

    varint::encode_to_vec(qsid, &mut buf)
        .map_err(|_| DatagramError::InvalidStreamId(dgram.stream_id))?;
    varint::encode_to_vec(dgram.context_id, &mut buf).map_err(|_| DatagramError::TooShort)?;
    buf.extend_from_slice(&dgram.payload);

    Ok(buf)
}

/// The `[Quarter Stream ID][Context ID = 0]` prefix for one stream.
///
/// Both fields are constant for the lifetime of a tunnel, so a tunnel encodes
/// them once at setup and then only has to prepend the bytes per datagram
/// instead of running the varint encoder on every packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramHeader {
    /// Quarter Stream ID varint (max 8 bytes) followed by the context ID (1
    /// byte, since context 0 always encodes as a single zero byte).
    bytes: [u8; 9],
    len: u8,
}

impl DatagramHeader {
    /// Build the header for `stream_id`, which must be a client-initiated
    /// bidirectional stream.
    pub fn new(stream_id: u64) -> Result<Self, DatagramError> {
        if !stream_id.is_multiple_of(4) || stream_id > varint::MAX_VALUE {
            return Err(DatagramError::InvalidStreamId(stream_id));
        }

        let mut bytes = [0u8; 9];
        let qlen = varint::encode(stream_id / 4, &mut bytes)
            .map_err(|_| DatagramError::InvalidStreamId(stream_id))?;
        // Context ID 0 is already in place as the trailing zero byte.

        Ok(Self {
            bytes,
            len: (qlen + 1) as u8,
        })
    }

    /// The encoded header bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Encode `payload` behind this header into an exactly-sized buffer.
    #[inline]
    pub fn encode(&self, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.len as usize + payload.len());
        buf.extend_from_slice(self.as_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    /// Encode `payload` behind this header into a reusable buffer.
    #[inline]
    pub fn encode_into(&self, payload: &[u8], buf: &mut Vec<u8>) {
        buf.clear();
        buf.reserve(self.len as usize + payload.len());
        buf.extend_from_slice(self.as_bytes());
        buf.extend_from_slice(payload);
    }
}

/// Convenience: encode a raw payload (context_id=0) for a given stream.
///
/// Prefer [`DatagramHeader`] when relaying repeatedly on the same stream.
pub fn encode_payload(stream_id: u64, payload: &[u8]) -> Result<Vec<u8>, DatagramError> {
    Ok(DatagramHeader::new(stream_id)?.encode(payload))
}

/// Encode a raw payload into a reusable output buffer.
pub fn encode_payload_into(
    stream_id: u64,
    payload: &[u8],
    buf: &mut Vec<u8>,
) -> Result<(), DatagramError> {
    DatagramHeader::new(stream_id)?.encode_into(payload, buf);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Decode tests ──────────────────────────────────────────────────

    #[test]
    fn decode_simple_context_zero() {
        // stream_id=0 -> qsid=0, context_id=0, payload=[0xaa, 0xbb]
        let buf = [0x00, 0x00, 0xaa, 0xbb];
        let dgram = decode(&buf).unwrap();
        assert_eq!(dgram.stream_id, 0);
        assert_eq!(dgram.context_id, 0);
        assert_eq!(dgram.payload, vec![0xaa, 0xbb]);
    }

    #[test]
    fn decode_stream_id_4() {
        // stream_id=4 -> qsid=1
        let buf = [0x01, 0x00, 0xcc];
        let dgram = decode(&buf).unwrap();
        assert_eq!(dgram.stream_id, 4);
        assert_eq!(dgram.context_id, 0);
        assert_eq!(dgram.payload, vec![0xcc]);
    }

    #[test]
    fn decode_large_stream_id() {
        // stream_id=400 -> qsid=100
        let mut buf = Vec::new();
        varint::encode_to_vec(100, &mut buf).unwrap(); // qsid
        varint::encode_to_vec(0, &mut buf).unwrap(); // context_id
        buf.extend_from_slice(&[0xdd, 0xee]);

        let dgram = decode(&buf).unwrap();
        assert_eq!(dgram.stream_id, 400);
        assert_eq!(dgram.context_id, 0);
        assert_eq!(dgram.payload, vec![0xdd, 0xee]);
    }

    #[test]
    fn decode_nonzero_context_id() {
        let mut buf = Vec::new();
        varint::encode_to_vec(0, &mut buf).unwrap(); // qsid
        varint::encode_to_vec(5, &mut buf).unwrap(); // context_id=5
        buf.push(0xff);

        let dgram = decode(&buf).unwrap();
        assert_eq!(dgram.context_id, 5);
        assert_eq!(dgram.payload, vec![0xff]);
    }

    #[test]
    fn decode_empty_payload() {
        let buf = [0x00, 0x00]; // qsid=0, context_id=0, no payload
        let dgram = decode(&buf).unwrap();
        assert_eq!(dgram.payload, Vec::<u8>::new());
    }

    #[test]
    fn decode_too_short_no_qsid() {
        for wire in [&[][..], &[0x40], &[0x80, 0, 0], &[0xc0, 0, 0, 0, 0, 0, 0]] {
            let error = decode_ref(wire).unwrap_err();
            assert_eq!(error, DatagramError::MissingQuarterStreamId);
            assert!(error.is_connection_error());
        }
    }

    #[test]
    fn decode_too_short_no_context_id() {
        // qsid only, no context_id
        assert_eq!(decode(&[0x00]), Err(DatagramError::TooShort));
        assert!(!decode_ref(&[0, 0x40]).unwrap_err().is_connection_error());
    }

    #[test]
    fn quarter_stream_id_bounds_are_enforced_before_context_decoding() {
        for qsid in [MAX_QUARTER_STREAM_ID + 1, varint::MAX_VALUE] {
            let mut wire = Vec::new();
            varint::encode_to_vec(qsid, &mut wire).unwrap();
            // Even with the context absent, the QSID violation takes precedence.
            for context in [None, Some(0)] {
                if let Some(context) = context {
                    wire.push(context);
                }
                let error = decode_ref(&wire).unwrap_err();
                assert_eq!(error, DatagramError::InvalidQuarterStreamId(qsid));
                assert!(error.is_connection_error());
                assert_eq!(decode(&wire).unwrap_err(), error);
            }
        }
    }

    #[test]
    fn largest_legal_request_stream_roundtrips() {
        let stream_id = MAX_QUARTER_STREAM_ID * 4;
        let wire = encode_payload(stream_id, b"boundary").unwrap();
        let decoded = decode_ref(&wire).unwrap();
        assert_eq!(decoded.stream_id, stream_id);
        assert_eq!(decoded.payload, b"boundary");
        assert_eq!(
            encode(&HttpDatagram {
                stream_id,
                context_id: 0,
                payload: b"boundary".to_vec()
            })
            .unwrap(),
            wire
        );
    }

    #[test]
    fn encoders_reject_stream_ids_above_the_quic_limit() {
        for stream_id in [1 << 62, u64::MAX - 3] {
            assert_eq!(
                DatagramHeader::new(stream_id),
                Err(DatagramError::InvalidStreamId(stream_id))
            );
            assert_eq!(
                encode_payload(stream_id, b"invalid"),
                Err(DatagramError::InvalidStreamId(stream_id))
            );
            assert_eq!(
                encode(&HttpDatagram {
                    stream_id,
                    context_id: 0,
                    payload: Vec::new()
                }),
                Err(DatagramError::InvalidStreamId(stream_id))
            );
        }
    }

    // ── Encode tests ──────────────────────────────────────────────────

    #[test]
    fn encode_simple() {
        let dgram = HttpDatagram {
            stream_id: 0,
            context_id: 0,
            payload: vec![0x01, 0x02],
        };
        let buf = encode(&dgram).unwrap();
        assert_eq!(buf, vec![0x00, 0x00, 0x01, 0x02]);
    }

    #[test]
    fn encode_stream_id_4() {
        let dgram = HttpDatagram {
            stream_id: 4,
            context_id: 0,
            payload: vec![0xab],
        };
        let buf = encode(&dgram).unwrap();
        assert_eq!(buf[0], 0x01); // qsid=1
        assert_eq!(buf[1], 0x00); // context_id=0
        assert_eq!(buf[2], 0xab);
    }

    #[test]
    fn encode_invalid_stream_id() {
        let dgram = HttpDatagram {
            stream_id: 3, // not divisible by 4
            context_id: 0,
            payload: vec![],
        };
        assert!(matches!(
            encode(&dgram),
            Err(DatagramError::InvalidStreamId(3))
        ));
    }

    #[test]
    fn encode_payload_convenience() {
        let buf = encode_payload(8, &[0xca, 0xfe]).unwrap();
        let dgram = decode(&buf).unwrap();
        assert_eq!(dgram.stream_id, 8);
        assert_eq!(dgram.context_id, 0);
        assert_eq!(dgram.payload, vec![0xca, 0xfe]);
    }

    #[test]
    fn encode_payload_into_reuses_buffer() {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&[0xff; 32]);
        encode_payload_into(8, &[0xca, 0xfe], &mut buf).unwrap();
        let dgram = decode_ref(&buf).unwrap();
        assert_eq!(dgram.stream_id, 8);
        assert_eq!(dgram.context_id, 0);
        assert_eq!(dgram.payload, &[0xca, 0xfe]);
    }

    // ── Precomputed header ────────────────────────────────────────────

    #[test]
    fn header_matches_encode_payload() {
        for stream_id in [0u64, 4, 400, 4_000, 4_000_000, 400_000_000_000] {
            let header = DatagramHeader::new(stream_id).unwrap();
            let expected = encode_payload(stream_id, &[0x11, 0x22]).unwrap();
            assert_eq!(
                header.encode(&[0x11, 0x22]),
                expected,
                "header mismatch for stream {stream_id}"
            );
        }
    }

    #[test]
    fn header_roundtrips_through_decode() {
        let header = DatagramHeader::new(400).unwrap();
        let wire = header.encode(&[0xde, 0xad, 0xbe, 0xef]);
        let dgram = decode_ref(&wire).unwrap();
        assert_eq!(dgram.stream_id, 400);
        assert_eq!(dgram.context_id, 0);
        assert_eq!(dgram.payload, &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn header_rejects_non_bidi_stream() {
        assert_eq!(
            DatagramHeader::new(3),
            Err(DatagramError::InvalidStreamId(3))
        );
    }

    #[test]
    fn header_encode_into_clears_previous_contents() {
        let header = DatagramHeader::new(8).unwrap();
        let mut buf = vec![0xff; 32];
        header.encode_into(&[0xca, 0xfe], &mut buf);
        assert_eq!(buf, header.encode(&[0xca, 0xfe]));
    }

    #[test]
    fn header_allocates_exactly() {
        let header = DatagramHeader::new(4).unwrap();
        let buf = header.encode(&[0u8; 1_200]);
        assert_eq!(buf.len(), 1_202);
        assert_eq!(buf.capacity(), 1_202);
    }

    // ── Round-trip ────────────────────────────────────────────────────

    #[test]
    fn roundtrip_various_streams() {
        for stream_id in [0, 4, 8, 100, 1024].iter().map(|&s| s * 4) {
            let original = HttpDatagram {
                stream_id,
                context_id: 0,
                payload: vec![0x11, 0x22, 0x33],
            };
            let wire = encode(&original).unwrap();
            let decoded = decode(&wire).unwrap();
            assert_eq!(decoded, original, "roundtrip failed for stream {stream_id}");
        }
    }

    #[test]
    fn roundtrip_nonzero_context() {
        let original = HttpDatagram {
            stream_id: 0,
            context_id: 42,
            payload: vec![0xde, 0xad],
        };
        let wire = encode(&original).unwrap();
        let decoded = decode(&wire).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn roundtrip_empty_payload() {
        let original = HttpDatagram {
            stream_id: 0,
            context_id: 0,
            payload: vec![],
        };
        let wire = encode(&original).unwrap();
        let decoded = decode(&wire).unwrap();
        assert_eq!(decoded, original);
    }
}
