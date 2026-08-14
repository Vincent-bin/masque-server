// HTTP Datagram framing (RFC 9297).
//
// QUIC DATAGRAM payload layout:
//   [Quarter Stream ID (varint)] [Context ID (varint)] [Payload]
//
// Quarter Stream ID = stream_id / 4 (only client-initiated bidi streams).
// Context ID 0 = raw UDP/IP payload.

use crate::varint;

/// Error from datagram parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatagramError {
    /// Buffer too short to decode the framing header.
    TooShort,
    /// The stream ID is not a valid client-initiated bidirectional stream
    /// (must be divisible by 4).
    InvalidStreamId(u64),
}

impl std::fmt::Display for DatagramError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatagramError::TooShort => write!(f, "datagram too short"),
            DatagramError::InvalidStreamId(id) => {
                write!(f, "invalid stream id for datagram: {id}")
            }
        }
    }
}

impl std::error::Error for DatagramError {}

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
    let (qsid, qlen) =
        varint::decode(buf).map_err(|_| DatagramError::TooShort)?;
    let (context_id, clen) = varint::decode(&buf[qlen..])
        .map_err(|_| DatagramError::TooShort)?;

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
    if dgram.stream_id % 4 != 0 {
        return Err(DatagramError::InvalidStreamId(dgram.stream_id));
    }

    let qsid = dgram.stream_id / 4;
    let mut buf = Vec::new();

    varint::encode_to_vec(qsid, &mut buf)
        .map_err(|_| DatagramError::InvalidStreamId(dgram.stream_id))?;
    varint::encode_to_vec(dgram.context_id, &mut buf)
        .map_err(|_| DatagramError::TooShort)?;
    buf.extend_from_slice(&dgram.payload);

    Ok(buf)
}

/// Convenience: encode a raw payload (context_id=0) for a given stream.
pub fn encode_payload(stream_id: u64, payload: &[u8]) -> Result<Vec<u8>, DatagramError> {
    let mut buf = Vec::with_capacity(payload.len() + 16);
    encode_payload_into(stream_id, payload, &mut buf)?;
    Ok(buf)
}

/// Encode a raw payload into a reusable output buffer.
pub fn encode_payload_into(
    stream_id: u64,
    payload: &[u8],
    buf: &mut Vec<u8>,
) -> Result<(), DatagramError> {
    if stream_id % 4 != 0 {
        return Err(DatagramError::InvalidStreamId(stream_id));
    }

    buf.clear();
    varint::encode_to_vec(stream_id / 4, buf)
        .map_err(|_| DatagramError::InvalidStreamId(stream_id))?;
    varint::encode_to_vec(0, buf).map_err(|_| DatagramError::TooShort)?;
    buf.extend_from_slice(payload);
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
        varint::encode_to_vec(0, &mut buf).unwrap();   // context_id
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
        assert_eq!(decode(&[]), Err(DatagramError::TooShort));
    }

    #[test]
    fn decode_too_short_no_context_id() {
        // qsid only, no context_id
        assert_eq!(decode(&[0x00]), Err(DatagramError::TooShort));
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
