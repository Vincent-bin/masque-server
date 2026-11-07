//! Incremental DATAGRAM capsule reader. Other capsule values are skipped.

use super::decoder::DecodeError;
use super::{
    CAPSULE_ADDRESS_ASSIGN, CAPSULE_ADDRESS_REQUEST, CAPSULE_DATAGRAM, CAPSULE_ROUTE_ADVERTISEMENT,
};
use crate::varint;

/// A bounded DATAGRAM decoder that skips other capsule values without buffering.
pub struct DatagramCapsules {
    header: [u8; 16],
    header_len: usize,
    remaining: u64,
    value: Option<Vec<u8>>,
    limit: usize,
    control_limit: Option<usize>,
    kind: u64,
}

impl DatagramCapsules {
    /// Limit the complete DATAGRAM value, including its Context ID.
    pub fn new(limit: usize) -> Self {
        Self {
            header: [0; 16],
            header_len: 0,
            remaining: 0,
            value: None,
            limit,
            control_limit: None,
            kind: CAPSULE_DATAGRAM,
        }
    }

    pub(super) fn with_ip_controls(limit: usize, control_limit: usize) -> Self {
        Self {
            control_limit: Some(control_limit),
            ..Self::new(limit)
        }
    }

    /// Whether an end-of-stream here would truncate a capsule.
    pub fn is_partial(&self) -> bool {
        self.header_len != 0 || self.remaining != 0
    }

    /// Feed a stream chunk and return complete HTTP Datagram payloads.
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>, DecodeError> {
        let mut datagrams = Vec::new();
        self.decode_with(data, |_, value| {
            datagrams.push(value);
            Ok(())
        })?;
        Ok(datagrams)
    }

    pub(crate) fn decode_with(
        &mut self,
        mut data: &[u8],
        mut receive: impl FnMut(u64, Vec<u8>) -> Result<(), DecodeError>,
    ) -> Result<(), DecodeError> {
        while !data.is_empty() {
            if self.remaining == 0 {
                self.header[self.header_len] = data[0];
                self.header_len += 1;
                data = &data[1..];
                let Ok((kind, type_len)) = varint::decode(&self.header[..self.header_len]) else {
                    continue;
                };
                let Ok((length, _)) = varint::decode(&self.header[type_len..self.header_len])
                else {
                    continue;
                };
                self.header_len = 0;
                self.remaining = length;
                self.kind = kind;
                let limit = match kind {
                    CAPSULE_DATAGRAM => Some(self.limit),
                    CAPSULE_ADDRESS_ASSIGN
                    | CAPSULE_ADDRESS_REQUEST
                    | CAPSULE_ROUTE_ADVERTISEMENT => self.control_limit,
                    _ => None,
                };
                self.value = if let Some(limit) = limit {
                    if length > limit as u64 {
                        return Err(DecodeError::TooLarge { length, max: limit });
                    }
                    Some(Vec::with_capacity(length as usize))
                } else {
                    None
                };
                if length == 0
                    && let Some(value) = self.value.take()
                {
                    receive(self.kind, value)?;
                }
                continue;
            }
            let take = self.remaining.min(data.len() as u64) as usize;
            if let Some(value) = &mut self.value {
                value.extend_from_slice(&data[..take]);
            }
            self.remaining -= take as u64;
            data = &data[take..];
            if self.remaining == 0
                && let Some(value) = self.value.take()
            {
                receive(self.kind, value)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::encoder;

    #[test]
    fn datagrams_survive_every_input_split_and_unknown_capsules() {
        let mut wire = vec![0x20, 3, 7, 8, 9];
        encoder::encode_datagram_context_zero(b"first", &mut wire);
        wire.extend_from_slice(&[0x21, 0]);
        encoder::encode_datagram_context_zero(b"second", &mut wire);
        for split in 0..=wire.len() {
            let mut decoder = DatagramCapsules::new(64);
            let mut packets = decoder.decode(&wire[..split]).unwrap();
            packets.extend(decoder.decode(&wire[split..]).unwrap());
            assert_eq!(packets, [b"\0first".to_vec(), b"\0second".to_vec()]);
            assert!(!decoder.is_partial());
        }
    }

    #[test]
    fn unknown_huge_values_are_skipped_without_buffering() {
        let mut decoder = DatagramCapsules::new(8);
        let mut header = vec![0x20];
        varint::encode_to_vec(varint::MAX_VALUE, &mut header).unwrap();
        assert!(decoder.decode(&header).unwrap().is_empty());
        for _ in 0..32 {
            assert!(decoder.decode(&[0xaa; 1024]).unwrap().is_empty());
        }
        assert!(decoder.value.is_none());
        assert!(decoder.is_partial());
        assert_eq!(decoder.header_len, 0);
    }

    #[test]
    fn oversized_datagram_is_rejected_from_its_header() {
        let mut decoder = DatagramCapsules::new(8);
        assert_eq!(
            decoder.decode(&[0, 9]).unwrap_err(),
            DecodeError::TooLarge { length: 9, max: 8 }
        );
        assert!(decoder.value.is_none());
    }

    #[test]
    fn large_unknown_values_and_grease_resume_datagrams_with_bounded_state() {
        let payload = b"\0packet";
        let mut wire = Vec::new();
        // Exercise all type varint widths, zero-length GREASE, and malformed
        // IP-only controls (which have no semantics for CONNECT-UDP).
        for (kind, length) in [
            (0x20, 70_000),
            (0x21, 0),
            (0x40, 3),
            (1 << 20, 2),
            (varint::MAX_VALUE, 1),
            (1, 3),
            (2, 3),
            (3, 3),
        ] {
            encoder::encode(
                &super::super::CapsuleFrame::Unknown {
                    capsule_type: kind,
                    value: vec![0xff; length],
                },
                &mut wire,
            );
        }
        encoder::encode_datagram(payload, &mut wire);
        for chunk_size in [1, 2, 3, 7, 16, 997, 16_384, wire.len()] {
            let mut decoder = DatagramCapsules::new(payload.len());
            let mut packets = Vec::new();
            for chunk in wire.chunks(chunk_size) {
                packets.extend(decoder.decode(chunk).unwrap());
                assert!(decoder.header_len <= decoder.header.len());
                if let Some(value) = &decoder.value {
                    assert_eq!(decoder.kind, CAPSULE_DATAGRAM);
                    assert!(value.capacity() <= payload.len());
                }
            }
            assert_eq!(packets, [payload.to_vec()]);
            assert!(!decoder.is_partial());
        }
    }

    #[test]
    fn every_partial_unknown_header_or_value_is_truncated() {
        let mut wire = Vec::new();
        // Force the longest possible header, including a non-minimal length
        // encoding, so every incremental header boundary is covered.
        varint::encode_to_vec(varint::MAX_VALUE, &mut wire).unwrap();
        wire.extend_from_slice(&[0xc0, 0, 0, 0, 0, 0, 0, 3, 1, 2, 3]);
        for end in 0..=wire.len() {
            let mut decoder = DatagramCapsules::new(1);
            for byte in &wire[..end] {
                assert!(decoder.decode(&[*byte]).unwrap().is_empty());
                assert!(decoder.value.is_none());
            }
            assert_eq!(decoder.is_partial(), end != 0 && end != wire.len());
        }
    }
}
