//! Incremental DATAGRAM capsule reader. Other capsule values are skipped.

use super::CAPSULE_DATAGRAM;
use super::decoder::DecodeError;
use crate::varint;

/// A bounded DATAGRAM decoder that skips other capsule values without buffering.
pub struct DatagramCapsules {
    header: [u8; 16],
    header_len: usize,
    remaining: u64,
    value: Option<Vec<u8>>,
    limit: usize,
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
        }
    }

    /// Whether an end-of-stream here would truncate a capsule.
    pub fn is_partial(&self) -> bool {
        self.header_len != 0 || self.remaining != 0
    }

    /// Feed a stream chunk and return complete HTTP Datagram payloads.
    pub fn decode(&mut self, mut data: &[u8]) -> Result<Vec<Vec<u8>>, DecodeError> {
        let mut datagrams = Vec::new();
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
                self.value = if kind == CAPSULE_DATAGRAM {
                    if length > self.limit as u64 {
                        return Err(DecodeError::TooLarge {
                            length,
                            max: self.limit,
                        });
                    }
                    Some(Vec::with_capacity(length as usize))
                } else {
                    None
                };
                if length == 0
                    && let Some(value) = self.value.take()
                {
                    datagrams.push(value);
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
                datagrams.push(value);
            }
        }
        Ok(datagrams)
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
}
