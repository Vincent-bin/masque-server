// A fast, non-cryptographic hasher for internal lookup tables.
//
// The default `SipHash-1-3` costs ~15-20ns per lookup, which is significant on
// the per-packet paths (connection table, routing table, tunnel tables). This
// is the multiply-xor-rotate construction used by rustc's `FxHash`: a few ns
// for the key sizes we care about (8 or 16 bytes).
//
// This is *not* DoS-resistant, so it must only be used for tables whose keys an
// attacker cannot grind for collisions:
//
// - `Server::connections` is keyed by an HMAC of the client's DCID under a key
//   randomly generated at startup, so the bucket for a chosen DCID is not
//   predictable offline.
// - `RoutingTable` is keyed by addresses the server allocates from its own pool.
// - The per-connection tunnel tables are keyed by stream ID, and their size is
//   capped by `max_tunnels_per_connection`.

use std::hash::{BuildHasherDefault, Hasher};

pub type FxHashMap<K, V> = std::collections::HashMap<K, V, BuildHasherDefault<FxHasher>>;
pub type FxHashSet<T> = std::collections::HashSet<T, BuildHasherDefault<FxHasher>>;

/// Multiplier from rustc's `FxHasher` (the 64-bit variant).
const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;
const ROTATE: u32 = 5;

#[derive(Default, Clone, Copy)]
pub struct FxHasher {
    hash: u64,
}

impl FxHasher {
    #[inline]
    fn add_to_hash(&mut self, word: u64) {
        self.hash = (self.hash.rotate_left(ROTATE) ^ word).wrapping_mul(SEED);
    }
}

impl Hasher for FxHasher {
    #[inline]
    fn write(&mut self, mut bytes: &[u8]) {
        while bytes.len() >= 8 {
            self.add_to_hash(u64::from_ne_bytes(bytes[..8].try_into().unwrap()));
            bytes = &bytes[8..];
        }
        if bytes.len() >= 4 {
            self.add_to_hash(u64::from(u32::from_ne_bytes(
                bytes[..4].try_into().unwrap(),
            )));
            bytes = &bytes[4..];
        }
        if bytes.len() >= 2 {
            self.add_to_hash(u64::from(u16::from_ne_bytes(
                bytes[..2].try_into().unwrap(),
            )));
            bytes = &bytes[2..];
        }
        if let Some(&byte) = bytes.first() {
            self.add_to_hash(u64::from(byte));
        }
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.add_to_hash(u64::from(i));
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.add_to_hash(u64::from(i));
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.add_to_hash(u64::from(i));
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add_to_hash(i);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.add_to_hash(i as u64);
    }

    #[inline]
    fn finish(&self) -> u64 {
        // `add_to_hash` propagates entropy upwards, so the low bits — the ones
        // hashbrown uses to pick a bucket — barely move for keys that differ
        // only in their low bits. Stream IDs (multiples of 4) and pool
        // addresses are exactly that shape, so finish with a full avalanche
        // step. It is a handful of ALU ops, against a probe chain if we don't.
        let mut hash = self.hash;
        hash ^= hash >> 32;
        hash = hash.wrapping_mul(0xd6e8_feb8_6659_fd93);
        hash ^= hash >> 32;
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::Hash;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn hash_of<T: Hash>(value: &T) -> u64 {
        let mut hasher = FxHasher::default();
        value.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn equal_keys_hash_equally() {
        assert_eq!(hash_of(&1234_u64), hash_of(&1234_u64));
        assert_eq!(hash_of(&vec![1_u8, 2, 3]), hash_of(&vec![1_u8, 2, 3]));
    }

    #[test]
    fn distinct_keys_usually_differ() {
        assert_ne!(hash_of(&1_u64), hash_of(&2_u64));
        assert_ne!(hash_of(&[0_u8; 16]), hash_of(&[1_u8; 16]));
    }

    #[test]
    fn tail_lengths_are_all_consumed() {
        // Exercises the 8/4/2/1-byte chunks of `write`.
        let bytes = [0xab_u8; 16];
        let mut seen = std::collections::HashSet::new();
        for len in 0..=16 {
            let mut hasher = FxHasher::default();
            hasher.write(&bytes[..len]);
            seen.insert(hasher.finish());
        }
        assert_eq!(seen.len(), 17, "lengths 0..=16 should hash distinctly");
    }

    #[test]
    fn works_as_a_hashmap_hasher() {
        let mut map: FxHashMap<IpAddr, u32> = FxHashMap::default();
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 89, 0, 1));
        let v6 = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));

        map.insert(v4, 1);
        map.insert(v6, 2);
        assert_eq!(map.get(&v4), Some(&1));
        assert_eq!(map.get(&v6), Some(&2));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn spreads_sequential_keys_across_buckets() {
        // Stream IDs are multiples of 4 and connection indices are sequential,
        // so the bucket bits must not degrade for keys that differ only in
        // their low bits.
        //
        // Throwing 1024 keys into 1024 buckets fills ~63% of them
        // (1 - 1/e) when the hash is well distributed; anything much below
        // that means the low bits are not moving.
        for stride in [1_u64, 4, 256] {
            let buckets: FxHashSet<u64> = (0..1_024_u64)
                .map(|i| hash_of(&(i * stride)) & 0x3ff)
                .collect();
            assert!(
                buckets.len() > 570,
                "stride {stride}: expected ~640 buckets used, got {}",
                buckets.len()
            );
        }
    }
}
