#![no_main]

use libfuzzer_sys::fuzz_target;
use masque::capsule::decoder::CapsuleDecoder;

fuzz_target!(|data: &[u8]| {
    let _ = masque::varint::decode(data);
    let _ = masque::datagram::decode_ref(data);
    let _ = masque::ip_packet::parse(data);
    let _ = masque::ip_packet::src_addr(data);
    let _ = masque::ip_packet::dst_addr(data);

    // Exercise the incremental state machine across different split points,
    // not only the one-shot parser path.
    let chunk_size = data
        .first()
        .map_or(1, |byte| usize::from(*byte % 32) + 1);
    let mut capsules = CapsuleDecoder::with_max_capsule_size(64 * 1024);
    for chunk in data.chunks(chunk_size) {
        if capsules.decode(chunk).is_err() {
            break;
        }
    }

    if let Ok(text) = std::str::from_utf8(data) {
        let _ = masque::uri::parse_connect_authority(text);
        let _ = masque::uri::parse_udp_path(
            text,
            "/.well-known/masque/udp/{target_host}/{target_port}/",
        );
        let _ = masque::uri::parse_ip_path(
            text,
            "/.well-known/masque/ip/{target}/{ipproto}/",
        );
    }
});
