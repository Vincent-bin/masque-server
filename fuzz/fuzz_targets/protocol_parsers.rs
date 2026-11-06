#![no_main]

use libfuzzer_sys::fuzz_target;
use masque::capsule::decoder::CapsuleDecoder;

fuzz_target!(|data: &[u8]| {
    let _ = masque::varint::decode(data);
    if let Ok(datagram) = masque::datagram::decode_ref(data) {
        assert!(datagram.stream_id <= masque::varint::MAX_VALUE);
        assert!(datagram.stream_id.is_multiple_of(4));
    }
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

    let mut datagrams = masque::capsule::datagram::DatagramCapsules::new(64 * 1024);
    for chunk in data.chunks(chunk_size) {
        if datagrams.decode(chunk).is_err() { break; }
    }

    let mut ip = masque::capsule::ip::IpCapsules::new(64 * 1024);
    let mut requests = masque::capsule::ip::AddressRequests::default();
    for chunk in data.chunks(chunk_size) {
        let Ok(frames) = ip.decode(chunk) else { break; };
        for frame in frames {
            if let masque::capsule::CapsuleFrame::AddressRequest(addresses) = frame {
                let _ = requests.respond(&addresses, &[]);
            }
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
        let _ = masque::uri::parse_ip_path(text, "/vpn{?target,ipproto}");
        let _ = masque::uri::validate_ip_template(text);
        // An operator-provided template and a client-provided URI are separate
        // inputs. Exercise their interaction as well as each parser alone.
        if let Some((template, path)) = text.split_once('\n') {
            let _ = masque::uri::parse_ip_path(path, template);
        }
    }
});
