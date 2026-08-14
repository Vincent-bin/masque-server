use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use masque::address_pool::AddressPool;
use masque::capsule::decoder::CapsuleDecoder;
use masque::capsule::{CapsuleFrame, encoder as capsule_encoder};
use masque::datagram::{self, HttpDatagram};
use masque::policy::TargetPolicy;
use masque::routing::{RoutingTable, TunnelOwner};

const SAMPLES: usize = 15;
const TARGET_SAMPLE_TIME: Duration = Duration::from_millis(30);

fn bench<F, R>(name: &str, bytes_per_op: Option<usize>, mut operation: F)
where
    F: FnMut() -> R,
{
    for _ in 0..1_000 {
        black_box(operation());
    }

    let mut iterations = 1_u64;
    loop {
        let start = Instant::now();
        for _ in 0..iterations {
            black_box(operation());
        }
        if start.elapsed() >= TARGET_SAMPLE_TIME || iterations >= (1 << 32) {
            break;
        }
        iterations *= 2;
    }

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        for _ in 0..iterations {
            black_box(operation());
        }
        samples.push(start.elapsed().as_secs_f64() * 1e9 / iterations as f64);
    }
    samples.sort_by(f64::total_cmp);

    let median = samples[SAMPLES / 2];
    let low = samples[SAMPLES / 10];
    let high = samples[SAMPLES - 1 - SAMPLES / 10];
    let mops = 1_000.0 / median;
    let throughput = bytes_per_op.map(|bytes| bytes as f64 / median);

    print!("{name:<32} {median:>10.2} ns/op  {mops:>8.2} Mops/s  (p10 {low:.2}, p90 {high:.2})");
    if let Some(gib_per_second) = throughput {
        print!("  {gib_per_second:>6.2} GB/s");
    }
    println!();
}

fn main() {
    println!("MASQUE core microbenchmarks (release, {SAMPLES} samples)");
    println!("Throughput is reported in decimal GB/s.\n");

    let mut encoded = [0_u8; 8];
    masque::varint::encode(1_000_000, &mut encoded).unwrap();
    bench("varint/decode-4byte", None, || {
        masque::varint::decode(black_box(&encoded))
    });
    bench("varint/encode-4byte", None, || {
        let mut output = [0_u8; 8];
        masque::varint::encode(black_box(1_000_000), black_box(&mut output))
    });

    let payload_64 = vec![0x5a; 64];
    let datagram_64 = HttpDatagram {
        stream_id: 400,
        context_id: 0,
        payload: payload_64,
    };
    let wire_64 = datagram::encode(&datagram_64).unwrap();
    bench("datagram/encode-64", Some(64), || {
        datagram::encode(black_box(&datagram_64))
    });
    bench("datagram/encode-payload-64", Some(64), || {
        datagram::encode_payload(black_box(400), black_box(&datagram_64.payload))
    });
    let mut reusable_64 = Vec::with_capacity(80);
    bench("datagram/encode-into-64", Some(64), || {
        datagram::encode_payload_into(
            black_box(400),
            black_box(&datagram_64.payload),
            black_box(&mut reusable_64),
        )
        .unwrap();
        reusable_64.len()
    });
    bench("datagram/decode-64", Some(64), || {
        datagram::decode(black_box(&wire_64))
    });
    bench("datagram/decode-ref-64", Some(64), || {
        datagram::decode_ref(black_box(&wire_64))
    });

    let datagram_1200 = HttpDatagram {
        stream_id: 400,
        context_id: 0,
        payload: vec![0xa5; 1_200],
    };
    let wire_1200 = datagram::encode(&datagram_1200).unwrap();
    bench("datagram/encode-1200", Some(1_200), || {
        datagram::encode(black_box(&datagram_1200))
    });
    bench("datagram/encode-payload-1200", Some(1_200), || {
        datagram::encode_payload(black_box(400), black_box(&datagram_1200.payload))
    });
    let mut reusable_1200 = Vec::with_capacity(1_216);
    bench("datagram/encode-into-1200", Some(1_200), || {
        datagram::encode_payload_into(
            black_box(400),
            black_box(&datagram_1200.payload),
            black_box(&mut reusable_1200),
        )
        .unwrap();
        reusable_1200.len()
    });
    bench("datagram/decode-1200", Some(1_200), || {
        datagram::decode(black_box(&wire_1200))
    });
    bench("datagram/decode-ref-1200", Some(1_200), || {
        datagram::decode_ref(black_box(&wire_1200))
    });

    let capsule = CapsuleFrame::Datagram(vec![0x3c; 1_200]);
    let mut capsule_wire = Vec::new();
    capsule_encoder::encode(&capsule, &mut capsule_wire);
    bench("capsule/encode-1200", Some(1_200), || {
        let mut output = Vec::new();
        capsule_encoder::encode(black_box(&capsule), &mut output);
        output
    });
    let mut decoder = CapsuleDecoder::new();
    bench("capsule/decode-1200", Some(1_200), || {
        decoder.decode(black_box(&capsule_wire))
    });

    let mut ipv4 = [0_u8; 20];
    ipv4[0] = 0x45;
    ipv4[2..4].copy_from_slice(&20_u16.to_be_bytes());
    ipv4[9] = 17;
    ipv4[12..16].copy_from_slice(&[10, 89, 0, 1]);
    ipv4[16..20].copy_from_slice(&[8, 8, 8, 8]);
    bench("ip-packet/parse-ipv4", Some(20), || {
        masque::ip_packet::parse(black_box(&ipv4))
    });

    let mut ipv6 = [0_u8; 40];
    ipv6[0] = 0x60;
    ipv6[6] = 17;
    ipv6[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
    ipv6[24..40].copy_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
    bench("ip-packet/parse-ipv6", Some(40), || {
        masque::ip_packet::parse(black_box(&ipv6))
    });

    let mut routes = RoutingTable::new();
    let mut route_keys = Vec::with_capacity(50_000);
    for host in 1..=50_000_u32 {
        let addr = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 | host));
        routes.insert(
            addr,
            TunnelOwner {
                conn_id: u64::from(host % 1_000),
                stream_id: u64::from(host % 100) * 4,
            },
        );
        route_keys.push(addr);
    }
    let mut route_index = 0_usize;
    bench("routing/lookup-50k", None, || {
        route_index = (route_index + 7_919) % route_keys.len();
        routes.lookup(black_box(&route_keys[route_index]))
    });

    let allow = vec!["0.0.0.0/0".to_owned()];
    let deny = [
        "10.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "224.0.0.0/4",
    ]
    .map(str::to_owned)
    .to_vec();
    let policy = TargetPolicy::new(&allow, &deny);
    let public_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    bench("policy/check-8-deny-rules", None, || {
        policy.is_allowed(black_box(public_ip))
    });

    let mut pool = AddressPool::new("10.89.0.0/16", "").unwrap();
    bench("address-pool/allocate-release", None, || {
        let addr = pool.allocate_v4().unwrap();
        black_box(pool.release(IpAddr::V4(addr)))
    });
}
