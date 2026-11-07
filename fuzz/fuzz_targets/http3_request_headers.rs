#![no_main]

use libfuzzer_sys::{arbitrary::Unstructured, fuzz_target};

// Exercise the server's actual parser without adding a public parser API.
#[path = "../../src/server/request_headers.rs"]
mod request_headers;

use request_headers::RequestHeaders;

type Field<'a> = (&'a [u8], &'a [u8]);

fuzz_target!(|data: &[u8]| {
    let mut input = Unstructured::new(data);
    let Ok(mode) = input.arbitrary::<u8>() else {
        return;
    };
    let mut fields: Vec<Field<'_>> = match mode % 4 {
        0 => vec![
            (b":method", b"CONNECT"),
            (b":authority", b"[2001:db8::1]:443"),
        ],
        1 => vec![
            (b":method", b"CONNECT"),
            (b":protocol", b"connect-udp"),
            (b":scheme", b"https"),
            (b":authority", b"proxy.example"),
            (b":path", b"/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/"),
        ],
        2 => vec![
            (b":method", b"OPTIONS"),
            (b":scheme", b"https"),
            (b":authority", b"proxy.example"),
            (b":path", b"*"),
            (b"te", b"trailers"),
        ],
        _ => Vec::new(),
    };

    // Mutate structured requests as well as arbitrary lists. The fallback
    // keeps names and values fully binary, including NUL and non-ASCII.
    for _ in 0..32 {
        if input.is_empty() {
            break;
        }
        let Ok((op, selector, raw_name, value)) = input.arbitrary::<(u8, u8, &[u8], &[u8])>()
        else {
            break;
        };
        let name: &[u8] = match selector % 9 {
            0 => b":method",
            1 => b":authority",
            2 => b":path",
            3 => b":scheme",
            4 => b":protocol",
            5 => b"proxy-authorization",
            6 => b"te",
            7 => b"connection",
            _ => raw_name,
        };
        let index = (usize::from(op) >> 1).min(fields.len());
        if op & 1 == 1 && index < fields.len() {
            fields[index] = (name, value);
        } else {
            fields.insert(index, (name, value));
        }
    }

    if let Some(parsed) = RequestHeaders::parse(fields.iter().copied()) {
        let method = parsed.method.expect("accepted requests have a method");
        if method == b"CONNECT" {
            assert!(parsed.authority.is_some());
            assert_eq!(parsed.protocol.is_some(), parsed.scheme.is_some());
            assert_eq!(parsed.protocol.is_some(), parsed.path.is_some());
        }
        let credentials = fields
            .iter()
            .filter(|(name, _)| *name == b"proxy-authorization")
            .count();
        assert_eq!(parsed.proxy_authorization.is_some(), credentials > 0);
        assert_eq!(parsed.duplicate_proxy_authorization, credentials > 1);
        fields.push((b":method", method));
        assert!(RequestHeaders::parse(fields).is_none());
    }
});
