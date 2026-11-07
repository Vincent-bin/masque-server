//! Syntax validation for the initial HTTP/3 request field section.

#[derive(Default)]
pub(super) struct RequestHeaders<'a> {
    pub(super) method: Option<&'a [u8]>,
    pub(super) path: Option<&'a [u8]>,
    pub(super) scheme: Option<&'a [u8]>,
    pub(super) protocol: Option<&'a [u8]>,
    pub(super) authority: Option<&'a [u8]>,
    pub(super) proxy_authorization: Option<&'a [u8]>,
    pub(super) duplicate_proxy_authorization: bool,
}

impl<'a> RequestHeaders<'a> {
    /// Validate the field section in one pass, borrowing the values.
    /// Target parsing still runs after authentication.
    pub(super) fn parse(headers: impl IntoIterator<Item = (&'a [u8], &'a [u8])>) -> Option<Self> {
        let mut request = Self::default();
        let mut regular_field_seen = false;
        for (name, value) in headers {
            if matches!(value.first(), Some(b' ' | b'\t'))
                || matches!(value.last(), Some(b' ' | b'\t'))
                || value
                    .iter()
                    .any(|byte| byte.is_ascii_control() && *byte != b'\t')
            {
                return None;
            }
            if name.starts_with(b":") {
                let field = match name {
                    b":method" => &mut request.method,
                    b":path" => &mut request.path,
                    b":scheme" => &mut request.scheme,
                    b":protocol" => &mut request.protocol,
                    b":authority" => &mut request.authority,
                    _ => return None,
                };
                if regular_field_seen || field.replace(value).is_some() {
                    return None;
                }
                continue;
            }

            regular_field_seen = true;
            if name.is_empty()
                || !name
                    .iter()
                    .all(|byte| token_byte(*byte) && !byte.is_ascii_uppercase())
            {
                return None;
            }
            match name {
                b"connection" | b"proxy-connection" | b"keep-alive" | b"transfer-encoding"
                | b"upgrade" => return None,
                b"te"
                    if !value
                        .split(|byte| *byte == b',')
                        .map(<[u8]>::trim_ascii)
                        .all(|coding| {
                            coding.is_empty() || coding.eq_ignore_ascii_case(b"trailers")
                        }) =>
                {
                    return None;
                }
                b"proxy-authorization" => {
                    request.duplicate_proxy_authorization |=
                        request.proxy_authorization.replace(value).is_some();
                }
                _ => {}
            }
        }

        let method = request
            .method
            .filter(|value| !value.is_empty() && value.iter().copied().all(token_byte))?;
        if method == b"CONNECT" {
            let authority = request.authority?;
            match request.protocol {
                None => {
                    if request.path.is_some()
                        || request.scheme.is_some()
                        || !valid_authority(authority, true)
                    {
                        return None;
                    }
                    return Some(request);
                }
                Some(protocol)
                    if !protocol.is_empty() && protocol.iter().copied().all(token_byte) => {}
                Some(_) => return None,
            }
        } else if request.protocol.is_some() {
            return None;
        }

        let scheme = request.scheme?;
        let (first, rest) = scheme.split_first()?;
        if !first.is_ascii_alphabetic()
            || !rest
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
        {
            return None;
        }
        if request
            .authority
            .is_some_and(|value| !valid_authority(value, false))
        {
            return None;
        }
        let path = request.path?;
        match path {
            [b'/', ..] if !path.starts_with(b"//") && valid_uri_component(path, b"/?:@") => {}
            b"*" if method == b"OPTIONS" => {}
            b"" if method != b"CONNECT"
                && !scheme.eq_ignore_ascii_case(b"http")
                && !scheme.eq_ignore_ascii_case(b"https") => {}
            _ => return None,
        }
        Some(request)
    }
}

fn token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^`_|~".contains(&byte)
}

/// Validate the host and optional port without resolving or normalizing the
/// target. A standard CONNECT requires a port; its numeric range is a target
/// check performed after authentication.
fn valid_authority(authority: &[u8], require_port: bool) -> bool {
    let valid_port =
        |port: &[u8]| (!require_port || !port.is_empty()) && port.iter().all(u8::is_ascii_digit);
    if let Some(literal) = authority.strip_prefix(b"[") {
        let Some(end) = literal.iter().position(|byte| *byte == b']') else {
            return false;
        };
        let (host, suffix) = literal.split_at(end);
        return valid_ip_literal(host)
            && match suffix {
                [b']'] => !require_port,
                [b']', b':', port @ ..] => valid_port(port),
                _ => false,
            };
    }

    let mut parts = authority.splitn(2, |byte| *byte == b':');
    let host = parts.next().unwrap_or_default();
    !host.is_empty()
        && valid_uri_component(host, b"")
        && parts.next().map_or(!require_port, valid_port)
}

fn valid_ip_literal(host: &[u8]) -> bool {
    let Ok(host) = std::str::from_utf8(host) else {
        return false;
    };
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        return true;
    }
    // RFC 3986 also reserves bracketed IPvFuture literals. Whether a target
    // address family can be reached is left to authenticated target setup.
    let Some((version, address)) = host.split_once('.') else {
        return false;
    };
    let Some(version) = version.strip_prefix(['v', 'V']) else {
        return false;
    };
    !version.is_empty()
        && version.as_bytes().iter().all(u8::is_ascii_hexdigit)
        && !address.is_empty()
        && !address.contains('%')
        && valid_uri_component(address.as_bytes(), b":")
}

/// RFC 3986 unreserved characters, sub-delimiters, and valid percent triplets.
/// The caller supplies the additional delimiters allowed in its component.
fn valid_uri_component(mut value: &[u8], delimiters: &[u8]) -> bool {
    while let Some((&byte, rest)) = value.split_first() {
        if byte == b'%' {
            let [high, low, tail @ ..] = rest else {
                return false;
            };
            if !high.is_ascii_hexdigit() || !low.is_ascii_hexdigit() {
                return false;
            }
            value = tail;
        } else if byte.is_ascii_alphanumeric()
            || b"-._~!$&'()*+,;=".contains(&byte)
            || delimiters.contains(&byte)
        {
            value = rest;
        } else {
            return false;
        }
    }
    true
}
