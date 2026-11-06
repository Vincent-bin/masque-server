//! Strict matching for the server's configured RFC 9484 path/query template.
//!
//! Only explicitly supported, unambiguous template forms are accepted. In
//! particular, matching a static prefix is not enough: it can discard a scope
//! constraint and accidentally turn a flow-specific request into a full VPN.

use std::collections::HashSet;
use std::net::IpAddr;

use super::{IpTarget, UriError, hex_digit};

#[derive(Clone, Copy)]
enum Variable {
    Target,
    Protocol,
}

impl Variable {
    fn parse(value: &str) -> Result<Self, UriError> {
        match value {
            "target" => Ok(Self::Target),
            "ipproto" => Ok(Self::Protocol),
            _ => Err(UriError::InvalidTemplate),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::Protocol => "ipproto",
        }
    }
}

enum Component<'a> {
    Literal(&'a str),
    Variable(Variable),
}

impl<'a> Component<'a> {
    fn parse(value: &'a str, variables: &mut HashSet<&'static str>) -> Result<Self, UriError> {
        if let Some(name) = value.strip_prefix('{').and_then(|v| v.strip_suffix('}')) {
            let variable = Variable::parse(name)?;
            if !variables.insert(variable.name()) {
                return Err(UriError::InvalidTemplate);
            }
            Ok(Self::Variable(variable))
        } else if value.contains(['{', '}']) || decode(value).is_none() {
            Err(UriError::InvalidTemplate)
        } else {
            Ok(Self::Literal(value))
        }
    }

    fn capture(&self, value: &str, target: &mut IpTarget) -> Result<(), UriError> {
        match self {
            Self::Literal(expected) if *expected == value => Ok(()),
            Self::Literal(_) => Err(UriError::PathMismatch),
            Self::Variable(Variable::Target) => {
                target.target = parse_target(value)?;
                Ok(())
            }
            Self::Variable(Variable::Protocol) => {
                target.ipproto = parse_protocol(value)?;
                Ok(())
            }
        }
    }
}

struct QueryParameter<'a> {
    name: &'a str,
    value: Component<'a>,
    optional: bool,
}

struct Template<'a> {
    path: Vec<Component<'a>>,
    query: Vec<QueryParameter<'a>>,
}

impl<'a> Template<'a> {
    fn parse(template: &'a str) -> Result<Self, UriError> {
        // The server config stores path/query only. Clients reconstruct the
        // absolute URI using the listener's own authority and secure scheme.
        if !template.starts_with('/')
            || template.starts_with("//")
            || template.contains('#')
            || !template.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(UriError::InvalidTemplate);
        }
        let mut variables = HashSet::new();
        let mut names = HashSet::new();
        let mut query = Vec::new();
        let (fixed, expansion) =
            if let Some(start) = template.find("{?").or_else(|| template.find("{&")) {
                let expression = template[start + 2..]
                    .strip_suffix('}')
                    .ok_or(UriError::InvalidTemplate)?;
                let fixed = &template[..start];
                if (template.as_bytes()[start + 1] == b'&') != fixed.contains('?') {
                    return Err(UriError::InvalidTemplate);
                }
                (fixed, Some(expression))
            } else {
                (template, None)
            };
        let (path, fixed_query) = fixed
            .split_once('?')
            .map_or((fixed, None), |(p, q)| (p, Some(q)));
        let path = path
            .split('/')
            .map(|part| Component::parse(part, &mut variables))
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(fixed_query) = fixed_query {
            for pair in fixed_query.split('&') {
                let (name, value) = pair.split_once('=').ok_or(UriError::InvalidTemplate)?;
                if name.is_empty()
                    || name.contains(['{', '}'])
                    || decode(name).is_none()
                    || !names.insert(name)
                {
                    return Err(UriError::InvalidTemplate);
                }
                query.push(QueryParameter {
                    name,
                    value: Component::parse(value, &mut variables)?,
                    optional: false,
                });
            }
        }
        if let Some(expansion) = expansion {
            for name in expansion.split(',') {
                let variable = Variable::parse(name)?;
                if !variables.insert(variable.name()) || !names.insert(name) {
                    return Err(UriError::InvalidTemplate);
                }
                query.push(QueryParameter {
                    name,
                    value: Component::Variable(variable),
                    optional: true,
                });
            }
        }
        Ok(Self { path, query })
    }

    fn capture(&self, uri: &str) -> Result<IpTarget, UriError> {
        if uri.contains('#') || !uri.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(UriError::PathMismatch);
        }
        let (path, query) = uri
            .split_once('?')
            .map_or((uri, None), |(p, q)| (p, Some(q)));
        let mut target = IpTarget {
            target: None,
            ipproto: None,
        };
        let mut segments = path.split('/');
        for component in &self.path {
            component.capture(segments.next().ok_or(UriError::PathMismatch)?, &mut target)?;
        }
        if segments.next().is_some() {
            return Err(UriError::PathMismatch);
        }
        // Reject unknown or repeated parameters rather than choosing one
        // interpretation or silently ignoring a possible scope restriction.
        let mut seen = HashSet::new();
        if let Some(query) = query {
            for pair in query.split('&') {
                let (name, value) = pair.split_once('=').ok_or(UriError::PathMismatch)?;
                let parameter = self
                    .query
                    .iter()
                    .find(|p| p.name == name)
                    .ok_or(UriError::PathMismatch)?;
                if !seen.insert(name) {
                    return Err(UriError::PathMismatch);
                }
                parameter.value.capture(value, &mut target)?;
            }
        }
        if self
            .query
            .iter()
            .any(|p| !p.optional && !seen.contains(p.name))
        {
            return Err(UriError::PathMismatch);
        }
        Ok(target)
    }
}

/// Validate the server's supported path/query template syntax at startup.
///
/// Supports literal paths, whole-segment `{target}` / `{ipproto}` variables,
/// literal or variable query values, and a final `{?target,ipproto}` (or
/// `{&target,ipproto}`) expansion. Variables can appear at most once.
pub fn validate_ip_template(template: &str) -> Result<(), UriError> {
    Template::parse(template).map(|_| ())
}

/// Match the complete configured URI and validate RFC 9484 scope variables.
/// A variable omitted from the template means wildcard, but one present in a
/// required component must be supplied and must not be empty.
pub fn parse_ip_path(path: &str, template: &str) -> Result<IpTarget, UriError> {
    Template::parse(template)?.capture(path)
}

/// Decode exactly once, rejecting malformed escapes and non-UTF-8 data.
fn decode(value: &str) -> Option<String> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        decoded.push(if byte == b'%' {
            (hex_digit(bytes.next()?)? << 4) | hex_digit(bytes.next()?)?
        } else {
            byte
        });
    }
    String::from_utf8(decoded).ok()
}

fn parse_protocol(value: &str) -> Result<Option<u8>, UriError> {
    let invalid = || UriError::InvalidProtocol(value.into());
    let decoded = decode(value).ok_or_else(invalid)?;
    if decoded == "*" {
        return Ok(None);
    }
    if decoded.is_empty() || decoded.len() > 3 || !decoded.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    decoded.parse::<u8>().map(Some).map_err(|_| invalid())
}

fn parse_target(value: &str) -> Result<Option<String>, UriError> {
    let invalid = || UriError::InvalidTarget;
    // RFC 9484 requires percent-encoded IPv6 colons and prefix slashes.
    if value.contains([':', '/']) {
        return Err(invalid());
    }
    let decoded = decode(value).ok_or_else(invalid)?;
    if decoded == "*" {
        return Ok(None);
    }
    if decoded.is_empty() {
        return Err(invalid());
    }
    if let Some((address, prefix)) = decoded.split_once('/') {
        let address: IpAddr = address.parse().map_err(|_| invalid())?;
        let bits = if address.is_ipv4() { 32 } else { 128 };
        let digits = if address.is_ipv4() { 2 } else { 3 };
        if prefix.is_empty() || prefix.len() > digits || !prefix.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(invalid());
        }
        let prefix: u8 = prefix.parse().map_err(|_| invalid())?;
        if prefix > bits {
            return Err(invalid());
        }
        let network = ipnet::IpNet::new(address, prefix).map_err(|_| invalid())?;
        if network.network() != address {
            return Err(invalid());
        }
    } else if decoded.contains(':') {
        decoded
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| invalid())?;
    } else if !decoded
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&b))
    {
        // RFC 3986 reg-name after one round of decoding; this also excludes
        // IPv6 zone identifiers, brackets, control characters and delimiters.
        return Err(invalid());
    }
    Ok(Some(decoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEMPLATE: &str = "/.well-known/masque/ip/{target}/{ipproto}/";

    #[test]
    fn wildcard_and_percent_encoded_wildcard_are_unscoped() {
        for path in [
            "/.well-known/masque/ip/*/*/",
            "/.well-known/masque/ip/%2A/%2a/",
        ] {
            assert_eq!(
                parse_ip_path(path, TEMPLATE).unwrap(),
                IpTarget {
                    target: None,
                    ipproto: None
                }
            );
        }
    }

    #[test]
    fn complete_path_is_required() {
        for path in [
            "/",
            "/.well-known/masque/ip/",
            "/.well-known/masque/ip/*/",
            "/.well-known/masque/ip//*/",
            "/.well-known/masque/ip/*//",
            "/.well-known/masque/ip/*/*",
            "/.well-known/masque/ip/*/*//",
            "/.well-known/masque/ip/*/*/extra",
            "/.well-known/masque/ip/*/*/?target=192.0.2.1",
            "/.well-known/masque/ip/*/*/#fragment",
        ] {
            assert!(parse_ip_path(path, TEMPLATE).is_err(), "{path}");
        }
    }

    #[test]
    fn scope_is_decoded_and_validated() {
        for (wire, expected) in [
            ("192.0.2.1", "192.0.2.1"),
            ("192.0.2.0%2F24", "192.0.2.0/24"),
            ("2001%3Adb8%3A%3A%2f32", "2001:db8::/32"),
            ("2001%3Adb8%3A%3A1", "2001:db8::1"),
            ("0.0.0.0%2F0", "0.0.0.0/0"),
            ("%3A%3A%2F0", "::/0"),
            ("example.com", "example.com"),
            ("example%2Ecom", "example.com"),
        ] {
            for (protocol, expected_protocol) in
                [("0", 0), ("255", 255), ("%31%37", 17), ("006", 6)]
            {
                let scope = parse_ip_path(
                    &format!("/.well-known/masque/ip/{wire}/{protocol}/"),
                    TEMPLATE,
                )
                .unwrap();
                assert_eq!(scope.target.as_deref(), Some(expected));
                assert_eq!(scope.ipproto, Some(expected_protocol));
            }
        }
    }

    #[test]
    fn malformed_scopes_are_never_treated_as_wildcards() {
        for target in [
            "192.0.2.1%2F24",
            "192.0.2.0%2F33",
            "192.0.2.0%2F024",
            "192.0.2.0%2F",
            "192.0.2.0%2F%2B24",
            "192.0.2.0%2F24%2F24",
            "example.com%2F24",
            "2001:db8::",
            "2001%3Adb8%3A%3A1%2F64",
            "2001%3Adb8%3A%3A%2F129",
            "fe80%3A%3A1%25eth0",
            "%5B2001%3Adb8%3A%3A1%5D",
            "%",
            "%2",
            "%XX",
            "%252A",
            "%00",
            "%0A",
            "%FF",
            "%20",
            "host%40example.com",
            "é",
        ] {
            assert!(
                parse_ip_path(&format!("/.well-known/masque/ip/{target}/*/"), TEMPLATE).is_err(),
                "{target}"
            );
        }
        for protocol in [
            "", "256", "0000", "+6", "%2B6", "-1", "%20", "tcp", "%", "%00", "%FF", "%252A",
        ] {
            assert!(
                parse_ip_path(&format!("/.well-known/masque/ip/*/{protocol}/"), TEMPLATE).is_err(),
                "{protocol}"
            );
        }
    }

    #[test]
    fn exact_static_and_partial_templates_default_omitted_variables_to_wildcard() {
        assert_eq!(
            parse_ip_path("/vpn", "/vpn").unwrap(),
            IpTarget {
                target: None,
                ipproto: None
            }
        );
        assert!(parse_ip_path("/vpn/extra", "/vpn").is_err());
        assert_eq!(
            parse_ip_path("/vpn/6/", "/vpn/{ipproto}/").unwrap().ipproto,
            Some(6)
        );
        assert_eq!(
            parse_ip_path("/vpn/6/192.0.2.1", "/vpn/{ipproto}/{target}")
                .unwrap()
                .target
                .as_deref(),
            Some("192.0.2.1")
        );
    }

    #[test]
    fn explicit_query_variables_are_required_and_not_discarded() {
        let template = "/vpn?t={target}&i={ipproto}&user=bob";
        assert_eq!(
            parse_ip_path("/vpn?user=bob&i=%2A&t=*", template).unwrap(),
            IpTarget {
                target: None,
                ipproto: None
            }
        );
        assert_eq!(
            parse_ip_path("/vpn?t=192.0.2.1&i=17&user=bob", template)
                .unwrap()
                .ipproto,
            Some(17)
        );
        for path in [
            "/vpn",
            "/vpn?t=*&i=*",
            "/vpn?t=&i=*&user=bob",
            "/vpn?t=*&i=*&user=bob&t=192.0.2.1",
            "/vpn?t=*&i=*&user=bob&extra=1",
        ] {
            assert!(parse_ip_path(path, template).is_err(), "{path}");
        }
    }

    #[test]
    fn optional_query_expansion_preserves_scope_and_rejects_ambiguous_fields() {
        let template = "/vpn{?target,ipproto}";
        for path in [
            "/vpn",
            "/vpn?target=*",
            "/vpn?ipproto=*",
            "/vpn?ipproto=%2A&target=%2A",
        ] {
            assert_eq!(
                parse_ip_path(path, template).unwrap(),
                IpTarget {
                    target: None,
                    ipproto: None
                }
            );
        }
        assert_eq!(
            parse_ip_path("/vpn?ipproto=17", template).unwrap().ipproto,
            Some(17)
        );
        for path in [
            "/vpn?",
            "/vpn?ipproto=",
            "/vpn?target=",
            "/vpn?target=*&target=192.0.2.1",
            "/vpn?target=*&%74arget=*",
            "/vpn?other=*",
        ] {
            assert!(parse_ip_path(path, template).is_err(), "{path}");
        }
        assert!(parse_ip_path("/vpn?user=bob&target=*", "/vpn?user=bob{&target,ipproto}").is_ok());
        assert!(parse_ip_path("/vpn?user=bob", "/vpn?user=bob{&target,ipproto}").is_ok());
    }

    #[test]
    fn unsupported_or_ambiguous_configuration_is_rejected() {
        for template in [
            "",
            "https://example.com/vpn",
            "//authority/vpn",
            "/vpn#fragment",
            "/vpn/é",
            "/vpn/{target}/{target}",
            "/vpn/{target,ipproto}",
            "/vpn/{+target}",
            "/vpn/{target:3}",
            "/vpn/{target*}",
            "/vpn/{other}",
            "/vpn/prefix{target}",
            "/vpn/{target}suffix",
            "/vpn/{target",
            "/vpn/target}",
            "/vpn/%ZZ",
            "/vpn{?target,ipproto}/extra",
            "/vpn{?target,target}",
            "/vpn{?target,other}",
            "/vpn?target={target}{&target}",
            "/vpn?user=bob{?ipproto}",
            "/vpn{&target}",
            "/vpn?a=1&a=2",
            "/vpn?={target}",
            "/vpn?x={target}&y={target}",
        ] {
            assert!(validate_ip_template(template).is_err(), "{template}");
        }
    }
}
