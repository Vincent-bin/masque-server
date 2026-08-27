use crate::report::ProbeFailure;

pub fn ensure_success_status(status: u16, target: &str) -> Result<(), ProbeFailure> {
    match status {
        200 => Ok(()),
        407 => Err(ProbeFailure::new(
            "AUTH_REJECTED",
            "server returned HTTP 407; credentials are missing or invalid",
        )),
        403 => Err(ProbeFailure::new(
            "TARGET_POLICY_DENIED",
            format!("server policy denied target {target} with HTTP 403"),
        )),
        404 => Err(ProbeFailure::new(
            "PROTOCOL_REJECTED",
            "server returned HTTP 404 for the requested CONNECT protocol",
        )),
        502 => Err(ProbeFailure::new(
            "TARGET_CONNECT_FAILED",
            format!("proxy was reached, but it could not connect to target {target} (HTTP 502)"),
        )),
        504 => Err(ProbeFailure::new(
            "TARGET_CONNECT_TIMEOUT",
            format!("proxy target setup timed out for {target} (HTTP 504)"),
        )),
        status => Err(ProbeFailure::new(
            "CONNECT_REJECTED",
            format!("server rejected CONNECT with HTTP {status}"),
        )),
    }
}

pub fn dns_query() -> Vec<u8> {
    let mut query = vec![
        0x4d, 0x51, // ID
        0x01, 0x00, // recursion desired
        0x00, 0x01, // one question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in ["example", "com"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]); // root, A, IN
    query
}

pub fn validate_dns_response(response: &[u8]) -> Result<(), ProbeFailure> {
    if response.len() < 12 || response[..2] != [0x4d, 0x51] || response[2] & 0x80 == 0 {
        return Err(ProbeFailure::new(
            "UDP_RESPONSE_INVALID",
            "received UDP payload is not the matching DNS response",
        ));
    }
    Ok(())
}

pub fn udp_probe_payload(dns: bool) -> Vec<u8> {
    if dns {
        dns_query()
    } else {
        b"masque-probe-connect-udp-echo".to_vec()
    }
}

pub fn validate_udp_probe_response(
    response: &[u8],
    request: &[u8],
    dns: bool,
) -> Result<(), ProbeFailure> {
    if dns {
        validate_dns_response(response)
    } else if response == request {
        Ok(())
    } else {
        Err(ProbeFailure::new(
            "UDP_RESPONSE_INVALID",
            "echo target returned a payload that does not match the request",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_query_and_response_validation_use_a_stable_id() {
        let query = dns_query();
        assert_eq!(&query[..2], &[0x4d, 0x51]);
        let mut response = query;
        response[2] |= 0x80;
        assert!(validate_dns_response(&response).is_ok());
        response[0] = 0;
        assert!(validate_dns_response(&response).is_err());
    }

    #[test]
    fn status_codes_have_actionable_categories() {
        assert_eq!(
            ensure_success_status(407, "example.com:443")
                .unwrap_err()
                .code,
            "AUTH_REJECTED"
        );
        assert_eq!(
            ensure_success_status(502, "example.com:443")
                .unwrap_err()
                .code,
            "TARGET_CONNECT_FAILED"
        );
        assert_eq!(
            ensure_success_status(504, "example.com:443")
                .unwrap_err()
                .code,
            "TARGET_CONNECT_TIMEOUT"
        );
    }
}
