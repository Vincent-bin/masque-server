//! Minimal `sd_notify(3)` client without a libsystemd runtime dependency.

/// Notify systemd when this process was launched with `Type=notify`.
///
/// An absent `NOTIFY_SOCKET` means the process was started manually and is not
/// an error. A present but unusable socket is an error: otherwise systemd would
/// wait until its startup timeout while the proxy appeared to be running.
pub(crate) fn notify(message: &str) -> std::io::Result<bool> {
    imp::notify(message)
}

/// Return systemd's service watchdog timeout when this process is the service
/// main PID. An absent or zero `WATCHDOG_USEC` means watchdog supervision is
/// disabled, including for manual launches.
pub(crate) fn watchdog_timeout() -> std::io::Result<Option<std::time::Duration>> {
    parse_watchdog(
        std::env::var_os("WATCHDOG_USEC").as_deref(),
        std::env::var_os("WATCHDOG_PID").as_deref(),
        std::process::id(),
    )
}

/// Ping well before the deadline. Very small synthetic values are clamped to
/// one nanosecond so a positive interval cannot create a zero-duration Tokio
/// timer.
pub(crate) fn watchdog_ping_interval(timeout: std::time::Duration) -> std::time::Duration {
    timeout
        .checked_div(3)
        .filter(|interval| !interval.is_zero())
        .unwrap_or(std::time::Duration::from_nanos(1))
}

fn parse_watchdog(
    usec: Option<&std::ffi::OsStr>,
    pid: Option<&std::ffi::OsStr>,
    current_pid: u32,
) -> std::io::Result<Option<std::time::Duration>> {
    use std::io::{Error, ErrorKind};

    if let Some(pid) = pid {
        let pid = pid
            .to_str()
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "WATCHDOG_PID is not UTF-8"))?
            .parse::<u32>()
            .map_err(|_| Error::new(ErrorKind::InvalidData, "WATCHDOG_PID is not an integer"))?;
        if pid != current_pid {
            return Ok(None);
        }
    }

    let Some(usec) = usec else {
        return Ok(None);
    };
    let usec = usec
        .to_str()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "WATCHDOG_USEC is not UTF-8"))?
        .parse::<u64>()
        .map_err(|_| Error::new(ErrorKind::InvalidData, "WATCHDOG_USEC is not an integer"))?;
    if usec == 0 {
        return Ok(None);
    }

    Ok(Some(std::time::Duration::from_micros(usec)))
}

#[cfg(unix)]
mod imp {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::net::UnixDatagram;

    pub(super) fn notify(message: &str) -> std::io::Result<bool> {
        let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
            return Ok(false);
        };
        notify_path(&path, message)?;
        Ok(true)
    }

    fn notify_path(path: &OsStr, message: &str) -> std::io::Result<()> {
        let socket = UnixDatagram::unbound()?;
        let bytes = path.as_bytes();
        if bytes.first() == Some(&b'@') {
            send_abstract(&socket, &bytes[1..], message.as_bytes())?;
        } else {
            socket.send_to(message.as_bytes(), path)?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn send_abstract(socket: &UnixDatagram, name: &[u8], message: &[u8]) -> std::io::Result<()> {
        use std::os::linux::net::SocketAddrExt as _;

        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
        socket.send_to_addr(message, &addr)?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn send_abstract(_socket: &UnixDatagram, _name: &[u8], _message: &[u8]) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "abstract NOTIFY_SOCKET addresses are Linux-only",
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::time::Duration;

        #[test]
        fn sends_a_notification_to_a_path_socket() {
            // macOS has a short sockaddr_un path limit, so keep this well
            // below it even when the workspace itself has a long path.
            let path =
                std::path::PathBuf::from(format!("/tmp/mq-notify-{}.sock", std::process::id()));
            let _ = std::fs::remove_file(&path);
            let receiver = UnixDatagram::bind(&path).unwrap();
            receiver
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();

            notify_path(path.as_os_str(), "READY=1\nSTATUS=ready").unwrap();
            let mut buf = [0u8; 128];
            let read = receiver.recv(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"READY=1\nSTATUS=ready");

            drop(receiver);
            std::fs::remove_file(path).unwrap();
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn sends_a_notification_to_an_abstract_socket() {
            use std::os::linux::net::SocketAddrExt as _;

            let name = format!("masque-notify-{}", std::process::id());
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
            let receiver = UnixDatagram::bind_addr(&addr).unwrap();
            receiver
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();

            send_abstract(
                &UnixDatagram::unbound().unwrap(),
                name.as_bytes(),
                b"READY=1",
            )
            .unwrap();
            let mut buf = [0u8; 32];
            let read = receiver.recv(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"READY=1");
        }
    }
}

#[cfg(test)]
mod watchdog_tests {
    use super::*;
    use std::ffi::OsStr;
    use std::time::Duration;

    #[test]
    fn absent_or_zero_watchdog_is_disabled() {
        assert_eq!(parse_watchdog(None, None, 42).unwrap(), None);
        assert_eq!(
            parse_watchdog(Some(OsStr::new("0")), None, 42).unwrap(),
            None
        );
    }

    #[test]
    fn watchdog_is_scoped_to_the_service_main_pid() {
        assert_eq!(
            parse_watchdog(Some(OsStr::new("30000000")), Some(OsStr::new("41")), 42).unwrap(),
            None
        );
        assert_eq!(
            parse_watchdog(Some(OsStr::new("30000000")), Some(OsStr::new("42")), 42).unwrap(),
            Some(Duration::from_secs(30))
        );
    }

    #[test]
    fn malformed_watchdog_environment_is_rejected() {
        assert!(parse_watchdog(Some(OsStr::new("later")), None, 42).is_err());
        assert!(
            parse_watchdog(Some(OsStr::new("30000000")), Some(OsStr::new("main")), 42).is_err()
        );
    }

    #[test]
    fn watchdog_ping_is_safely_ahead_of_the_deadline() {
        assert_eq!(
            watchdog_ping_interval(Duration::from_secs(30)),
            Duration::from_secs(10)
        );
        assert_eq!(
            watchdog_ping_interval(Duration::from_micros(1)),
            Duration::from_nanos(333)
        );
    }
}

#[cfg(not(unix))]
mod imp {
    pub(super) fn notify(_message: &str) -> std::io::Result<bool> {
        Ok(false)
    }
}
