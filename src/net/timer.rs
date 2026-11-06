//! One reusable deadline timer per QUIC shard.
//!
//! Linux timerfd can wake between Tokio's millisecond timer ticks without
//! spinning or blocking a runtime worker. If creation or I/O fails, retain
//! Tokio deadlines for the rest of the shard.

use std::time::Instant;

#[derive(Default)]
pub(crate) struct DeadlineTimer {
    #[cfg(target_os = "linux")]
    precise: Option<linux::Timer>,
}

impl DeadlineTimer {
    pub(crate) fn new() -> Self {
        #[cfg(target_os = "linux")]
        {
            let precise = linux::Timer::new()
                .map_err(|error| {
                    tracing::warn!(%error, "high-resolution timer unavailable; using Tokio deadlines");
                })
                .ok();
            Self { precise }
        }
        #[cfg(not(target_os = "linux"))]
        Self {}
    }

    fn has_precise_timer(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.precise.is_some()
        }
        #[cfg(not(target_os = "linux"))]
        false
    }

    /// Preserve receive-before-timeout behavior and avoid arming timerfd while
    /// socket I/O is already ready. Datagram-only deadlines keep Tokio timers.
    pub(crate) async fn timeout_at<F: std::future::Future>(
        &mut self,
        deadline: Instant,
        precise: bool,
        future: F,
    ) -> Option<F::Output> {
        if !precise || !self.has_precise_timer() {
            return tokio::time::timeout_at(deadline.into(), future).await.ok();
        }
        tokio::select! {
            biased;
            result = future => Some(result),
            _ = self.wait_until(deadline) => None,
        }
    }

    /// Safe to cancel in `select!`: the next wait replaces the kernel deadline
    /// and clears any unread expiration from the canceled wait.
    pub(crate) async fn wait_until(&mut self, deadline: Instant) {
        #[cfg(target_os = "linux")]
        if let Some(timer) = &self.precise {
            match timer.wait_until(deadline).await {
                Ok(()) => return,
                Err(error) => {
                    tracing::warn!(%error, "high-resolution timer failed; using Tokio deadlines");
                    self.precise = None;
                }
            }
        }
        tokio::time::sleep_until(deadline.into()).await;
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::Instant;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use tokio::io::unix::AsyncFd;

    pub(super) struct Timer {
        pub(super) fd: AsyncFd<OwnedFd>,
    }

    impl Timer {
        pub(super) fn new() -> io::Result<Self> {
            // SAFETY: timerfd_create takes no pointers. A successful result
            // is a new descriptor, transferred exactly once to OwnedFd below.
            let fd = unsafe {
                libc::timerfd_create(
                    libc::CLOCK_MONOTONIC,
                    libc::TFD_NONBLOCK | libc::TFD_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fd is newly created and no other owner will close it.
            // OwnedFd also closes it if AsyncFd registration fails.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            // SAFETY: OwnedFd retains this valid descriptor for the entire
            // registration lifetime. We never replace it or close it through
            // a raw descriptor while AsyncFd owns it.
            let fd = unsafe { AsyncFd::register(fd) }?;
            Ok(Self { fd })
        }

        pub(super) async fn wait_until(&self, deadline: Instant) -> io::Result<()> {
            let wait = deadline.saturating_duration_since(Instant::now());
            if wait.is_zero() {
                // A zero timerfd interval disarms the timer; an already-due
                // deadline must instead complete without waiting for I/O.
                return Ok(());
            }
            let spec = libc::itimerspec {
                it_interval: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: libc::timespec {
                    tv_sec: wait.as_secs().try_into().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "timer deadline too distant")
                    })?,
                    // A subsecond value is below 1e9 and fits a 32-bit long.
                    tv_nsec: wait.subsec_nanos() as _,
                },
            };
            // SAFETY: AsyncFd owns the live descriptor, spec is initialized
            // and readable for the call, and no previous-value output is used.
            if unsafe { libc::timerfd_settime(self.fd.as_raw_fd(), 0, &spec, std::ptr::null_mut()) }
                < 0
            {
                return Err(io::Error::last_os_error());
            }
            loop {
                let mut ready = self.fd.readable().await?;
                match ready.try_io(|fd| {
                    let mut expirations = 0u64;
                    // SAFETY: the nonblocking descriptor remains owned by
                    // AsyncFd. expirations is writable for the requested eight
                    // bytes and its pointer does not escape this read call.
                    let count = unsafe {
                        libc::read(
                            fd.as_raw_fd(),
                            (&mut expirations as *mut u64).cast(),
                            std::mem::size_of::<u64>(),
                        )
                    };
                    if count < 0 {
                        Err(io::Error::last_os_error())
                    } else if count == std::mem::size_of::<u64>() as isize {
                        Ok(())
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "short timer expiration read",
                        ))
                    }
                }) {
                    Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Ok(result) => return result,
                    // try_io clears a stale readiness indication on EAGAIN.
                    Err(_) => continue,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    use std::time::Duration;

    async fn check_rearming(mut timer: DeadlineTimer) {
        for delay in [Duration::from_secs(1), Duration::from_millis(50)] {
            // Poll once so cancellation happens after the timer was armed.
            {
                let wait = timer.wait_until(Instant::now() + delay);
                tokio::pin!(wait);
                poll_fn(|cx| {
                    assert!(wait.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
            }
            // Let the short canceled deadline expire, leaving unread I/O.
            tokio::time::sleep(Duration::from_millis(75)).await;
            let deadline = Instant::now() + Duration::from_millis(20);
            tokio::time::timeout(Duration::from_secs(2), timer.wait_until(deadline))
                .await
                .expect("rearmed timer must make progress");
            assert!(Instant::now() >= deadline, "stale expiration fired early");
        }
        tokio::time::timeout(Duration::from_secs(1), timer.wait_until(Instant::now()))
            .await
            .expect("an already-due deadline must not disarm and wait forever");
    }

    #[tokio::test]
    async fn portable_timer_survives_cancellation_and_rearming() {
        let timer = DeadlineTimer::default();
        assert!(!timer.has_precise_timer());
        check_rearming(timer).await;
    }

    #[tokio::test]
    async fn timeout_preserves_ready_io_and_expires_pending_io() {
        let mut timer = DeadlineTimer::new();
        for precise in [false, true] {
            let ready = timer
                .timeout_at(Instant::now(), precise, std::future::ready(7))
                .await;
            assert_eq!(ready, Some(7));
            let deadline = Instant::now() + Duration::from_millis(20);
            let timed_out = tokio::time::timeout(
                Duration::from_secs(2),
                timer.timeout_at(deadline, precise, std::future::pending::<()>()),
            )
            .await
            .expect("pending I/O must not prevent the timer from firing");
            assert_eq!(timed_out, None);
            assert!(Instant::now() >= deadline);
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn precise_timer_survives_cancellation_and_rearming() {
        let timer = DeadlineTimer {
            precise: Some(linux::Timer::new().expect("Linux timerfd")),
        };
        assert!(timer.has_precise_timer());
        check_rearming(timer).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn timer_io_failure_preserves_deadline_and_disables_precise_timer() {
        // A socket is a valid owned/registered fd but timerfd_settime rejects
        // it. Exercise the fallback without closing or corrupting any live fd.
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        socket.set_nonblocking(true).unwrap();
        let fd: std::os::fd::OwnedFd = socket.into();
        // SAFETY: the owned socket descriptor stays valid and unchanged until
        // AsyncFd is dropped; the failed timer operation does not close it.
        let fd = unsafe { tokio::io::unix::AsyncFd::register(fd) }.unwrap();
        let mut timer = DeadlineTimer {
            precise: Some(linux::Timer { fd }),
        };
        let deadline = Instant::now() + Duration::from_millis(20);
        tokio::time::timeout(Duration::from_secs(2), timer.wait_until(deadline))
            .await
            .unwrap();
        assert!(Instant::now() >= deadline);
        assert!(!timer.has_precise_timer());
        check_rearming(timer).await;
    }
}
