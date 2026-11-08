//! Bounded, stream-local retries for empty HTTP/3 error responses.

use std::time::{Duration, Instant};

use crate::fxhash::FxHashMap;

/// Rejected requests must not grow an unauthenticated connection without bound.
/// Each entry stores only a status and its original deadline basis, never headers,
/// credentials, target sockets, or request-body bytes.
const MAX_PENDING_ERROR_RESPONSES: usize = 64;

#[derive(Default)]
pub(crate) struct PendingErrorResponses {
    responses: FxHashMap<u64, PendingErrorResponse>,
}

struct PendingErrorResponse {
    status: u16,
    started: Instant,
}

impl PendingErrorResponses {
    pub(crate) fn len(&self) -> usize {
        self.responses.len()
    }

    pub(crate) fn contains(&self, stream_id: u64) -> bool {
        self.responses.contains_key(&stream_id)
    }

    pub(crate) fn cancel(&mut self, quic: &mut crate::connection::ServerQuic, stream_id: u64) {
        if self.responses.remove(&stream_id).is_some() {
            Self::reset(quic, stream_id, quiche::h3::WireErrorCode::RequestCancelled);
        }
    }

    pub(crate) fn clear(&mut self) {
        self.responses.clear();
    }

    pub(crate) fn send(
        &mut self,
        h3: &mut quiche::h3::Connection,
        quic: &mut crate::connection::ServerQuic,
        stream_id: u64,
        status: u16,
    ) {
        // Preserve the first decision and timeout if additional HEADERS arrive.
        if self.responses.contains_key(&stream_id) {
            return;
        }
        if !Self::try_send(h3, quic, stream_id, status) {
            return;
        }
        if self.responses.len() >= MAX_PENDING_ERROR_RESPONSES {
            // A STOP_SENDING and this request can arrive in the same packet,
            // before the next output drive. Reclaim terminal entries before
            // deciding that admission is still exhausted.
            self.retry(h3, quic);
            if self.responses.len() >= MAX_PENDING_ERROR_RESPONSES {
                Self::reset(quic, stream_id, quiche::h3::WireErrorCode::ExcessiveLoad);
                return;
            }
        }
        self.responses.insert(
            stream_id,
            PendingErrorResponse {
                status,
                started: Instant::now(),
            },
        );
    }

    /// Retry only when the connection is already being driven (for example by
    /// MAX_DATA/MAX_STREAM_DATA or STOP_SENDING), without scheduling a busy loop.
    pub(crate) fn retry(
        &mut self,
        h3: &mut quiche::h3::Connection,
        quic: &mut crate::connection::ServerQuic,
    ) {
        self.responses
            .retain(|id, pending| Self::try_send(h3, quic, *id, pending.status));
    }

    /// The regular idle sweep provides the same bounded lifetime as pending
    /// tunnel responses. Retries never refresh the original timestamp.
    pub(crate) fn expire(
        &mut self,
        quic: &mut crate::connection::ServerQuic,
        timeout: Duration,
    ) -> bool {
        let before = self.responses.len();
        self.responses.retain(|id, pending| {
            if pending.started.elapsed() < timeout {
                return true;
            }
            Self::reset(quic, *id, quiche::h3::WireErrorCode::RequestCancelled);
            false
        });
        before != self.responses.len()
    }

    /// True means the atomic HEADERS write is blocked and must be retained.
    fn try_send(
        h3: &mut quiche::h3::Connection,
        quic: &mut crate::connection::ServerQuic,
        stream_id: u64,
        status: u16,
    ) -> bool {
        let status_buf = [
            b'0' + (status / 100 % 10) as u8,
            b'0' + (status / 10 % 10) as u8,
            b'0' + (status % 10) as u8,
        ];
        let headers = [
            quiche::h3::Header::new(b":status", &status_buf),
            quiche::h3::Header::new(b"content-length", b"0"),
        ];
        match h3.send_response(quic, stream_id, &headers, true) {
            Ok(()) => {
                // No error path consumes a request body. Release unread input
                // after queuing the complete response without resetting output.
                let _ = quic.stream_shutdown(
                    stream_id,
                    quiche::Shutdown::Read,
                    quiche::h3::WireErrorCode::NoError as u64,
                );
                false
            }
            Err(quiche::h3::Error::StreamBlocked | quiche::h3::Error::Done) => true,
            Err(error) => {
                tracing::debug!(stream_id, %error, "error response stream unavailable");
                Self::reset(quic, stream_id, quiche::h3::WireErrorCode::RequestCancelled);
                false
            }
        }
    }

    fn reset(
        quic: &mut crate::connection::ServerQuic,
        stream_id: u64,
        code: quiche::h3::WireErrorCode,
    ) {
        let _ = quic.stream_shutdown(stream_id, quiche::Shutdown::Read, code as u64);
        let _ = quic.stream_shutdown(stream_id, quiche::Shutdown::Write, code as u64);
    }
}
