//! Bounded, loopback-only P1 compatibility observations; not a MASQUE server.
mod client;
mod identity;
mod server;

use anyhow::{Result, bail, ensure};
use bytes::Bytes;
use futures_util::SinkExt;
use quiche::h3::Header;
use serde::Serialize;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::time::Instant;
use tokio_quiche::http3::driver::{InboundFrame, OutboundFrame, StreamShutdown};

use client::DEADLINE;
use server::Pair;

#[derive(Serialize)]
struct Observation {
    case: String,
    candidate: &'static str,
    profile: &'static str,
    gate: &'static str,
    compatible: bool,
    evidence: Value,
}

async fn observe(case: &str) -> Result<Observation> {
    let (gate, compatible, evidence) = match case {
        "stream_control" | "empty_error" | "raw_cid16" | "tls_hook" => {
            let mut p = match case {
                "raw_cid16" => Pair::new_raw().await?,
                "tls_hook" => Pair::new_with_tls_hook(20, true).await?,
                _ => Pair::new(20).await?,
            };
            if case == "tls_hook" {
                ensure!(
                    p.tls_hook_calls.load(std::sync::atomic::Ordering::SeqCst) == 1,
                    "TLS hook was not used exactly once"
                );
            }
            if case == "raw_cid16" {
                ensure!(p.client.quic.destination_id().len() == 16, "raw CID length");
            }
            let mut request = p.headers(None, false).await?;
            let status = if case == "empty_error" {
                b"404"
            } else {
                b"200"
            };
            request
                .send
                .send(OutboundFrame::Headers(
                    vec![Header::new(b":status", status)],
                    None,
                ))
                .await?;
            let expected = if case == "empty_error" {
                b"".as_slice()
            } else {
                b"response after request FIN".as_slice()
            };
            p.client.body(request.stream_id, b"upload", true)?;
            let (n, fin) = p.receive_body(&mut request).await?;
            ensure!(n == 6, "control upload mismatch");
            if !fin {
                ensure!(
                    p.receive_body(&mut request).await? == (0, true),
                    "missing upload FIN"
                );
            }
            request
                .send
                .send(OutboundFrame::Body(Bytes::copy_from_slice(expected), true))
                .await?;
            let finished = p.client.wait_response(request.stream_id).await?;
            let response = p
                .client
                .responses
                .get(&request.stream_id)
                .ok_or_else(|| anyhow::anyhow!("missing control response"))?;
            let matched = response.status.as_deref() == Some(status.as_slice())
                && response.body == expected
                && finished;
            (
                match case {
                    "raw_cid16" => "G4",
                    "tls_hook" => "G7",
                    _ => "G5",
                },
                matched,
                json!({"response_bytes":response.body.len(),"response_fin":finished,"status_matches":response.status.as_deref()==Some(status.as_slice())}),
            )
        }
        "cid16" => match Pair::new(16).await {
            Ok(mut p) => {
                let headers = p.headers(None, false).await;
                (
                    "G4",
                    headers.is_ok(),
                    json!({"handshake_and_settings":true,"request_delivered":headers.is_ok()}),
                )
            }
            Err(error) => {
                ensure!(
                    matches!(
                        error.to_string().as_str(),
                        "handshake/settings deadline" | "handshake closed"
                    ),
                    "unexpected CID probe setup error"
                );
                (
                    "G4",
                    false,
                    json!({"handshake_and_settings":false,"deadline_ms":DEADLINE.as_millis()}),
                )
            }
        },
        "raw_worker_shutdown" => {
            let mut p = Pair::new_raw().await?;
            p.client.quic.close(false, 0, b"test complete")?;
            let end = Instant::now() + DEADLINE;
            while !p.worker_stopped.load(std::sync::atomic::Ordering::SeqCst)
                && Instant::now() < end
            {
                p.client.pump().await?;
            }
            let stopped = p.worker_stopped.load(std::sync::atomic::Ordering::SeqCst);
            (
                "G8",
                stopped,
                json!({"raw_worker_completion_observed":stopped}),
            )
        }
        "retry_privacy" => {
            let p = Pair::new_with_retry().await?;
            let token = p
                .client
                .retry_token
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Retry not observed"))?;
            let visible = token.get(32..36) == Some([127, 0, 0, 1].as_slice());
            (
                "G3",
                !visible,
                json!({"retry_seen":true,"token_bytes":token.len(),"source_address_visible_in_token":visible}),
            )
        }
        "native_datagram_control" => {
            let mut p = Pair::new(20).await?;
            let mut request = p.headers(Some(b"connect-udp"), false).await?;
            p.datagram(&[0, 0, 0x5a]).await?;
            let flow = request
                .dgram_flow
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("missing flow"))?;
            let InboundFrame::Datagram(bytes) = flow.recv.try_recv()? else {
                bail!("missing native datagram")
            };
            ensure!(
                bytes.as_ref() == [0, 0x5a],
                "input QSID or Context ID boundary"
            );
            flow.send
                .send(OutboundFrame::Datagram(bytes, flow.flow_id))
                .await?;
            let end = Instant::now() + DEADLINE;
            while p.client.quic.dgram_recv_queue_len() == 0 && Instant::now() < end {
                p.client.pump().await?;
            }
            let payload = p.client.quic.dgram_recv_buf()?;
            (
                "G6",
                payload == [0, 0, 0x5a],
                json!({"roundtrip_bytes":payload.len(),"framing_matches":payload==[0,0,0x5a]}),
            )
        }
        "shutdown_read" => {
            let mut p = Pair::new(20).await?;
            let mut request = p.headers(None, false).await?;
            p.controller.shutdown_stream(
                request.stream_id,
                StreamShutdown::Read { error_code: 0x100 },
            );
            p.barrier().await?;
            let can_send = request
                .send
                .send(OutboundFrame::Headers(
                    vec![Header::new(b":status", b"200")],
                    None,
                ))
                .await
                .is_ok();
            let mut delivered = false;
            if can_send {
                request
                    .send
                    .send(OutboundFrame::Body(
                        Bytes::from_static(b"still writable"),
                        true,
                    ))
                    .await?;
                delivered = p.client.wait_response(request.stream_id).await?;
            }
            (
                "G5",
                can_send && delivered,
                json!({"write_channel_alive_after_read_shutdown":can_send,"response_fin":delivered}),
            )
        }
        "shutdown_write" => {
            let mut p = Pair::new(20).await?;
            let mut request = p.headers(None, false).await?;
            p.controller.shutdown_stream(
                request.stream_id,
                StreamShutdown::Write { error_code: 0x100 },
            );
            p.barrier().await?;
            p.client.body(request.stream_id, b"upload survives", true)?;
            let received = p.receive_body(&mut request).await;
            let matched = received.as_ref().is_ok_and(|(n, _)| *n == 15);
            (
                "G5",
                matched,
                json!({"read_channel_delivers_after_write_shutdown":matched}),
            )
        }
        "unknown_flow" => {
            let mut p = Pair::new(20).await?;
            p.datagram(&[0, 0, 0x5a]).await?;
            let mut request = p.headers(Some(b"connect-udp"), false).await?;
            let flow = request
                .dgram_flow
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("missing flow"))?;
            let replayed = matches!(flow.recv.try_recv(), Ok(InboundFrame::Datagram(_)));
            (
                "G6",
                !replayed,
                json!({"pre_connect_datagram_replayed":replayed}),
            )
        }
        "late_datagram" => {
            let mut p = Pair::new(20).await?;
            let mut request = p.headers(Some(b"connect-udp"), false).await?;
            p.client.body(request.stream_id, b"", true)?;
            ensure!(
                p.receive_body(&mut request).await? == (0, true),
                "missing FIN barrier"
            );
            p.datagram(&[0, 0, 0x5a]).await?;
            let flow = request
                .dgram_flow
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("missing flow"))?;
            let late = matches!(flow.recv.try_recv(), Ok(InboundFrame::Datagram(_)));
            request
                .send
                .send(OutboundFrame::Headers(
                    vec![Header::new(b":status", b"200")],
                    None,
                ))
                .await?;
            request
                .send
                .send(OutboundFrame::Body(
                    Bytes::from_static(b"queued response"),
                    true,
                ))
                .await?;
            let response_fin = p.client.wait_response(request.stream_id).await?;
            let response_preserved = p
                .client
                .responses
                .get(&request.stream_id)
                .is_some_and(|response| response.body == b"queued response");
            (
                "G6",
                !late && response_fin && response_preserved,
                json!({"native_datagram_delivered_after_request_fin":late,"response_fin":response_fin,"response_preserved":response_preserved}),
            )
        }
        "blocked_body_fin" => {
            let mut p = Pair::new(20).await?;
            let mut request = p.headers(Some(b"connect-udp"), false).await?;
            let capacity = request.recv.max_capacity();
            // Complete, ignorable capsules, one body frame per round trip.
            // Pause the application, as during slow authentication/setup.
            for queued in 1..=capacity {
                p.client.body(request.stream_id, &[0x21, 0], false)?;
                let end = Instant::now() + DEADLINE;
                while request.recv.len() < queued {
                    ensure!(Instant::now() < end, "body channel did not fill");
                    p.client.pump().await?;
                }
            }
            p.client.body(request.stream_id, &[0x21, 0], true)?;
            let end = Instant::now() + DEADLINE;
            while !p.stream_readable(request.stream_id).await? {
                ensure!(Instant::now() < end, "terminal body did not reach server");
            }
            p.datagram(&[0, 0, 0x5a]).await?;
            let flow = request
                .dgram_flow
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("missing flow"))?;
            let late = matches!(flow.recv.try_recv(), Ok(InboundFrame::Datagram(_)));
            (
                "G6",
                !late,
                json!({"body_channel_capacity":capacity,"body_consumer_paused":true,"terminal_body_buffered_at_server":true,"native_datagram_delivered":late}),
            )
        }
        "qsid_empty" | "qsid_truncated" | "qsid_out_of_range" => {
            let mut p = Pair::new(20).await?;
            let bytes = match case {
                "qsid_empty" => vec![],
                "qsid_truncated" => vec![0x40],
                _ => vec![0xd0, 0, 0, 0, 0, 0, 0, 0], // 2^60 encoded as a QUIC varint.
            };
            p.datagram(&bytes).await?;
            let end = Instant::now() + DEADLINE;
            while p.client.quic.peer_error().is_none()
                && !p.client.quic.is_closed()
                && Instant::now() < end
            {
                p.client.pump().await?;
            }
            let error = p.client.quic.peer_error().map(|e| (e.is_app, e.error_code));
            (
                "G6",
                error == Some((true, 0x33)),
                json!({"application_close":error.map(|e|e.0),"close_code":error.map(|e|e.1),"required_code":0x33}),
            )
        }
        "event_backlog" => {
            let mut p = Pair::new(20).await?;
            let mut request = p.headers(None, false).await?;
            let mut samples = Vec::new();
            for i in 0..512 {
                p.client.body(request.stream_id, &[0x5a; 64], false)?;
                let (n, fin) = p.receive_body(&mut request).await?;
                ensure!(n == 64 && !fin, "event probe body mismatch");
                if i == 255 || i == 511 {
                    samples.push(p.controller.event_receiver_mut().len());
                }
            }
            ensure!(
                samples[1] >= samples[0],
                "event count regressed without consumer"
            );
            let accounted = request.h3_audit_stats.downstream_bytes_recvd();
            while p.controller.event_receiver_mut().try_recv().is_ok() {}
            p.client.body(request.stream_id, b"", true)?;
            let end = Instant::now() + DEADLINE;
            let mut fin_event = false;
            while !fin_event && Instant::now() < end {
                p.client.pump().await?;
                while let Ok(event) = p.controller.event_receiver_mut().try_recv() {
                    if let tokio_quiche::http3::driver::ServerH3Event::Core(
                        tokio_quiche::http3::driver::H3Event::BodyBytesReceived {
                            stream_id,
                            fin: true,
                            ..
                        },
                    ) = event
                    {
                        fin_event |= stream_id == request.stream_id;
                    }
                }
            }
            // This covers only body-progress events; other event and command
            // queues still require a separate bounded design.
            let no_progress_backlog = samples == [0, 0] && accounted == 512 * 64 && fin_event;
            (
                "G1",
                no_progress_backlog,
                json!({"body_chunks":512,"payload_bytes":512*64,"queued_events_after_256_and_512_chunks":samples,"audit_body_bytes":accounted,"fin_event_delivered":fin_event,"other_event_and_command_queues_bounded":false}),
            )
        }
        _ => bail!("unknown observation case"),
    };
    Ok(Observation {
        case: case.to_owned(),
        candidate: if cfg!(feature = "upstream-patch") {
            "prototype_patch"
        } else {
            "stock"
        },
        profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        gate,
        compatible,
        evidence,
    })
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 1 {
        eprintln!("usage: tokio-quiche-gate CASE");
        std::process::exit(2);
    }
    match tokio::time::timeout(Duration::from_secs(15), observe(&args[0])).await {
        Ok(Ok(observation)) => {
            println!("{}", serde_json::to_string(&observation).unwrap());
            if !observation.compatible {
                std::process::exit(1)
            }
        }
        Ok(Err(error)) => {
            // The runner captures stderr in a private temporary directory.
            eprintln!("observation failed: {error:#}");
            std::process::exit(2);
        }
        Err(_) => {
            // No endpoint, certificate path or raw diagnostics escape this runner.
            eprintln!("observation failed before producing a compatibility result");
            std::process::exit(2);
        }
    }
}
