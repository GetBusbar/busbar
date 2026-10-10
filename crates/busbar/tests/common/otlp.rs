// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A LOOPBACK OTLP COLLECTOR for the tests that drive the shipped binary's `traces` sinks: every
//! request's head and body kept, each answered `200`, and the spans read back by the OpenTelemetry
//! project's own generated types — each request required to re-encode to the very bytes received.

#![allow(dead_code)]

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::trace::v1::Span;
use prost::Message as _;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

/// Every request the collector received: its head (lowercased) and its body.
pub type Received = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// A loopback collector on a free port: every request kept, answered 200.
///
/// It is an HTTP/1.1 server as a real OTLP collector is one: a connection is PERSISTENT, so every
/// request on it is read and answered until the client closes it (or asks to, `connection: close`).
/// The host's connector keeps an HTTP/1.1 line whose exchange finished whole and lends it to the
/// next export to the same place (its per-worker pool, 1.5.5's pooled egress client), and an export
/// whose bytes left on a line is never sent again (ARCHITECT ruling Q-L18-RETRY). A collector that
/// answered one request and then closed the connection unannounced lost every export the pool lent
/// that line to before its close arrived: the request was written, the socket was dropped with it
/// unread, and the batch's spans were gone — how often depended only on how late this thread ran.
pub fn collector() -> (u16, Received) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the collector");
    let port = listener.local_addr().expect("an address").port();
    let seen: Received = Arc::default();
    let keep = seen.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let keep = keep.clone();
            std::thread::spawn(move || serve(conn, &keep));
        }
    });
    (port, seen)
}

/// Every request on one persistent connection, kept and answered `200`, until the client closes it
/// or asks to.
fn serve(mut conn: std::net::TcpStream, keep: &Received) {
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        // One whole request at the front of `raw`: its head, then the body its length states.
        let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
            match conn.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => raw.extend_from_slice(&buf[..n]),
            }
            continue;
        };
        let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
        let length: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        if raw.len() < end + 4 + length {
            match conn.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => raw.extend_from_slice(&buf[..n]),
            }
            continue;
        }
        let body = raw[end + 4..end + 4 + length].to_vec();
        raw.drain(..end + 4 + length);
        let closing = head
            .lines()
            .any(|l| l.replace(' ', "") == "connection:close");
        keep.lock().unwrap().push((head, body));
        let answered = conn.write_all(if closing {
            b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".as_slice()
        } else {
            b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n".as_slice()
        });
        if closing || answered.is_err() {
            return;
        }
    }
}

/// The requests the collector received at `path` (every path when `None`), each decoded and
/// required to be the canonical encoding of what arrived.
pub fn requests(seen: &Received, path: Option<&str>) -> Vec<ExportTraceServiceRequest> {
    let received = seen.lock().unwrap().clone();
    received
        .iter()
        .filter(|(head, _)| {
            path.is_none_or(|p| head.starts_with(&format!("post {p} http/1.1\r\n")))
        })
        .map(|(_, body)| {
            let request = ExportTraceServiceRequest::decode(&body[..]).expect("an OTLP request");
            assert_eq!(
                request.encode_to_vec(),
                *body,
                "the canonical OTLP encoding"
            );
            request
        })
        .collect()
}

/// Every span of `requests`, in order.
pub fn spans(requests: &[ExportTraceServiceRequest]) -> Vec<Span> {
    requests
        .iter()
        .flat_map(|r| &r.resource_spans)
        .flat_map(|rs| &rs.scope_spans)
        .flat_map(|ss| ss.spans.iter().cloned())
        .collect()
}
