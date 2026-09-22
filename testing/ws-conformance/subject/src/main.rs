// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTOBAHN|TESTSUITE SUBJECT: `WsTransport::over(TcpTransport)`, echoing on loopback.
//!
//! `busbar-transport-ws` opens no socket by design (see that crate's `lib.rs`); it is a pure
//! adapter composed over a lower transport. Autobahn's `fuzzingclient` needs a real listening
//! WebSocket peer to drive its case suite against, so this binary composes the SAME
//! `WsTransport::over(TcpTransport)` chain the architecture names -- the identical composition
//! `crates/busbar-transport-tcp/src/tests/mod.rs` builds for its own battery -- binds it on
//! loopback, and echoes every inbound message back unmodified. That is the whole of an Autobahn
//! echo peer: the fuzzingclient sends every case's frames and grades the echo it gets back.
//!
//! Prints `WS_SUBJECT_PORT=<port>` on its own line to stdout once bound, then serves forever.
//! No plane, no protocol meaning -- this is a testkit binary, not a build of `busbar`.

use std::sync::Arc;

use busbar_contract::plugin::KernelSeal;
use busbar_contract::transport::wire::Listener;
use busbar_contract::{
    ConfigView, ScratchBytes, StreamId, Transport, TransportConfigView, TransportKeyHandle,
};
use busbar_transport_tcp::TcpTransport;
use busbar_transport_ws::WsTransport;
use futures::StreamExt;

struct SubjectCfg;

impl ConfigView for SubjectCfg {
    fn get_str(&self, _key: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, _key: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _key: &str) -> Option<bool> {
        None
    }
}

impl TransportConfigView for SubjectCfg {
    fn bind(&self) -> Option<&str> {
        Some("127.0.0.1:0")
    }
}

/// The subject arms itself; there is no kernel here to issue a real key handle. This mirrors the
/// fixture seal every in-tree transport battery uses (`busbar-transport-tcp/src/tests/mod.rs`).
struct SubjectSeal;
impl KernelSeal for SubjectSeal {
    fn seal_origin(&self) -> &'static str {
        "ws-conformance-subject: no key material -- this transport upgrade needs none"
    }
}

#[tokio::main]
async fn main() {
    let tcp: Arc<dyn Transport> = Arc::new(TcpTransport::new());
    let ws = Arc::new(WsTransport::over(tcp));
    let key = TransportKeyHandle::issue(&SubjectSeal, 0, "ws-conformance-subject");

    let listener: Listener = ws
        .listen(&SubjectCfg, &key)
        .await
        .expect("ws-conformance-subject: bind failed");
    let addr = listener.local_addr();
    let port = addr.rsplit(':').next().unwrap_or("0");
    println!("WS_SUBJECT_PORT={port}");
    use std::io::Write;
    std::io::stdout().flush().ok();

    loop {
        let conn = match ws.accept(&listener).await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("ws-conformance-subject: accept error: {e:?}");
                continue;
            }
        };
        let ws = ws.clone();
        tokio::spawn(async move {
            let mut frames = ws.frames(conn.clone());
            while let Some(item) = frames.next().await {
                match item {
                    Ok((_stream, frame)) => {
                        let bytes = ScratchBytes::new(frame.bytes.as_slice());
                        if ws.write(&conn, StreamId(0), bytes).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }
}
