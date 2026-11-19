// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! HTTP/2 on the data listener: an upload its caller resets gives its bytes back to the
//! connection. A caller that abandons uploads on a connection, more of them than the connection's
//! flow-control window holds, still gets its other streams on that connection answered.

#![cfg(unix)]
#![cfg(all(
    linked_section_pools,
    linked_section_tools,
    linked_section_agents,
    linked_section_decisions,
    linked_section_streams
))]

mod common;
mod e2e_support;

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use e2e_support::{bearer, chat_answer, llm, Scripted, CHAT};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The connection window the http transport grants an accepted HTTP/2 connection
/// (`busbar-transport-http` `H2_CONN_WINDOW`), and the stream window beside it.
const CONNECTION_WINDOW: usize = 4 << 20;
const STREAM_WINDOW: usize = 1 << 20;

/// What each abandoned upload sends before its reset: inside one stream's window and inside the
/// body cap, so the stream itself never waits and is never refused for its size.
const ABANDONED: usize = STREAM_WINDOW / 2;

/// Abandoned uploads in a row: three connection windows' worth of bytes never consumed.
const UPLOADS: usize = 3 * CONNECTION_WINDOW / ABANDONED;

/// How long the caller waits for the connection to take more bytes before calling it stalled.
const STALLED: Duration = Duration::from_secs(10);

/// The caller's socket, counting the bytes the connection took from it.
struct Counted {
    io: tokio::net::TcpStream,
    written: Arc<AtomicU64>,
}

impl AsyncRead for Counted {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Counted {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.io).poll_write(cx, buf);
        if let Poll::Ready(Ok(taken)) = &polled {
            this.written.fetch_add(*taken as u64, Ordering::SeqCst);
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

fn chat_request(port: u16, token: &str) -> http::Request<()> {
    http::Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:{port}/v1/chat/completions"))
        .header("authorization", bearer(token))
        .header("content-type", "application/json")
        .body(())
        .expect("a chat request head")
}

/// Send `body` on `stream` as the windows allow. `Err` when no window reopens in time.
async fn upload(stream: &mut h2::SendStream<Bytes>, body: &[u8]) -> Result<(), String> {
    let mut left = body.len();
    while left > 0 {
        stream.reserve_capacity(left.min(16 * 1024));
        let granted =
            tokio::time::timeout(STALLED, std::future::poll_fn(|cx| stream.poll_capacity(cx)))
                .await
                .map_err(|_| format!("no window for {left} more bytes within {STALLED:?}"))?
                .ok_or("the stream ended while it was uploading")?
                .map_err(|error| format!("the stream failed while it was uploading: {error}"))?;
        let now = granted.min(left);
        if now == 0 {
            continue;
        }
        stream
            .send_data(
                Bytes::copy_from_slice(&body[body.len() - left..][..now]),
                false,
            )
            .map_err(|error| format!("the stream refused its data: {error}"))?;
        left -= now;
    }
    Ok(())
}

/// Wait until the connection has taken `more` bytes beyond `from`.
async fn taken(written: &AtomicU64, from: u64, more: usize) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + STALLED;
    while written.load(Ordering::SeqCst) < from + more as u64 {
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "the connection took {} of {more} bytes within {STALLED:?}",
                written.load(Ordering::SeqCst) - from
            ));
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    Ok(())
}

/// The status of an answer, read to its end.
async fn answered(response: h2::client::ResponseFuture) -> Result<u16, String> {
    let response = tokio::time::timeout(STALLED, response)
        .await
        .map_err(|_| format!("no answer within {STALLED:?}"))?
        .map_err(|error| format!("the stream failed: {error}"))?;
    let status = response.status().as_u16();
    let mut body = response.into_body();
    while let Some(data) = tokio::time::timeout(STALLED, body.data())
        .await
        .map_err(|_| format!("the answer's body stopped within {STALLED:?}"))?
    {
        let data = data.map_err(|error| format!("the answer's body failed: {error}"))?;
        body.flow_control()
            .release_capacity(data.len())
            .map_err(|error| format!("release the answer's window: {error}"))?;
    }
    Ok(status)
}

#[test]
fn a_reset_upload_does_not_stall_the_other_streams_of_its_connection() {
    let upstream = Scripted::start(200, &chat_answer(1, 1));
    let node = llm("h2-credit", &upstream, None).boot();
    let key = node.mint(&json!({ "name": "e2e-h2" }));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");

    let outcome: Result<(u16, u16), String> = runtime.block_on(async {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", node.data))
            .await
            .map_err(|error| format!("connect: {error}"))?;
        let written = Arc::new(AtomicU64::new(0));
        let (client, connection) = h2::client::handshake(Counted {
            io: tcp,
            written: Arc::clone(&written),
        })
        .await
        .map_err(|error| format!("the HTTP/2 handshake: {error}"))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });

        // A sibling opened first: its head is in, its body is still to come.
        let mut client = client.ready().await.map_err(|error| error.to_string())?;
        let (sibling_answer, mut sibling) = client
            .send_request(chat_request(node.data, &key.token), false)
            .map_err(|error| format!("open the sibling: {error}"))?;

        let filler = vec![b' '; ABANDONED];
        for upload_number in 1..=UPLOADS {
            client = client.ready().await.map_err(|error| error.to_string())?;
            let (_unread, mut abandoned) = client
                .send_request(chat_request(node.data, &key.token), false)
                .map_err(|error| format!("open upload {upload_number}: {error}"))?;
            let before = written.load(Ordering::SeqCst);
            upload(&mut abandoned, &filler)
                .await
                .map_err(|why| format!("upload {upload_number} of {UPLOADS} stalled: {why}"))?;
            // Reset only once its bytes are on the connection, so each one spends real window.
            taken(&written, before, ABANDONED)
                .await
                .map_err(|why| format!("upload {upload_number} of {UPLOADS} stalled: {why}"))?;
            abandoned.send_reset(h2::Reason::CANCEL);
        }

        // The sibling finishes its upload on the same connection and is answered.
        upload(&mut sibling, CHAT)
            .await
            .map_err(|why| format!("the sibling stalled behind the resets: {why}"))?;
        sibling
            .send_data(Bytes::new(), true)
            .map_err(|error| format!("end the sibling: {error}"))?;
        let sibling_status = answered(sibling_answer)
            .await
            .map_err(|why| format!("the sibling was not answered: {why}"))?;

        // And a stream opened after the resets is served on it too.
        client = client.ready().await.map_err(|error| error.to_string())?;
        let (later_answer, mut later) = client
            .send_request(chat_request(node.data, &key.token), false)
            .map_err(|error| format!("open the later stream: {error}"))?;
        later
            .send_data(Bytes::from_static(CHAT), true)
            .map_err(|error| format!("send the later stream: {error}"))?;
        let later_status = answered(later_answer)
            .await
            .map_err(|why| format!("the later stream was not answered: {why}"))?;
        Ok((sibling_status, later_status))
    });

    assert_eq!(
        outcome,
        Ok((200, 200)),
        "{UPLOADS} uploads of {ABANDONED} bytes were reset on one connection; its other streams \
         are answered as if none had been"
    );
}
