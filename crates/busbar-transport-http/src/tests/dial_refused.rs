//! The dial is refused before any socket, and before any name is resolved (TODO #145).
//!
//! The rebinding shape: a destination names a host, and whatever resolves that name at dial time
//! chooses the address. `localhost` stands for every such name here. It resolves on any host, and
//! it resolves to the loopback the watched listener holds, so a transport that resolved the name
//! and connected would be SEEN connecting. The kernel's one destination judge never saw that
//! answer. This transport must not ask for it: the connector dials only an IP literal the judge
//! passed. An IP literal is refused here too, because this transport dials nothing at all.

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::transport::wire::TransportError;
use busbar_contract::{ScratchBytes, StreamId, Transport};

use super::{fixture_key, upstream_dest};
use crate::sse::SseTransport;
use crate::{ClientSettings, HttpTransport};

/// A loopback listener, and a task that answers whether anything connected to it within the window.
async fn watched_listener() -> (u16, tokio::task::JoinHandle<bool>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connected = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_millis(1500), listener.accept())
            .await
            .is_ok()
    });
    (port, connected)
}

/// Dial `authority` through `wire`, and if the dial is (wrongly) granted, hand it a request so a
/// client that connects lazily, at its first exchange, connects now.
async fn dial_and_ask(wire: &dyn Transport, authority: &str) -> Result<(), TransportError> {
    let conn = wire.dial(&upstream_dest(authority), &fixture_key()).await?;
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        wire.write(
            &conn,
            StreamId(0),
            ScratchBytes::new(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        ),
    )
    .await;
    Ok(())
}

#[tokio::test]
async fn a_hostname_is_refused_before_any_socket_through_http_and_what_composes_over_it() {
    let (port, connected) = watched_listener().await;
    let http = Arc::new(HttpTransport::new(ClientSettings::default()));
    let sse = SseTransport::over(http.clone());

    let named = [
        format!("http://localhost:{port}/"),
        format!("localhost:{port}"),
        format!("https://localhost:{port}/v1/messages"),
    ];
    let mut answers = Vec::new();
    for authority in &named {
        answers.push((authority.clone(), dial_and_ask(&*http, authority).await));
        answers.push((authority.clone(), dial_and_ask(&sse, authority).await));
    }
    // A literal is not dialled either: nothing here opens a socket.
    let literal = format!("http://127.0.0.1:{port}/");
    answers.push((literal.clone(), dial_and_ask(&*http, &literal).await));

    assert!(
        !connected.await.unwrap(),
        "a connection reached the listener: the transport resolved a name (or dialled a literal) \
         itself, out of sight of the kernel's destination judge"
    );
    for (authority, answer) in answers {
        assert_eq!(
            answer,
            Err(TransportError::AddressRefused),
            "{authority} is refused at the dial"
        );
    }
}
