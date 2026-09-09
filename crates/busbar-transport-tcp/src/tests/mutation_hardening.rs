//! Mutation-hardening battery for `tcp`: closes gaps a mutation run found where the existing
//! battery happened to pass regardless of what a mutated body returned. Every cell here pins one
//! fact the parent battery left unpinned: `READ_CHUNK_BYTES`'s actual value, that a connection
//! handle's `id()`/`peer()` report the real registered values rather than a placeholder, that
//! `Debug` on the transport actually names it, that `key()` and `composed_over()` report the
//! transport's real identity, and that a `detach` on an idle connection actually hands the stream
//! up rather than silently refusing every caller.

use super::*;

/// `READ_CHUNK_BYTES` is `16 * 1024`. A mutant that turns the `*` into a `+` changes this to
/// `1040` — every other cell here only checks that frames are no bigger than the constant,
/// which stays true no matter what the constant is. Pin the value itself.
#[test]
fn read_chunk_bytes_is_16_kib() {
    assert_eq!(READ_CHUNK_BYTES, 16 * 1024);
}

/// Two connections registered on the same transport must carry their own, distinct ids. A mutant
/// that hard-codes `TcpConnHandle::id` to `1` survives against a single connection, because the
/// first id this transport ever hands out really is `1`.
#[tokio::test]
async fn a_second_connections_id_is_not_the_first_connections_id() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();

    let _first_client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key())
        .await
        .unwrap();
    let first_server_conn = server.accept(&listener).await.unwrap();

    let _second_client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key())
        .await
        .unwrap();
    let second_server_conn = server.accept(&listener).await.unwrap();

    assert_ne!(first_server_conn.id(), second_server_conn.id());
    assert_ne!(second_server_conn.id(), 1);
}

/// `TcpConnHandle::peer` must report the address this connection actually dialled, not a
/// placeholder: a mutant that replaces the clone with `String::new()` or `"xyzzy".into()`
/// otherwise survives, because nothing else reads the client-side handle's `peer()`.
#[tokio::test]
async fn a_dialled_connections_peer_is_the_address_it_dialled() {
    let (_server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();

    let conn = client
        .dial(&upstream_dest(&addr), &fixture_key())
        .await
        .unwrap();

    assert_eq!(conn.peer(), addr);
}

/// `Debug` on the transport must actually name it. A mutant that replaces the body with
/// `Ok(Default::default())` writes nothing at all and still returns `Ok`, so a caller that never
/// inspects the formatted string cannot tell the difference.
#[test]
fn transport_debug_names_itself() {
    let transport = TcpTransport::new();
    let formatted = format!("{transport:?}");
    assert!(
        formatted.contains("TcpTransport"),
        "expected the Debug output to name the transport, got {formatted:?}"
    );
}

/// `Plugin::key` must report this transport's real key. A mutant that replaces it with `""` or
/// `"xyzzy"` survives everywhere the value is only ever compared to itself.
#[test]
fn plugin_key_is_tcp() {
    let transport = TcpTransport::new();
    assert_eq!(Plugin::key(&transport), "tcp");
    assert_eq!(Plugin::key(&transport), TcpTransport::KEY);
}

/// `tcp` is the bottom of every composition chain in this design: `composed_over` must report
/// `None`. A mutant that replaces it with `Some("xyzzy")` or `Some("")` survives unless something
/// actually reads the value.
#[test]
fn tcp_is_not_composed_over_anything() {
    let transport = TcpTransport::new();
    assert_eq!(Transport::composed_over(&transport), None);
}

/// A `detach` on a connection with no live frame reader must actually hand the stream up, naming
/// the layer it came from and the peer it was talking to. A mutant that replaces `take_stream`'s
/// body — or `detach`'s own body — with `None` survives against every OTHER cell in this crate's
/// battery, because they only ever exercise the refusal path (a live reader racing the detach).
#[tokio::test]
async fn detach_on_an_idle_connection_hands_the_stream_up() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();

    let _client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key())
        .await
        .unwrap();
    let server_conn = server.accept(&listener).await.unwrap();

    let expected_peer = server_conn.peer();
    let raw = Transport::detach(&*server, &server_conn).expect("an idle connection detaches");
    assert_eq!(raw.from(), "tcp");
    assert_eq!(raw.peer(), expected_peer);
}
