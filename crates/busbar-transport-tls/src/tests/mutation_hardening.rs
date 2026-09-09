//! Mutation-hardening battery for `tls`: closes gaps a mutation run found where the existing
//! battery happened to pass regardless of what a mutated body returned. Every cell here pins one
//! fact the parent battery left unpinned: `READ_CHUNK_BYTES`'s actual value, that a connection
//! handle's `id()`/`peer()` report the real registered values rather than a placeholder, that
//! `Debug` on the transport actually names it, that `key()` and `composed_over()` report the
//! transport's real identity, and that `detach` on an idle connection — server side and client
//! side — actually hands the stream up rather than silently refusing every caller.

use super::*;

/// `READ_CHUNK_BYTES` is `16 * 1024`. A mutant that turns the `*` into a `+` changes this to
/// `1040`, and nothing else in this crate's battery reads the constant itself.
#[test]
fn read_chunk_bytes_is_16_kib() {
    assert_eq!(READ_CHUNK_BYTES, 16 * 1024);
}

/// Two connections registered on the same transport must carry their own, distinct ids. A mutant
/// that hard-codes `TlsConnHandle::id` to `1` survives against a single connection, because the
/// first id this transport ever hands out really is `1`.
#[tokio::test]
async fn a_second_connections_id_is_not_the_first_connections_id() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();

    let accept_fut = tokio::spawn({
        let server = server.clone();
        let listener = listener.clone();
        async move { server.accept(&listener).await.unwrap() }
    });
    let _first_client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key(0))
        .await
        .unwrap();
    let first_server_conn = accept_fut.await.unwrap();

    let accept_fut = tokio::spawn({
        let server = server.clone();
        let listener = listener.clone();
        async move { server.accept(&listener).await.unwrap() }
    });
    let _second_client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key(0))
        .await
        .unwrap();
    let second_server_conn = accept_fut.await.unwrap();

    assert_ne!(first_server_conn.id(), second_server_conn.id());
    assert_ne!(second_server_conn.id(), 1);
}

/// `TlsConnHandle::peer` must report the address this connection actually dialled, not a
/// placeholder: a mutant that replaces the clone with `"xyzzy".into()` otherwise survives, because
/// nothing else reads the client-side handle's `peer()`.
#[tokio::test]
async fn a_dialled_connections_peer_is_the_address_it_dialled() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn(async move { server.accept(&listener).await.unwrap() });

    let conn = client
        .dial(&upstream_dest(&addr), &fixture_key(0))
        .await
        .unwrap();
    let _server_conn = accept_fut.await.unwrap();

    assert_eq!(conn.peer(), addr);
}

/// `Debug` on the transport must actually name it. A mutant that replaces the body with
/// `Ok(Default::default())` writes nothing at all and still returns `Ok`.
#[test]
fn transport_debug_names_itself() {
    let transport = TlsTransport::new();
    let formatted = format!("{transport:?}");
    assert!(
        formatted.contains("TlsTransport"),
        "expected the Debug output to name the transport, got {formatted:?}"
    );
}

/// `Plugin::key` must report this transport's real key. A mutant that replaces it with `"xyzzy"`
/// (or `""`) survives everywhere the value is only ever compared to itself.
#[test]
fn plugin_key_is_tls() {
    let transport = TlsTransport::new();
    assert_eq!(Plugin::key(&transport), "tls");
    assert_eq!(Plugin::key(&transport), TlsTransport::KEY);
}

/// `tls` opens its own socket at `listen`/`dial` (the STARTTLS handoff `adopt` answers is a
/// per-connection upgrade, not a property of this instance): `composed_over` must report `None`.
#[test]
fn tls_is_not_composed_over_anything() {
    let transport = TlsTransport::new();
    assert_eq!(Transport::composed_over(&transport), None);
}

/// A `detach` on a server-side connection with no live frame reader must actually hand the stream
/// up. This is also what the strong-count check (`!=` mutated to `==`) and the `(Server, Server)`
/// match arm (deleted by a mutant that leaves only the wildcard `None`) both have to pass through.
#[tokio::test]
async fn detach_on_an_idle_server_side_connection_hands_the_stream_up() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });
    let _client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key(0))
        .await
        .unwrap();
    let server_conn = accept_fut.await.unwrap();

    let expected_peer = server_conn.peer();
    let raw = Transport::detach(&*server, &server_conn).expect("an idle connection detaches");
    assert_eq!(raw.from(), "tls");
    assert_eq!(raw.peer(), expected_peer);
}

/// The client-side twin of the cell above: a mutant that deletes the `(Client, Client)` match arm
/// in `detach` leaves only the wildcard `None`, which the server-side cell above cannot catch
/// because it only ever exercises the `Server` variant.
#[tokio::test]
async fn detach_on_an_idle_client_side_connection_hands_the_stream_up() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn(async move { server.accept(&listener).await.unwrap() });

    let client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key(0))
        .await
        .unwrap();
    let _server_conn = accept_fut.await.unwrap();

    let expected_peer = client_conn.peer();
    let raw = Transport::detach(&*client, &client_conn).expect("an idle connection detaches");
    assert_eq!(raw.from(), "tls");
    assert_eq!(raw.peer(), expected_peer);
}

/// A mutant that turns `close` into a no-op does not fail the existing
/// `half_close_and_cancel_mid_frame` battery cell cleanly: that cell's second
/// `frames.next().await`, on the peer of the connection that was supposedly closed, has no bound
/// of its own, so a `close` that never sends the peer anything and never drops the socket leaves
/// that read parked forever — the mutant run reported a timeout rather than a caught mutant.
/// Bounding the same read here turns that hang into a fast, explicit failure.
#[tokio::test]
async fn a_broken_close_does_not_hang_the_peers_read() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });
    let client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key(0))
        .await
        .unwrap();
    let server_conn = accept_fut.await.unwrap();

    client
        .write(&client_conn, StreamId(0), ArenaBytes::new(b"bye"))
        .await
        .unwrap();
    client.close(client_conn, CloseReason::Normal);

    let mut frames = server.frames(server_conn);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"bye");

    // A real close (`close_notify` sent, socket dropped) ends this read quickly with `None` or an
    // error. A `close` that does nothing leaves the client's write half open and this read parked
    // on a peer that will never write again: bounded here so that failure mode is a fast panic
    // rather than a hang.
    let next = tokio::time::timeout(std::time::Duration::from_secs(3), frames.next())
        .await
        .expect(
            "a closed connection's peer must see the close promptly, not hang waiting for a byte \
             the closed side will never send",
        );
    match next {
        None => {}
        Some(Err(_)) => {}
        Some(Ok(_)) => panic!("no further data should arrive after the client closed"),
    }
}
