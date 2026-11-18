// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TLS PLAINTEXT PATH ON AN ACCEPTED, UNFRAMED LINE (TRANSPORT-TLS T6), driven sans-IO: the
//! carrier is an in-memory pipe and the far end is a rustls client the test steps by hand, so every
//! record boundary is deterministic.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::Outcome;

use super::*;
use crate::carrier::{Carry, Side};
use crate::framer::{Call, Crossed, DoorFacts};
use crate::secure_vec::scratch_misses;
use crate::support::{allocations_during, TestDoor};

/// The bytes in flight between the accepted connection and the test's client.
#[derive(Default)]
struct Wire {
    to_server: VecDeque<u8>,
    to_client: Vec<u8>,
    /// The client's end of file (a FIN): reads answer 0 once `to_server` is drained.
    eof: bool,
}

/// An in-memory carrier: reads take `to_server`, writes append to `to_client`.
struct Pipe {
    inner: TestDoor,
    wire: Mutex<Wire>,
}

impl FramerDoor for Pipe {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        self.inner.cross(call)
    }
    fn side(&self) -> Option<Box<dyn Side>> {
        self.inner.side()
    }
    fn carry(&self, _: &dyn Side, _: bool, call: Carry<'_>) -> Crossed {
        let mut w = self.wire.lock().unwrap();
        let mut outcome = Outcome::Ready;
        match call {
            Carry::Read(i, o) => {
                let n = i.cap.min(w.to_server.len());
                if n == 0 {
                    if !w.eof {
                        outcome = Outcome::Pending;
                    }
                    o.len = 0;
                } else {
                    #[expect(unsafe_code, reason = "the connector lends cap writable bytes")]
                    // SAFETY: the connector lends exactly `cap` initialized, writable bytes.
                    let dst = unsafe { std::slice::from_raw_parts_mut(i.buf, n) };
                    for (d, b) in dst.iter_mut().zip(w.to_server.drain(..n)) {
                        *d = b;
                    }
                    o.len = n as u64;
                }
            }
            Carry::Write(i, o) => {
                let bytes = crate::support::lent(i.bytes, i.len);
                w.to_client.extend_from_slice(&bytes);
                o.len = i.len as u64;
            }
            _ => {}
        }
        Crossed {
            outcome,
            error: None,
        }
    }
}

fn pipe() -> Arc<Pipe> {
    Arc::new(Pipe {
        inner: TestDoor::identity("tls-pipe"),
        wire: Mutex::new(Wire::default()),
    })
}

fn accepted_over(pipe: &Arc<Pipe>, tls: Option<Arc<rustls::ServerConfig>>) -> Connection {
    let carried = crate::carrier::Carried::accepted(
        Arc::clone(pipe) as Arc<dyn FramerDoor>,
        Arc::new(crate::hostio::HostIo::new()),
        1,
        None,
    )
    .expect("the pipe is a drivable carrier");
    Connection::accepted(
        None,
        carried,
        &Accept {
            tls,
            alpn: Vec::new(),
            handshake_timeout: Duration::from_secs(5),
        },
        None,
    )
    .expect("the line is accepted")
}

/// An accepted TLS line over a pipe, and the rustls client on its far end.
fn accepted_tls() -> (Connection, Arc<Pipe>, rustls::ClientConnection) {
    let ca = crate::test_support::private_ca();
    let anchor = crate::test_support::certs_from_pem(&ca.ca_pem).remove(0);
    let server = std::sync::Arc::unwrap_or_clone(
        busbar_contract::crypto::tls::server_config(|b| {
            b.with_no_client_auth().with_single_cert(
                vec![ca.leaf_der.into()],
                rustls_pki_types::PrivateKeyDer::try_from(ca.key_der).unwrap(),
            )
        })
        .unwrap(),
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(anchor.into()).unwrap();
    let client = std::sync::Arc::unwrap_or_clone(
        busbar_contract::crypto::tls::client_config(|b| {
            Ok(b.with_root_certificates(roots).with_no_client_auth())
        })
        .unwrap(),
    );
    let client = rustls::ClientConnection::new(
        Arc::new(client),
        rustls_pki_types::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let pipe = pipe();
    let conn = accepted_over(&pipe, Some(Arc::new(server)));
    (conn, pipe, client)
}

/// Step both ends until neither has anything more to say. `Ok(true)` = the line ended.
fn pump(
    conn: &mut Connection,
    pipe: &Pipe,
    client: &mut rustls::ClientConnection,
    got: &mut Vec<Got>,
) -> Result<bool, Failure> {
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut quiet = 0;
    for _ in 0..64 {
        loop {
            match conn.poll_piece(&mut cx) {
                Poll::Ready(Ok(Some(p))) => got.push(p),
                Poll::Ready(Ok(None)) => return Ok(true),
                Poll::Ready(Err(f)) => return Err(f),
                Poll::Pending => break,
            }
        }
        let back = std::mem::take(&mut pipe.wire.lock().unwrap().to_client);
        let mut rd = back.as_slice();
        while !rd.is_empty() {
            client.read_tls(&mut rd).unwrap();
            client.process_new_packets().unwrap();
        }
        let mut out = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut out).unwrap();
        }
        if back.is_empty() && out.is_empty() {
            quiet += 1;
            if quiet >= 2 {
                break;
            }
        } else {
            quiet = 0;
            pipe.wire.lock().unwrap().to_server.extend(out);
        }
    }
    Ok(false)
}

/// The client's next records, encrypted, without sending them.
fn records(client: &mut rustls::ClientConnection, plain: &[u8]) -> Vec<u8> {
    client.writer().write_all(plain).unwrap();
    let mut out = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut out).unwrap();
    }
    out
}

fn handshaken() -> (Connection, Arc<Pipe>, rustls::ClientConnection) {
    let (mut conn, pipe, mut client) = accepted_tls();
    let mut got = Vec::new();
    assert!(!pump(&mut conn, &pipe, &mut client, &mut got).unwrap());
    assert!(!client.is_handshaking(), "the handshake completed");
    assert!(conn.is_open());
    assert!(got.is_empty());
    (conn, pipe, client)
}

fn tls_plain_is_zero() -> bool {
    TLS_PLAIN.with(|slot| {
        let held = slot.take().expect("no read holds the plaintext scratch");
        let zero = held.allocation().iter().all(|b| *b == 0);
        slot.set(Some(held));
        zero
    })
}

/// RED against the r7 snippet (no `tls_out` after the reads): the server's flight is queued by
/// `tls_out` and a rustls client completes its handshake against the accepted line.
#[test]
fn tls_accept_handshake_completes_via_compose() {
    // The connection's deadlines are tokio timers: a worker's runtime must be entered.
    let rt = crate::support::worker();
    let _entered = rt.enter();
    let (conn, _pipe, client) = handshaken();
    assert!(!client.is_handshaking());
    assert!(conn.is_open());
}

/// RED against the r7 snippet (no `Phase::Open` gate): a post-handshake record that carries no
/// plaintext delivers nothing on an unframed, open line: no empty `Got`, no `unfed` entry, no
/// `ingest`. The test's peer is a client, so its no-plaintext record is a KeyUpdate; a
/// NewSessionTicket takes the same path (`plaintext_bytes_to_read() == 0`, probe `WouldBlock`).
#[test]
fn tls_ticket_only_record_on_unframed_line_delivers_no_got() {
    // The connection's deadlines are tokio timers: a worker's runtime must be entered.
    let rt = crate::support::worker();
    let _entered = rt.enter();
    let (mut conn, pipe, mut client) = handshaken();
    let before = crate::compose::tls_probe::ingests();
    client.refresh_traffic_keys().unwrap();
    let mut got = Vec::new();
    assert!(!pump(&mut conn, &pipe, &mut client, &mut got).unwrap());
    assert!(got.is_empty(), "no piece for a record without plaintext");
    assert!(conn.inbox.is_empty());
    assert!(conn.unfed.is_empty());
    assert_eq!(
        crate::compose::tls_probe::ingests(),
        before,
        "a record without plaintext makes no ingest call"
    );
    // The line still carries data after the key update.
    pipe.wire
        .lock()
        .unwrap()
        .to_server
        .extend(records(&mut client, b"after"));
    assert!(!pump(&mut conn, &pipe, &mut client, &mut got).unwrap());
    let bytes: Vec<u8> = got.iter().flat_map(|g| g.bytes.iter().copied()).collect();
    assert_eq!(bytes, b"after");
}

/// The last data record and close_notify in one read: the data, then the end, exactly once.
#[test]
fn tls_data_then_close_notify_ends_once() {
    // The connection's deadlines are tokio timers: a worker's runtime must be entered.
    let rt = crate::support::worker();
    let _entered = rt.enter();
    let (mut conn, pipe, mut client) = handshaken();
    let (calls, ends) = crate::compose::tls_probe::ingests();
    let mut bytes = records(&mut client, b"data");
    client.send_close_notify();
    while client.wants_write() {
        client.write_tls(&mut bytes).unwrap();
    }
    pipe.wire.lock().unwrap().to_server.extend(bytes);
    let mut got = Vec::new();
    assert!(
        pump(&mut conn, &pipe, &mut client, &mut got).unwrap(),
        "close_notify ends the line"
    );
    let data: Vec<u8> = got.iter().flat_map(|g| g.bytes.iter().copied()).collect();
    assert_eq!(data, b"data");
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(matches!(conn.poll_piece(&mut cx), Poll::Ready(Ok(None))));
    assert_eq!(
        crate::compose::tls_probe::ingests(),
        (calls + 1, ends + 1),
        "one ingest carries the data and the end together"
    );
}

/// A FIN with no close_notify after data is a truncation: the line fails.
#[test]
fn tls_unclean_eof_is_refused() {
    // The connection's deadlines are tokio timers: a worker's runtime must be entered.
    let rt = crate::support::worker();
    let _entered = rt.enter();
    let (mut conn, pipe, mut client) = handshaken();
    {
        let mut w = pipe.wire.lock().unwrap();
        w.to_server.extend(records(&mut client, b"partial"));
        w.eof = true;
    }
    let mut got = Vec::new();
    let r = pump(&mut conn, &pipe, &mut client, &mut got);
    assert!(
        r.is_err(),
        "an unclean end is refused, never a clean end: {r:?}"
    );
}

/// RED against a feed that keeps whatever count the reader gives: when rustls' stated plaintext
/// and its reader disagree, the line fails closed and the scratch is wiped.
#[test]
fn tls_plaintext_count_mismatch_fails() {
    // The connection's deadlines are tokio timers: a worker's runtime must be entered.
    let rt = crate::support::worker();
    let _entered = rt.enter();
    let (mut conn, pipe, mut client) = handshaken();
    pipe.wire
        .lock()
        .unwrap()
        .to_server
        .extend(records(&mut client, b"secret-plaintext"));
    crate::compose::tls_probe::inflate(true);
    let mut got = Vec::new();
    let r = pump(&mut conn, &pipe, &mut client, &mut got);
    crate::compose::tls_probe::inflate(false);
    assert!(
        format!("{r:?}").contains("tls: plaintext count mismatch"),
        "the line fails closed on the disagreement: {r:?}"
    );
    assert!(got.is_empty(), "nothing of a disagreeing read is delivered");
    assert!(tls_plain_is_zero(), "the guard wiped the scratch");
}

/// An open plaintext line over its own pipe, to price what an unframed ingest costs without TLS.
fn plain_line() -> (Connection, Arc<Pipe>) {
    let pipe = pipe();
    let conn = accepted_over(&pipe, None);
    assert!(conn.is_open());
    (conn, pipe)
}

const RECORD: usize = 600;

/// RED against today's plaintext `Vec`: once warm, a TLS read costs at most rustls' own plaintext
/// chunk more than the same bytes read in the clear (the unframed `Got` both pay).
#[test]
fn tls_read_allocates_nothing() {
    // The connection's deadlines are tokio timers: a worker's runtime must be entered.
    let rt = crate::support::worker();
    let _entered = rt.enter();
    let (mut conn, _pipe, mut client) = handshaken();
    let (mut plain, _plain_pipe) = plain_line();
    // Warm both: buffers, the inbox and the scratch slots reach their working size.
    for _ in 0..3 {
        let rec = records(&mut client, &[b'w'; RECORD]);
        conn.feed(&rec, false, false, &mut None).unwrap();
        plain
            .feed(&[b'w'; RECORD], false, false, &mut None)
            .unwrap();
        conn.inbox.clear();
        plain.inbox.clear();
    }
    let rec = records(&mut client, &[b'r'; RECORD]);
    let bytes = [b'r'; RECORD];
    let ((), clear) = allocations_during(|| plain.feed(&bytes, false, false, &mut None).unwrap());
    let ((), secured) = allocations_during(|| conn.feed(&rec, false, false, &mut None).unwrap());
    assert_eq!(conn.inbox.back().map(|g| g.bytes.len()), Some(RECORD));
    assert!(
        secured <= clear + 1,
        "a warm TLS read made {secured} allocations against {clear} in the clear: the plaintext \
         path itself allocates nothing"
    );
    assert!(tls_plain_is_zero());
}

/// The same through `Connection::read`, which holds `READ_SCRATCH` while `feed` takes `TLS_PLAIN`:
/// the two slots never contend, so the read allocates nothing more and no taker misses its slot.
#[test]
fn tls_read_with_carrier_scratch_held_allocates_nothing() {
    // The connection's deadlines are tokio timers: a worker's runtime must be entered.
    let rt = crate::support::worker();
    let _entered = rt.enter();
    let (mut conn, pipe, mut client) = handshaken();
    let (mut plain, plain_pipe) = plain_line();
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut step = |c: &mut Connection, p: &Pipe, bytes: Vec<u8>| -> u64 {
        p.wire.lock().unwrap().to_server.extend(bytes);
        let (piece, n) = allocations_during(|| c.poll_piece(&mut cx));
        assert!(
            matches!(piece, Poll::Ready(Ok(Some(_)))),
            "the read delivers"
        );
        n
    };
    for _ in 0..3 {
        let rec = records(&mut client, &[b'w'; RECORD]);
        step(&mut conn, &pipe, rec);
        step(&mut plain, &plain_pipe, vec![b'w'; RECORD]);
    }
    let misses = scratch_misses();
    let rec = records(&mut client, &[b'r'; RECORD]);
    let clear = step(&mut plain, &plain_pipe, vec![b'r'; RECORD]);
    let secured = step(&mut conn, &pipe, rec);
    assert_eq!(
        scratch_misses(),
        misses,
        "READ_SCRATCH and TLS_PLAIN never contend"
    );
    assert!(
        secured <= clear + 1,
        "a warm TLS read through the carrier made {secured} allocations against {clear} in the clear"
    );
}
