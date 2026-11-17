// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_plugin_abi::transport::{MSG_BINARY, MSG_FIN, MSG_TEXT};

#[test]
fn native_signed_subject_requires_complete_canonical_build_digest() {
    for value in [
        "",
        "00",
        &"0".repeat(63),
        &"0".repeat(65),
        &"G".repeat(64),
        &"A".repeat(64),
    ] {
        assert_eq!(build_digest(value), Err(Failure::Admission));
    }
    assert_eq!(build_digest(&"00".repeat(32)), Ok([0; 32]));
    assert_eq!(build_digest(&"a5".repeat(32)), Ok([0xa5; 32]));
}

#[cfg(target_os = "linux")]
#[test]
fn native_signed_subject_refuses_permissive_trust_and_absent_package() {
    for trust in [
        TrustConfig::default(),
        TrustConfig {
            allow_untrusted: true,
            ..TrustConfig::default()
        },
    ] {
        let subject =
            MessageStreamSubject::http_upgrade(&fixture::PLUGIN, b"{}", limits()).unwrap();
        assert!(matches!(
            subject.serve_signed_package(&[], &"00".repeat(32), &trust),
            Err(Failure::Admission)
        ));
    }
}

#[test]
fn native_upgrade_preserves_coalesced_leftover_after_bodyless_framing() {
    for length in ["", "Content-Length: 0\r\n", "Content-Length: 000\r\n"] {
        let input = format!("GET /echo HTTP/1.1\r\nHost: peer.test\r\n{length}\r\n");
        let mut bytes = input.as_bytes().to_vec();
        bytes.extend_from_slice(b"\x81\x00");
        let (head, used) = upgrade_head(&bytes, 16).unwrap().unwrap();
        assert_eq!(&bytes[used..], b"\x81\x00");
        assert!(!head.as_bytes().is_empty());
        assert!(upgrade_head(&bytes[..input.len() - 1], 16)
            .unwrap()
            .is_none());
    }
}

#[test]
fn native_upgrade_rejects_body_framing_before_any_body_arrives() {
    for framing in [
        "Content-Length: 1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Content-Length: 0\r\nContent-Length: 0\r\n",
        "Content-Length: 0\r\nContent-Length: 1\r\n",
        "Content-Length: +0\r\n",
        "Content-Length: 0,0\r\n",
        "Content-Length: \r\n",
        "Content-Length: x\r\n",
    ] {
        let bytes = format!("GET /echo HTTP/1.1\r\nHost: peer.test\r\n{framing}\r\n");
        assert!(upgrade_head(bytes.as_bytes(), 16).is_err(), "{framing}");
    }
}

#[test]
fn native_message_echo_preserves_kind_fin_fragments_and_empty_messages() {
    for kind in [MSG_TEXT, MSG_BINARY] {
        let mut state = EchoState::new(2, 3, 32);
        state.body(7, kind, b"ab").unwrap();
        assert_eq!(state.next(), None);
        state.body(7, kind | MSG_FIN, b"cd").unwrap();
        assert_eq!(
            state.next(),
            Some(Message {
                stream: 7,
                flags: kind | MSG_FIN,
                bytes: b"abcd".to_vec()
            })
        );
        state.body(7, kind | MSG_FIN, b"").unwrap();
        assert_eq!(state.next().unwrap().bytes, b"");
    }
}

#[test]
fn native_message_subject_refuses_byte_streams_and_fragment_kind_changes() {
    let mut state = EchoState::new(2, 3, 32);
    assert_eq!(state.body(7, 0, b"body"), Err(Failure::UnsupportedBodyMode));
    state.body(7, MSG_TEXT, b"first").unwrap();
    assert_eq!(
        state.body(7, MSG_BINARY | MSG_FIN, b"second"),
        Err(Failure::Shape)
    );
}

#[test]
fn native_full_consumes_current_message_and_never_replays_it() {
    let mut state = EchoState::new(2, 3, 32);
    state.body(7, MSG_BINARY | MSG_FIN, b"first").unwrap();
    assert_eq!(state.next().unwrap().bytes, b"first");
    state.full(7).unwrap();
    state.body(7, MSG_BINARY | MSG_FIN, b"next").unwrap();
    assert_eq!(state.next(), None);
    state.writable(7);
    assert_eq!(state.next().unwrap().bytes, b"next");
    assert_eq!(state.next(), None);
}

#[test]
fn native_empty_messages_and_zero_byte_streams_have_finite_object_bounds() {
    let mut state = EchoState::new(2, 2, 32);
    state.body(7, MSG_TEXT | MSG_FIN, b"one").unwrap();
    state.next().unwrap();
    state.full(7).unwrap();
    state.body(7, MSG_TEXT | MSG_FIN, b"").unwrap();
    state.body(7, MSG_TEXT | MSG_FIN, b"").unwrap();
    assert_eq!(state.body(7, MSG_TEXT | MSG_FIN, b""), Err(Failure::Limit));
    state.end(7);
    state.body(8, MSG_TEXT, b"").unwrap();
    state.body(9, MSG_TEXT, b"").unwrap();
    assert_eq!(state.body(10, MSG_TEXT, b""), Err(Failure::Limit));
}

#[test]
fn native_callback_budget_counts_empty_records_before_copying() {
    let mut batch = Batch::default();
    batch.capture(TransportOut::Write(b""), 2, 32);
    batch.capture(TransportOut::Write(b""), 2, 32);
    assert_eq!(batch.failure, None);
    batch.capture(TransportOut::Write(b""), 2, 32);
    assert_eq!(batch.failure, Some(Failure::Limit));
}

fn limits() -> StreamLimits {
    StreamLimits {
        header_bytes: 4096,
        header_fields: 16,
        streams: 4,
        messages: 4,
        message_bytes: 4096,
        assembly_bytes: 4096,
        queued_bytes: 4096,
        output_records: 32,
        output_bytes: 4096,
        wire_records: 32,
        wire_bytes: 8192,
        connections: 2,
        io_timeout: Duration::from_secs(2),
        run_timeout: Duration::from_secs(10),
    }
}

#[test]
fn native_close_and_backpressure_enforce_call_origin() {
    let limits = limits();
    let end = Instant::now() + limits.run_timeout;
    for (call, out) in [
        (Call::Begin, TransportOut::StreamFull(1)),
        (Call::Ingest, TransportOut::StreamFull(1)),
        (Call::Timer, TransportOut::StreamFull(1)),
        (Call::Emit(1), TransportOut::StreamFull(2)),
        (Call::Emit(1), TransportOut::StreamWritable(1)),
        (Call::Close, TransportOut::WakeAt(0)),
    ] {
        let mut driver = Driver::new(&limits);
        let mut batch = Batch::default();
        batch.capture(out, 32, 4096);
        assert_eq!(driver.batch(batch, call, &limits, end), Err(Failure::Shape));
    }
    let mut driver = Driver::new(&limits);
    let mut batch = Batch::default();
    batch.capture(TransportOut::Write(b"bye"), 32, 4096);
    batch.capture(TransportOut::Close { abort: false }, 32, 4096);
    batch.capture(TransportOut::Write(b"after close"), 32, 4096);
    assert_eq!(
        driver.batch(batch, Call::Close, &limits, end),
        Err(Failure::Shape)
    );
}

#[test]
fn native_callback_bytes_and_pending_empty_writes_are_bounded() {
    let mut batch = Batch::default();
    batch.capture(TransportOut::Write(b"123"), 8, 2);
    assert_eq!(batch.failure, Some(Failure::Limit));
    assert!(batch.records.is_empty());
    let mut limits = limits();
    limits.wire_records = 2;
    let mut driver = Driver::new(&limits);
    let end = Instant::now() + limits.run_timeout;
    let mut batch = Batch::default();
    for _ in 0..3 {
        batch.capture(TransportOut::Write(b""), 8, 2);
    }
    assert_eq!(
        driver.batch(batch, Call::Ingest, &limits, end),
        Err(Failure::Limit)
    );
    assert_eq!(driver.wire.len(), 2);
}

// This fixture is deliberately not a WS implementation. Its native session reports the adopted
// leftover and each subsequent input as a complete binary message. Wire bytes expose native calls.
mod fixture {
    use super::*;
    use busbar_plugin_abi::fail::{failed, Fail};
    use busbar_plugin_abi::host::Host;
    use busbar_plugin_abi::need::ChainBytes;
    use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
    use busbar_plugin_abi::records::{Out, Records};
    use busbar_plugin_abi::transport::{
        self as tp, tag as tt, CloseRec, ConnInfo, StreamBody, StreamFlow, WakeAt,
    };
    use busbar_plugin_abi::types::Bytes;
    use busbar_plugin_abi::Transport;
    use std::sync::atomic::AtomicUsize;

    pub static LOCK: Mutex<()> = Mutex::new(());
    pub static BEGINS: AtomicUsize = AtomicUsize::new(0);
    pub static CLOSES: AtomicUsize = AtomicUsize::new(0);
    pub static EOFS: AtomicUsize = AtomicUsize::new(0);
    pub static DROPS: AtomicUsize = AtomicUsize::new(0);
    pub static TIMERS: AtomicUsize = AtomicUsize::new(0);
    pub struct Framer {
        mode: u8,
    }
    pub struct Session {
        mode: u8,
        terminal: bool,
        ticks: u8,
    }
    impl Drop for Session {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn full<T>(_: T) -> Fail {
        Fail::failed(failed::F_LIMIT)
    }
    fn body(out: &mut Out<'_>, bytes: &[u8]) -> Result<(), Fail> {
        out.put_pod_tail(
            tt::STREAM_BODY,
            &StreamBody {
                stream: 1,
                flags: MSG_BINARY | MSG_FIN,
                _r: 0,
            },
            bytes,
        )
        .map_err(full)
    }
    fn wake(out: &mut Out<'_>, h: &Host) -> Result<(), Fail> {
        out.put_pod(
            tt::WAKE_AT,
            &WakeAt {
                mono_ns: h.mono_ns(),
            },
        )
        .map_err(full)
    }
    impl Open for Framer {
        async fn open(_h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
            let mode = config.with(|b| match b {
                b"{\"mode\":1}" => 1,
                b"{\"mode\":2}" => 2,
                b"{\"mode\":3}" => 3,
                b"{\"mode\":4}" => 4,
                _ => 0,
            });
            Ok(Self { mode })
        }
        fn check(_h: &Host, _config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
            Ok(())
        }
        fn describe(d: &mut Describe<'_>) {
            d.methods(tp::M_BEGIN | tp::M_INGEST | tp::M_EMIT | tp::M_TIMER | tp::M_OFFER)
                .facts(tp::FB_SERVER)
                .schema(r#"{"type":"object"}"#)
                .item_text(tt::D_PROTOCOL, "native-fixture");
        }
    }
    impl Transport for Framer {
        type Session = Session;
        fn begin(&self, h: &Host, conn: &ConnInfo<'_>, out: &mut Out<'_>) -> Result<Session, Fail> {
            BEGINS.fetch_add(1, Ordering::SeqCst);
            assert_eq!(conn.role, ROLE_SERVER);
            assert_eq!(conn.flags, CONN_UPGRADED);
            assert!(conn.mono_ns <= h.mono_ns());
            let status = Records::new(conn.head.get()).find_map(|r| {
                let r = r.ok()?;
                (r.tag == tag::H_STATUS).then(|| r.pod::<U32Rec>().unwrap().value)
            });
            assert_eq!(status, Some(101));
            out.put(tt::WRITE, b"ready\n").map_err(full)?;
            if !conn.leftover.get().is_empty() {
                body(out, conn.leftover.get())?;
            }
            if self.mode == 1 || self.mode == 2 {
                wake(out, h)?;
            }
            Ok(Session {
                mode: self.mode,
                terminal: false,
                ticks: 0,
            })
        }
        fn ingest(
            &self,
            _h: &Host,
            s: &mut Session,
            bytes: Bytes<'_>,
            out: &mut Out<'_>,
        ) -> Result<(), Fail> {
            assert!(!s.terminal);
            if bytes.get().is_empty() {
                EOFS.fetch_add(1, Ordering::SeqCst);
                s.terminal = true;
                return out
                    .put_pod(tt::STREAM_END, &StreamFlow { stream: 1 })
                    .map_err(full);
            }
            if s.mode == 3 {
                s.terminal = true;
                return out
                    .put_pod(
                        tt::CLOSE,
                        &CloseRec {
                            how: tp::CLOSE_GRACEFUL,
                            _r: 0,
                        },
                    )
                    .map_err(full);
            }
            if s.mode == 4 {
                s.terminal = true;
                return Err(Fail::failed(failed::F_LIMIT));
            }
            body(out, bytes.get())
        }
        fn emit(
            &self,
            _h: &Host,
            s: &mut Session,
            stream: u64,
            piece: u32,
            arg: u32,
            bytes: Bytes<'_>,
            out: &mut Out<'_>,
        ) -> Result<(), Fail> {
            assert!(!s.terminal);
            if piece == E_CLOSE {
                assert_eq!((stream, arg, bytes.get()), (0, CR_DRAIN, &[][..]));
                CLOSES.fetch_add(1, Ordering::SeqCst);
                s.terminal = true;
                out.put(tt::WRITE, b"drain\n").map_err(full)
            } else {
                assert_eq!(piece, E_BODY);
                assert_eq!(stream, 1);
                assert_eq!(arg, MSG_BINARY | MSG_FIN);
                out.put(tt::WRITE, bytes.get()).map_err(full)
            }
        }
        fn timer(&self, h: &Host, s: &mut Session, out: &mut Out<'_>) -> Result<(), Fail> {
            assert!(!s.terminal);
            TIMERS.fetch_add(1, Ordering::SeqCst);
            if s.mode == 2 {
                return wake(out, h);
            }
            if s.ticks < 2 {
                s.ticks += 1;
                out.put(tt::WRITE, b"tick\n").map_err(full)?;
                wake(out, h)?;
            }
            Ok(())
        }
        fn offer(&self, _h: &Host, _role: u32, _out: &mut Out<'_>) -> Result<(), Fail> {
            Ok(())
        }
    }
    busbar_plugin_abi::plugin!(Transport, Framer, name: "fixture-native-stream");
    pub fn reset() {
        for count in [&BEGINS, &CLOSES, &EOFS, &DROPS, &TIMERS] {
            count.store(0, Ordering::SeqCst);
        }
    }
}

fn start(mode: u8, mutant: bool) -> Served {
    let config = format!("{{\"mode\":{mode}}}");
    let target =
        MessageStreamSubject::http_upgrade(&fixture::PLUGIN, config.as_bytes(), limits()).unwrap();
    if mutant { target.mutant() } else { target }
        .serve_linked()
        .unwrap()
}
fn connect(target: &Served, leftover: &[u8]) -> TcpStream {
    let mut socket = TcpStream::connect(target.addr()).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut input = b"GET / HTTP/1.1\r\nHost: peer.test\r\nContent-Length: 0\r\n\r\n".to_vec();
    input.extend_from_slice(leftover);
    socket.write_all(&input).unwrap();
    let mut ready = [0u8; 6];
    socket.read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"ready\n");
    socket
}

#[test]
fn native_linked_subject_uses_real_session_and_preserves_leftover() {
    let _lock = fixture::LOCK.lock().unwrap();
    fixture::reset();
    let target = start(0, false);
    let mut socket = connect(&target, b"coalesced");
    let mut echoed = [0u8; 9];
    socket.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"coalesced");
    let report = target.finish().unwrap();
    let mut goodbye = Vec::new();
    socket.read_to_end(&mut goodbye).unwrap();
    assert_eq!(goodbye, b"drain\n");
    assert_eq!(report.subject, "host target; kernel not present");
    assert_eq!(fixture::CLOSES.load(Ordering::SeqCst), 1);
    assert_eq!(fixture::DROPS.load(Ordering::SeqCst), 1);
}

#[test]
fn native_linked_eof_and_transport_close_never_emit_another_close() {
    let _lock = fixture::LOCK.lock().unwrap();
    for mode in [0, 3, 4] {
        fixture::reset();
        let target = start(mode, false);
        let mut socket = connect(&target, b"");
        if mode == 0 {
            socket.shutdown(Shutdown::Write).unwrap();
        } else {
            socket.write_all(b"end").unwrap();
        }
        let mut rest = Vec::new();
        socket.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
        let report = target.finish();
        assert_eq!(report.is_err(), mode == 4);
        assert_eq!(fixture::CLOSES.load(Ordering::SeqCst), 0);
        assert_eq!(fixture::EOFS.load(Ordering::SeqCst), usize::from(mode == 0));
        assert_eq!(fixture::DROPS.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn native_host_wakes_progress_and_nonprogress_is_bounded() {
    let _lock = fixture::LOCK.lock().unwrap();
    fixture::reset();
    let target = start(1, false);
    let mut socket = connect(&target, b"");
    let mut ticks = [0u8; 10];
    socket.read_exact(&mut ticks).unwrap();
    assert_eq!(&ticks, b"tick\ntick\n");
    target.finish().unwrap();
    fixture::reset();
    let target = start(2, false);
    let mut socket = connect(&target, b"");
    let mut rest = Vec::new();
    socket.read_to_end(&mut rest).unwrap();
    assert_eq!(
        target.finish().unwrap_err().first_failure,
        Some(Failure::TimerNoProgress)
    );
    assert_eq!(fixture::TIMERS.load(Ordering::SeqCst), 64);
    assert_eq!(fixture::CLOSES.load(Ordering::SeqCst), 0);
}

#[test]
fn native_subject_mutates_only_one_byte_and_records_actual_mutation() {
    let _lock = fixture::LOCK.lock().unwrap();
    fixture::reset();
    let target = start(0, true);
    let mut socket = connect(&target, b"abc");
    let mut first = [0u8; 3];
    socket.read_exact(&mut first).unwrap();
    assert_eq!(first, [b'a' ^ 1, b'b', b'c']);
    socket.write_all(b"xyz").unwrap();
    let mut second = [0u8; 3];
    socket.read_exact(&mut second).unwrap();
    assert_eq!(&second, b"xyz");
    assert_eq!(target.finish().unwrap().mutations, 1);
}

#[test]
fn native_invalid_split_framing_never_calls_begin() {
    let _lock = fixture::LOCK.lock().unwrap();
    fixture::reset();
    let target = start(0, false);
    let mut socket = TcpStream::connect(target.addr()).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
        .write_all(b"GET / HTTP/1.1\r\nHost: peer.test\r\nContent-Length: 1\r\n")
        .unwrap();
    socket.write_all(b"\r\n").unwrap();
    let mut rest = Vec::new();
    socket.read_to_end(&mut rest).unwrap();
    assert_eq!(
        target.finish().unwrap_err().first_failure,
        Some(Failure::Framing)
    );
    assert_eq!(fixture::BEGINS.load(Ordering::SeqCst), 0);
}

#[test]
fn native_slow_header_cannot_renew_its_collection_deadline() {
    let _lock = fixture::LOCK.lock().unwrap();
    fixture::reset();
    let mut bound = limits();
    bound.io_timeout = Duration::from_millis(60);
    let target = MessageStreamSubject::http_upgrade(&fixture::PLUGIN, b"{}", bound)
        .unwrap()
        .serve_linked()
        .unwrap();
    let mut socket = TcpStream::connect(target.addr()).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut writer = socket.try_clone().unwrap();
    let sender = std::thread::spawn(move || {
        for byte in b"GET /a-very-slow-head HTTP/1.1\r\nHost: peer.test\r\n\r\n" {
            if writer.write_all(&[*byte]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });
    let mut rest = Vec::new();
    let _ = socket.read_to_end(&mut rest);
    sender.join().unwrap();
    assert_eq!(
        target.finish().unwrap_err().first_failure,
        Some(Failure::Deadline)
    );
    assert_eq!(fixture::BEGINS.load(Ordering::SeqCst), 0);
}

#[test]
fn native_finished_connection_handles_are_reclaimed_before_slot_reuse() {
    let _lock = fixture::LOCK.lock().unwrap();
    fixture::reset();
    let mut bound = limits();
    bound.connections = 1;
    let target = MessageStreamSubject::http_upgrade(&fixture::PLUGIN, b"{}", bound)
        .unwrap()
        .serve_linked()
        .unwrap();
    for _ in 0..4 {
        let mut socket = connect(&target, b"");
        socket.shutdown(Shutdown::Write).unwrap();
        let mut rest = Vec::new();
        socket.read_to_end(&mut rest).unwrap();
    }
    assert_eq!(target.finish().unwrap().connections, 4);
    assert_eq!(fixture::DROPS.load(Ordering::SeqCst), 4);
    assert_eq!(fixture::CLOSES.load(Ordering::SeqCst), 0);
}

#[test]
fn native_mutant_without_a_payload_is_not_success() {
    let _lock = fixture::LOCK.lock().unwrap();
    fixture::reset();
    let target = start(0, true);
    let _socket = connect(&target, b"");
    assert_eq!(
        target.finish().unwrap_err().first_failure,
        Some(Failure::MutationMissing)
    );
}
