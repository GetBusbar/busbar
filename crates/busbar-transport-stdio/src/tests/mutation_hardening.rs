//! Mutation-hardening battery for `stdio`: closes gaps a mutation run found where the existing
//! battery happened to pass regardless of what a mutated body returned. Every cell here pins one
//! fact the parent battery left unpinned: `StdioConnHandle::peer`/`ConnState::is_closed` reporting
//! the real value rather than a placeholder, `StaticConfig` answering `None` for every declared
//! key rather than some, the transport's real `key()`/`composed_over()`/listener address, the
//! `frames()` end-of-stream guard's three independent conditions, `encode_envelope`'s delimiter
//! check, and `read_line`'s exact byte-boundary arithmetic.

use super::*;
use busbar_contract::unit::ConfigView;
use busbar_contract::{
    Scratch, ArenaBudget, ArenaBytes as ContractArenaBytes, Plugin, Transport, TransportConfigView,
    TransportMeta,
};

/// A trivial arena, leaking rather than tracking a budget: this crate's `encode_envelope` battery
/// only needs somewhere to copy bytes into, never a budget to exhaust.
struct TestArena;
impl Scratch for TestArena {
    fn alloc_bytes<'a>(&'a self, src: &[u8]) -> Result<ContractArenaBytes<'a>, ArenaBudget> {
        let leaked: &'static [u8] = Box::leak(src.to_vec().into_boxed_slice());
        Ok(ContractArenaBytes::new(leaked))
    }
    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, ArenaBudget> {
        let leaked: &'static str = Box::leak(src.to_string().into_boxed_str());
        Ok(leaked)
    }
    fn alloc_spans<'a>(
        &'a self,
        src: &[(&'a str, busbar_contract::Span)],
    ) -> Result<&'a [(&'a str, busbar_contract::Span)], ArenaBudget> {
        Ok(Box::leak(src.to_vec().into_boxed_slice()))
    }
    fn remaining(&self) -> usize {
        usize::MAX
    }
}

/// `StdioConnHandle::peer` must report the peer this connection was actually built with, not a
/// placeholder: a mutant that replaces the clone with `String::new()` or `"xyzzy".into()`
/// otherwise survives, because nothing else in the parent battery reads `Conn::peer()` directly.
#[test]
fn a_wrapped_connections_peer_is_what_it_was_given() {
    let t = StdioTransport::new();
    let (end_a, _end_b) = tokio::io::duplex(64);
    let (ar, aw) = split(end_a);
    let conn = t.wrap_pair(ar, aw, "the-declared-peer");
    assert_eq!(conn.peer(), "the-declared-peer");
}

/// `ConnState::is_closed` must report the real flag. A mutant that hard-codes it to `false`
/// survives against every test that only ever checks OBSERVABLE behaviour after a close (the
/// stream ending, a write answering `Closed`) rather than the flag itself.
#[tokio::test]
async fn is_closed_reports_the_real_flag() {
    let t = Arc::new(StdioTransport::new());
    let (a, _b) = pair(&t, 64);
    let state = t.state_of(a.id()).unwrap();
    assert!(!state.is_closed());
    t.close(a, busbar_contract::transport::wire::CloseReason::Normal);
    assert!(state.is_closed());
}

/// `StaticConfig` declares nothing: every accessor must answer `None`. A mutant that replaces any
/// of them with `Some(_)` survives everywhere a caller only ever reads `bind()` (which stays
/// `None` in every existing test's fixture, but never through `StaticConfig` itself).
#[test]
fn static_config_declares_nothing() {
    let cfg = crate::StaticConfig;
    assert_eq!(ConfigView::get_str(&cfg, "anything"), None);
    assert_eq!(ConfigView::get_int(&cfg, "anything"), None);
    assert_eq!(ConfigView::get_bool(&cfg, "anything"), None);
    assert_eq!(TransportConfigView::bind(&cfg), None);
}

/// `Plugin::key` must report this transport's real key. A mutant that replaces it with `""` or
/// `"xyzzy"` survives everywhere the value is only ever compared to itself.
#[test]
fn plugin_key_is_stdio() {
    let t = StdioTransport::new();
    assert_eq!(Plugin::key(&t), "stdio");
    assert_eq!(Plugin::key(&t), <StdioTransport as TransportMeta>::KEY);
}

/// stdio opens its own channel (the process's own stdin/stdout, or a spawned child's pipes) and
/// was never built over another transport's stream: `composed_over` must report `None`.
#[test]
fn stdio_is_not_composed_over_anything() {
    let t = StdioTransport::new();
    assert_eq!(Transport::composed_over(&t), None);
}

/// The single-shot listener's address names what it is. A mutant that replaces
/// `StdioListenerHandle::local_addr` with `String::new()` or `"xyzzy".into()` survives everywhere
/// the parent battery never calls `listen()`/`local_addr()` at all.
#[tokio::test]
async fn the_listener_names_itself() {
    let t = StdioTransport::new();
    let listener = t
        .listen(&crate::StaticConfig, &test_key_handle())
        .await
        .unwrap();
    assert_eq!(listener.local_addr(), "stdio:own-process");
}

/// `frames()`'s end-of-stream guard is `done || state.is_poisoned() || state.is_closed()`: any ONE
/// of the three must end the stream. A mutant that turns either `||` into `&&` survives unless a
/// case pins each condition true in isolation, with the other two false.
///
/// This cell pins `done`: after a too-long line ends the stream with an error (which sets `done`),
/// the very next poll must answer `None` immediately — not attempt another read — even though the
/// connection is neither poisoned nor closed.
#[tokio::test]
async fn a_stream_that_ended_on_an_error_stays_ended() {
    let t = StdioTransport::new();
    let (end_a, end_b) = tokio::io::duplex(64 * 1024);
    let (br, bw) = split(end_b);
    let b = t.wrap_pair(br, bw, "a");
    let (_ar, mut aw) = split(end_a);

    let over = vec![b'x'; crate::transport::MAX_LINE_BYTES + 1];
    let flood = tokio::spawn(async move {
        let _ = aw.write_all(&over).await;
        futures::future::pending::<()>().await;
    });

    let mut frames = t.frames(b.clone_for_test());
    let err = tokio::time::timeout(Duration::from_secs(5), frames.next())
        .await
        .expect("an over-long line must be answered, not read forever")
        .expect("the stream must report it")
        .expect_err("a line past the maximum is not a frame");
    assert_eq!(err, TransportError::Framing);

    // Neither poisoned nor closed: only `done` (set by the error above) can be ending this stream.
    let state = t.state_of(b.id()).unwrap();
    assert!(!state.is_poisoned());
    assert!(!state.is_closed());
    assert!(
        frames.next().await.is_none(),
        "a stream that already ended on an error must stay ended, not attempt another read"
    );
    flood.abort();
}

/// A too-long line is a NON-FATAL framing error: this crate's contract (see
/// `a_stream_that_ended_on_an_error_stays_ended` above) is that it leaves the connection neither
/// poisoned nor closed, i.e. re-usable. But the rejected line's bytes stay in the connection's
/// carried-over buffer, and a `read_line` that answered `TooLong` from a full buffer WITHOUT ever
/// reading again wedged the connection forever: every later `frames()` on it returned a synthetic
/// framing error with no read, so the fd/child leaked while the contract claimed the connection was
/// still usable. This pins the recovery — after a too-long line, a fresh `frames()` on the SAME
/// connection discards the rejected line and delivers the NEXT well-formed one. A mutant that drops
/// the recovery drain (leaving the wedge) hangs this cell at the second pump; one that discards the
/// wrong amount delivers a spurious frame instead of `after`.
#[tokio::test]
async fn a_too_long_line_is_recovered_and_the_next_line_delivered() {
    let t = StdioTransport::new();
    let (end_a, end_b) = tokio::io::duplex(64 * 1024);
    let (br, bw) = split(end_b);
    let b = t.wrap_pair(br, bw, "a");
    let (_ar, mut aw) = split(end_a);

    // An over-long TERMINATED line, then a well-formed line behind it. The writer is spawned: the
    // payload is larger than the duplex buffer, so it drains only as the reader consumes it.
    let feeder = tokio::spawn(async move {
        let mut over = vec![b'x'; crate::transport::MAX_LINE_BYTES + 1];
        over.push(b'\n');
        aw.write_all(&over).await.unwrap();
        aw.write_all(b"after\n").await.unwrap();
        aw.flush().await.unwrap();
        aw
    });

    // First pump: the over-long line is a framing error and ends this stream.
    let mut frames = t.frames(b.clone_for_test());
    let err = tokio::time::timeout(Duration::from_secs(5), frames.next())
        .await
        .expect("the over-long line must be answered, not read forever")
        .expect("the stream must report it")
        .expect_err("a line past the maximum is not a frame");
    assert_eq!(err, TransportError::Framing);
    drop(frames);

    // The connection is left usable: not poisoned, not closed.
    let state = t.state_of(b.id()).unwrap();
    assert!(!state.is_poisoned());
    assert!(!state.is_closed());

    // A fresh pump on the SAME connection must discard the rejected line and deliver the next one,
    // reading the pipe rather than answering a synthetic `TooLong` forever.
    let mut frames = t.frames(b.clone_for_test());
    let (_stream, frame) = tokio::time::timeout(Duration::from_secs(5), frames.next())
        .await
        .expect("the connection must recover and read the pipe, not stay wedged")
        .expect("the next line must arrive")
        .expect("the next line is a well-formed frame, not a framing error");
    assert_eq!(
        frame.bytes.as_slice(),
        b"after",
        "recovery must consume the whole rejected line, then deliver the NEXT line intact"
    );

    feeder.await.unwrap();
}

/// The other end of `encode_envelope`'s check: the same delimiter and trailing-`\r` refusal
/// `write` enforces at the byte level, enforced again where a plane builds the frame. A mutant
/// that turns the `||` into `&&`, or the trailing-`\r` `==` into `!=`, survives unless each half is
/// exercised on its own — a body that ONLY carries an embedded newline (no trailing `\r`), and a
/// body that ONLY ends in `\r` (no embedded newline).
#[test]
fn encode_envelope_refuses_either_half_of_the_delimiter_check_on_its_own() {
    let t = StdioTransport::new();
    let arena = TestArena;

    let embedded_newline = b"one\ntwo";
    assert!(
        Transport::encode_envelope(&t, &[], embedded_newline, &arena).is_err(),
        "an embedded newline alone must be refused"
    );

    let trailing_cr = b"just a trailing cr\r";
    assert!(
        Transport::encode_envelope(&t, &[], trailing_cr, &arena).is_err(),
        "a trailing carriage return alone must be refused"
    );

    let clean = b"neither condition applies";
    assert!(
        Transport::encode_envelope(&t, &[], clean, &arena).is_ok(),
        "a body with neither must be accepted"
    );
}

/// `read_line`'s budget is `(MAX_LINE_BYTES + 1).saturating_sub(buf.len())`: exactly one byte past
/// the maximum is what lets `read_until` see the delimiter that ends a line of exactly the maximum
/// length. A mutant that turns the `+` into a `*` shrinks the budget by one on a fresh buffer,
/// which truncates the read one byte short of that delimiter and turns a line the parent battery's
/// own "within the maximum" cell never reaches (`MAX_LINE_BYTES - 1`) into a spurious framing
/// error. The boundary the `>` in the over-length check enforces also has to get exactly right —
/// `==` or `>=` in its place would refuse this same line.
#[tokio::test]
async fn a_line_of_exactly_the_maximum_is_still_a_frame() {
    let t = StdioTransport::new();
    let (a, b) = pair(&t, 256 * 1024);
    let payload = vec![b'z'; crate::transport::MAX_LINE_BYTES];
    t.write(&a, busbar_contract::StreamId(0), ArenaBytes::new(&payload))
        .await
        .expect("a line of exactly the maximum byte count is still one frame");

    let mut frames = t.frames(b);
    let (_s, frame) = tokio::time::timeout(Duration::from_secs(5), frames.next())
        .await
        .expect("the exactly-maximum line must arrive")
        .unwrap()
        .expect("a line of exactly the maximum is a frame, not a framing error");
    assert_eq!(frame.bytes.len(), payload.len());
}
