//! Tests for `serve_lines.rs`: the line carrier is the transports' declared fact, never a name the
//! root holds.

use super::*;
use crate::root::linked::LinkedTransport;

/// A transport row whose claims are `claims` and whose first-line claims are `lines`, built never.
fn row(
    key: crate::root::linked::KeyOf,
    claims: fn() -> Vec<&'static str>,
    lines: fn() -> Vec<&'static str>,
) -> LinkedTransport {
    LinkedTransport {
        key,
        composes_over: || &[],
        build: |_| unreachable!("the carrier is read off the rows, never off a built wire"),
        claims,
        upgrades: Vec::new,
        lines,
        offered: crate::root::doors::offers_unstated,
    }
}

/// THE CARRIER IS WHAT THE ROWS DECLARE: the one claim whose row opens on the first line, whatever
/// it is called; a build with none carries no lines.
#[test]
fn the_line_carrier_is_the_claim_a_row_declares_opening_on_its_first_line() {
    let rows = [
        row(
            || "framed-wire",
            || vec!["framed-wire", "framed-too"],
            Vec::new,
        ),
        row(|| "pipe-wire", || vec!["pipe-wire"], || vec!["pipe-wire"]),
    ];
    assert_eq!(line_carrier(&rows), Ok(Some("pipe-wire")));
    assert_eq!(line_carrier(&rows[..1]), Ok(None));
    assert_eq!(line_carrier(&[]), Ok(None));
}

/// TWO LINE CARRIERS ARE REFUSED, naming both: the process has one stdin/stdout, and which claim it
/// carries is never decided by picking the first.
#[test]
fn two_claims_opening_on_their_first_line_are_refused() {
    let rows = [
        row(|| "pipe-wire", || vec!["pipe-wire"], || vec!["pipe-wire"]),
        row(
            || "other-pipe",
            || vec!["other-pipe"],
            || vec!["other-pipe"],
        ),
    ];
    let refusal = line_carrier(&rows).expect_err("two line carriers are ambiguous");
    assert!(refusal.contains("`pipe-wire`"), "{refusal}");
    assert!(refusal.contains("`other-pipe`"), "{refusal}");
}

/// The build's own carrier is read off its linked rows, and a build that links one serves it.
#[test]
fn the_builds_carrier_is_read_off_its_linked_rows() {
    assert_eq!(refusal(), None, "the build states one line carrier at most");
    assert_eq!(
        carrier(),
        line_carrier(crate::LINKED.transports).expect("one line carrier")
    );
    assert!(carrier().is_some(), "this build links a line carrier");
}

/// THE SESSION CREDENTIAL'S VARIABLE is spelled from the plane's key and the carrier's key, both
/// upper-cased: the shape the launching client's `env` block has always carried.
#[test]
fn the_credential_variable_is_spelled_from_the_plane_and_the_carrier() {
    assert_eq!(
        env_credential("tool-door", "pipe"),
        "BUSBAR_TOOL-DOOR_PIPE_CREDENTIAL"
    );
    assert_eq!(env_credential("x", "y"), "BUSBAR_X_Y_CREDENTIAL");
}

/// A LINE PAST THE BOUND IS DROPPED WHOLE, its tail with it, and the next line is read as it is
/// (the carrier's own contract: "a longer one is read to its end and dropped ... so the session
/// goes on"). The reader hands the line over in pieces smaller than the bound, so the bound is
/// crossed mid-line and pieces of the same line follow it. RED before the fix: the buffer
/// was cleared where the bound was crossed and the rest of the line kept, so its tail (`bb`) came
/// back as a line of its own.
#[tokio::test]
async fn a_line_past_the_bound_is_dropped_with_its_tail() {
    let input: &[u8] = b"aaaaaaaaaaaabb\nok\n";
    let mut reader = tokio::io::BufReader::with_capacity(4, input);
    let mut over = Vec::new();
    let read = read_line(&mut reader, &mut over, 8)
        .await
        .expect("the over-long line reads");
    assert_eq!(read, 15, "the whole over-long line is consumed");
    assert!(
        trim(&over).is_empty(),
        "nothing of the over-long line is kept: {:?}",
        String::from_utf8_lossy(&over)
    );
    let mut next = Vec::new();
    read_line(&mut reader, &mut next, 8)
        .await
        .expect("the next line reads");
    assert_eq!(trim(&next), b"ok", "the session goes on at the next line");
}

/// A caller over `reader`, its writes kept nowhere.
fn caller_over<R: AsyncRead + Unpin + Send>(reader: R) -> LineCaller<R> {
    LineCaller {
        lines: AsyncMutex::new(tokio::io::BufReader::new(reader)),
        max_line: 1024,
        out: mpsc::unbounded_channel().0,
    }
}

/// THE SHUTDOWN SIGNAL ENDS THE READ (THE DESIGN §7: a unit is settled and recorded, never lost
/// with the process): a stop that fires while the caller sends nothing ends the line loop with no
/// line, so the serve goes on to drain its units and to the shutdown tail instead of waiting on
/// stdin.
/// RED before the fix: the line loop could not be stopped; `main` dropped the whole serve future on
/// the signal, units in flight with it.
#[tokio::test]
async fn the_shutdown_signal_ends_the_read_with_no_line() {
    let (_held, reader) = tokio::io::duplex(64);
    let caller = caller_over(reader);
    let stop = std::pin::pin!(std::future::ready(()));
    assert_eq!(next_line(&caller, stop).await, None);
}

/// The green twin: with no signal, the next line is read as it always was.
#[tokio::test]
async fn with_no_signal_the_next_line_is_read() {
    let caller = caller_over(&b"one\n"[..]);
    let stop = std::pin::pin!(std::future::pending::<()>());
    assert_eq!(next_line(&caller, stop).await, Some(b"one".to_vec()));
}

/// A UNIT IN FLIGHT WHEN THE SERVE STOPS FINISHES AND ANSWERS (THE DESIGN §7; the listener path
/// lets its in-flight requests drain on the same signal): the drain waits for it within the grace,
/// and nothing is ended.
/// RED before the fix: every unit still open was aborted where the read loop ended.
#[tokio::test(start_paused = true)]
async fn a_unit_in_flight_when_the_serve_stops_finishes_and_answers() {
    let answered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut units = tokio::task::JoinSet::new();
    let flag = Arc::clone(&answered);
    units.spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    let ended = drain_units(&mut units, std::time::Duration::from_secs(5)).await;
    assert_eq!(ended, 0, "no unit is ended inside the grace");
    assert!(answered.load(std::sync::atomic::Ordering::SeqCst));
}

/// The green twin: a unit still running when the grace is spent is ended, so a stop is bounded.
#[tokio::test(start_paused = true)]
async fn a_unit_still_running_past_the_drain_grace_is_ended() {
    let mut units = tokio::task::JoinSet::new();
    units.spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    });
    let ended = drain_units(&mut units, std::time::Duration::from_secs(5)).await;
    assert_eq!(ended, 1, "the unit past the grace is ended");
    assert!(units.is_empty());
}
