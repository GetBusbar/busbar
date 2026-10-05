// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The stdio CARRIER's own battery: what the carrier promises, driven through the contract's
//! `Carrier` trait exactly as the host drives it — a dialled program's pipes carry bytes both ways
//! exactly, the program is started with exactly the argument vector and environment the destination
//! declared and nothing inherited, a relative path and an address are refused before anything is
//! spawned, the process's own standard input and output are handed out once, and closing a connection ends it.

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// COVERAGE MAPPING — the removed in-process `StdioTransport` battery (`src/tests/battery.rs`, 22
// cells) and the `StdioTransport`-driving mutation cells, and where each behaviour now lives. The
// crate is DOOR-ONLY: the live paths are the in-process CARRIER (`StdioCarrier: Carrier`, this file)
// and the memory-ABI line-framer DOOR (`src/door.rs`, driven in `tests/door.rs`). Conformance
// (`tests/conformance.rs`) folds the linked + dropped-in carrier to one row.
//
// battery.rs cell                                   -> where its behaviour now lives
// --------------------------------------------------   ------------------------------------------------
//  1 round_trip_byte_exact                           FOLD: byte-exact both ways is carrier
//                                                       `a_dialled_programs_pipes_carry_every_byte_exactly`;
//                                                       "honest frame meta" (transport_units None,
//                                                       status None) is `transport_meta_matches_the_
//                                                       architecture_row` (below) + the door pieces'
//                                                       status_class/code 0 in `tests/door.rs`.
//  2 a_payload_carrying_the_delimiter_is_refused     FOLD: door `a_message_that_is_not_one_line_is_
//                                                       refused_before_a_byte_is_written` + door
//                                                       `an_envelope_refuses_each_half_of_the_one_line_
//                                                       check_on_its_own`; inner CR travels byte-exact
//                                                       via carrier byte-exact (every byte value).
//  3 multiple_frames_in_order_no_data_loss           FOLD: door `every_line_is_one_frame_with_its_
//                                                       newline_stripped` + `a_small_sink_is_back_
//                                                       pressure_and_every_line_comes_out_whole_once`.
//  4 half_close_peer_sees_clean_eof_and_can_still_    ADDED: door `a_far_side_end_is_a_clean_eof_and_
//    be_written_to                                      the_near_side_can_still_emit` (far-side EOF is
//                                                       YIELD_ENDED, this side still emits). Carrier
//                                                       clean EOF: `read_to_end` hitting Ok(0).
//  5 cancel_mid_frame_fences_the_connection          FOLD (no live analogue): the carrier frames
//                                                       nothing, so a dropped write leaves no partial
//                                                       LINE to fence; its write lock is a per-poll
//                                                       `try_lock` a dropped future cannot hold. The
//                                                       door is one synchronous call per ingest, so no
//                                                       read is cancelled mid-line. Witnessed cancel-
//                                                       safe by `k_concurrent_writers_do_not_interleave_
//                                                       within_a_line` (below) and the concurrent
//                                                       write/drain in the byte-exact cell.
//  6 backpressure_is_bidirectional                   FOLD: door `a_small_sink_is_back_pressure...`;
//                                                       carrier byte-exact drives concurrent write_all
//                                                       + drain over /bin/cat (full-duplex), so a write
//                                                       only completes as the peer drains — both ways.
//  7 a_line_of_whitespace_is_a_frame_but_an_empty_    ADDED: door `a_line_of_only_spaces_is_a_frame_
//    line_is_not                                        and_an_empty_line_is_an_empty_frame`. NOTE a
//                                                       deliberate live change: the door frames an
//                                                       empty line as an EMPTY frame (the removed
//                                                       carrier dropped empty lines); the whitespace-
//                                                       is-a-real-frame intent is preserved.
//  8 a_second_pump_on_one_connection_is_reported     FOLD (no live analogue): the door frames one
//                                                       connection with one host-driver by construction;
//                                                       the carrier hands its own pipes out once —
//                                                       `the_processs_own_stdin_and_stdout_are_handed_
//                                                       out_once` (second accept -> Closed) and reads
//                                                       under a single `try_lock`.
//  9 k_writers_serialise_without_interleaving        ADDED: `k_concurrent_writers_do_not_interleave_
//                                                       within_a_line` (below).
// 10 a_handoff_onto_stdio_is_a_mismatch              FOLD: composes-over-nothing is door
//                                                       `the_tail_is_a_framer_composing_over_nothing`
//                                                       (composes_over_len 0) + COMPOSES_OVER empty in
//                                                       `transport_meta_matches_the_architecture_row`.
//                                                       The HandoffMismatch enum was the removed
//                                                       Transport trait's; the host composes handoffs.
// 11 unit0_refusal_writes_then_closes                ADDED: door `a_refusal_goes_out_as_one_line_then_
//                                                       finish_ends_the_framing` (refuse slot = one
//                                                       line; finish = YIELD_ENDED).
// 12 a_refusal_that_never_reached_the_peer_is_        FOLD (no live analogue): delivery failure is the
//    reported                                          carrier's `poll_write` mapping a broken pipe to
//                                                       Reset (`map_io`); the refusal's wording is the
//                                                       door's. The removed cell tested the in-process
//                                                       side-table's error mapping.
// 13 a_refusal_on_a_fenced_connection_is_reported_   FOLD (no live analogue): there is no "fenced"
//    closed                                            flag; a write to a closed/unknown connection is
//                                                       Closed — carrier `an_unknown_connection_is_
//                                                       closed_and_close_is_idempotent` and the closed-
//                                                       write leg of the byte-exact cell.
// 14 transport_meta_matches_the_architecture_row     MOVED here verbatim (below).
// 15 argv_and_env_reach_the_spawned_child            FOLD: carrier `the_child_sees_its_declared_argv_
//                                                       and_env_and_nothing_else` + conformance fold.
// 16 the_child_inherits_no_environment_it_was_not_   FOLD: same carrier cell (asserts the inherited
//    given                                             var comes through empty) + conformance fold.
// 17 an_unterminated_final_line_is_a_framing_error   FOLD (deliberate live change): the door delivers
//                                                       an unterminated final line as the LAST frame on
//                                                       the far side's end, then YIELD_ENDED — door
//                                                       `every_line_is_one_frame_with_its_newline_
//                                                       stripped`. An UNBOUNDED unterminated line is
//                                                       still a framing error (cell 19).
// 18 a_partial_line_carried_across_a_cancelled_read  FOLD: same deliberate change as 17 (tail is a
//    _is_still_a_framing_error                         frame, not an error) + the door is one
//                                                       synchronous call per ingest (no cancelled read).
// 19 a_line_past_the_maximum_is_a_framing_error      FOLD: door `a_line_past_the_ceiling_fails_the_
//                                                       framing`.
// 20 a_line_within_the_maximum_is_still_a_frame      ADDED: door `a_line_of_exactly_the_ceiling_is_
//                                                       one_frame` (the exact boundary; stronger).
// 21 a_closed_connection_delivers_no_further_frames  FOLD: carrier `closing_a_connection_kills_its_
//                                                       child_and_wakes_a_parked_read` (close wakes the
//                                                       parked read) + the closed-write leg of the
//                                                       byte-exact cell (arrival -> None, write ->
//                                                       Closed).
// 22 a_write_dropped_while_queued_for_the_lock_does  FOLD (no live analogue): the carrier's write lock
//    _not_fence_the_connection                         is a per-poll `try_lock`; a write that never
//                                                       took it holds nothing, and there is no fence to
//                                                       trip. Witnessed by the K-writers cell.
//
// mutation_hardening `StdioTransport` cell           -> where its behaviour now lives
// --------------------------------------------------   ------------------------------------------------
//  a_wrapped_connections_peer_is_what_it_was_given   FOLD: the carrier reports the dialled program as
//                                                       the peer — asserted literally ("/bin/cat") in
//                                                       `a_dialled_programs_pipes_carry_every_byte_
//                                                       exactly`.
//  is_closed_reports_the_real_flag                   FOLD: there is no `is_closed` flag; "closed" is
//                                                       observable as `arrival` -> None and write ->
//                                                       Closed after `poll_close` — the byte-exact cell.
//  static_config_declares_nothing                    KEPT in mutation_hardening.rs (StaticConfig lives).
//  plugin_key_is_stdio                               MIGRATED to mutation_hardening.rs (StdioCarrier).
//  stdio_is_not_composed_over_anything               FOLD: COMPOSES_OVER empty in
//                                                       `transport_meta_matches_the_architecture_row`;
//                                                       door tail composes_over_len 0.
//  the_listener_names_itself                         MIGRATED to mutation_hardening.rs (Carrier::listen).
//  a_stream_that_ended_on_an_error_stays_ended       FOLD (no live analogue): the `frames()` Stream's
//                                                       three-way end guard was in-process; the door
//                                                       reports a framing failure via its Outcome —
//                                                       door `a_line_past_the_ceiling_fails_the_framing`.
//  a_too_long_line_is_recovered_and_the_next_line_   FOLD (no live analogue): that in-process `frames()`
//    delivered                                         recovery-drain had no door equivalent; the door
//                                                       fails the framing outright on an over-long line.
//  encode_envelope_refuses_either_half...            MIGRATED to door `an_envelope_refuses_each_half_
//                                                       of_the_one_line_check_on_its_own`.
//  a_line_of_exactly_the_maximum_is_still_a_frame    MIGRATED to door `a_line_of_exactly_the_ceiling_
//                                                       is_one_frame`.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

use std::task::Context;

use busbar_contract::transport::wire::{CloseReason, TransportError};
use busbar_contract::transport::{Carrier, CarrierPoll, Dest};

use crate::StdioCarrier;

/// Poll one carrier method to its answer, on the calling task.
async fn wait<T>(
    mut method: impl FnMut(&mut Context<'_>) -> CarrierPoll<T>,
) -> Result<T, TransportError> {
    std::future::poll_fn(|cx| method(cx)).await
}

async fn write_all(c: &StdioCarrier, conn: u64, bytes: &[u8]) {
    let mut at = 0;
    while at < bytes.len() {
        at += wait(|cx| c.poll_write(conn, cx, &bytes[at..]))
            .await
            .expect("write");
    }
    wait(|cx| c.poll_flush(conn, cx)).await.expect("flush");
}

async fn read_exact(c: &StdioCarrier, conn: u64, n: usize) -> Vec<u8> {
    let mut all = Vec::with_capacity(n);
    let mut buf = vec![0_u8; 1024];
    while all.len() < n {
        let got = wait(|cx| c.poll_read(conn, cx, &mut buf))
            .await
            .expect("read");
        assert!(got > 0, "the pipe ended after {} of {n} bytes", all.len());
        all.extend_from_slice(&buf[..got]);
    }
    all
}

async fn read_to_end(c: &StdioCarrier, conn: u64) -> Vec<u8> {
    let mut all = Vec::new();
    let mut buf = vec![0_u8; 1024];
    loop {
        match wait(|cx| c.poll_read(conn, cx, &mut buf)).await {
            Ok(0) => return all,
            Ok(n) => all.extend_from_slice(&buf[..n]),
            Err(e) => panic!("read failed: {e:?}"),
        }
    }
}

fn payload(len: usize) -> Vec<u8> {
    // Every byte value, newlines and carriage returns included: a carrier frames nothing.
    (0..len).map(|i| (i as u8).wrapping_mul(37)).collect()
}

/// A dialled program's pipes carry bytes both ways EXACTLY — every byte value, the delimiter a line
/// framing would have split on included — in however many reads the pipe hands them over.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dialled_programs_pipes_carry_every_byte_exactly() {
    let c = StdioCarrier::new();
    let conn = c
        .dial(&Dest::Program {
            program: "/bin/cat",
            args: &[],
            env: &[],
        })
        .expect("spawn");
    let sent = payload(100_000);
    let ((), r) = tokio::join!(write_all(&c, conn, &sent), read_exact(&c, conn, sent.len()));
    assert_eq!(r, sent);
    assert_eq!(
        c.arrival(conn).map(|f| (f.peer, f.local_port)),
        Some(("/bin/cat".to_string(), 0))
    );
    wait(|cx| c.poll_close(conn, cx, CloseReason::Normal))
        .await
        .unwrap();
    assert_eq!(
        wait(|cx| c.poll_write(conn, cx, b"x")).await,
        Err(TransportError::Closed),
        "a closed connection takes no bytes"
    );
    assert_eq!(c.arrival(conn), None);
}

/// The program starts with EXACTLY the declared argument vector and environment: the environment is
/// cleared first, so the child sees the declared variable and nothing the node itself carries.
#[tokio::test]
async fn the_child_sees_its_declared_argv_and_env_and_nothing_else() {
    std::env::set_var("BUSBAR_STDIO_CARRIER_INHERITED", "leak");
    let c = StdioCarrier::new();
    let conn = c
        .dial(&Dest::Program {
            program: "/bin/sh",
            args: &[
                "-c",
                "printf '%s|%s|%s' \"$0\" \"$DECLARED\" \"$BUSBAR_STDIO_CARRIER_INHERITED\"",
                "first-arg",
            ],
            env: &[("DECLARED", "yes")],
        })
        .expect("spawn");
    assert_eq!(read_to_end(&c, conn).await, b"first-arg|yes|");
    let conn = c
        .dial(&Dest::Program {
            program: "/usr/bin/env",
            args: &[],
            env: &[],
        })
        .expect("spawn");
    assert_eq!(
        read_to_end(&c, conn).await,
        b"",
        "an empty declaration is an empty environment"
    );
}

/// A bare program name is refused — it would be resolved through a search path nobody declared —
/// and so is an address: a pipe reaches a program, never a place. Neither spawns anything.
#[tokio::test]
async fn a_relative_program_and_an_address_are_refused_before_anything_spawns() {
    let c = StdioCarrier::new();
    assert_eq!(
        c.dial(&Dest::Program {
            program: "cat",
            args: &[],
            env: &[],
        }),
        Err(TransportError::AddressRefused)
    );
    assert_eq!(
        c.dial(&Dest::Authority("127.0.0.1:1")),
        Err(TransportError::AddressRefused)
    );
    assert!(c.conns.lock().unwrap().is_empty());
}

/// The process has exactly one stdin and one stdout: the one listener hands them out once, and
/// `Closed` after — never a second connection over the same pipes.
#[tokio::test]
async fn the_processs_own_stdin_and_stdout_are_handed_out_once() {
    let c = StdioCarrier::new();
    let (listener, addr) = c.listen("ignored").unwrap();
    assert_eq!(addr, crate::carrier::OWN_PROCESS);
    let (conn, peer) = wait(|cx| c.poll_accept(listener, cx)).await.unwrap();
    assert_eq!(peer, crate::carrier::OWN_PROCESS);
    assert_eq!(
        wait(|cx| c.poll_accept(listener, cx)).await,
        Err(TransportError::Closed)
    );
    assert_eq!(
        wait(|cx| c.poll_accept(listener + 1, cx)).await,
        Err(TransportError::Closed)
    );
    wait(|cx| c.poll_close(conn, cx, CloseReason::Normal))
        .await
        .unwrap();
}

/// An unknown connection is closed on every method, and closing is idempotent.
#[tokio::test]
async fn an_unknown_connection_is_closed_and_close_is_idempotent() {
    let c = StdioCarrier::new();
    let mut buf = [0_u8; 4];
    assert_eq!(
        wait(|cx| c.poll_read(99, cx, &mut buf)).await,
        Err(TransportError::Closed)
    );
    assert_eq!(
        wait(|cx| c.poll_write(99, cx, b"x")).await,
        Err(TransportError::Closed)
    );
    assert_eq!(
        wait(|cx| c.poll_flush(99, cx)).await,
        Err(TransportError::Closed)
    );
    assert_eq!(
        wait(|cx| c.poll_close(99, cx, CloseReason::Normal)).await,
        Ok(())
    );
    assert_eq!(c.arrival(99), None);
}

/// Closing a connection kills the child it owns: a child that would otherwise outlive the session
/// (here, one that sleeps) is gone, and a read parked on its pipe wakes to see the end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closing_a_connection_kills_its_child_and_wakes_a_parked_read() {
    let c = std::sync::Arc::new(StdioCarrier::new());
    let conn = c
        .dial(&Dest::Program {
            program: "/bin/sleep",
            args: &["30"],
            env: &[],
        })
        .expect("spawn");
    let reader = {
        let c = std::sync::Arc::clone(&c);
        tokio::spawn(async move {
            let mut buf = [0_u8; 8];
            wait(|cx| c.poll_read(conn, cx, &mut buf)).await
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    wait(|cx| c.poll_close(conn, cx, CloseReason::Normal))
        .await
        .unwrap();
    let parked = tokio::time::timeout(std::time::Duration::from_secs(10), reader)
        .await
        .expect("the parked read wakes")
        .unwrap();
    assert!(
        matches!(parked, Ok(0) | Err(TransportError::Closed)),
        "{parked:?}"
    );
}

/// The row's `TransportMeta` constants are exactly the architecture's stdio row (MOVED from the
/// removed `battery.rs`; `TransportMeta` is impl'd on `StdioCarrier`, see `src/meta.rs`).
#[allow(clippy::assertions_on_constants)]
#[tokio::test]
async fn transport_meta_matches_the_architecture_row() {
    use busbar_contract::transport::wire::Unit0Trigger;
    use busbar_contract::TransportMeta;
    assert_eq!(<StdioCarrier as TransportMeta>::KEY, "stdio");
    assert!(<StdioCarrier as TransportMeta>::SESSION);
    assert!(<StdioCarrier as TransportMeta>::SESSION_BOUND);
    assert_eq!(
        <StdioCarrier as TransportMeta>::UNIT0_TRIGGER,
        Some(Unit0Trigger::FirstMessage)
    );
    assert!(<StdioCarrier as TransportMeta>::UPGRADES_TO.is_empty());
    assert!(<StdioCarrier as TransportMeta>::COMPOSES_OVER.is_empty());
    assert!(!<StdioCarrier as TransportMeta>::DECODES_PAYLOAD);
    assert_eq!(<StdioCarrier as TransportMeta>::STATUS_CLASS, None);
}

/// K concurrent writers each put ONE whole short line on the connection, ALL OF THEM WAITING ON A
/// FULL PIPE at once. The pipe's readiness keeps only the waker of the LAST poll that found it not
/// writable, so the carrier must wake every writer it left waiting once a write makes progress;
/// otherwise every writer but one is never woken and the connection hangs. The carrier's per-poll
/// write lock keeps each line's bytes contiguous — a line that fits a single `poll_write` is written
/// under the lock in one go — so every line comes back intact and exactly once, no two writers'
/// bytes interleaved within a line.
///
/// Deterministic: the child reads NOTHING until the test opens a gate (it waits on a fifo, then
/// becomes `/bin/cat`), so the pipe is filled to `Pending` by the test itself (with newlines only,
/// which are empty lines and so tear no line however a write splits them); each writer is polled
/// once on this one-thread runtime and parks on the full pipe; only then does the gate open.
#[tokio::test(flavor = "current_thread")]
async fn k_concurrent_writers_do_not_interleave_within_a_line() {
    let dir = std::env::temp_dir().join(format!("stdio-k-writers-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let gate = dir.join("gate");
    let made = std::process::Command::new("mkfifo")
        .arg(&gate)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "mkfifo {}", gate.display());
    let script = format!("read -r go < '{}'; exec /bin/cat", gate.display());
    let c = std::sync::Arc::new(StdioCarrier::new());
    let conn = c
        .dial(&Dest::Program {
            program: "/bin/sh",
            args: &["-c", &script],
            env: &[],
        })
        .expect("spawn");

    // Fill the child's input until the pipe takes no more: big writes, then single bytes, so not
    // even a short line fits. A freshly opened pipe's writability is not known until its reactor
    // has reported it, and until then a poll answers `Pending` with the pipe empty; so the first
    // byte is written by an AWAITED write, which waits for that report. From then on `Pending`
    // means the pipe refused a write (it is full), the only thing that clears its writability.
    write_all(&c, conn, b"\n").await;
    let mut noop = Context::from_waker(std::task::Waker::noop());
    let mut filler = 1usize;
    for chunk in [vec![b'\n'; 4096], vec![b'\n'; 1]] {
        loop {
            match c.poll_write(conn, &mut noop, &chunk) {
                std::task::Poll::Ready(Ok(n)) => filler += n,
                std::task::Poll::Ready(Err(e)) => panic!("filling the pipe: {e:?}"),
                std::task::Poll::Pending => break,
            }
        }
    }
    assert!(filler > 1, "the pipe took nothing past its first byte");

    const K: usize = 32;
    // Each line is "writer-NN\n": 7 + 2 + 1 = 10 bytes, so K of them is a known total length.
    const LINE: usize = 10;
    let mut handles = Vec::new();
    for i in 0..K {
        let c = std::sync::Arc::clone(&c);
        handles.push(tokio::spawn(async move {
            let line = format!("writer-{i:02}\n");
            write_all(&c, conn, line.as_bytes()).await;
        }));
    }
    // One runtime thread: yielding runs every spawned writer to its first `Pending` (the pipe is full
    // and nothing reads it), so all K are waiting on the pipe before it drains.
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert!(
        handles.iter().all(|h| !h.is_finished()),
        "a writer finished on a full pipe"
    );
    std::fs::write(&gate, b"go\n").expect("open the gate");

    // The writers and the reader run together: the child's output drains as its input does.
    let all = async {
        let writers = async {
            for h in handles {
                h.await.unwrap();
            }
        };
        tokio::join!(writers, read_exact(&c, conn, filler + LINE * K)).1
    };
    // A bound, not a synchronisation: a writer the carrier never wakes leaves this pending forever.
    let bytes = tokio::time::timeout(std::time::Duration::from_secs(30), all)
        .await
        .expect("every waiting writer was woken and wrote its line");
    let mut seen = std::collections::BTreeSet::new();
    for line in bytes.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
        let line = std::str::from_utf8(line).expect("utf8");
        assert!(
            line.starts_with("writer-") && line.len() == 9,
            "no interleaving within a line: {line:?}"
        );
        seen.insert(line.to_string());
    }
    assert_eq!(
        seen.len(),
        K,
        "every writer's line arrived exactly once, unmangled"
    );
    wait(|cx| c.poll_close(conn, cx, CloseReason::Normal))
        .await
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
