// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STREAM TARGET (SDK-SAFE-TEST-HOST §11.1-11.3, §11.9 T1b): the facade's own line framer
//! (`tests/fixtures/framer_door.rs`), linked and as its cdylib, served on loopback TCP and driven
//! as the connector drives a framer. Lines come back from both images; a partial line then EOF
//! ends in FINISH; a line longer than the fixture's eight-byte frame cap arrives through
//! `YIELD_MORE` re-calls and comes back whole; a full stream gets no EMIT until the framer hands it
//! writable; a PENDING answer and a message over `max_message` fail the run; a failing READY is
//! refused at start, and `main` writes the error; and `--mutant` serves the corrupting mutant, so
//! the fixture's echo check fails.

#[path = "fixtures/framer_door.rs"]
mod framer_door;

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use busbar_plugin_test::target::stream::Framer;
use busbar_plugin_test::target::{Images, Refused, Target, Unserved};
use busbar_plugin_test::{Host, Mutant, Refused as HostRefused};
use sonic_rs::JsonValueTrait;

/// The fixture's cdylib.
const LIB: &str = "framer_fixture";

/// What the fixture's FINISH writes when the target finishes with `CLOSE_PEER_CLOSED`.
const PEER_CLOSED: &[u8] = b"closed 1\n";

/// Each image's host, on the contract's dev-only test caller binding.
fn host() -> Host {
    Host::new(busbar_contract::services::test_caller_binding())
}

fn framer() -> Framer {
    Framer::new(LIB, framer_door::door, host)
}

/// Writes `bytes`, ends the write side, and reads everything back until the target closes.
fn exchange(addr: SocketAddr, bytes: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(60)))
        .expect("a timeout");
    s.write_all(bytes).expect("write");
    s.shutdown(Shutdown::Write).expect("end the write side");
    let mut back = Vec::new();
    s.read_to_end(&mut back)
        .expect("read until the target closes");
    back
}

/// `lines`, then what FINISH writes on EOF.
fn then_closed(lines: &[u8]) -> Vec<u8> {
    let mut v = lines.to_vec();
    v.extend_from_slice(PEER_CLOSED);
    v
}

#[test]
fn lines_come_back_from_both_images() {
    let served = Target::new(framer()).serve().expect("the target serves");
    for image in ["linked", "cdylib"] {
        let addr = served.addr(image);
        assert!(addr.ip().is_loopback(), "{image}: {addr}");
        assert_eq!(
            String::from_utf8_lossy(&exchange(addr, b"a\nb\n")),
            String::from_utf8_lossy(&then_closed(b"a\nb\n")),
            "{image}"
        );
    }
    served.finish().expect("everything asked was served");
}

#[test]
fn a_partial_line_then_eof_ends_in_finish() {
    let served = Target::new(framer())
        .images(Images::Linked)
        .serve()
        .expect("the target serves");
    assert_eq!(
        String::from_utf8_lossy(&exchange(served.addr("linked"), b"a\npart")),
        String::from_utf8_lossy(&then_closed(b"a\n")),
        "the partial line is dropped and FINISH says CLOSE_PEER_CLOSED"
    );
    served.finish().expect("an EOF is not a gap");
}

#[test]
fn a_line_past_the_fixture_s_frame_cap_comes_back_whole_through_yield_more() {
    let served = Target::new(framer()).serve().expect("the target serves");
    let mut line: Vec<u8> = (0..100u8).map(|i| b'a' + i % 26).collect();
    line.push(b'\n');
    for image in ["linked", "cdylib"] {
        assert_eq!(
            String::from_utf8_lossy(&exchange(served.addr(image), &line)),
            String::from_utf8_lossy(&then_closed(&line)),
            "{image}: thirteen eight-byte pieces make one message, and its echo crosses re-calls"
        );
    }
    served.finish().expect("everything asked was served");
}

#[test]
fn a_full_stream_gets_no_emit_until_the_framer_hands_it_writable() {
    let served = Target::new(framer()).serve().expect("the target serves");
    for image in ["linked", "cdylib"] {
        assert_eq!(
            String::from_utf8_lossy(&exchange(served.addr(image), b"full\nx\n")),
            String::from_utf8_lossy(&then_closed(b"full\nx\n")),
            "{image}: `x` waits for the TIMER that hands the stream writable; an EMIT before it \
             echoes `emit-while-full`, and a target that never calls TIMER never echoes `x`"
        );
    }
    served.finish().expect("everything asked was served");
}

#[test]
fn a_pending_answer_fails_the_run() {
    let served = Target::new(framer())
        .images(Images::Linked)
        .serve()
        .expect("the target serves");
    let back = exchange(served.addr("linked"), b"pending\n");
    assert!(!back.starts_with(b"pending"), "nothing is echoed: {back:?}");
    let Err(Unserved(unserved)) = served.finish() else {
        panic!("a PENDING answer (judged FAULT, no ticket) must fail the run");
    };
    assert!(
        unserved
            .iter()
            .any(|u| u.starts_with("linked: the framer answered FAULT on ingest")),
        "{unserved:?}"
    );
}

#[test]
fn a_message_over_max_message_fails_the_run() {
    let served = Target::new(framer().max_message(16))
        .images(Images::Linked)
        .serve()
        .expect("the target serves");
    let mut line = vec![b'm'; 100];
    line.push(b'\n');
    assert_eq!(
        String::from_utf8_lossy(&exchange(served.addr("linked"), &line)),
        "closed 7\n",
        "nothing is echoed or truncated; FINISH says CLOSE_CAPACITY_EXHAUSTED"
    );
    let Err(Unserved(unserved)) = served.finish() else {
        panic!("a message over max_message must fail the run");
    };
    assert_eq!(
        unserved,
        ["linked: a message over max_message (16 bytes) on stream 1"]
    );
}

#[test]
fn a_failing_ready_image_is_refused_at_start() {
    let refused = Target::new(
        framer()
            .mutant(Mutant::of(framer_door::door).failing_ready("fixture: never ready"))
            .arm(),
    )
    .images(Images::Linked)
    .serve()
    .err();
    assert!(
        matches!(
            &refused,
            Some(Refused::Image("linked", HostRefused::Ready(text)))
                if text == "plugin 'host-fixture-framer' ready failed: fixture: never ready"
        ),
        "{refused:?}"
    );
    let unarmed = Target::new(
        framer().mutant(Mutant::of(framer_door::door).failing_ready("fixture: never ready")),
    )
    .images(Images::Linked)
    .serve()
    .expect("an unarmed mutant is never served");
    unarmed.finish().expect("nothing was asked");
}

/// The facade's `[[example]]` binary `name`, built beside this test by `cargo test`.
fn example(name: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary");
    let profile = exe
        .parent()
        .and_then(Path::parent)
        .expect("target/<profile>/deps/<test>");
    let path = profile
        .join("examples")
        .join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    assert!(path.is_file(), "no example {}", path.display());
    path
}

/// A fresh scratch directory for one test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "busbar-target-stream-{}-{name}",
        std::process::id()
    ));
    drop(std::fs::remove_dir_all(&dir));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

#[test]
fn main_writes_the_error_of_a_failing_ready_image() {
    let dir = scratch("failing-ready");
    let ready = dir.join("ready.json");
    let out = Command::new(example("framer_target"))
        .args(["--mutant", "--images", "linked", "--ready-file"])
        .arg(&ready)
        .env("FRAMER_TARGET_MUTANT", "failing-ready")
        .stdin(Stdio::null())
        .output()
        .expect("run the framer target");
    assert_eq!(out.status.code(), Some(2), "refused at start: {out:?}");
    let text = std::fs::read_to_string(&ready).expect("the ready file names the error");
    assert!(
        text.contains("\"error\"") && text.contains("fixture: never ready"),
        "{text}"
    );
    drop(std::fs::remove_dir_all(&dir));
}

/// Starts the framer target on the linked image with `args`, and answers it and its address.
fn start(dir: &Path, args: &[&str]) -> (Child, SocketAddr) {
    let ready = dir.join("ready.json");
    drop(std::fs::remove_file(&ready));
    let mut child = Command::new(example("framer_target"))
        .args(["--images", "linked", "--ready-file"])
        .arg(&ready)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the framer target");
    let mut waited = 0;
    while !ready.is_file() {
        if let Some(status) = child.try_wait().expect("poll the target") {
            panic!("the target ended before it was ready: {status}");
        }
        assert!(waited < 3000, "the target was not ready within 60 s");
        std::thread::sleep(Duration::from_millis(20));
        waited += 1;
    }
    let text = std::fs::read_to_string(&ready).expect("the ready file");
    let doc: sonic_rs::Value = sonic_rs::from_str(&text).expect("the ready file is JSON");
    let addr = doc
        .get("images")
        .and_then(|v| v.get("linked"))
        .and_then(|v| v.get("addr"))
        .and_then(|v| v.as_str())
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| panic!("the linked address in {text}"));
    (child, addr)
}

/// Closes the target's stdin and answers its exit code and stderr.
fn stop(mut child: Child) -> (Option<i32>, String) {
    drop(child.stdin.take());
    let out = child
        .wait_with_output()
        .expect("the target ends when stdin closes");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn main_serves_the_corrupting_mutant_only_when_armed() {
    let dir = scratch("mutant");
    let (door, addr) = start(&dir, &[]);
    assert_eq!(
        exchange(addr, b"a\n"),
        then_closed(b"a\n"),
        "unarmed, the door itself is served"
    );
    let (code, stderr) = stop(door);
    assert_eq!(code, Some(0), "{stderr}");

    let (mutant, addr) = start(&dir, &["--mutant"]);
    let back = exchange(addr, b"a\n");
    assert_ne!(
        back,
        then_closed(b"a\n"),
        "the echo check fails on the mutant"
    );
    assert_eq!(
        (back.first().copied(), back.get(1..)),
        (Some(!b'a'), Some(&then_closed(b"\n")[..])),
        "exactly the first EMIT's first wire byte is flipped"
    );
    let (code, stderr) = stop(mutant);
    assert_eq!(
        code,
        Some(0),
        "the target served everything; the suite's own check is what fails: {stderr}"
    );
    drop(std::fs::remove_dir_all(&dir));
}
