// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! 1f (§A3 1f): a 1.5.5 still serving on this host is found by its `listen` before anything is
//! written; a free address passes and stays free; a bind error that is not `EADDRINUSE` is skipped.

use std::net::TcpListener;
use std::time::{Duration, Instant};

use super::*;

const QUICK: Duration = Duration::from_millis(300);
const STEP: Duration = Duration::from_millis(50);

/// (o) an address another process serves on is refused LIVE_WRITER, after the retries.
#[test]
fn an_address_in_use_is_a_live_writer() {
    let serving = TcpListener::bind("127.0.0.1:0").expect("a 1.5.5 stand-in serves");
    let address = serving.local_addr().expect("its address").to_string();
    let started = Instant::now();
    let refused = probe_within(&[&address], QUICK, STEP).unwrap_err();
    assert_eq!(refused.word(), "LIVE_WRITER");
    let text = refused.to_string();
    assert!(text.contains(&address), "{text}");
    assert!(text.contains("stop every 1.5.5 instance"), "{text}");
    assert!(started.elapsed() >= QUICK, "retried until the bound");
}

/// (o) the second address counts too: `admin_listen` held, `listen` free.
#[test]
fn the_admin_address_is_probed_too() {
    let free = TcpListener::bind("127.0.0.1:0").expect("a free port");
    let listen = free.local_addr().expect("its address").to_string();
    drop(free);
    let serving = TcpListener::bind("127.0.0.1:0").expect("a 1.5.5 stand-in serves");
    let admin = serving.local_addr().expect("its address").to_string();
    let refused = probe_within(&[&listen, &admin], QUICK, STEP).unwrap_err();
    assert!(refused.to_string().contains(&admin), "{refused}");
}

/// (o1) the probe binds and releases each address: a free one passes and is free afterwards.
#[test]
fn a_free_address_passes_and_is_released() {
    let free = TcpListener::bind("127.0.0.1:0").expect("a free port");
    let address = free.local_addr().expect("its address").to_string();
    drop(free);
    assert_eq!(probe_within(&[&address], QUICK, STEP), Ok(()));
    assert!(
        TcpListener::bind(&address).is_ok(),
        "the probe released {address}"
    );
}

/// (o1) the holder going away within the bound passes: the retry sees the port free.
#[test]
fn a_holder_that_stops_within_the_bound_passes() {
    let serving = TcpListener::bind("127.0.0.1:0").expect("a 1.5.5 stand-in serves");
    let address = serving.local_addr().expect("its address").to_string();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(serving);
        });
        assert_eq!(
            probe_within(&[&address], Duration::from_secs(5), STEP),
            Ok(())
        );
    });
}

/// Not a sign of 1.5.5: an address that does not parse or cannot be bound for another reason is
/// skipped here (the boot's own bind reports it).
#[test]
fn another_bind_error_is_skipped() {
    assert_eq!(
        probe_within(&["not an address", "unix:/run/busbar.sock"], QUICK, STEP),
        Ok(())
    );
}
