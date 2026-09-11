// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plugin/src/hot/pipe.rs` — the FAIL-CLOSED edges of the byte duplex: an id
//! the registry does not hold, and a call that arrives with no live host context at all.
//!
//! These spawn nothing. The duplex over a real child — bytes written, bytes echoed back, the arena
//! reclaiming a child the plane never closed — is proved on the SERVED path, where the engine composes
//! the real host vtable over a live snapshot, which only that engine can construct. What is proved
//! here is what needs no engine and no child: every verb's answer when the id is not in the map, and
//! that the host-context check comes FIRST, before the map is even consulted.

use super::*;

/// A non-null stand-in for the opaque host context. These two verbs never dereference it (a pipe is
/// keyed by its `PipeId`); they check only that a live one was passed, so any live address serves.
fn live_host(buf: &mut [u8; 8]) -> HostCtx {
    std::ptr::from_mut(buf).cast::<std::ffi::c_void>()
}

#[test]
fn an_id_the_registry_does_not_hold_is_gone_to_every_verb() {
    // `NONE` is the reserved sentinel; a maximal id was never minted by this process's atomic.
    for pipe in [PipeId::NONE, PipeId(u64::MAX)] {
        assert!(!is_open(pipe), "an id the map does not hold is never open");
        assert!(!close_pipe(pipe), "closing it elects no closer");
        let mut buf = [0u8; 8];
        let mut written = 0usize;
        let host = live_host(&mut buf.clone());
        // The ABI's stale-handle class — not a fault, and never a silent success.
        assert_eq!(
            pipe_read(host, pipe, buf.as_mut_ptr(), buf.len(), &mut written),
            StatusClass::Gone
        );
        assert_eq!(
            pipe_write(host, pipe, buf.as_ptr(), buf.len()),
            StatusClass::Gone
        );
    }
}

#[test]
fn a_null_host_context_is_refused_before_the_registry_is_consulted() {
    // A null `HostCtx` is never a live call, so both verbs refuse. The ORDER is the assertion: the same
    // id answers `Gone` under a live context (above) and `Refused` under a null one, which can only be
    // true if the context check runs FIRST. A verb that looked the id up first would answer `Gone` here
    // and quietly serve a null-context call for an id that WAS open.
    let mut buf = [0u8; 8];
    let mut written = 0usize;
    let pipe = PipeId(u64::MAX);
    assert_eq!(
        pipe_read(
            std::ptr::null_mut(),
            pipe,
            buf.as_mut_ptr(),
            buf.len(),
            &mut written
        ),
        StatusClass::Refused
    );
    assert_eq!(
        pipe_write(std::ptr::null_mut(), pipe, buf.as_ptr(), buf.len()),
        StatusClass::Refused
    );
}

#[test]
fn a_null_out_written_is_refused_rather_than_written_through() {
    // The read's out-param is where the byte count lands; with nowhere to put it the call is refused
    // rather than performed and its result dropped (a read whose count nobody hears is a lost byte).
    let mut buf = [0u8; 8];
    let host = live_host(&mut buf.clone());
    assert_eq!(
        pipe_read(
            host,
            PipeId(u64::MAX),
            buf.as_mut_ptr(),
            buf.len(),
            std::ptr::null_mut()
        ),
        StatusClass::Refused
    );
}

#[test]
fn the_none_sentinel_is_never_open_even_as_a_raw_zero() {
    // `PipeId::NONE` is zero and the mint starts at one, so zero can never be a live key; `is_open` says
    // so without consulting the map, which is what makes it safe for a caller to ask about any id.
    assert_eq!(PipeId::NONE.0, 0, "the sentinel is the reserved zero");
    assert!(!is_open(PipeId(0)));
}
