// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One validator per answer grammar (DESIGN-interface-revision C.2 rule 2, G.1 item 3).
//!
//! An answer is judged in two steps, and each step has exactly one function behind it:
//!
//! 1. the envelope (the status, the FAIL record and what may stand beside it, a leading TOKEN):
//!    `Answer::parse`, run by the one crossing place on every answer of every kind;
//! 2. the method's own grammar on an OK answer (which records, how many, in what order, with which
//!    field values): the functions named below, one per method.
//!
//! The adapters decode with these same functions and the conformance suites judge with them through
//! this module, so the engine and a suite cannot disagree about whether an answer is a breach: there is
//! no second copy of any grammar to disagree with. A kind's module here holds no grammar of its own; it
//! only names the method's function and discards the decoded value.
//!
//! Every function takes the validated envelope of an OK answer and says `Ok(())` or the fault the
//! engine would charge the instance with.

use busbar_plugin_abi::fail::FaultReason;
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::records::RecErr;
use busbar_plugin_abi::types::Status;

/// The fault of a grammar breach: an unknown tag is `UnknownTag`, anything else `BadRecords`.
pub fn fault(e: RecErr) -> FaultReason {
    match e {
        RecErr::Unknown(tag) => FaultReason::UnknownTag(tag),
        other => FaultReason::BadRecords(other),
    }
}

/// A method grammar speaks only of OK answers; REFUSED and FAILED were judged whole by the envelope.
fn ok_only(a: &Answer<'_>) -> bool {
    a.status == Status::OK
}

fn judged<T>(
    a: &Answer<'_>,
    decode: impl FnOnce() -> Result<T, RecErr>,
) -> Result<(), FaultReason> {
    if !ok_only(a) {
        return Ok(());
    }
    decode().map(drop).map_err(fault)
}

/// Store: `read`, `scan`, `commit`, `clock`, `info`.
pub mod store {
    use super::{judged, Answer, FaultReason};
    use busbar_ports::codec::store as codec;

    /// `read` of `n` keys.
    pub fn read(a: &Answer<'_>, n: usize) -> Result<(), FaultReason> {
        judged(a, || codec::decode_read(a, n))
    }
    /// `scan` of `namespace`.
    pub fn scan(a: &Answer<'_>, namespace: [u8; 16]) -> Result<(), FaultReason> {
        judged(a, || codec::decode_scan(a, namespace))
    }
    pub fn commit(a: &Answer<'_>) -> Result<(), FaultReason> {
        judged(a, || codec::decode_decision(a))
    }
    pub fn clock(a: &Answer<'_>) -> Result<(), FaultReason> {
        judged(a, || codec::decode_clock(a))
    }
    pub fn info(a: &Answer<'_>) -> Result<(), FaultReason> {
        judged(a, || codec::decode_info(a))
    }
}

/// Secret: `resolve`.
pub mod secret {
    use super::{judged, Answer, FaultReason};

    pub fn resolve(a: &Answer<'_>) -> Result<(), FaultReason> {
        judged(a, || crate::adapters::secret::answer_value(a.records()))
    }
}

/// Auth: `verify`, `verify_io`, `login`, `outbound`, `refresh`, `serve`.
pub mod auth {
    use super::{judged, Answer, FaultReason};
    use crate::adapters::auth as grammar;

    /// `verify` and `verify_io` share one answer grammar.
    pub fn verify(a: &Answer<'_>) -> Result<(), FaultReason> {
        judged(a, || busbar_ports::auth::decode_verify_ok(a.records()))
    }
    /// `login` at `step`; `connect` says the COMPLETE step was for a caller connection (a GRANT answer).
    pub fn login(a: &Answer<'_>, step: u32, connect: bool) -> Result<(), FaultReason> {
        judged(a, || grammar::decode_login(step, connect, a.records()))
    }
    pub fn outbound(a: &Answer<'_>) -> Result<(), FaultReason> {
        judged(a, || grammar::decode_outbound(a.records()))
    }
    pub fn refresh(a: &Answer<'_>) -> Result<(), FaultReason> {
        judged(a, || grammar::decode_refresh(a.records()))
    }
    pub fn serve(a: &Answer<'_>) -> Result<(), FaultReason> {
        judged(a, || busbar_ports::codec::auth::decode_serve(a))
    }
}

/// Hook: `on`, `on_io` (one grammar).
pub mod hook {
    use super::{judged, Answer, FaultReason};
    use busbar_plugin_abi::host_side::scrub::Scrub;

    pub fn on(a: &Answer<'_>, scrub: &Scrub) -> Result<(), FaultReason> {
        judged(a, || {
            crate::adapters::hook::decode_answer(a.records(), scrub)
        })
    }
}

/// Export: `deliver`, `render`, `confirm`.
pub mod export {
    use super::{judged, Answer, FaultReason};
    use crate::adapters::export as grammar;
    use busbar_ports::codec::export as codec;

    /// `deliver`; `confirm` says the image declared `confirm`, `dest_count` its bound destinations.
    pub fn deliver(a: &Answer<'_>, confirm: bool, dest_count: u32) -> Result<(), FaultReason> {
        judged(a, || {
            let (accepted, append, custody) = codec::decode_delivered(a, confirm)?;
            grammar::delivered_from(accepted, append, custody, dest_count)
        })
    }
    pub fn render(a: &Answer<'_>) -> Result<(), FaultReason> {
        judged(a, || grammar::rendered(a.records()))
    }
    pub fn confirm(a: &Answer<'_>) -> Result<(), FaultReason> {
        judged(a, || codec::decode_confirmed(a))
    }
}

/// Plane: the eleven methods, through the plane's one answer walk.
pub mod plane {
    use super::{ok_only, Answer, FaultReason};
    use crate::adapters::plane as grammar;
    use busbar_plugin_abi::fallback_usage::SelectedResource;
    use busbar_ports::codec::fallback_usage::Declaration;

    pub use crate::adapters::plane::Call;

    /// What the plane's grammar depends on beside the call: whether the image declared `demux`, its
    /// usage declaration, the resource selected for an `upstream` attempt, and a `piece`'s exchange.
    #[derive(Clone, Copy)]
    pub struct Context<'a> {
        pub demux: bool,
        pub declaration: Declaration<'a>,
        pub selected: Option<SelectedResource<'a>>,
        pub exchange: Option<u32>,
    }

    /// An OK answer of `call` (request, upstream, channel, piece, end, rewrite, render, probe, demux, or
    /// the admin tick).
    pub fn answer(a: &Answer<'_>, call: Call, cx: Context<'_>) -> Result<(), FaultReason> {
        if !ok_only(a) {
            return Ok(());
        }
        grammar::decode_answer(
            call,
            cx.demux,
            cx.declaration,
            cx.selected,
            cx.exchange,
            a.records(),
            &mut |_: busbar_ports::plane::PlaneOut<'_>| {},
        )
    }
}

/// Transport: `begin`, `ingest`, `emit`, `timer`, `datagram`, `event` through the transport's one
/// answer walk, and `offer`.
pub mod transport {
    use super::{judged, ok_only, Answer, FaultReason};
    use crate::adapters::transport as grammar;

    pub use crate::adapters::transport::Call;

    /// An OK answer of a session call.
    pub fn answer(a: &Answer<'_>, call: Call<'_>) -> Result<(), FaultReason> {
        if !ok_only(a) {
            return Ok(());
        }
        grammar::decode(
            a.records(),
            call,
            &mut |_: busbar_ports::transport::TransportOut<'_>| {},
        )
        .map_err(grammar::Bad::reason)
    }
    /// `offer` for `role`.
    pub fn offer(a: &Answer<'_>, role: u32) -> Result<(), FaultReason> {
        judged(a, || busbar_ports::codec::transport::decode_offer(a, role))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin_abi::records::{Reply, Writer};

    fn ok(reply: &Reply) -> Answer<'_> {
        Answer::parse(Status::OK, reply.as_bytes()).expect("a well-formed envelope")
    }

    #[test]
    fn an_unknown_tag_is_an_unknown_tag_fault_and_anything_else_bad_records() {
        assert_eq!(
            fault(RecErr::Unknown(0x0177)),
            FaultReason::UnknownTag(0x0177)
        );
        assert_eq!(
            fault(RecErr::Truncated),
            FaultReason::BadRecords(RecErr::Truncated)
        );
    }

    #[test]
    fn an_empty_render_answer_is_a_breach_for_the_adapter_and_the_suite_alike() {
        let reply = Reply::new();
        let a = ok(&reply);
        assert_eq!(
            export::render(&a),
            Err(FaultReason::BadRecords(RecErr::Truncated))
        );
        assert_eq!(
            crate::adapters::export::rendered(a.records()).map(drop),
            Err(RecErr::Truncated)
        );
    }

    #[test]
    fn a_foreign_record_in_a_secret_answer_is_named_by_its_tag() {
        let mut reply = Reply::new();
        reply.put(0x01F0, b"x").unwrap();
        let a = ok(&reply);
        assert_eq!(secret::resolve(&a), Err(FaultReason::UnknownTag(0x01F0)));
    }

    #[test]
    fn an_empty_transport_answer_is_a_valid_answer_of_every_session_call() {
        let reply = Reply::new();
        let a = ok(&reply);
        for call in [
            transport::Call::Begin,
            transport::Call::Ingest,
            transport::Call::Other,
        ] {
            assert_eq!(transport::answer(&a, call), Ok(()));
        }
    }
}
