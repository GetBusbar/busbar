// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STREAM TARGET (SDK-SAFE-TEST-HOST §11.1-11.3, Part A): a stream framer
//! (`FRAMING_STREAM`, `FACT_ACCEPTS`: ws) served on loopback TCP, on `std::net` only. Each image
//! is opened on its own [`PluginThread`] with the driver's host, and each accepted connection
//! gets a thread that reads its socket and drives the framer through the loader's real
//! dispatcher, exactly as the connector drives one (§11.2):
//!
//! - **Accept:** BEGIN on `SIDE_ACCEPT`, with the scheme ([`Framer::scheme`]) and the facts
//!   ([`Framer::facts`]).
//! - **Read:** INGEST each read, then act on every answer's yield flags: `YIELD_MORE` re-calls the
//!   same op with no new bytes (a BEGIN's re-call is TIMER, as the connector's is);
//!   `YIELD_HAS_DEADLINE` arms TIMER at `next_deadline_ns`; `YIELD_ENDED` FINISHes.
//! - **Write:** `wire` bytes go to the socket as each answer hands them; payload pieces are
//!   assembled into whole messages for the handler ([`Framer::handler`], default [`echo`]), and
//!   each [`Emit`] becomes an EMIT on its stream. Field blocks (a head, trailers) are never a
//!   message.
//! - **Stream flow:** an EMIT answered `YIELD_STREAM_FULL` holds every later message of its
//!   stream until the framer hands a `PIECE_WRITABLE` piece on it (or the stream's end or
//!   failure), as the contract's stream flow says and the connector does.
//! - **EOF:** INGEST with `end = 1`, then FINISH with `CLOSE_PEER_CLOSED`.
//!
//! The sink lends the connector's real initial sizes ([`WIRE_CAP`], [`FRAME_CAP`],
//! [`PIECES_CAP`], [`HEADS_CAP`]). The run fails (§10.3) when a framer answers SHORT, or FAULT
//! (a ticket-less PENDING is judged FAULT), when a message grows past [`Framer::max_message`]
//! (the connection is FINISHed, never truncated), when a framer owes more [`MORE_STALLS`] times in
//! a row and writes nothing, and when an image's plugin thread or a connection's thread is gone.

use std::sync::Arc;

use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::sdk::test_support::loans::Loans;
use busbar_contract::abi::sdk::test_support::mutant::Mutant;
use busbar_contract::abi::transport::ConnFacts;
use busbar_plugin_loader::test_host::Host;

use super::{Binding, Listening, Refused, Subject};

/// The wire buffer every framer op is lent: the connector's initial size.
pub const WIRE_CAP: usize = 64 * 1024;
/// The frame buffer every framer op is lent: the connector's initial size.
pub const FRAME_CAP: usize = 64 * 1024;
/// The frame pieces every framer op is lent: the connector's initial count.
pub const PIECES_CAP: usize = 64;
/// The head slots every framer op is lent: the connector's initial count.
pub const HEADS_CAP: usize = 16;
/// The default bound on one message under assembly (§11.3): Autobahn's largest case is 16 MiB.
pub const MAX_MESSAGE: usize = 64 * 1024 * 1024;
/// `YIELD_MORE` answers in a row that write nothing before the run fails: the connector's bound.
pub const MORE_STALLS: usize = 64;

/// Builds each image's host on its plugin thread.
type MakeHost = dyn Fn() -> Host + Send + Sync;
/// Writes what connection security established into BEGIN's facts.
type FactsFn = dyn Fn(&mut Loans<ConnFacts>) + Send + Sync;
/// Answers one whole message with what to emit.
type HandlerFn = dyn Fn(Message<'_>) -> Vec<Emit> + Send + Sync;

#[derive(Debug, Clone, Copy)]
pub struct Message<'a> {
    /// The stream it arrived on.
    pub stream: u64,
    /// Its bytes, every piece of it in order.
    pub bytes: &'a [u8],
    /// The framer marked it text (`PIECE_TEXT`).
    pub text: bool,
}

/// One message to hand the framer: an EMIT on `stream`, the whole frame in one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Emit {
    /// The stream.
    pub stream: u64,
    /// The bytes.
    pub bytes: Vec<u8>,
    /// A text message (`EMIT_TEXT`).
    pub text: bool,
}

/// The default handler (§11.3): each whole message back on its stream, in order, with its text
/// flag kept. It never validates UTF-8 and never looks inside a payload: validation is the
/// framer's, which is what a conformance suite judges.
#[must_use]
pub fn echo(m: Message<'_>) -> Vec<Emit> {
    vec![Emit {
        stream: m.stream,
        bytes: m.bytes.to_vec(),
        text: m.text,
    }]
}

/// A stream framer target: this plugin's own framer door, linked and as its cdylib, each image on
/// its own loopback TCP listener.
pub struct Framer {
    lib: String,
    door: DoorFn,
    host: Arc<MakeHost>,
    settings: Arc<[u8]>,
    scheme: u8,
    facts: Option<Arc<FactsFn>>,
    handler: Arc<HandlerFn>,
    max_message: usize,
    mutant: Option<Box<Mutant>>,
    armed: bool,
}

impl From<Framer> for Subject {
    fn from(framer: Framer) -> Self {
        Self::Stream(framer)
    }
}

impl Framer {
    /// The framer `door`, whose cdylib is built from `lib_name`, opened on the host `host` builds.
    #[must_use]
    pub fn new(
        _lib_name: &str,
        _door: DoorFn,
        _host: impl Fn() -> Host + Send + Sync + 'static,
    ) -> Self {
        todo!("T1b: the stream target")
    }

    /// The OPEN settings (JSON).
    #[must_use]
    pub fn settings(self, _json: &[u8]) -> Self {
        todo!("T1b: the stream target")
    }

    /// BEGIN's scheme (`SCHEME_*`); default `SCHEME_PLAIN`.
    #[must_use]
    pub fn scheme(self, _code: u8) -> Self {
        todo!("T1b: the stream target")
    }

    /// Writes what connection security established into each BEGIN's facts.
    #[must_use]
    pub fn facts(self, _f: impl Fn(&mut Loans<ConnFacts>) + Send + Sync + 'static) -> Self {
        todo!("T1b: the stream target")
    }

    /// Answers each whole message; default [`echo`].
    #[must_use]
    pub fn handler(self, _f: impl Fn(Message<'_>) -> Vec<Emit> + Send + Sync + 'static) -> Self {
        todo!("T1b: the stream target")
    }

    /// The most bytes one message may grow to under assembly.
    #[must_use]
    pub fn max_message(self, _bytes: usize) -> Self {
        todo!("T1b: the stream target")
    }

    /// The negative-control leg's mutant (§11.6), served once armed.
    #[must_use]
    pub fn mutant(self, _m: Mutant) -> Self {
        todo!("T1b: the stream target")
    }

    /// Arms the mutant leg in-process: what `--mutant` does for `main`.
    #[must_use]
    pub fn arm(self) -> Self {
        todo!("T1b: the stream target")
    }

    /// Opens `image` and serves it on a loopback TCP listener.
    ///
    /// # Errors
    /// When the image is refused or the listener cannot start.
    pub fn bind(&self, _image: &'static str, _at: &Binding<'_>) -> Result<Listening, Refused> {
        todo!("T1b: the stream target")
    }

    /// The stream target's one flag with a value, `--max-message BYTES`.
    ///
    /// # Errors
    /// When `flag` is not `--max-message`, or its value is not a byte count.
    pub fn flag(&mut self, _flag: &str, _value: &str) -> Result<(), Refused> {
        todo!("T1b: the stream target")
    }

    /// The stream target's one flag with no value, `--mutant`.
    pub fn switch(&mut self, _flag: &str) -> bool {
        todo!("T1b: the stream target")
    }
}
