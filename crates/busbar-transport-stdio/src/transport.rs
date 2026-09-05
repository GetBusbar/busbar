// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The [`busbar_contract::Transport`] implementation itself.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as SyncMutex};

use futures::Stream;
use tokio::io::AsyncWriteExt;

use busbar_contract::dest::{DestinationFacts, VerifiedDestination};
use busbar_contract::unit::Refusal;
use busbar_contract::wire::Frame;
use busbar_contract::{
    grammar::SelectorForm, ArenaBytes, Fut, Kind, Plugin, SlabBytes, StreamId, Transport,
    TransportConfigView, TransportKeyHandle, TransportMeta,
};
use busbar_contract_transport::wire::ArrivalRecord;
use busbar_contract_transport::wire::CloseReason;
use busbar_contract_transport::wire::Conn;
use busbar_contract_transport::wire::Direction;
use busbar_contract_transport::wire::FrameMeta;
use busbar_contract_transport::wire::Listener;
use busbar_contract_transport::wire::ListenerHandle;
use busbar_contract_transport::wire::TransportError;
use busbar_contract_transport::wire::Unit0Trigger;
use busbar_contract_transport::AbiVersion;

use crate::conn::{ConnState, StdioConnHandle};

/// stdio's own frame stream: bytes split one line at a time, exactly the "duplex framed" shape the
/// architecture's stdio row names.
type FrameStream =
    std::pin::Pin<Box<dyn Stream<Item = Result<(StreamId, Frame), TransportError>> + Send>>;

/// Poisons a connection unless disarmed — the "cancel mid-frame" fence. A write that never reaches
/// its clean-completion disarm, for ANY reason (an I/O error via the early-return `?`, or this
/// whole future being dropped by a cancelling caller), leaves the connection unable to serve
/// another write or read: the wire may hold a partial line, and this transport refuses to guess
/// where it ends.
struct PoisonGuard<'a> {
    state: &'a ConnState,
    armed: bool,
}

impl Drop for PoisonGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.state.poisoned.store(true, Ordering::Release);
        }
    }
}

/// A single-shot listener: stdio has no notion of repeated accepts on one bind, because the process
/// has exactly one stdin/stdout. `accept` succeeds exactly once.
struct StdioListenerHandle;

impl ListenerHandle for StdioListenerHandle {
    fn local_addr(&self) -> String {
        "stdio:own-process".to_string()
    }
}

/// The stdio transport. In-tree, inside the trusted computing base, never dynamically loaded — see
/// the architecture doc's transport and transports-table sections.
pub struct StdioTransport {
    next_id: AtomicU64,
    conns: SyncMutex<HashMap<u64, Arc<ConnState>>>,
    /// Whether the process's own stdio has already been handed out by `accept`. `None` until
    /// `listen` is called for real process stdio (as opposed to the test-only [`Self::wrap_pair`]
    /// path, which never touches this).
    own_stdio_taken: AtomicBool,
}

impl Default for StdioTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl StdioTransport {
    /// A fresh transport instance with no live connections.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            conns: SyncMutex::new(HashMap::new()),
            own_stdio_taken: AtomicBool::new(false),
        }
    }

    fn mint_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn insert(&self, id: u64, state: Arc<ConnState>) {
        self.conns.lock().unwrap().insert(id, state);
    }

    pub(crate) fn state_of(&self, id: u64) -> Option<Arc<ConnState>> {
        self.conns.lock().unwrap().get(&id).cloned()
    }

    /// Wrap ANY reader/writer pair as a live connection. Generic so the battery drives an in-memory
    /// duplex through the identical path real stdio and a spawned child use — mirroring the
    /// 1.5.5-era `serve_io` test seam this crate's byte-level behaviour was moved out of.
    #[must_use]
    pub fn wrap_pair<R, W>(&self, reader: R, writer: W, peer: &str) -> Conn
    where
        R: tokio::io::AsyncRead + Send + Unpin + 'static,
        W: tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let id = self.mint_id();
        let state = ConnState::new(Box::new(reader), Box::new(writer), None);
        self.insert(id, state);
        Conn::new(Arc::new(StdioConnHandle {
            id,
            peer: peer.to_string(),
        }))
    }

    /// Spawn a child process and wrap its stdin/stdout as a live connection.
    ///
    /// No shell and an absolute path only. The environment is cleared first and then set from what
    /// the destination declared, so a child never inherits the node's own credentials by accident:
    /// an empty declaration is an empty environment, which is the posture to default to.
    async fn spawn_child(
        &self,
        program: &str,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> Result<Conn, TransportError> {
        if !program.starts_with('/') {
            return Err(TransportError::AddressRefused);
        }
        let mut cmd = tokio::process::Command::new(program);
        cmd.args(args);
        cmd.env_clear();
        for (name, value) in env {
            cmd.env(name, value);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|_| TransportError::Refused)?;
        let stdin = child.stdin.take().ok_or(TransportError::Refused)?;
        let stdout = child.stdout.take().ok_or(TransportError::Refused)?;
        let id = self.mint_id();
        let state = ConnState::new(Box::new(stdout), Box::new(stdin), Some(child));
        self.insert(id, state);
        Ok(Conn::new(Arc::new(StdioConnHandle {
            id,
            peer: program.to_string(),
        })))
    }
}

impl Plugin for StdioTransport {
    fn key(&self) -> &'static str {
        <Self as TransportMeta>::KEY
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> AbiVersion {
        busbar_contract_transport::registry::TRANSPORT_ABI
    }
}

impl TransportMeta for StdioTransport {
    const KEY: &'static str = "stdio";
    // stdio carries no header, path or handshake surface to select on: a claim on this transport
    // can only ever be the whole channel. Empty rather than guessed — see the crate report.
    const SELECTOR_FORMS: &'static [SelectorForm] = &[];
    const EGRESS_SELECTOR_FORMS: &'static [SelectorForm] = &[];
    const COMPOSES_OVER: &'static [&'static str] = &[];
    const HANDOFF: Option<busbar_contract_transport::wire::Handoff> = None;
    const FRAMING: busbar_contract_transport::wire::Framing =
        busbar_contract_transport::wire::Framing::Stream;
    const SESSION: bool = true;
    const SESSION_BOUND: bool = true;
    const UNIT0_TRIGGER: Option<Unit0Trigger> = Some(Unit0Trigger::FirstMessage);
    const UPGRADES_TO: &'static [&'static str] = &[];
    const HANDSHAKE_TRIGGER: Option<busbar_contract_transport::wire::HandshakeTrigger> = None;
    // No transport-level fact this carrier writes beyond the arrival record itself.
    const TRANSPORT_FACTS: &'static [&'static str] = &[];
    const DECODES_PAYLOAD: bool = false;
    // The transports table names no status leg for stdio; the plane's own `finish` class is the fee's sole
    // source here.
    const STATUS_CLASS: Option<busbar_contract_transport::wire::StatusAt> = None;
}

impl Transport for StdioTransport {
    fn arrival(&self, conn: &Conn) -> ArrivalRecord {
        ArrivalRecord {
            source: conn.peer(),
            port: 0,
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: vec!["stdio"],
        }
    }

    fn listen<'a>(
        &'a self,
        _cfg: &'a dyn TransportConfigView,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Listener> {
        Box::pin(async move { Ok(Listener::new(Arc::new(StdioListenerHandle))) })
    }

    fn accept<'a>(&'a self, _l: &'a Listener) -> Fut<'a, Conn> {
        Box::pin(async move {
            if self
                .own_stdio_taken
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                // stdio has exactly one connection for the life of the process; a second accept
                // on the same listener has nothing left to hand out.
                return Err(TransportError::Closed);
            }
            let id = self.mint_id();
            let state = ConnState::new(
                Box::new(tokio::io::stdin()),
                Box::new(tokio::io::stdout()),
                None,
            );
            self.insert(id, state);
            Ok(Conn::new(Arc::new(StdioConnHandle {
                id,
                peer: "stdio:own-process".to_string(),
            })))
        })
    }

    fn dial<'a>(
        &'a self,
        dest: &'a VerifiedDestination,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            let DestinationFacts::Upstream { address, .. } = dest.facts() else {
                return Err(TransportError::AddressRefused);
            };
            let program = address.program().ok_or(TransportError::AddressRefused)?;
            self.spawn_child(program, address.args(), address.env())
                .await
        })
    }

    fn frames(&self, conn: Conn) -> FrameStream {
        let id = conn.id();
        let Some(state) = self.state_of(id) else {
            return Box::pin(futures::stream::once(async {
                Err::<(StreamId, Frame), TransportError>(TransportError::Closed)
            }));
        };
        Box::pin(futures::stream::unfold(
            (state, false),
            move |(state, done)| async move {
                if done || state.is_poisoned() {
                    return None;
                }
                let mut guard = state.reader.lock().await;
                let Some(mut buf) = guard.take() else {
                    // Another `frames()` call already consumed this connection's reader — a
                    // transport connection is read by exactly one pump, matching every other
                    // in-tree transport's `frames` contract.
                    return None;
                };
                drop(guard);
                let mut line: Vec<u8> = Vec::new();
                let item = loop {
                    line.clear();
                    match read_line(&mut buf, &mut line).await {
                        Ok(0) => break None, // EOF: the session ends
                        Ok(_) => {
                            if line.iter().all(u8::is_ascii_whitespace) {
                                continue; // a blank line carries no frame
                            }
                            let bytes = SlabBytes::new(Arc::<[u8]>::from(line.clone()));
                            let meta = FrameMeta {
                                bytes: bytes.len() as u64,
                                transport_units: None,
                                status: None,
                            };
                            break Some(Ok((
                                StreamId(0),
                                Frame {
                                    direction: Direction::Inbound,
                                    stream: StreamId(0),
                                    bytes,
                                    meta,
                                },
                            )));
                        }
                        Err(_) => break Some(Err(TransportError::Reset)),
                    }
                };
                // Hand the SAME `BufReader` back (readahead intact) so the NEXT poll of this
                // stream keeps reading exactly where this one left off.
                *state.reader.lock().await = Some(buf);
                match item {
                    None => None,
                    Some(result) => {
                        let done_next = result.is_err();
                        Some((result, (state, done_next)))
                    }
                }
            },
        ))
    }

    fn write<'a>(
        &'a self,
        conn: &'a Conn,
        _stream: StreamId,
        bytes: ArenaBytes<'a>,
    ) -> Fut<'a, usize> {
        let id = conn.id();
        Box::pin(async move {
            let Some(state) = self.state_of(id) else {
                return Err(TransportError::Closed);
            };
            if state.is_poisoned() {
                return Err(TransportError::Framing);
            }
            let payload = bytes.as_slice().to_vec();
            let n = payload.len();
            // Armed for the whole write; disarmed only on a clean completion. If THIS future is
            // dropped mid-write (a cancellation) the guard's `Drop` still runs and poisons the
            // connection — the same fencing an I/O error gets, and for the same reason: a write
            // that did not finish leaves no promise about what reached the wire.
            let mut guard = PoisonGuard {
                state: &state,
                armed: true,
            };
            let mut w = state.writer.lock().await;
            w.write_all(&payload)
                .await
                .map_err(|_| TransportError::Reset)?;
            w.write_all(b"\n")
                .await
                .map_err(|_| TransportError::Reset)?;
            w.flush().await.map_err(|_| TransportError::Reset)?;
            drop(w);
            guard.armed = false;
            Ok(n)
        })
    }

    /// One framed line. stdio has no header surface at all, so an envelope has nothing to write
    /// here: the frame IS the body, and `write` is what appends the delimiter.
    fn encode_envelope<'a>(
        &self,
        _fields: &[(&str, &[u8])],
        body: &[u8],
        arena: &'a dyn busbar_contract::Arena,
    ) -> Result<ArenaBytes<'a>, busbar_contract_transport::wire::Encode> {
        arena
            .alloc_bytes(body)
            .map_err(|_| busbar_contract_transport::wire::Encode::ArenaExhausted)
    }

    fn adopt<'a>(
        &'a self,
        _from: &'a dyn Transport,
        _conn: Conn,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        // stdio composes over nothing, so there is no layer whose stream it could take: a handoff
        // offered to it is one neither leg declared, which is what the mismatch says.
        Box::pin(async move { Err(TransportError::HandoffMismatch) })
    }

    fn close(&self, conn: Conn, _reason: CloseReason) {
        let id = conn.id();
        if let Some(state) = self.conns.lock().unwrap().remove(&id) {
            tokio::spawn(async move {
                if let Some(mut child) = state.child.lock().await.take() {
                    let _ = child.start_kill();
                }
            });
        }
    }

    fn unit0_refusal<'a>(
        &'a self,
        conn: Conn,
        // stdio is one channel; the connection is the whole of what can be refused.
        _stream: Option<StreamId>,
        _refusal: &'a Refusal,
        bytes: ArenaBytes<'a>,
    ) -> Fut<'a, ()> {
        Box::pin(async move {
            let id = conn.id();
            if let Some(state) = self.state_of(id) {
                if !state.is_poisoned() {
                    let payload = bytes.as_slice().to_vec();
                    let mut w = state.writer.lock().await;
                    let _ = w.write_all(&payload).await;
                    let _ = w.write_all(b"\n").await;
                    let _ = w.flush().await;
                }
            }
            self.close(conn, CloseReason::Normal);
            Ok(())
        })
    }
}

/// `read_until('\n', ...)` with the terminator stripped, and any trailing `\r` stripped too so a
/// peer that writes CRLF line endings is not handed a frame with a dangling carriage return.
async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> std::io::Result<usize> {
    use tokio::io::AsyncBufReadExt;
    let n = reader.read_until(b'\n', buf).await?;
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    }
    Ok(n)
}
