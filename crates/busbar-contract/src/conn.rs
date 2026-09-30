// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTION TABLE (the design's connections: "every plugin that needs an external connection
//! declares a need, and the kernel instantiates the transport"). One host table serves every kind —
//! a plane, an exporter, a store driver, a secret plugin — and never learns which: a plugin opens a
//! connection for one of the needs it DECLARED, then writes, reads, waits and closes it by a
//! [`ConnId`]. No plugin opens a socket, dials, binds or does TLS; the connector behind this table
//! does.
//!
//! A [`ConnId`] belongs to the plugin instance that opened it. Every operation names the caller
//! (the host knows it from the instance's own context, a plugin cannot state it), and an id the
//! caller does not own is refused — as is an id already closed, and a need the caller never
//! declared. [`ConnSlab`] is that bookkeeping, shared by every host implementation.
//!
//! This is the LINKED source of truth; `abi::host::conn` is its mechanical `#[repr(C)]` lowering, one
//! slot per [`Conns`] method.

use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use crate::abi::mechanism::rendering::ReadNeed;
use crate::ids::StreamId;
use crate::transport::wire::WireStatusClass;
use crate::transport::ConnFacts;

/// A plugin instance, as the host numbers it. Never stated by a plugin: the host reads it off the
/// instance's own context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InstanceId(pub u64);

/// One need a plugin declared, by its position in the plugin's declared needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NeedId(pub u32);

/// An open connection. Its value carries a generation, so a closed id never names a later
/// connection that reused its slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnId(pub u64);

/// What opening a connection asks for: where, the head fields and body to open with (a framed
/// transport sends them as its first message; a raw byte stream takes none), and how long the open
/// may take.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpenDesc<'a> {
    /// The target, as the operator's settings spell it (the need's `target_from`).
    pub target: &'a str,
    /// Head fields, in order.
    pub fields: &'a [(&'a str, &'a [u8])],
    /// The body sent with the opening message.
    pub body: &'a [u8],
    /// Milliseconds the open may take; `0` = the host's default.
    pub timeout_ms: u64,
}

/// What a piece a connection delivered carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PieceKind {
    /// Payload bytes.
    Body,
    /// A head: the far end's fields, as the field block
    /// ([`crate::abi::transport::fields`]) renders them, hop-by-hop fields dropped. The far end's
    /// HEAD is ONE fields frame, the answer's FIRST, carrying the status; it comes even when empty
    /// (a `len` of `0`), so it always precedes the first [`PieceKind::Body`]. A fields frame after
    /// the body is the far end's trailers.
    Fields,
    /// A hook's answer.
    HookReply,
    /// The exchange finished; no bytes.
    Completion,
}

/// One piece a connection delivered: what it is, the stream it came on, how many bytes of the
/// caller's buffer it filled, whether it ends its frame, and the status it reports where the wire
/// reports one — in the numbering `status_namespace` names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Piece {
    /// What the piece carries.
    pub kind: PieceKind,
    /// The stream it came on (`StreamId(0)` on a wire with one).
    pub stream: StreamId,
    /// How many bytes of the caller's buffer it filled.
    pub len: usize,
    /// This piece ends its frame.
    pub end: bool,
    /// The status class it reports.
    pub status: Option<WireStatusClass>,
    /// The exact status number it reports.
    pub status_code: Option<u32>,
    /// The numbering `status_code` is spelled in.
    pub status_namespace: Option<String>,
    /// How long the far side asked to be left alone, in seconds.
    pub retry_after_secs: Option<u64>,
}

/// Why a connection operation did not answer with what was asked. The refusals carry the text an
/// operator reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConnError {
    /// Nothing is ready yet. Interest is registered for the caller's [`Ticket`]; the host wakes the
    /// ticket when something is, and the caller asks again then. Never a block.
    Pending,
    /// The operation's deadline CLASS passed, as the host enforces it.
    Timeout,
    /// The connection is closed, or was never opened.
    Closed,
    /// The connection belongs to another plugin instance.
    NotOwner,
    /// The caller never declared this need.
    UndeclaredNeed,
    /// The open was refused (the target, the egress rules, or the far end said no).
    Refused,
    /// The host failed the call.
    Fault,
    /// The plugin was handed no connection table: its host's open/refresh tables gave THIS instance
    /// none. Decided per instance, never per image.
    Unarmed,
}

impl ConnError {
    /// The refusal's text, as an operator reads it.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::Pending => "nothing is ready on the connection yet",
            Self::Timeout => "the connection's deadline passed",
            Self::Closed => "the connection is closed",
            Self::NotOwner => "the connection belongs to another plugin instance",
            Self::UndeclaredNeed => "the plugin did not declare this need",
            Self::Refused => "the connection was refused",
            Self::Fault => "the host failed the connection call",
            Self::Unarmed => "this plugin was handed no connection table",
        }
    }
}

impl std::fmt::Display for ConnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.text())
    }
}

impl std::error::Error for ConnError {}

/// THE CALLER'S WAKE TICKET: an opaque number the caller mints for the task waiting on a read or a
/// wait. Nothing blocks (THE DESIGN: every wait returns pending and a wake): a call with nothing
/// ready answers [`ConnError::Pending`] and registers interest under the ticket, and the host wakes
/// the ticket once the operation may progress. [`NO_TICKET`] registers nothing. Deadlines are not an
/// argument: each operation has a deadline CLASS the host enforces, answering
/// [`ConnError::Timeout`] when it passes.
pub type Ticket = u64;

/// The ticket that names no waiting task: a call handed it registers no interest.
pub const NO_TICKET: Ticket = 0;

/// THE HOST'S CONNECTION TABLE, as the host implements it. Every method names the `caller`, which
/// the host reads off the instance's own context.
pub trait Conns: Send + Sync {
    /// Open a connection for the caller's declared `need`.
    ///
    /// # Errors
    ///
    /// [`ConnError::UndeclaredNeed`], [`ConnError::Refused`], [`ConnError::Timeout`].
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError>;

    /// Offer `bytes` to the connection (`end` = the caller's message is complete); answers how many
    /// were taken.
    ///
    /// # Errors
    ///
    /// [`ConnError::NotOwner`], [`ConnError::Closed`], [`ConnError::Timeout`].
    fn write(
        &self,
        caller: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        end: bool,
    ) -> Result<usize, ConnError>;

    /// The next piece, its bytes into `buf`; with nothing ready, [`ConnError::Pending`] and interest
    /// registered under `ticket`.
    ///
    /// # Errors
    ///
    /// [`ConnError::Pending`], [`ConnError::Timeout`], [`ConnError::NotOwner`],
    /// [`ConnError::Closed`].
    fn read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        ticket: Ticket,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError>;

    /// The position in `set` of a connection with a piece ready; with none ready,
    /// [`ConnError::Pending`] and interest registered under `ticket` for every id in the set.
    ///
    /// # Errors
    ///
    /// [`ConnError::Pending`], [`ConnError::Timeout`], and any id's own refusal.
    fn wait(&self, caller: InstanceId, set: &[ConnId], ticket: Ticket) -> Result<usize, ConnError>;

    /// What connection security established on the connection.
    ///
    /// # Errors
    ///
    /// [`ConnError::NotOwner`], [`ConnError::Closed`].
    fn facts(&self, caller: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError>;

    /// Close the connection.
    ///
    /// # Errors
    ///
    /// [`ConnError::NotOwner`], [`ConnError::Closed`].
    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError>;
}

/// THE HOST'S CONNECTION TABLE, as the host declares an instance's needs on it (host-side: never
/// lowered to a plugin). The loader declares every need an instance's signed Statement states: a
/// need whose target the plugin names at bind, a need whose `target_from` names a config path at
/// every `open` and `refresh`, with the target that path resolved to in the instance's settings.
/// The host's need-admission service reads the answers back.
pub trait DeclaredConns: Conns {
    /// Record that `owner` declared `need` (its index in the instance's Statement), as the Statement
    /// states it: the whole need — direction, transport, auth, egress class, target and trust
    /// sources, details. `target` is what the need's `target_from` resolved to in the instance's
    /// settings (`None`: it resolved to nothing, or the need has no `target_from`); a need declared
    /// with a target dials that target only. Declaring the same need again replaces its record. The
    /// answer is kept: [`DeclaredConns::declared`] reads it back.
    ///
    /// # Errors
    ///
    /// [`ConnError::Refused`] when the host will not carry the need as declared, and for a need
    /// whose `target_from` resolved to nothing.
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
    ) -> Result<(), ConnError>;

    /// What [`DeclaredConns::declare`] answered for `owner`'s `need`; `None` = never declared.
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>>;
}

/// THE HOST-SIDE READER'S CONNECTION TABLE: [`Conns`] plus a read that wakes a [`Waker`] instead of
/// a plugin's ticket, for the kernel's egress walk, which awaits a far end on the caller's runtime
/// task. It is not part of [`Conns`] because it is never lowered: a waker does not cross the plugin
/// boundary (`abi::host::conn` lowers [`Conns`] slot for slot), and a plugin reads with its ticket.
///
/// [`Waker`]: std::task::Waker
pub trait PollConns: Conns {
    /// [`Conns::read`], for a reader on the host's own side (the kernel's egress walk): with nothing
    /// ready, [`Poll::Pending`] and `cx`'s waker woken once the read may progress. Never lowered:
    /// a waker does not cross the plugin boundary, and a plugin reads with its ticket.
    ///
    /// # Errors
    ///
    /// As [`Conns::read`], less [`ConnError::Pending`], which is [`Poll::Pending`] here.
    fn poll_read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<Piece, ConnError>>;
}

// ── the bookkeeping every host shares ────────────────────────────────────────────────────────────

/// One slab entry: free (with the generation the next occupant takes) or live.
enum Entry<T> {
    Free {
        generation: u32,
    },
    Live {
        generation: u32,
        owner: InstanceId,
        need: NeedId,
        state: Arc<T>,
    },
}

/// THE OWNERSHIP BOOK of a host's connections: which needs each instance declared, and which
/// instance owns each live [`ConnId`] and for which need. Every operation goes through it, so an id
/// another instance owns, an id already closed and a need nobody declared are refused the same way
/// in every host.
pub struct ConnSlab<T> {
    entries: Mutex<Vec<Entry<T>>>,
    declared: Mutex<std::collections::BTreeSet<(InstanceId, NeedId)>>,
}

impl<T> Default for ConnSlab<T> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            declared: Mutex::new(std::collections::BTreeSet::new()),
        }
    }
}

impl<T> std::fmt::Debug for ConnSlab<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnSlab").finish_non_exhaustive()
    }
}

impl<T> ConnSlab<T> {
    /// Record that `owner` declared `need`.
    pub fn declare(&self, owner: InstanceId, need: NeedId) {
        self.declared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert((owner, need));
    }

    /// Whether `caller` declared `need`.
    ///
    /// # Errors
    ///
    /// [`ConnError::UndeclaredNeed`].
    pub fn check_need(&self, caller: InstanceId, need: NeedId) -> Result<(), ConnError> {
        if self
            .declared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&(caller, need))
        {
            Ok(())
        } else {
            Err(ConnError::UndeclaredNeed)
        }
    }

    /// Hold `state` as a connection `owner` opened for `need`, answering its id.
    ///
    /// # Errors
    ///
    /// [`ConnError::UndeclaredNeed`] when `owner` never declared `need`.
    pub fn insert(&self, owner: InstanceId, need: NeedId, state: T) -> Result<ConnId, ConnError> {
        self.check_need(owner, need)?;
        let mut entries = self.lock();
        let state = Arc::new(state);
        let free = entries.iter().position(|e| matches!(e, Entry::Free { .. }));
        let (index, generation) = match free {
            Some(i) => {
                let Entry::Free { generation } = entries[i] else {
                    unreachable!("found free above")
                };
                entries[i] = Entry::Live {
                    generation,
                    owner,
                    need,
                    state,
                };
                (i, generation)
            }
            None => {
                entries.push(Entry::Live {
                    generation: 0,
                    owner,
                    need,
                    state,
                });
                (entries.len() - 1, 0)
            }
        };
        Ok(ConnId((u64::from(generation) << 32) | (index as u64 + 1)))
    }

    /// The live connection `conn`, when `caller` owns it: its need and state.
    ///
    /// # Errors
    ///
    /// [`ConnError::Closed`] for an id not live; [`ConnError::NotOwner`] for one another instance
    /// owns.
    pub fn get(&self, caller: InstanceId, conn: ConnId) -> Result<(NeedId, Arc<T>), ConnError> {
        let entries = self.lock();
        match Self::slot(&entries, conn)? {
            Entry::Live {
                owner, need, state, ..
            } if *owner == caller => Ok((*need, Arc::clone(state))),
            Entry::Live { .. } => Err(ConnError::NotOwner),
            Entry::Free { .. } => Err(ConnError::Closed),
        }
    }

    /// Release `conn`, when `caller` owns it, answering its state.
    ///
    /// # Errors
    ///
    /// As [`ConnSlab::get`].
    pub fn remove(&self, caller: InstanceId, conn: ConnId) -> Result<Arc<T>, ConnError> {
        let mut entries = self.lock();
        let index = match Self::slot(&entries, conn)? {
            Entry::Live { owner, .. } if *owner == caller => Self::index(conn),
            Entry::Live { .. } => return Err(ConnError::NotOwner),
            Entry::Free { .. } => return Err(ConnError::Closed),
        };
        let generation = (conn.0 >> 32) as u32;
        match std::mem::replace(
            &mut entries[index],
            Entry::Free {
                generation: generation.wrapping_add(1),
            },
        ) {
            Entry::Live { state, .. } => Ok(state),
            Entry::Free { .. } => unreachable!("checked live above"),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Entry<T>>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn index(conn: ConnId) -> usize {
        ((conn.0 & 0xffff_ffff) as usize).wrapping_sub(1)
    }

    /// The entry `conn` names at its generation; a stale generation reads as closed.
    fn slot(entries: &[Entry<T>], conn: ConnId) -> Result<&Entry<T>, ConnError> {
        let entry = entries.get(Self::index(conn)).ok_or(ConnError::Closed)?;
        let generation = (conn.0 >> 32) as u32;
        match entry {
            Entry::Live { generation: g, .. } if *g == generation => Ok(entry),
            _ => Err(ConnError::Closed),
        }
    }
}

#[cfg(test)]
#[path = "tests/conn_tests.rs"]
mod tests;
