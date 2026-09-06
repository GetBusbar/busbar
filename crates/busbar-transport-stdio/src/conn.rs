// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-connection side table: the reader, the single write lock, and the optional child
//! process — everything a [`busbar_contract_transport::wire::Conn`] cannot carry itself because it is a
//! sealed, opaque handle. Keyed by `Conn::id()` from [`crate::transport::StdioTransport`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use busbar_contract::unit::ConfigView;
use busbar_contract::TransportConfigView;
use busbar_contract_transport::wire::ConnHandle;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::sync::Mutex as AsyncMutex;

/// The opaque handle this transport hands the kernel through [`busbar_contract_transport::wire::Conn::new`].
/// It carries nothing but identity: the real state lives in [`ConnState`], looked up by `id`.
pub(crate) struct StdioConnHandle {
    pub(crate) id: u64,
    pub(crate) peer: String,
}

impl ConnHandle for StdioConnHandle {
    fn id(&self) -> u64 {
        self.id
    }
    fn peer(&self) -> String {
        self.peer.clone()
    }
}

/// Everything the read side of one connection carries between polls of `frames()`.
///
/// The `BufReader` is here rather than the raw reader because a `BufReader` reads ahead of the line
/// it returns, and destroying it between polls would silently drop already-buffered bytes belonging
/// to the NEXT frame. `partial` is here for the same reason one poll further out: `read_until` is
/// not cancellation-safe, so a `frames()` future dropped mid-line has already consumed bytes from
/// the reader, and the only place they can survive is the connection.
pub(crate) struct ReaderSlot {
    pub(crate) reader: BufReader<Box<dyn AsyncRead + Send + Unpin>>,
    /// Bytes of a line read but not yet terminated by a newline.
    pub(crate) partial: Vec<u8>,
}

/// One connection's real state: a boxed reader (taken exactly once by `frames()`), a boxed writer
/// behind the single write lock every outbound frame passes through, and the child process this
/// connection owns, where it is a dialled one.
pub(crate) struct ConnState {
    /// Taken by whichever `frames()` pump is reading, and put back when it stops — see
    /// [`ReaderSlot`] for why the whole slot, not just the raw reader, is what travels.
    pub(crate) reader: AsyncMutex<Option<ReaderSlot>>,
    pub(crate) writer: AsyncMutex<Box<dyn AsyncWrite + Send + Unpin>>,
    pub(crate) child: AsyncMutex<Option<tokio::process::Child>>,
    /// Set by a write that did not run to completion — a cancelled or errored write leaves no
    /// promise about what reached the wire, so the connection is FENCED rather than reused. See
    /// the crate report's note on the "cancel mid-frame" battery cell.
    pub(crate) poisoned: AtomicBool,
    /// Set once the connection has been closed. A `frames()` pump captured its own clone of this
    /// state before the close, so removing the transport's registry entry does not reach it; this
    /// is the flag that pump checks, so a closed connection stops delivering inbound frames at the
    /// same moment its writes start answering `Closed`.
    pub(crate) closed: AtomicBool,
}

impl ConnState {
    pub(crate) fn new(
        reader: Box<dyn AsyncRead + Send + Unpin>,
        writer: Box<dyn AsyncWrite + Send + Unpin>,
        child: Option<tokio::process::Child>,
    ) -> Arc<Self> {
        Arc::new(Self {
            reader: AsyncMutex::new(Some(ReaderSlot {
                reader: BufReader::new(reader),
                partial: Vec::new(),
            })),
            writer: AsyncMutex::new(writer),
            child: AsyncMutex::new(child),
            poisoned: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        })
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

/// A trivial read-only config view, for callers (and tests) that have nothing to declare. stdio
/// binds no address, so [`TransportConfigView::bind`] always answers `None`.
#[derive(Debug, Default, Clone)]
pub struct StaticConfig;

impl ConfigView for StaticConfig {
    fn get_str(&self, _key: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, _key: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _key: &str) -> Option<bool> {
        None
    }
}

impl TransportConfigView for StaticConfig {
    fn bind(&self) -> Option<&str> {
        None
    }
}
