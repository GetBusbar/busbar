// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-connection side table: the reader, the single write lock, and the optional child
//! process — everything a [`busbar_contract::wire::Conn`] cannot carry itself because it is a
//! sealed, opaque handle. Keyed by `Conn::id()` from [`crate::transport::StdioTransport`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use busbar_contract::unit::ConfigView;
use busbar_contract::wire::ConnHandle;
use busbar_contract::TransportConfigView;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::sync::Mutex as AsyncMutex;

/// The opaque handle this transport hands the kernel through [`busbar_contract::wire::Conn::new`].
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

/// One connection's real state: a boxed reader (taken exactly once by `frames()`), a boxed writer
/// behind the single write lock every outbound frame passes through, and the child process this
/// connection owns, where it is a dialled one.
pub(crate) struct ConnState {
    /// The `BufReader` itself, not just the raw reader, is what persists across polls of
    /// `frames()`: a `BufReader` can read ahead of the line it returns, and destroying it between
    /// polls to keep only the inner reader would silently drop already-buffered bytes belonging to
    /// the NEXT frame. See the crate's own report for the bug this shape closes.
    pub(crate) reader: AsyncMutex<Option<BufReader<Box<dyn AsyncRead + Send + Unpin>>>>,
    pub(crate) writer: AsyncMutex<Box<dyn AsyncWrite + Send + Unpin>>,
    pub(crate) child: AsyncMutex<Option<tokio::process::Child>>,
    /// Set by a write that did not run to completion — a cancelled or errored write leaves no
    /// promise about what reached the wire, so the connection is FENCED rather than reused. See
    /// the crate report's note on the "cancel mid-frame" battery cell.
    pub(crate) poisoned: AtomicBool,
}

impl ConnState {
    pub(crate) fn new(
        reader: Box<dyn AsyncRead + Send + Unpin>,
        writer: Box<dyn AsyncWrite + Send + Unpin>,
        child: Option<tokio::process::Child>,
    ) -> Arc<Self> {
        Arc::new(Self {
            reader: AsyncMutex::new(Some(BufReader::new(reader))),
            writer: AsyncMutex::new(writer),
            child: AsyncMutex::new(child),
            poisoned: AtomicBool::new(false),
        })
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
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
