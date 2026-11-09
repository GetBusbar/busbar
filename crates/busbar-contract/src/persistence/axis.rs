// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Neutral asynchronous Store selection and opening boundary.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use super::PersistenceBackend;

/// Where one store's door comes from: a compiled-in row's door, or a dropped-in plugin's verified
/// tarball bytes and the signed Statement it is admitted against.
pub enum StoreDoor {
    /// A compiled-in row's door.
    Linked(crate::abi::mechanism::door::DoorFn),
    /// A dropped-in plugin.
    Dropped {
        /// Its tarball's file name (diagnostics).
        file: String,
        /// The library bytes its signed manifest's `sha256` names.
        bytes: std::sync::Arc<Vec<u8>>,
        /// The Statement rendering its signed manifest states: what the door is admitted against.
        stated: Vec<u8>,
    },
}

impl std::fmt::Debug for StoreDoor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreDoor::Linked(_) => f.debug_tuple("Linked").finish_non_exhaustive(),
            StoreDoor::Dropped { file, .. } => f
                .debug_struct("Dropped")
                .field("file", file)
                .finish_non_exhaustive(),
        }
    }
}

/// One opened backend; its instance facts are available through `info()`.
pub type OpenedBackend = Arc<dyn PersistenceBackend>;

/// An asynchronous open, retaining its inputs until completion or cancellation.
pub type OpenCall<'a> = Pin<Box<dyn Future<Output = Result<OpenedBackend, String>> + Send + 'a>>;

/// Load and open a Store through the explicitly selected persistence ABI.
pub trait PersistenceAxis: Send + Sync {
    /// Bind and retain a native inspection session without executing ordinary OPEN.
    fn prepare<'a>(
        &'a self,
        door: StoreDoor,
        label: &'a str,
        settings: &'a [u8],
    ) -> super::lifecycle::PrepareCall<'a>;
    /// Open `door` under the host instance label using the supplied settings.
    fn open<'a>(&'a self, door: StoreDoor, label: &'a str, settings: &'a [u8]) -> OpenCall<'a>;
}
