// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE INSTANCE: the handles (generation data), and the per-op envelope storage the host copies
//! after each control-lane call. No token cache, no waker, no waiting tickets: a header binding
//! never mints and never pends.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{PoisonError, RwLock};

use busbar_contract::abi::mechanism::call::{AbiStr, Diag};

use crate::abi::abi;
use crate::style::{Binding, OpenNote};

/// The index of each diagnostic id in the Statement (`crate::DIAG_IDS`).
pub(crate) mod diag {
    /// A static header omitted for invalid bytes (1.5.5 `EGRESS_APIKEY_INVALID_BYTES`).
    pub const APIKEY_INVALID_BYTES: u32 = 0;
    /// A bearer omitted for invalid bytes (1.5.5 `PROTO_AUTH_INVALID_HEADER_BYTES`).
    pub const AUTH_INVALID_HEADER_BYTES: u32 = 1;
    /// A credential-family table's credential omitted for invalid bytes.
    pub const CREDENTIAL_INVALID_BYTES: u32 = 2;
}

/// `0` info, `1` warn (the `Diag::severity` scale).
const INFO: u8 = 0;
const WARN: u8 = 1;

/// One op's envelope storage: the diagnostics and the texts they point into, kept until the next
/// call of the same op (the host copies them before it makes any other call on that thread).
#[derive(Default)]
pub(crate) struct EnvStore {
    texts: Vec<String>,
    diags: Vec<Diag>,
    /// The error text of the last FAILED/REFUSED answer.
    pub(crate) error: String,
}

impl EnvStore {
    /// Start a call: drop what the previous call left.
    pub(crate) fn clear(&mut self) {
        self.diags.clear();
        self.texts.clear();
        self.error.clear();
    }

    /// Add one diagnostic.
    pub(crate) fn push(&mut self, id: u32, severity: u8, text: String) {
        self.texts.push(text);
        let t = self.texts.last().map_or(
            AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            |t| abi(t),
        );
        self.diags.push(Diag {
            id_idx: id,
            severity,
            _reserved: [0; 3],
            text: t,
        });
    }

    /// The diagnostics, as the envelope carries them.
    pub(crate) fn diags(&self) -> &[Diag] {
        &self.diags
    }
}

/// One plugin instance.
pub(crate) struct Header {
    generation: AtomicU64,
    next_handle: AtomicU64,
    handles: RwLock<HashMap<u64, (u64, Binding)>>,
    /// `open_outbound`'s envelope and error.
    pub(crate) open_env: std::sync::Mutex<EnvStore>,
}

impl Header {
    /// An instance at `generation`.
    pub(crate) fn new(generation: u64) -> Self {
        Self {
            generation: AtomicU64::new(generation),
            next_handle: AtomicU64::new(1),
            handles: RwLock::new(HashMap::new()),
            open_env: std::sync::Mutex::default(),
        }
    }

    /// `refresh`: the generation later handles belong to.
    pub(crate) fn set_generation(&self, generation: u64) {
        self.generation.store(generation, Ordering::Release);
    }

    /// Keep `binding` under a new handle of the current generation.
    pub(crate) fn keep(&self, binding: Binding) -> u64 {
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let generation = self.generation.load(Ordering::Acquire);
        self.handles
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(handle, (generation, binding));
        handle
    }

    /// Run `f` over the binding behind `handle`.
    pub(crate) fn with_binding<T>(&self, handle: u64, f: impl FnOnce(&Binding) -> T) -> Option<T> {
        self.handles
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&handle)
            .map(|(_, b)| f(b))
    }

    /// `retire`: drop the handles opened at `generation`.
    pub(crate) fn retire(&self, generation: u64) {
        self.handles
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, (g, _)| *g != generation);
    }

    /// Report an open's notes into `env`, in the lines 1.5.5's builders logged.
    pub(crate) fn note_open(env: &mut EnvStore, notes: &[OpenNote]) {
        for n in notes {
            match n {
                OpenNote::Header(header) => env.push(
                    diag::APIKEY_INVALID_BYTES,
                    WARN,
                    format!(
                        "egress credential contains invalid header bytes (ASCII control \
                         character); omitting auth header — upstream will reject with 401 \
                         header={header}"
                    ),
                ),
                OpenNote::Bearer => env.push(
                    diag::AUTH_INVALID_HEADER_BYTES,
                    INFO,
                    "authorization credential contains invalid header bytes (ASCII control \
                     character); omitting auth header — upstream will reject with 401"
                        .to_string(),
                ),
                OpenNote::Family(header) => env.push(
                    diag::CREDENTIAL_INVALID_BYTES,
                    WARN,
                    format!(
                        "auth credential contains bytes invalid for an HTTP header value (e.g. a \
                         trailing newline); omitting the credential header — upstream will return \
                         401, check the key configuration header={header}"
                    ),
                ),
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/instance_tests.rs"]
mod tests;
