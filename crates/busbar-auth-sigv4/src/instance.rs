// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE INSTANCE: the handles (generation data), and the per-op envelope storage the host copies
//! after each control-lane call. No token cache, no waker, no waiting tickets: a sigv4 binding
//! never mints and never pends — `tick` only pre-derives day keys ahead of midnight.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use busbar_contract::abi::mechanism::call::{AbiStr, Diag};

use crate::abi::abi;
use crate::signing::SigV4Binding;
use crate::style::OpenNote;

/// The index of each diagnostic id in the Statement (`crate::DIAG_IDS`).
pub(crate) mod diag {
    /// A signing credential's session token is not a legal header value.
    pub const SESSION_TOKEN_INVALID_BYTES: u32 = 0;
}

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

/// How often `tick` re-checks the SigV4 day keys while a binding is open.
const PREDERIVE_TICK_NS: u64 = 60 * 1_000_000_000;

/// One plugin instance.
pub(crate) struct SigV4 {
    generation: AtomicU64,
    next_handle: AtomicU64,
    handles: RwLock<HashMap<u64, (u64, Arc<SigV4Binding>)>>,
    /// `open_outbound`'s envelope and error.
    pub(crate) open_env: std::sync::Mutex<EnvStore>,
}

impl SigV4 {
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
    pub(crate) fn keep(&self, binding: SigV4Binding) -> u64 {
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let generation = self.generation.load(Ordering::Acquire);
        self.handles
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(handle, (generation, Arc::new(binding)));
        handle
    }

    /// The binding behind `handle`.
    pub(crate) fn binding(&self, handle: u64) -> Option<Arc<SigV4Binding>> {
        self.handles
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&handle)
            .map(|(_, b)| b.clone())
    }

    /// `retire`: drop the handles opened at `generation`.
    pub(crate) fn retire(&self, generation: u64) {
        self.handles
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, (g, _)| *g != generation);
    }

    /// Report an open's notes into `env`, in the line 1.5.5's builder logged.
    pub(crate) fn note_open(env: &mut EnvStore, notes: &[OpenNote]) {
        for OpenNote::SessionToken(service) in notes {
            let (initial, rest) = service.split_at(service.len().min(1));
            env.push(
                diag::SESSION_TOKEN_INVALID_BYTES,
                WARN,
                format!(
                    "{}{rest} lane session token contains a byte rejected by HeaderValue; \
                     skipping signing to avoid a signed-but-absent x-amz-security-token header.",
                    initial.to_uppercase()
                ),
            );
        }
    }

    /// `tick`: pre-derive every live binding's day keys ahead of midnight. Answers the next tick
    /// (`0`: none wanted — no binding is open).
    pub(crate) fn tick(&self, now_ns: u64) -> u64 {
        let bindings: Vec<Arc<SigV4Binding>> = self
            .handles
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .map(|(_, b)| b.clone())
            .collect();
        if bindings.is_empty() {
            return 0;
        }
        let now = crate::now_epoch();
        for b in &bindings {
            b.prederive(now);
        }
        now_ns.saturating_add(PREDERIVE_TICK_NS)
    }
}

#[cfg(test)]
#[path = "tests/instance_tests.rs"]
mod tests;
