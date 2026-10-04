// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE INSTANCE: the handles (generation data), the token cache (outlives handles), the waiting
//! tickets, and the per-op envelope storage the host copies after each control-lane call.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::Instant;

use busbar_contract::abi::mechanism::call::{AbiStr, Diag};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::conn::Host;

use crate::abi::{abi, Waker};
use crate::mint::host_wire::HostWire;
use crate::mint::{Minted, Minter, Report, Wire, MIN_SLEEP_SECS};

/// The index of each diagnostic id in the Statement (`crate::DIAG_IDS`).
pub(crate) mod diag {
    /// A minted token holds bytes invalid in a header value (1.5.5 `EGRESS_OAUTH_TOKEN_INVALID_BYTES`).
    pub const OAUTH_TOKEN_INVALID_BYTES: u32 = 0;
    /// A 200 with an empty access token (1.5.5 `EGRESS_OAUTH_EMPTY_TOKEN`).
    pub const OAUTH_EMPTY_TOKEN: u32 = 1;
    /// A mint failed (1.5.5 `EGRESS_OAUTH_MINT_FAILED`).
    pub const OAUTH_MINT_FAILED: u32 = 2;
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

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One plugin instance.
pub(crate) struct Oauth {
    waker: Option<Waker>,
    /// A test's need double; production reaches its need through [`Oauth::host`].
    wire: Option<Box<dyn Wire>>,
    /// The host's connector tables `open` was handed (`None`: no need was granted).
    host: Option<Host>,
    /// The instance's driver ticket, as its first `tick` names it: a binding opened, or a request
    /// waiting on a token nothing has minted yet, wakes it so a `drive` starts the mint at once.
    driver: Mutex<Ticket>,
    /// The handle count of the driver ticket's cycle ([`HostWire`]): reset at each `tick`, carried
    /// on through each `drive`.
    issued: AtomicU32,
    /// The last `tick`'s clock (`TickIn::now_ns`) and when it was read: a `drive` reads the tick
    /// clock from it.
    clock: Mutex<Option<(u64, Instant)>>,
    generation: AtomicU64,
    next_handle: AtomicU64,
    handles: RwLock<HashMap<u64, (u64, Arc<Minted>)>>,
    cache: Mutex<HashMap<[u8; 32], Arc<Minted>>>,
    waiters: Mutex<Vec<Ticket>>,
    /// `open_outbound`'s envelope and error.
    pub(crate) open_env: Mutex<EnvStore>,
    /// `tick`'s envelope.
    pub(crate) tick_env: Mutex<EnvStore>,
    /// `drive`'s envelope.
    pub(crate) drive_env: Mutex<EnvStore>,
}

impl crate::style::TokenCache for Oauth {
    fn cell(&self, key: [u8; 32], minter: Minter, max: usize) -> Arc<Minted> {
        lock(&self.cache)
            .entry(key)
            .or_insert_with(|| Arc::new(Minted::new(minter, max)))
            .clone()
    }
}

impl Oauth {
    /// An instance at `generation` over the host's wake and its connector tables (`host`; `None`:
    /// no need was granted, and a minted style reports that no connection was).
    pub(crate) fn new(generation: u64, waker: Option<Waker>, host: Option<Host>) -> Self {
        let mut o = Self::with_wire(generation, waker, None);
        o.host = host;
        o
    }

    /// An instance over any [`Wire`] (the unit tests' double).
    pub(crate) fn with_wire(
        generation: u64,
        waker: Option<Waker>,
        wire: Option<Box<dyn Wire>>,
    ) -> Self {
        Self {
            waker,
            wire,
            host: None,
            driver: Mutex::new(Ticket::NONE),
            issued: AtomicU32::new(0),
            clock: Mutex::new(None),
            generation: AtomicU64::new(generation),
            next_handle: AtomicU64::new(1),
            handles: RwLock::new(HashMap::new()),
            cache: Mutex::new(HashMap::new()),
            waiters: Mutex::new(Vec::new()),
            open_env: Mutex::default(),
            tick_env: Mutex::default(),
            drive_env: Mutex::default(),
        }
    }

    /// `refresh`: the generation later handles belong to.
    pub(crate) fn set_generation(&self, generation: u64) {
        self.generation.store(generation, Ordering::Release);
    }

    /// Keep `cell` under a new handle of the current generation.
    pub(crate) fn keep(&self, cell: Arc<Minted>) -> u64 {
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let generation = self.generation.load(Ordering::Acquire);
        self.handles
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(handle, (generation, cell));
        handle
    }

    /// The token cell behind `handle`.
    pub(crate) fn binding(&self, handle: u64) -> Option<Arc<Minted>> {
        self.handles
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&handle)
            .map(|(_, b)| b.clone())
    }

    /// `retire`: drop the handles opened at `generation`, then every token cell no handle holds.
    pub(crate) fn retire(&self, generation: u64) {
        self.handles
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, (g, _)| *g != generation);
        lock(&self.cache).retain(|_, c| Arc::strong_count(c) > 1);
    }

    /// Park `ticket` until a mint lands.
    pub(crate) fn park(&self, ticket: Ticket) {
        let mut w = lock(&self.waiters);
        if !w.contains(&ticket) {
            w.push(ticket);
        }
    }

    /// `cancel`: forget `ticket`.
    pub(crate) fn unpark(&self, ticket: Ticket) {
        lock(&self.waiters).retain(|t| *t != ticket);
    }

    /// A mint is wanted now (a binding opened; a request waits on a token nothing has minted):
    /// wake the driver ticket, so a `drive` starts it without waiting for the next `tick`. Before
    /// the first `tick` nothing is woken: that tick, made at once, starts it.
    pub(crate) fn mint_soon(&self) {
        let driver = *lock(&self.driver);
        if let (Some(w), false) = (&self.waker, driver.is_none()) {
            w.wake(driver);
        }
    }

    /// `tick` at tick-clock `now_ns` on the driver ticket `ticket`: a new cycle (its handle count
    /// starts again), the refresh ahead of expiry, the wakes. Answers the next tick; an instance
    /// with no binding yet still asks for one ([`MIN_SLEEP_SECS`] on), never ending its schedule.
    pub(crate) fn tick(&self, now_ns: u64, ticket: Ticket, env: &mut EnvStore) -> u64 {
        if !ticket.is_none() {
            *lock(&self.driver) = ticket;
        }
        *lock(&self.clock) = Some((now_ns, Instant::now()));
        self.issued.store(0, Ordering::Release);
        self.advance(now_ns, ticket, env)
            .unwrap_or(now_ns.saturating_add(MIN_SLEEP_SECS * crate::mint::NS))
    }

    /// `drive` on the driver ticket `ticket` (a wake: a read that pended, [`Oauth::mint_soon`], or
    /// the timer the last `drive` set): the cycle goes on, at the tick clock as it now reads. Answers
    /// when the earliest cell is next due, the instant the `drive` asks to be resumed at (a mint
    /// landed between ticks schedules its own refresh: the tick schedule was set before it), or
    /// `None` (no cell, or no `tick` yet).
    pub(crate) fn drive(&self, ticket: Ticket, env: &mut EnvStore) -> Option<u64> {
        let (at, read) = (*lock(&self.clock))?;
        let elapsed = u64::try_from(read.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.advance(at.saturating_add(elapsed), ticket, env)
    }

    /// Advance every token cell at `now_ns`, over the need on `ticket`: when the next tick is
    /// wanted (`None`: no cell).
    fn advance(&self, now_ns: u64, ticket: Ticket, env: &mut EnvStore) -> Option<u64> {
        let host = self
            .host
            .as_ref()
            .map(|h| HostWire::new(h, ticket, &self.issued));
        let wire: Option<&dyn Wire> = match (&self.wire, &host) {
            (Some(w), _) => Some(w.as_ref()),
            (None, Some(h)) => Some(h),
            (None, None) => None,
        };
        let cells: Vec<Arc<Minted>> = lock(&self.cache).values().cloned().collect();
        let mut next = u64::MAX;
        let mut minted = false;
        for cell in cells {
            let (due, report) = cell.tick(now_ns, wire);
            next = next.min(due);
            match report {
                Some(Report::Minted) => minted = true,
                Some(Report::TokenInvalidBytes) => {
                    minted = true;
                    env.push(
                        diag::OAUTH_TOKEN_INVALID_BYTES,
                        WARN,
                        "minted an OAuth token with bytes invalid for an HTTP header value; \
                         omitting the auth header — upstream will reject with 401"
                            .to_string(),
                    );
                }
                Some(Report::EmptyToken) => env.push(
                    diag::OAUTH_EMPTY_TOKEN,
                    WARN,
                    "OAuth token endpoint returned a 200 with an empty access_token; treating as a \
                     mint failure and will retry"
                        .to_string(),
                ),
                Some(Report::MintFailed(e)) => env.push(
                    diag::OAUTH_MINT_FAILED,
                    WARN,
                    format!("OAuth token mint failed; will retry error={e}"),
                ),
                None => {}
            }
        }
        if minted {
            let woken: Vec<Ticket> = std::mem::take(&mut *lock(&self.waiters));
            if let Some(w) = &self.waker {
                for t in woken {
                    w.wake(t);
                }
            }
        }
        (next != u64::MAX).then_some(next)
    }
}

#[cfg(test)]
#[path = "tests/instance_tests.rs"]
mod tests;
