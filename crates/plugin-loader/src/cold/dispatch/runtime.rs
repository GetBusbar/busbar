// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The cold code of the dispatch runtime: `crate::dispatch::{worker, conditional, watchdog, lifecycle, ticks, ..}`.

use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::RefusalStatus;
use busbar_contract::conn::InstanceId;
use busbar_contract::plane_calls::CancelWrite;
use foldhash::{HashMap, HashSet};

use crate::dispatch::export_bindings::Generation;
use crate::dispatch::handle::TicketKey;
use crate::dispatch::measurement::{Authority, Binding};
use crate::dispatch::plugin::Instance;
use crate::dispatch::worker::{Entry, Msg, Worker, WorkerSlot};

// ---------------------------------------------------------------------------------------------
// dispatch (mod.rs): the dispatch clock's source.

/// The dispatch clock's epoch, fixed once at its first use.
#[cold]
pub(crate) fn dispatch_epoch() -> Instant {
    Instant::now()
}

/// The one OS clock read behind `crate::dispatch::now_ns`: every op reads the dispatch clock once at
/// its entry and passes the value down, so this is the single source of every reading.
#[inline(never)]
pub(crate) fn dispatch_clock_since(epoch: Instant) -> Duration {
    epoch.elapsed()
}

// ---------------------------------------------------------------------------------------------
// dispatch::worker: a dispatcher's workers, started once when it is built or when the watchdog
// replaces a wedged one.

/// A dispatch worker thread's name, given once when it starts.
#[cold]
pub(crate) fn worker_thread_name(index: u32) -> String {
    format!("busbar-dispatch-{index}")
}

/// A worker's ticket table, built once at dispatcher start or watchdog replacement: one entry per
/// slot count, numbered in order.
#[cold]
pub(crate) fn worker_table(
    counts: Vec<Option<u32>>,
    entry: impl FnMut((Option<u32>, u32)) -> Entry,
) -> Vec<Entry> {
    counts.into_iter().zip(0u32..).map(entry).collect()
}

/// A worker's free slots at start (every counted slot), highest first so the lowest is taken first.
#[cold]
pub(crate) fn worker_free_slots(counts: &[Option<u32>]) -> Vec<u32> {
    let mut free: Vec<u32> = counts
        .iter()
        .zip(0u32..)
        .filter_map(|(c, idx)| c.map(|_| idx))
        .collect();
    free.reverse();
    free
}

/// The workers a new dispatcher spawns once its pool is built, each with its receiver.
type Started = Vec<(Arc<Worker>, Receiver<Msg>)>;

/// A new dispatcher's `n` workers: their slots, and each worker with its receiver, to spawn once the
/// pool is built.
#[cold]
pub(crate) fn start_workers(n: u32, key: TicketKey) -> (Box<[WorkerSlot]>, Started) {
    let mut started = Vec::with_capacity(n as usize);
    let slots = (0..n)
        .map(|i| {
            let (w, rx) = Worker::new(i, Vec::new(), key);
            started.push((Arc::clone(&w), rx));
            WorkerSlot {
                current: RwLock::new(w),
            }
        })
        .collect();
    (slots, started)
}

/// Whether `authority` refuses any bound instance's declarations: installed once, at boot.
#[cold]
pub(crate) fn authority_refuses(
    adopted: &Mutex<Vec<Weak<Instance>>>,
    authority: &dyn Authority,
) -> bool {
    let bound = adopted.lock().unwrap_or_else(|e| e.into_inner());
    bound
        .iter()
        .filter_map(Weak::upgrade)
        .any(|instance| authority.admit(&instance.measurement_binding).is_err())
}

/// The declarations of every bound instance, listed once per config check.
#[cold]
pub(crate) fn measurement_bindings(adopted: &Mutex<Vec<Weak<Instance>>>) -> Vec<Binding> {
    let bound = adopted.lock().unwrap_or_else(|e| e.into_inner());
    bound
        .iter()
        .filter_map(Weak::upgrade)
        .map(|instance| instance.measurement_binding.clone())
        .collect()
}

// ---------------------------------------------------------------------------------------------
// dispatch::worker::unit_cancel: a wedged worker's entries, sorted into orphans once at its
// replacement.

/// A wedged worker's entries, each with its ticket, taken apart once at its replacement.
#[cold]
pub(crate) fn orphan_slots<E>(
    gone: Vec<Entry>,
    slot: impl FnMut((usize, Entry)) -> Option<E>,
) -> Vec<Option<E>> {
    gone.into_iter().enumerate().map(slot).collect()
}

/// A wedged worker's pending orphans, grouped once at its replacement: `group` answers the group a
/// slot index starts, if any.
#[cold]
pub(crate) fn orphan_groups<O>(slots: usize, group: impl FnMut(usize) -> Option<O>) -> Vec<O> {
    (0..slots).filter_map(group).collect()
}

/// A wedged worker's remaining entries, forgotten once at its replacement.
#[cold]
pub(crate) fn orphan_rest<E>(
    slots: Vec<Option<(Ticket, Entry)>>,
    forget: impl FnMut((Ticket, Entry)) -> E,
) -> Vec<E> {
    slots.into_iter().flatten().map(forget).collect()
}

// ---------------------------------------------------------------------------------------------
// dispatch::watchdog: the crossing watchdog's own thread, never a request.

/// The watchdog's sweep scratch: allocated once when its thread starts, cleared and reused by every
/// scan.
#[cold]
pub(crate) fn watchdog_scratch() -> Vec<Arc<Instance>> {
    Vec::new()
}

/// The watchdog's periodic sweep of the adoptions: one pass drops the dead ones and takes the live
/// ones into `live`.
#[cold]
pub(crate) fn live_adoptions(adopted: &Mutex<Vec<Weak<Instance>>>, live: &mut Vec<Arc<Instance>>) {
    let mut bound = adopted.lock().unwrap_or_else(|e| e.into_inner());
    bound.retain(|w| match w.upgrade() {
        Some(inst) => {
            live.push(inst);
            true
        }
        None => false,
    });
}

/// A wedged worker's successor's slab generations, computed once at its replacement.
#[cold]
pub(crate) fn successor_counts(entries: &[Entry]) -> Vec<Option<u32>> {
    entries
        .iter()
        .map(|e| crate::dispatch::worker::next_count(e.count))
        .collect()
}

/// The connections a wedged worker's faulted tickets held, listed once at its replacement.
#[cold]
pub(crate) fn wedged_conns(gone: &[Entry]) -> Vec<InstanceId> {
    gone.iter().flat_map(|e| e.conns.iter().copied()).collect()
}

// ---------------------------------------------------------------------------------------------
// dispatch::held: driver tickets start and stop with their instances; no service call does.

/// The lock-free snapshot of the tracked driver tickets, republished when one starts or stops.
#[cold]
pub(crate) fn driver_snapshot<V>(all: &HashMap<Ticket, V>) -> HashSet<Ticket> {
    all.keys().copied().collect()
}

/// A wedged worker's replacement forgets every driver ticket it held.
#[cold]
pub(crate) fn forget_worker_drivers<V>(all: &mut HashMap<Ticket, V>, worker: u32) {
    all.retain(|t, _| crate::dispatch::ticket::decode(t.slot).0 != worker);
}

// ---------------------------------------------------------------------------------------------
// dispatch::export_bindings

/// The export pins a wedged worker's tickets held, forgotten once at its replacement.
#[cold]
pub(crate) fn worker_pins<'a>(
    pins: impl Iterator<Item = (&'a Ticket, &'a Arc<Generation>)>,
    worker: u32,
) -> Vec<(Ticket, Arc<Generation>)> {
    pins.filter(|(ticket, _)| crate::dispatch::ticket::decode(ticket.slot).0 == worker)
        .map(|(ticket, binding)| (*ticket, Arc::clone(binding)))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// dispatch::plane_calls

/// The plane driver's config takes its own copy of the refusal table once.
#[cold]
pub(crate) fn refusal_table(statuses: &[RefusalStatus]) -> Vec<RefusalStatus> {
    statuses.to_vec()
}

/// The writes a cancelled piece's cancel owes, read only after it was cancelled.
#[cold]
pub(crate) fn cancel_writes(writes: &[CancelWrite]) -> Vec<CancelWrite> {
    writes.to_vec()
}

// ---------------------------------------------------------------------------------------------
// dispatch::conditional

/// The receipt of a commit or observation the provider refused, kept once.
#[cold]
pub(crate) fn refusal_receipt(bytes: Vec<u8>) -> Arc<[u8]> {
    Arc::from(bytes)
}

// ---------------------------------------------------------------------------------------------
// dispatch::framing_context

/// The adopted-session reply an adopting leg answers, built once when the leg adopts its session.
#[cold]
pub(crate) fn adoption_reply(bytes: Vec<u8>) -> Arc<[u8]> {
    Arc::from(bytes)
}

// ---------------------------------------------------------------------------------------------
// dispatch::handle

/// The entropy source refused the process-wide handle key, drawn once at load.
#[cold]
pub(crate) fn entropy_refused<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

// ---------------------------------------------------------------------------------------------
// dispatch::ready

/// A plugin that did not become ready at load.
#[cold]
pub(crate) fn ready_failed(name: &str, reason: &dyn std::fmt::Display) -> String {
    format!("plugin '{name}' ready failed: {reason}")
}

// ---------------------------------------------------------------------------------------------
// dispatch::lifecycle

/// A plugin's error text that was not UTF-8, rendered lossily.
#[cold]
pub(crate) fn lossy_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The outcome of a failed plugin call that stated no error text.
#[cold]
pub(crate) fn outcome_name(outcome: Outcome) -> String {
    format!("{outcome:?}")
}

// ---------------------------------------------------------------------------------------------
// dispatch::io_slots

/// A configured child process's argument or environment list, read once when it is spawned:
/// `None` when any item does not read.
#[cold]
pub(crate) fn spawn_list<T, R>(items: &[T], each: impl FnMut(&T) -> Option<R>) -> Option<Vec<R>> {
    items.iter().map(each).collect()
}
