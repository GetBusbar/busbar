// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **Plugin code runs on threads this module owns, and those threads never retire.**
//!
//! # The defect this exists to make impossible
//!
//! A plugin cdylib statically links its OWN copy of Rust `std`. The first time plugin code touches a
//! `thread_local!` that has a destructor, that copy arms its TLS-destructor guard by calling
//! `pthread_key_create(&key, run)` — where `run` is a function INSIDE THE PLUGIN IMAGE. A POSIX TSD
//! destructor carries no DSO handle (this is exactly where it differs from
//! `__cxa_thread_atexit_impl`, which pins the library that registered it), so glibc has no way to
//! keep the image alive for it. `dlclose` unmaps the image; the key survives holding a pointer into
//! the hole; and the thread that armed it dies the instant it exits:
//!
//! ```text
//! #0  0x0000e999284a2e84 in ?? ()                  <- unmapped, == the plugin's own `destr`
//! #1  __GI___nptl_deallocate_tsd () at nptl_deallocate_tsd.c:73
//! #2  start_thread () at pthread_create.c:453
//! ```
//!
//! Captured from a core dump of `store-mysql`'s plugin e2e and reproduced on `store-sqlite`'s. On
//! `ubuntu-latest` x86_64 it fires on 12 of 150 e2e runs at `--test-threads=8`.
//!
//! # Why the fix is here and not at the `dlopen`
//!
//! The obvious fix — never unmap, via `RTLD_NODELETE` — was tried and WITHDRAWN, because glibc's
//! `_dl_map_object` matches an already-loaded object by its NAME STRING before it stats anything.
//! The from-bytes path `dlopen`s `/proc/self/fd/N`, and N is recycled when the staging memfd closes,
//! so with the old image still resident under that name a later load silently received the FIRST
//! plugin's image instead of its own verified bytes. That is a wrong-code substitution inside the
//! signature-verified load path, and it made in-place hot-upgrade serve pre-upgrade code forever.
//! Both are silent, so both are worse than the crash. Do not reintroduce it.
//!
//! The crash does not actually require the image to stay mapped. It requires a thread that RAN
//! PLUGIN CODE to exit AFTER the unmap. So the invariant is about threads, and it is enforced here:
//!
//! > Every crossing into plugin code runs on a worker owned by this module, and a worker is never
//! > dropped, never joined, and never returns from its receive loop for the life of the process.
//!
//! Because the guarantee lives in the loader rather than in the host's threading policy, it holds
//! for the engine, for `cargo test`'s libtest harness (which spawns and retires a thread per test —
//! the shape that produced every observed crash), and for any third-party embedder, with no
//! configuration and nothing for a caller to get wrong.
//!
//! # What "plugin code" means here — all four categories
//!
//! 1. `dlopen` — runs the image's ELF `.init_array`;
//! 2. the six ABI symbols (`busbar_abi`/`busbar_plugin_kind`/`busbar_open`/`busbar_call`/
//!    `busbar_close`/`busbar_free`), which reach this module through [`crate::ffi_guard`];
//! 3. `busbar_set_log_sink`, which installs a `tracing` dispatcher inside the plugin and is
//!    therefore a prime toucher of plugin-side thread-locals;
//! 4. `dlclose` — runs the image's ELF `.fini_array`.
//!
//! Miss any one of them and a caller thread still gets plugin TLS, so all four are routed.

use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Mutex, OnceLock};

/// One unit of work handed to a permanent worker: an erased closure pointer, the trampoline that
/// knows its concrete type, and the channel the worker reports completion on.
struct Job {
    /// # Safety
    /// Must be called exactly once with the `data` pointer from the same [`Job`].
    run: unsafe fn(*mut ()),
    data: *mut (),
    done: SyncSender<()>,
}

// SAFETY: `data` points at a `Slot` living on the CALLER's stack, and `run` is a monomorphized
// trampoline in the caller's crate. Neither is `Send` in general — the closure captures raw plugin
// handles and `&str`s. This is sound only because of the rendezvous in `on_plugin_thread`: the
// caller sends the job and then BLOCKS on `done` until the worker has finished touching both
// pointers, so the pointed-to state cannot be dropped, moved, or observed concurrently for the whole
// window in which the worker holds it. That is the same argument `std::thread::scope` makes, with
// the join replaced by the `done` rendezvous. The plugin handle itself is additionally required to
// be `Send + Sync` by the ABI's own contract (see `unsafe impl Send for RawPlugin`).
unsafe impl Send for Job {}

/// Every worker ever created, by index, and the subset currently idle.
///
/// The `SyncSender`s in `all` are the reason a worker never exits: its receive loop ends only when
/// every sender is dropped, and `all` never shrinks, so that cannot happen. Handing callers a CLONE
/// (rather than moving a sender out) is deliberate — if a caller panics between acquire and release,
/// the clone drops, but `all` still holds the original, so the worker survives with plugin TLS
/// intact instead of exiting into the very crash this module prevents. The cost of that panic is one
/// permanently idle thread, which is a leak we accept in exchange for never taking the unsafe path.
struct Pool {
    all: Vec<SyncSender<Job>>,
    idle: Vec<usize>,
}

fn pool() -> &'static Mutex<Pool> {
    static POOL: OnceLock<Mutex<Pool>> = OnceLock::new();
    POOL.get_or_init(|| {
        Mutex::new(Pool {
            all: Vec::new(),
            idle: Vec::new(),
        })
    })
}

/// A worker's receive loop. NEVER returns: `pool().all` holds a sender for this receiver for the
/// life of the process, so `recv` can never see a disconnect. That is the whole invariant.
fn worker(rx: Receiver<Job>) {
    while let Ok(job) = rx.recv() {
        // SAFETY: `run`/`data` come from the same `Job`, and the caller is blocked on `done`.
        unsafe { (job.run)(job.data) };
        // The caller is waiting on this; capacity 1 so the worker never blocks handing it over.
        let _ = job.done.send(());
    }
}

/// A borrowed worker, returned to the idle list on drop (including on unwind).
struct Lease {
    idx: usize,
    tx: SyncSender<Job>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        pool()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .idle
            .push(self.idx);
    }
}

/// Borrow an idle worker, or create a new permanent one. Growing on demand (rather than capping) is
/// what makes re-entrancy deadlock-free: plugin code that calls back into the loader takes a fresh
/// worker instead of waiting for the one its own caller is occupying.
fn acquire() -> Lease {
    {
        let mut p = pool().lock().unwrap_or_else(|p| p.into_inner());
        if let Some(idx) = p.idle.pop() {
            return Lease {
                tx: p.all[idx].clone(),
                idx,
            };
        }
    }
    let (tx, rx) = sync_channel::<Job>(0);
    std::thread::Builder::new()
        .name("busbar-plugin-ffi".to_string())
        .spawn(move || worker(rx))
        .expect("spawn a plugin FFI worker thread");
    let mut p = pool().lock().unwrap_or_else(|p| p.into_inner());
    p.all.push(tx.clone());
    Lease {
        idx: p.all.len() - 1,
        tx,
    }
}

/// Run `f` on a worker thread that will never exit, block until it finishes, and hand back what it
/// returned — or `Err` if it panicked.
///
/// The `catch_unwind` lives on the WORKER, not the caller: a panic that escaped the trampoline would
/// unwind past the `done` send and hang the caller forever, so the guard is what makes the
/// rendezvous total. This also preserves [`crate::ffi_guard`]'s existing contract exactly — it used
/// to catch here itself — so no call site changes meaning.
///
/// Neither `F` nor `R` is `Send`, deliberately: the closures capture raw plugin handles and the
/// returns include raw pointers. Soundness comes from the caller blocking for the entire window (see
/// the `unsafe impl Send for Job` note), not from the types.
pub(crate) fn on_plugin_thread<F: FnOnce() -> R, R>(f: F) -> std::thread::Result<R> {
    struct Slot<F, R> {
        f: Option<F>,
        r: Option<std::thread::Result<R>>,
    }

    /// # Safety
    /// `p` must point at a live `Slot<F, R>` whose `f` has not yet been taken.
    unsafe fn trampoline<F: FnOnce() -> R, R>(p: *mut ()) {
        let slot = unsafe { &mut *(p as *mut Slot<F, R>) };
        let f = slot
            .f
            .take()
            .expect("the trampoline runs exactly once per job");
        slot.r = Some(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)));
    }

    let mut slot = Slot {
        f: Some(f),
        r: None,
    };
    // Capacity 1: the worker must be able to report completion without blocking.
    let (done_tx, done_rx) = sync_channel::<()>(1);
    let lease = acquire();
    let job = Job {
        run: trampoline::<F, R>,
        data: (&raw mut slot) as *mut (),
        done: done_tx,
    };
    lease
        .tx
        .send(job)
        .expect("a plugin FFI worker never exits, so its receiver is always live");
    // THE RENDEZVOUS. Everything the worker borrowed stays valid until this returns.
    done_rx
        .recv()
        .expect("the worker always reports completion, panic or not");
    drop(lease);
    slot.r.take().expect("the trampoline always fills the slot")
}

#[cfg(test)]
#[path = "tests/ffi_thread_tests.rs"]
mod tests;
