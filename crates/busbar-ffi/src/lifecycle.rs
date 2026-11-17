// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one permanent native lifecycle worker owner.
//!
//! Plugin TLS destructors can retain addresses in an unloaded image. These workers never retire;
//! callbacks finish, including capture destruction, before their borrowed caller state is released.
//! This boundary does not own image admission or decide whether an image may be unloaded.

#![allow(unsafe_code)]

use std::cell::Cell;
use std::mem::ManuallyDrop;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Mutex, OnceLock};

struct Job {
    run: Box<dyn FnOnce() + Send + 'static>,
    done: SyncSender<()>,
}

struct Pool {
    all: Vec<SyncSender<Job>>,
    idle: Vec<usize>,
}

impl Pool {
    const fn empty() -> Self {
        Self {
            all: Vec::new(),
            idle: Vec::new(),
        }
    }
}

fn pool() -> &'static Mutex<Pool> {
    static POOL: OnceLock<Mutex<Pool>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(Pool::empty()))
}

std::thread_local! {
    static PERMANENT: Cell<bool> = const { Cell::new(false) };
}

/// Whether the calling thread belongs to this owner. This is an observation, not admission.
pub fn is_worker() -> bool {
    PERMANENT.with(Cell::get)
}

fn worker(rx: Receiver<Job>) {
    PERMANENT.set(true);
    loop {
        let Ok(job) = rx.recv() else {
            // Even an invariant failure cannot retire a thread carrying plugin TLS destructors.
            loop {
                std::thread::park();
            }
        };
        (job.run)();
        if job.done.send(()).is_err() {
            std::process::abort();
        }
    }
}

struct Lease {
    pool: &'static Mutex<Pool>,
    index: usize,
    sender: SyncSender<Job>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.pool
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .idle
            .push(self.index);
    }
}

fn acquire(pool: &'static Mutex<Pool>) -> Lease {
    {
        let mut held = pool.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(index) = held.idle.pop() {
            return Lease {
                pool,
                index,
                sender: held.all[index].clone(),
            };
        }
    }
    let (sender, receiver) = sync_channel(0);
    let _worker = std::thread::Builder::new()
        .name("busbar-plugin-ffi".into())
        .spawn(move || {
            if let Err(payload) = catch_unwind(AssertUnwindSafe(|| worker(receiver))) {
                // Callback unwinds are caught inside their job. An unexpected host unwind cannot
                // release the caller's borrow or let this permanent thread run TLS destructors.
                std::mem::forget(payload);
                std::process::abort();
            }
        })
        .expect("spawn a permanent plugin lifecycle worker");
    let mut held = pool.lock().unwrap_or_else(|p| p.into_inner());
    held.all.push(sender.clone());
    Lease {
        pool,
        index: held.all.len() - 1,
        sender,
    }
}

struct Completion {
    done: Receiver<()>,
    finished: bool,
}

impl Completion {
    fn finish(&mut self) {
        if !self.finished {
            if self.done.recv().is_err() {
                std::process::abort();
            }
            self.finished = true;
        }
    }
}

impl Drop for Completion {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Execute a cold native lifecycle callback and wait for all accesses to its captures to finish.
/// Both the callback and its result may borrow caller state, but must obey Rust's thread-transfer
/// rules. Recursive calls reserve another worker. Callback panic returns its opaque payload;
/// callers must retain that payload when its destructor may belong to an unloaded image.
///
/// # Submission failure
/// Acquisition failure panics before invocation. The callback and its captures are deliberately
/// retained without Drop, including any owned resources or locks. They are never retried. Image
/// hosts must additionally retain backing held outside those captures whenever teardown is uncertain.
///
/// ```
/// let mut text = String::from("borrowed");
/// busbar_ffi::lifecycle::run(|| text.push_str(" result")).unwrap();
/// assert_eq!(busbar_ffi::lifecycle::run(|| text.as_str()).unwrap(), "borrowed result");
/// ```
/// ```compile_fail,E0277
/// let value = std::rc::Rc::new(1);
/// busbar_ffi::lifecycle::run(move || drop(value));
/// ```
/// ```compile_fail,E0277
/// busbar_ffi::lifecycle::run(|| std::rc::Rc::new(1));
/// ```
/// ```compile_fail,E0277
/// let lock = std::sync::Mutex::new(());
/// let guard = lock.lock().unwrap();
/// busbar_ffi::lifecycle::run(move || drop(guard));
/// ```
pub fn run<F: FnOnce() -> R + Send, R: Send>(work: F) -> std::thread::Result<R> {
    run_with(work, || acquire(pool()))
}

fn run_with<F: FnOnce() -> R + Send, R: Send>(
    work: F,
    reserve: impl FnOnce() -> Lease,
) -> std::thread::Result<R> {
    // First, before acquisition/allocation: caller-side failure may not destroy image-owning captures.
    let work = ManuallyDrop::new(work);
    let lease = reserve();
    let (done, receiver) = sync_channel(1);
    let mut result = None;
    let borrowed: Box<dyn FnOnce() + Send + '_> = Box::new(|| {
        result = Some(catch_unwind(AssertUnwindSafe(|| {
            ManuallyDrop::into_inner(work)()
        })));
    });
    // SAFETY: F and R are Send; the job exclusively borrows this result slot. The caller cannot
    // access or destroy it until Completion receives the worker's acknowledgement, sent only AFTER
    // invoking and destroying this entire job. The channel owns the job exactly once. Publication
    // failure aborts rather than releasing the slot; Completion also waits on any host unwind after
    // publication. No cancel, detach or early return exists. Pre-invocation destruction retains F.
    let erased: Box<dyn FnOnce() + Send + 'static> = unsafe { std::mem::transmute(borrowed) };
    let mut completion = Completion {
        done: receiver,
        finished: false,
    };
    if lease.sender.send(Job { run: erased, done }).is_err() {
        std::process::abort();
    }
    completion.finish();
    drop(lease);
    result.expect("a completed lifecycle callback writes its outcome exactly once")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier, Mutex, mpsc};

    #[test]
    fn borrowed_input_and_result_complete_on_the_canonical_worker() {
        let caller = std::thread::current().id();
        let mut value = String::from("borrowed");
        run(|| {
            assert!(is_worker());
            assert_eq!(std::thread::current().name(), Some("busbar-plugin-ffi"));
            assert_ne!(std::thread::current().id(), caller);
            value.push_str(" result");
        })
        .unwrap();
        let result = run(|| value.as_str()).unwrap();
        assert_eq!(result, "borrowed result");
    }

    #[test]
    fn a_panicking_callback_keeps_its_worker_alive_and_its_payload_intact() {
        let own: &'static Mutex<Pool> = Box::leak(Box::new(Mutex::new(Pool::empty())));
        let before = run_with(|| std::thread::current().id(), || acquire(own)).unwrap();
        let failed = run_with(
            || std::panic::panic_any(String::from("opaque payload")),
            || acquire(own),
        );
        assert_eq!(
            *failed.unwrap_err().downcast::<String>().unwrap(),
            "opaque payload"
        );
        let after = run_with(|| std::thread::current().id(), || acquire(own)).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn nested_callbacks_use_distinct_permanent_workers() {
        let (outer, inner) = run(|| {
            let outer = std::thread::current().id();
            let inner = run(|| {
                assert!(is_worker());
                std::thread::current().id()
            })
            .unwrap();
            (outer, inner)
        })
        .unwrap();
        assert_ne!(outer, inner);
    }

    #[test]
    fn concurrent_callbacks_reserve_distinct_workers() {
        let barrier = Arc::new(Barrier::new(4));
        let callers: Vec<_> = (0..4)
            .map(|_| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    run(|| {
                        barrier.wait();
                        assert!(is_worker());
                        std::thread::current().id()
                    })
                    .unwrap()
                })
            })
            .collect();
        let ids: std::collections::HashSet<_> = callers
            .into_iter()
            .map(|call| call.join().unwrap())
            .collect();
        assert_eq!(ids.len(), 4);
    }

    #[test]
    fn caller_cannot_return_while_the_worker_holds_its_borrow() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (returned_tx, returned_rx) = mpsc::channel();
        let caller = std::thread::spawn(move || {
            let mut borrowed = String::from("before");
            let held = &mut borrowed;
            run(move || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                held.push_str(" after");
            })
            .unwrap();
            returned_tx.send(borrowed).unwrap();
        });
        entered_rx.recv().unwrap();
        assert!(matches!(
            returned_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        release_tx.send(()).unwrap();
        assert_eq!(returned_rx.recv().unwrap(), "before after");
        caller.join().unwrap();
    }

    struct OnDrop(Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for OnDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn acquisition_failure_retains_owned_captures_without_invocation_or_retry() {
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let owned = OnDrop(drops.clone());
        let called = calls.clone();
        let failed = std::panic::catch_unwind(|| {
            run_with(
                move || {
                    called.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    drop(owned);
                },
                || panic!("injected acquisition failure"),
            )
        });
        assert!(failed.is_err());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
