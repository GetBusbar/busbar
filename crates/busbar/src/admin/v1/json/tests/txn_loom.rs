//! §5.5 — a TARGETED loom model of the one invariant the config-mutation lock exists to protect.
//!
//! Run with `scripts/loom.sh` (`cargo test -p busbar --features loom-model txn_loom`). The whole
//! file sits behind the optional `loom-model` feature, so it never compiles into a normal build or
//! CI test run. It is a cargo FEATURE rather than loom's usual `--cfg loom` because RUSTFLAGS is
//! global: `--cfg loom` makes tokio compile out `tokio::net`, which the server needs.
//!
//! SCOPE, deliberately narrow. Loom explores thread interleavings over ITS OWN sync primitives; it
//! cannot model `tokio::sync::Mutex`, `spawn_blocking`, or thread parking, so the
//! blocking-under-the-lock class is proven instead by the executor-not-stalled assertion in
//! `txn_tests.rs` (loom could not see a parked worker anyway) and by the compile fence. What loom
//! CAN decide exactly is the LOST-UPDATE question: the `read snapshot → build next → swap` sequence
//! that `AppHandle::load`/`AppHandle::swap` implement over an `RwLock<Arc<App>>`, and whether the
//! mutual exclusion `config_transaction` wraps it in is actually sufficient. That is modelled here
//! over loom's `RwLock` + `Mutex`, both directions:
//!
//! - WITHOUT the section (the shape the tree had before every mutation funnelled through one door),
//!   loom finds an interleaving where one increment is silently lost — the exact defect;
//! - WITH the section, no interleaving loses one.

use loom::sync::{Arc, Mutex, RwLock};

/// The `AppHandle` shape under test: a swappable snapshot behind an `RwLock`, read by `load` and
/// replaced wholesale by `swap` — `crate::state::AppHandle` in miniature, with `config_version`
/// standing in for the whole `App`.
struct Handle {
    current: RwLock<Arc<usize>>,
}

impl Handle {
    fn load(&self) -> Arc<usize> {
        self.current.read().unwrap().clone()
    }
    fn swap(&self, next: Arc<usize>) {
        *self.current.write().unwrap() = next;
    }
}

/// WITH the transaction: `read → build → swap` runs under one mutual-exclusion section, exactly as
/// `config_transaction` runs it under `CONFIG_MUTATION_LOCK`. No interleaving may lose an update.
#[test]
fn transaction_never_loses_a_swap() {
    loom::model(|| {
        let handle = Arc::new(Handle {
            current: RwLock::new(Arc::new(0usize)),
        });
        let section = Arc::new(Mutex::new(()));
        let ths: Vec<_> = (0..2)
            .map(|_| {
                let (handle, section) = (handle.clone(), section.clone());
                loom::thread::spawn(move || {
                    let _guard = section.lock().unwrap();
                    let current = handle.load(); // the FRESH post-lock snapshot
                    handle.swap(Arc::new(*current + 1)); // build + swap, still under the guard
                })
            })
            .collect();
        for t in ths {
            t.join().unwrap();
        }
        assert_eq!(
            *handle.load(),
            2,
            "LOST UPDATE: two transactions both read version N and one swap was silently \
             discarded — the section must span read→build→swap"
        );
    });
}

/// WITHOUT the transaction (documentation of the defect the door closes): loom is expected to find
/// an interleaving in which both threads read the same version and one swap is lost. The model
/// records whether ANY execution lost an update and asserts that it did — so if this ever stops
/// failing, the model itself has gone blind and the positive test above means nothing.
#[test]
fn unsectioned_read_build_swap_loses_an_update() {
    let lost = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let witness = lost.clone();
    loom::model(move || {
        let handle = Arc::new(Handle {
            current: RwLock::new(Arc::new(0usize)),
        });
        let ths: Vec<_> = (0..2)
            .map(|_| {
                let handle = handle.clone();
                loom::thread::spawn(move || {
                    let current = handle.load(); // NO section: the read and the swap can interleave
                    handle.swap(Arc::new(*current + 1));
                })
            })
            .collect();
        for t in ths {
            t.join().unwrap();
        }
        if *handle.load() != 2 {
            witness.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });
    assert!(
        lost.load(std::sync::atomic::Ordering::SeqCst) > 0,
        "the model found NO lost-update interleaving without the section — the model is not \
         exercising the race it claims to, so the positive test proves nothing"
    );
}
