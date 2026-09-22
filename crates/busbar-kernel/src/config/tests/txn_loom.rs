//! A TARGETED loom model of the one invariant the config-mutation lock exists to protect.
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

/// `loom::thread::Builder::stack_size` forwards, unconverted, straight through to `generator`'s
/// `Gn::new_opt(size, f)` -> `Stack::new(size)`, which computes `bytes = size *
/// size_of::<usize>()` -- i.e. this parameter counts 8-byte WORDS, not bytes, despite the "in
/// bytes" wording in loom's own public doc comment. That much of the old note here was right, and
/// it is confirmed in `generator-0.8.*/src/stack/mod.rs`. Everything the old note built on top of
/// it was not, and it is why this gate had never once been observed green:
///
/// 1. **THE SIZE IS NOT A REQUEST, IT IS AN ASSERTION.** `Stack::new` calls
///    `SysStack::allocate(bytes, true)` and `.expect("failed to alloc sys stack")` on the result,
///    and `allocate` REFUSES anything larger than `getrlimit(RLIMIT_STACK).rlim_max`
///    (`StackError::ExceedsMaximumSize`). It does not clamp. So an oversized value is not
///    "generous margin that only a real runner can prove" -- it is an unconditional abort on every
///    host whose hard stack limit is finite. macOS's is 64 MiB (`ulimit -Hs` = 65520 KiB), so the
///    previous 512 MiB value killed this test on every developer machine, 100% of the time; Linux
///    CI runners report `rlim_max` = unlimited, so the SAME constant allocates there. One constant,
///    two opposite outcomes, and no host on which both were ever checked.
///
/// 2. **THE ABORT DOES NOT EVEN REPORT ITSELF.** When `Gn::new_opt` panics, loom's
///    `Scheduler::run` unwinds while dropping the spawned closure -- which owns `loom::sync::Arc`s
///    whose `Drop` calls `Scheduler::with_state` OUTSIDE any model state. That second panic is a
///    panic in a destructor during cleanup, so the process aborts (SIGABRT) with loom's "cannot
///    access Loom execution state from outside a Loom model" on top and the real
///    "failed to alloc sys stack" scrolled off above it. The message that reads like a loom-usage
///    bug is a red herring; read the FIRST panic in the output, not the last.
///
/// 3. **THIS KNOB CANNOT REACH THE MODEL THREAD AT ALL, so it was never the right lever for the
///    original overflow.** `loom::rt::scheduler::Scheduler::run` spawns thread 0 -- the
///    `loom::model` closure itself, which is where this file's setup, `join`s and assertions run --
///    with `spawn_thread(Box::new(f), None)`, a hardcoded `None`. Thread 0 therefore ALWAYS gets
///    `generator::DEFAULT_STACK_SIZE` (0x1000 words = 32 KiB), and no `Builder::stack_size` here
///    can change it. Raising this constant to 48 MiB and then to 512 MiB could not have fixed an
///    overflow of the model body, which is the most likely reading of the earlier CI report that
///    48 MiB "also still overflowed": the stack that overflowed was not the one being resized.
///
/// The value below is therefore small, and chosen to be provable rather than hopeful: 2 MiB is
/// ~64x the spawned bodies' default and sits far below every hard `RLIMIT_STACK` seen (macOS
/// 64 MiB, Linux unlimited), so it allocates everywhere. Measured, not assumed: these two bodies,
/// lifted verbatim into a standalone crate, run clean at the bare 32 KiB default on macOS/arm64
/// AND Linux/arm64, in BOTH debug and release -- so this is margin over a footprint that already
/// fits, not a guess at one that does not. If a
/// future model body genuinely needs more, raise it -- but keep it under 64 MiB or it stops being
/// runnable on macOS, and do not expect it to affect thread 0.
const LOOM_STACK_WORDS: usize = 262_144; // 2 MiB real (words x 8), allocatable on every host

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
                // See LOOM_STACK_WORDS's doc comment for why this is needed and what it's in units of.
                loom::thread::Builder::new()
                    .stack_size(LOOM_STACK_WORDS)
                    .spawn(move || {
                        let _guard = section.lock().unwrap();
                        let current = handle.load(); // the FRESH post-lock snapshot
                        handle.swap(Arc::new(*current + 1)); // build + swap, still under the guard
                    })
                    .unwrap()
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
                // See LOOM_STACK_WORDS's doc comment for why this is needed and what it's in units of.
                loom::thread::Builder::new()
                    .stack_size(LOOM_STACK_WORDS)
                    .spawn(move || {
                        let current = handle.load(); // NO section: the read and the swap can interleave
                        handle.swap(Arc::new(*current + 1));
                    })
                    .unwrap()
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
