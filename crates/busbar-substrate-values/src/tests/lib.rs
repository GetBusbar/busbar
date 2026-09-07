//! Tests for `lib.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

/// `test_support::warn_capture` and `testkit::warn_capture` were two byte-identical COPIES of
/// the same `WarnCapture` layer, each with its OWN process-global serialization gate (see
/// either module's docs). Both compile into `cargo test -p busbar-substrate-values`, so a
/// `test_support` capture and a `testkit` capture never actually serialize against each
/// other — contradicting both files' stated one-gate invariant. Prove it: hold a `test_support`
/// capture on this thread, spawn a thread that constructs a `testkit` capture, and assert it
/// BLOCKS until the first drops (a single shared gate), rather than acquiring immediately (two
/// independent gates).
#[test]
fn test_support_and_testkit_share_one_capture_gate() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let held = crate::test_support::warn_capture::WarnCapture::default();
    let acquired = Arc::new(AtomicBool::new(false));
    let acquired_writer = acquired.clone();
    // The spawned thread says "I am about to try" BEFORE it tries. Without it, the negative check
    // below could pass on a loaded machine simply because the thread had not been scheduled yet —
    // "it did not acquire" and "it never ran" are the same observation, and only the first is the
    // claim. Waiting on the barrier makes the sleep a window for the ACQUIRE, not for the spawn.
    let ready = Arc::new(std::sync::Barrier::new(2));
    let ready_writer = ready.clone();

    let handle = std::thread::spawn(move || {
        ready_writer.wait();
        let _other = crate::testkit::warn_capture::WarnCapture::default();
        acquired_writer.store(true, Ordering::SeqCst);
    });

    // Both threads are now past the barrier, so the spawned one is inside (or entering) the
    // constructor. Give it every chance to (wrongly) acquire immediately.
    ready.wait();
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(
        !acquired.load(Ordering::SeqCst),
        "a testkit::WarnCapture acquired while a test_support::WarnCapture is still held — \
         the two are not sharing one process-global gate"
    );

    drop(held);
    handle.join().unwrap();
    assert!(
        acquired.load(Ordering::SeqCst),
        "the testkit::WarnCapture must acquire once the test_support::WarnCapture drops"
    );
}
