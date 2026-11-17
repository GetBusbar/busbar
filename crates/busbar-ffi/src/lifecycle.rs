// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
            assert_ne!(std::thread::current().id(), caller);
            value.push_str(" result");
        })
        .unwrap();
        let result = run(|| value.as_str()).unwrap();
        assert_eq!(result, "borrowed result");
    }

    #[test]
    fn a_panicking_callback_keeps_its_worker_alive_and_its_payload_intact() {
        let own = Box::leak(Box::new(Mutex::new(Pool::empty())));
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
