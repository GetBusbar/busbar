// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use super::OpenOnce;

#[test]
fn a_wedged_open_blocks_no_other_caller() {
    let once: Arc<OpenOnce<&'static str, u32>> = Arc::new(OpenOnce::new());
    once.get_or_open(&"held", || Ok::<_, ()>(1)).unwrap();
    let (entered_tx, entered) = mpsc::channel();
    let (release, release_rx) = mpsc::channel::<()>();
    let wedged = {
        let once = Arc::clone(&once);
        std::thread::spawn(move || {
            once.get_or_open(&"wedged", || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok::<_, ()>(2)
            })
            .unwrap()
        })
    };
    entered.recv().unwrap();

    let (done_tx, done) = mpsc::channel();
    {
        let once = Arc::clone(&once);
        std::thread::spawn(move || {
            let held = once.get_or_open(&"held", || Ok::<_, ()>(9)).unwrap();
            let other = once.get_or_open(&"other", || Ok::<_, ()>(3)).unwrap();
            done_tx.send((*held.0, *other.0)).unwrap();
        });
    }
    let answered = done.recv_timeout(Duration::from_secs(5));
    release.send(()).unwrap();
    assert_eq!(
        answered,
        Ok((1, 3)),
        "a wedged open held another caller behind the lock"
    );
    let (v, installed) = wedged.join().unwrap();
    assert_eq!((*v, installed), (2, true));
}

#[test]
fn one_instance_per_key() {
    let once: OpenOnce<u8, u32> = OpenOnce::new();
    let (a, first) = once.get_or_open(&1, || Ok::<_, ()>(10)).unwrap();
    let (b, again) = once
        .get_or_open(&1, || -> Result<u32, ()> { panic!("opened twice") })
        .unwrap();
    assert!(first && !again);
    assert!(Arc::ptr_eq(&a, &b));
}

#[test]
fn a_failed_open_installs_nothing() {
    let once: OpenOnce<u8, u32> = OpenOnce::new();
    assert_eq!(
        once.get_or_open(&1, || Err::<u32, _>("no")).unwrap_err(),
        "no"
    );
    assert!(once.get(&1).is_none());
    assert_eq!(*once.get_or_open(&1, || Ok::<_, &str>(4)).unwrap().0, 4);
}

#[test]
fn of_two_racing_opens_the_first_installed_is_kept() {
    let once: OpenOnce<u8, u32> = OpenOnce::new();
    let (kept, installed) = once
        .get_or_open(&1, || {
            assert!(once.get_or_open(&1, || Ok::<_, ()>(7)).unwrap().1);
            Ok::<_, ()>(8)
        })
        .unwrap();
    assert_eq!((*kept, installed), (7, false));
    assert_eq!(*once.get(&1).unwrap(), 7);
}
