// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::{Arc, Mutex};

type Events = Arc<Mutex<Vec<(&'static str, std::thread::ThreadId)>>>;
struct Witness(&'static str, Events);
impl Drop for Witness {
    fn drop(&mut self) {
        self.1
            .lock()
            .unwrap()
            .push((self.0, std::thread::current().id()));
    }
}
fn custody(events: &Events) -> ImageCustody<Witness, Witness> {
    let mut owner = ImageCustody::new(Witness("backing", events.clone()));
    owner.opened = Some(Witness("image", events.clone()));
    owner
}

#[test]
fn submission_failure_retains_paired_image_and_backing() {
    let events = Events::default();
    let owner = custody(&events);
    assert!(!close_with(owner, |_| panic!("submission refused")));
    assert!(events.lock().unwrap().is_empty());
}

#[test]
fn successful_worker_close_releases_image_then_backing() {
    let events = Events::default();
    let caller = std::thread::current().id();
    assert!(close_with(custody(&events), |owner| {
        busbar_ffi::lifecycle::run(|| {
            owner.close_once(|image| {
                drop(image);
                true
            })
        })
    }));
    let seen = events.lock().unwrap();
    assert_eq!(
        seen.iter().map(|event| event.0).collect::<Vec<_>>(),
        ["image", "backing"]
    );
    assert_ne!(seen[0].1, caller);
    assert_eq!(seen[0].1, seen[1].1);
}

#[test]
fn uncertain_close_retains_backing_and_is_never_retried() {
    let events = Events::default();
    let mut owner = custody(&events);
    let mut calls = 0;
    assert!(!owner.close_once(|image| {
        calls += 1;
        std::mem::forget(image);
        false
    }));
    assert!(!owner.close_once(|_| {
        calls += 1;
        true
    }));
    drop(owner);
    assert_eq!(calls, 1);
    assert!(events.lock().unwrap().is_empty());
}

#[test]
fn close_panic_retains_backing_and_opaque_payload() {
    let events = Events::default();
    let payload = Witness("payload", events.clone());
    assert!(!close_with(custody(&events), |owner| {
        busbar_ffi::lifecycle::run(|| {
            owner.close_once(|image| {
                std::mem::forget(image);
                std::panic::panic_any(payload);
            })
        })
    }));
    assert!(events.lock().unwrap().is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn nested_residency_submission_failure_retains_real_retirement_backing() {
    let events = Events::default();
    let mut attempts = 0;
    retire_backing(Witness("backing", events.clone()), |_| {
        name_still_loaded_with("unused", |_| {
            attempts += 1;
            panic!("nested acquisition refused");
        })
    });
    assert_eq!(attempts, 1);
    assert!(events.lock().unwrap().is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn residency_callback_panic_retains_backing_and_payload() {
    let events = Events::default();
    let payload = Witness("payload", events.clone());
    retire_backing(Witness("backing", events.clone()), |_| {
        name_still_loaded_with("unused", |_| {
            busbar_ffi::lifecycle::run(|| std::panic::panic_any(payload))
        })
    });
    assert!(events.lock().unwrap().is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn only_a_definitely_nonresident_backing_is_released() {
    let events = Events::default();
    retire_backing(Witness("resident", events.clone()), |_| {
        name_still_loaded_with("unused", |_| Ok(true))
    });
    retire_backing(Witness("absent", events.clone()), |_| {
        name_still_loaded_with("unused", |_| Ok(false))
    });
    assert_eq!(
        events
            .lock()
            .unwrap()
            .iter()
            .map(|event| event.0)
            .collect::<Vec<_>>(),
        ["absent"]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn actual_native_refusal_submission_failure_retains_its_memfd_name() {
    use std::os::fd::AsRawFd as _;
    let bytes = std::fs::read(crate::both_ways::example_cdylib("native_pack_fixture")).unwrap();
    let owner =
        open_image(&bytes, "native-pack-fixture").unwrap_or_else(|_| panic!("fixture open"));
    let path = match owner.backing.as_ref().unwrap() {
        Staged::Memfd { fd } => format!("/proc/self/fd/{}", fd.as_ref().unwrap().as_raw_fd()),
        Staged::TempFile { .. } => panic!("Linux native fixture requires memfd"),
    };
    assert!(name_still_loaded(&path));
    assert!(!close_with(owner, |_| panic!(
        "actual refused-image close submission"
    )));
    assert!(std::fs::metadata(&path).is_ok());
    assert!(name_still_loaded(&path));
}
