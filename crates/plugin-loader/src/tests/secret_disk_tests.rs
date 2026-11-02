// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use busbar_contract::abi::secret::{
    ERROR_KIND_DENIED, ERROR_KIND_INTERNAL, ERROR_KIND_UNAVAILABLE,
};
use busbar_contract::config_time::{ConfigScope, RESOLVE_OFF_CONFIG_TIME};
use busbar_contract::redacted::Secret;
use busbar_contract::secret::{SecretAxis, SecretRefused};
use busbar_contract::secret_ref::SecretRef;

use super::SecretRows;
use crate::boot::Candidate;
use crate::dispatch::{DispatchConfig, Dispatcher};

use crate::actual_env_secret as secret_fixture;
use secret_fixture::door;
use secret_fixture::NAME;

const MATERIAL: &str = "s3cr3t-on-the-disk-lane";
const HIT: &str = "BUSBAR_LOADER_SECRET_DISK_HIT";

fn environment() {
    std::env::set_var(HIT, MATERIAL);
}

fn dispatcher() -> Arc<Dispatcher> {
    static ONE: std::sync::OnceLock<Arc<Dispatcher>> = std::sync::OnceLock::new();
    ONE.get_or_init(|| Arc::new(Dispatcher::new(DispatchConfig::default())))
        .clone()
}

fn unreached(r: &SecretRef) -> Result<busbar_contract::redacted::Secret<Vec<u8>>, String> {
    panic!("no secret reference to resolve: {}", r.describe())
}

fn hit() -> Vec<u8> {
    format!(r#"{{"key":"{HIT}"}}"#).into_bytes()
}

fn spell(r: Result<Secret<Vec<u8>>, SecretRefused>) -> String {
    match r {
        Ok(m) => format!(
            "ok {}",
            String::from_utf8_lossy(m.expose(&busbar_contract::plugin::TestKernelSeal))
        ),
        Err(e) => format!("refused {} {}", e.error_kind, e.text),
    }
}

fn lane(job: Box<dyn FnOnce() + Send>) -> Result<(), String> {
    std::thread::Builder::new()
        .name("test-disk-lane".into())
        .spawn(job)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn full_lane(_job: Box<dyn FnOnce() + Send>) -> Result<(), String> {
    Err("the host's disk lane is full".to_string())
}

fn dropping_lane(job: Box<dyn FnOnce() + Send>) -> Result<(), String> {
    drop(job);
    Ok(())
}

static COUNTED_JOBS: AtomicUsize = AtomicUsize::new(0);
fn counted_lane(job: Box<dyn FnOnce() + Send>) -> Result<(), String> {
    COUNTED_JOBS.fetch_add(1, Ordering::SeqCst);
    lane(job)
}

static UNTOUCHED_JOBS: AtomicUsize = AtomicUsize::new(0);
fn untouched_lane(job: Box<dyn FnOnce() + Send>) -> Result<(), String> {
    UNTOUCHED_JOBS.fetch_add(1, Ordering::SeqCst);
    drop(job);
    Err("this lane is not for a source that declares no disk need".to_string())
}

fn disk_rows(run: Option<super::DiskRun>) -> SecretRows {
    let mut rows = SecretRows::new(dispatcher, || None);
    if let Some(run) = run {
        rows = rows.with_disk_lane(run);
    }
    rows.link(door).expect("the env source's door links");
    rows.declare_linked(door, r#"{"disk": true}"#)
        .expect("its declares section reads");
    rows
}

#[test]
fn a_disk_source_answers_only_at_config_time_and_only_on_the_lane() {
    environment();
    let rows = disk_rows(Some(counted_lane));
    let shared = rows
        .shared(NAME)
        .expect("the linked source has a shared instance");

    let request = spell(shared.resolve(&hit()));
    assert!(
        request.starts_with(&format!("refused {ERROR_KIND_DENIED} ")),
        "{request}"
    );
    assert!(request.contains(RESOLVE_OFF_CONFIG_TIME), "{request}");

    let before = COUNTED_JOBS.load(Ordering::SeqCst);
    let at_config = spell(shared.resolve_at_config(&hit(), &ConfigScope::config_time()));
    assert_eq!(at_config, format!("ok {MATERIAL}"));
    assert_eq!(
        COUNTED_JOBS.load(Ordering::SeqCst),
        before + 1,
        "the config-time resolve ran as one job on the lane"
    );
}

#[test]
fn a_dropped_in_disk_source_is_refused_on_a_request_path() {
    environment();
    let rows = SecretRows::new(dispatcher, || None).with_disk_lane(lane);
    let candidate = Candidate::linked(door)
        .expect("the door states itself")
        .reading_disk(true);
    rows.set_dropped([candidate]);
    let opened = rows
        .open(NAME, &serde_json::json!({}), &unreached)
        .expect("the source opens");
    let request = spell(opened.resolve(&hit()));
    assert!(
        request.starts_with(&format!("refused {ERROR_KIND_DENIED} ")),
        "{request}"
    );
    assert_eq!(
        spell(opened.resolve_at_config(&hit(), &ConfigScope::config_time())),
        format!("ok {MATERIAL}")
    );
}

#[test]
fn a_source_with_no_disk_need_is_unchanged_and_never_reaches_the_lane() {
    environment();
    let mut rows = SecretRows::new(dispatcher, || None).with_disk_lane(untouched_lane);
    rows.link(door).expect("the env source's door links");
    let shared = rows
        .shared(NAME)
        .expect("the linked source has a shared instance");
    let request = spell(shared.resolve(&hit()));
    let at_config = spell(shared.resolve_at_config(&hit(), &ConfigScope::config_time()));
    assert_eq!(request, format!("ok {MATERIAL}"));
    assert_eq!(at_config, request);
    assert_eq!(UNTOUCHED_JOBS.load(Ordering::SeqCst), 0);
}

#[test]
fn a_lane_that_will_not_run_the_job_answers_at_once() {
    environment();
    let scope = ConfigScope::config_time();

    let full = disk_rows(Some(full_lane));
    let refused = spell(
        full.shared(NAME)
            .expect("shared")
            .resolve_at_config(&hit(), &scope),
    );
    assert!(
        refused.starts_with(&format!("refused {ERROR_KIND_UNAVAILABLE} ")),
        "{refused}"
    );
    assert!(
        refused.contains("the host's disk lane is full"),
        "{refused}"
    );

    let dropping = disk_rows(Some(dropping_lane));
    let started = std::time::Instant::now();
    let dropped = spell(
        dropping
            .shared(NAME)
            .expect("shared")
            .resolve_at_config(&hit(), &scope),
    );
    assert!(
        dropped.starts_with(&format!("refused {ERROR_KIND_INTERNAL} ")),
        "{dropped}"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "a dropped job is answered at once, not at the wait's bound"
    );
}

#[test]
fn a_disk_source_with_no_lane_refuses_every_resolve() {
    environment();
    let rows = disk_rows(None);
    let shared = rows.shared(NAME).expect("shared");
    let at_config = spell(shared.resolve_at_config(&hit(), &ConfigScope::config_time()));
    assert!(
        at_config.starts_with(&format!("refused {ERROR_KIND_UNAVAILABLE} ")),
        "{at_config}"
    );
    assert!(spell(shared.resolve(&hit())).starts_with(&format!("refused {ERROR_KIND_DENIED} ")));
}

#[test]
fn a_linked_declares_section_that_does_not_read_is_refused() {
    let mut rows = SecretRows::new(dispatcher, || None);
    rows.link(door).expect("the env source's door links");
    let Err(refused) = rows.declare_linked(door, r#"{"disk": "yes"}"#) else {
        panic!("`disk` is a bool");
    };
    assert!(refused.contains(NAME), "{refused}");
}

#[test]
fn an_expired_queued_disk_resolve_releases_its_instance_before_the_queue_runs() {
    use crate::dispatch::kinds::secret::Secret as SecretKind;
    use crate::dispatch::{load_linked, Bind, ConnTable, LinkedRow, NoSink};
    use busbar_contract::secret::SecretCalls;

    type Job = Box<dyn FnOnce() + Send>;
    static QUEUED: std::sync::Mutex<Option<Job>> = std::sync::Mutex::new(None);
    fn queue(job: Job) -> Result<(), String> {
        *QUEUED.lock().unwrap() = Some(job);
        Ok(())
    }

    environment();
    let d = dispatcher();
    let plugin = load_linked::<SecretKind>(
        &LinkedRow::of(door).unwrap(),
        Bind {
            instance: Arc::from("expired-disk-resolve"),
            max_inflight_cap: 16,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .unwrap();
    let source = super::LoadedSecret::open(plugin, d, b"{}", &[])
        .unwrap()
        .reading_disk(Some(queue));
    let weak = Arc::downgrade(&source.opened);
    let started = std::time::Instant::now();
    let caller =
        std::thread::spawn(move || source.resolve_at_config(&hit(), &ConfigScope::config_time()));

    let result = caller.join().unwrap();
    let elapsed = started.elapsed();
    let retained = weak.strong_count() != 0;
    let queued = QUEUED
        .lock()
        .unwrap()
        .take()
        .expect("the resolver was queued");
    queued();
    assert!(
        result.is_err(),
        "a resolve still queued at its deadline is refused"
    );
    assert!(
        elapsed < super::WAIT + std::time::Duration::from_secs(5),
        "queue delay never extends the original deadline"
    );
    assert!(
        !retained,
        "the timed-out queue entry no longer owns the plugin instance"
    );
    assert_eq!(
        weak.strong_count(),
        0,
        "draining the expired callback cannot resurrect its owner"
    );
}

#[test]
fn an_expired_callback_with_an_unscheduled_waiter_drops_without_running() {
    let owned = Arc::new(());
    let weak = Arc::downgrade(&owned);
    let ran = Arc::new(AtomicUsize::new(0));
    let called = Arc::clone(&ran);
    let work: super::DiskJob = Box::new(move || {
        called.fetch_add(1, Ordering::SeqCst);
        drop(owned);
    });
    let pending = Arc::new(std::sync::Mutex::new(Some(work)));
    let waiting = super::QueuedDiskResolve {
        pending: Arc::clone(&pending),
        deadline: std::time::Instant::now(),
    };
    let queued = super::QueuedDiskResolve {
        pending,
        deadline: waiting.deadline,
    };
    queued.run();
    assert_eq!(ran.load(Ordering::SeqCst), 0);
    assert_eq!(
        weak.strong_count(),
        0,
        "no waiter poll is needed for expiry"
    );
    drop(waiting);
}

#[test]
fn dropped_waiter_and_completed_callback_release_queued_custody() {
    for abandon in [true, false] {
        let owned = Arc::new(());
        let weak = Arc::downgrade(&owned);
        let ran = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&ran);
        let work: super::DiskJob = Box::new(move || {
            called.fetch_add(1, Ordering::SeqCst);
            drop(owned);
        });
        let pending = Arc::new(std::sync::Mutex::new(Some(work)));
        let waiting = super::QueuedDiskResolve {
            pending: Arc::clone(&pending),
            deadline: std::time::Instant::now() + super::WAIT,
        };
        let queued = super::QueuedDiskResolve {
            pending,
            deadline: waiting.deadline,
        };
        if abandon {
            drop(waiting);
            assert_eq!(
                weak.strong_count(),
                0,
                "the queue retains no abandoned owner"
            );
            queued.run();
        } else {
            queued.run();
            assert_eq!(
                weak.strong_count(),
                0,
                "the waiter retains no completed owner"
            );
            drop(waiting);
        }
        assert_eq!(ran.load(Ordering::SeqCst), usize::from(!abandon));
    }
}

#[test]
fn withdrawing_queued_custody_runs_reentrant_drop_outside_the_mutex() {
    struct Reenter {
        pending: std::sync::Weak<std::sync::Mutex<Option<super::DiskJob>>>,
        answered: std::sync::mpsc::Sender<bool>,
    }
    impl Drop for Reenter {
        fn drop(&mut self) {
            let outside = self
                .pending
                .upgrade()
                .is_some_and(|pending| pending.try_lock().is_ok_and(|job| job.is_none()));
            let _ = self.answered.send(outside);
        }
    }

    let pending = Arc::new(std::sync::Mutex::new(None));
    let (answered, answer) = std::sync::mpsc::channel();
    let reenter = Reenter {
        pending: Arc::downgrade(&pending),
        answered,
    };
    let work: super::DiskJob = Box::new(move || drop(reenter));
    *pending.lock().unwrap() = Some(work);
    let waiting = super::QueuedDiskResolve {
        pending: Arc::clone(&pending),
        deadline: std::time::Instant::now() + super::WAIT,
    };
    drop(waiting);
    assert!(answer
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap());
    assert!(pending.lock().unwrap().is_none());
}

#[test]
fn abandoning_a_running_resolve_keeps_its_custody_until_the_crossing_returns() {
    let owned = Arc::new(());
    let weak = Arc::downgrade(&owned);
    let (entered_tx, entered) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let (finished_tx, finished) = std::sync::mpsc::channel();
    let work: super::DiskJob = Box::new(move || {
        let _ = entered_tx.send(());
        let _ = released.recv_timeout(std::time::Duration::from_secs(30));
        drop(owned);
        let _ = finished_tx.send(());
    });
    let pending = Arc::new(std::sync::Mutex::new(Some(work)));
    let waiting = super::QueuedDiskResolve {
        pending: Arc::clone(&pending),
        deadline: std::time::Instant::now() + super::WAIT,
    };
    let queued = super::QueuedDiskResolve {
        pending,
        deadline: waiting.deadline,
    };
    let crossing = std::thread::spawn(move || queued.run());
    let running = entered.recv_timeout(std::time::Duration::from_secs(10));
    drop(waiting);
    let retained = weak.strong_count();
    let _ = release.send(());
    let returned = finished.recv_timeout(std::time::Duration::from_secs(10));
    running.expect("the crossing took custody before abandonment");
    returned.expect("the controlled crossing returns");
    crossing.join().unwrap();
    assert_eq!(
        retained, 1,
        "the running crossing still owns its lent memory"
    );
    assert_eq!(weak.strong_count(), 0, "return releases that final owner");
}
