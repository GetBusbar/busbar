// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **A SECRET SOURCE THAT READS THE DISK** (THE DESIGN §11.11 R4, as the OWNER amended it
//! 2026-10-13): a source whose `declares` states a disk need resolves ONLY at config time, with the
//! proof, on the host's disk lane — never on a request path. The kind's real plugin (the env
//! source, as `secret_calls_tests` reaches it) stands in for the disk-reading one, declared so
//! through the linked-declares conduit or a dropped-in candidate's fact.
//!
//! RED arms: (a) a request-path `resolve` of a disk source is refused before anything is read;
//! (b) its config-time resolve runs through the lane hook, not the dispatcher; (c)/(e) a source that
//! declares no disk need answers byte-identically through both forms and never touches the lane;
//! (d) a lane that refuses or drops the job answers the caller at once, never a hang; and a disk
//! source on a host with no lane refuses every resolve.

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

use crate::both_ways::secret_fixture;
use secret_fixture::door::door;
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

/// A resolver no plugin reference reaches (the env source states no `secret_refs`).
fn unreached(r: &SecretRef) -> Result<Vec<u8>, String> {
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

/// A lane that runs each job on a thread of its own.
fn lane(job: Box<dyn FnOnce() + Send>) -> Result<(), String> {
    std::thread::Builder::new()
        .name("test-disk-lane".into())
        .spawn(job)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// A lane no job ever reaches: the host's own refusal.
fn full_lane(_job: Box<dyn FnOnce() + Send>) -> Result<(), String> {
    Err("the host's disk lane is full".to_string())
}

/// A lane that takes the job and drops it unrun.
fn dropping_lane(job: Box<dyn FnOnce() + Send>) -> Result<(), String> {
    drop(job);
    Ok(())
}

/// [`lane`] for the one test that counts its jobs: no other test's resolve runs on it, so the
/// count is that test's alone (tests run at once).
static COUNTED_JOBS: AtomicUsize = AtomicUsize::new(0);
fn counted_lane(job: Box<dyn FnOnce() + Send>) -> Result<(), String> {
    COUNTED_JOBS.fetch_add(1, Ordering::SeqCst);
    lane(job)
}

/// A lane a source that declares no disk need must never reach.
static UNTOUCHED_JOBS: AtomicUsize = AtomicUsize::new(0);
fn untouched_lane(job: Box<dyn FnOnce() + Send>) -> Result<(), String> {
    UNTOUCHED_JOBS.fetch_add(1, Ordering::SeqCst);
    drop(job);
    Err("this lane is not for a source that declares no disk need".to_string())
}

/// The env source, linked, declared a disk source through the linked-declares conduit, its lane
/// `run`.
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

/// (a) + (b): refused on a request path, answered at config time through the lane.
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

/// (a), DROPPED IN: a candidate whose signed manifest declares the disk need is held the same way.
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

/// (c) + (e): a source that declares no disk need answers byte-identically through both forms and
/// never reaches the lane.
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

/// (d): a lane that refuses the job, or takes it and drops it, answers the caller at once.
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

/// A disk source on a host that wired no lane refuses every resolve, at config time too.
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

/// The conduit refuses a declares section that is not one, naming the plugin.
#[test]
fn a_linked_declares_section_that_does_not_read_is_refused() {
    let mut rows = SecretRows::new(dispatcher, || None);
    rows.link(door).expect("the env source's door links");
    let Err(refused) = rows.declare_linked(door, r#"{"disk": "yes"}"#) else {
        panic!("`disk` is a bool");
    };
    assert!(refused.contains(NAME), "{refused}");
}
