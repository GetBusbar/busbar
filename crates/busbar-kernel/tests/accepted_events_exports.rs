// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::export::{ExportField as F, ExportStream};
use busbar_contract::abi::mechanism::route::Route;
use busbar_contract::export_calls::{
    Delivered, ExportAxis, ExportCalls, Family, Probed, ServeRequest, Served,
};
use busbar_contract::plugin::Kind;
use busbar_contract::records::*;
use busbar_kernel::audit::auditlog::{
    emit_admin_hostless_now, plugin_refusal_resource, record_plugin_refusal, PluginRefusal,
    AUDIT_LOG,
};
use busbar_kernel::audit_ring::OUTCOME_APPLIED;
use busbar_kernel::config::{resolve_export, ExportDefCfg, ExportDefs};
use busbar_kernel::governance::GovState;
use busbar_kernel::preflight::{publish_root_rows, RootInstall};
use busbar_kernel_testkit::test_support::store_double::MemoryStore;
use serde_json::Value;

const MODULE: &str = "accepted-events-fixture";
const FULL: &str = "full";
const NARROW: &str = "narrow";
const LOGS_ONLY: &str = "logs-only";
const ACTION: &str = "fixture.mutate";
const FIRST_RESOURCE: &str = "fixture:first";
const QUEUED_RESOURCE: &str = "fixture:queued";
const RECOVERY_RESOURCE: &str = "fixture:recovered";
const FAILURE_RECOVERY_RESOURCE: &str = "fixture:failure-recovered";
const PRINCIPAL: &str = "fixture-admin";
const FAILURE_INSTANCE: &str = "accepted-events-failure";
const FAILURE_CODE: &str = "fixture-delivery-failed";
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
const ONE_RECORD: usize = 1;
const FIRST_PAGE: usize = 0;
const CARRIES: &[u8] = &[ExportStream::Events as u8, ExportStream::Logs as u8];

#[derive(Default)]
struct Durable {
    inner: MemoryStore,
    down: AtomicBool,
    rows: Mutex<Vec<PlaneRecord>>,
}

impl RecordStore for Durable {
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(&self, bucket: &str, window: u64) -> RecordStoreResult<UsageLedger> {
        self.inner.get_usage(bucket, window)
    }
    fn put_usage(&self, bucket: &str, window: u64, usage: &UsageLedger) -> RecordStoreResult<()> {
        self.inner.put_usage(bucket, window, usage)
    }
    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(bucket)
    }
    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        if self.down.load(Ordering::SeqCst) {
            return Err(RecordStoreError("fixture durable store is down".into()));
        }
        self.rows.lock().unwrap().push(record.to_record());
        Ok(())
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        let mut rows: Vec<_> = self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|row| {
                row.kind == kind
                    && match selector {
                        PlaneSelector::All => true,
                        PlaneSelector::Parent(parent) => {
                            row.parent.as_deref() == Some(parent.as_ref())
                        }
                    }
            })
            .cloned()
            .collect();
        rows.sort_by_key(|row| row.seq);
        Ok(rows.into_iter().map(|row| row.body).collect())
    }
    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>> {
        let mut parents: Vec<_> = self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|row| row.kind == kind)
            .filter_map(|row| row.parent.clone())
            .collect();
        parents.sort();
        parents.dedup();
        Ok(parents)
    }
}

struct Sink {
    lines: Mutex<Vec<Value>>,
    fail_once: AtomicBool,
    failure: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Sink {
    fn new() -> Self {
        Self {
            lines: Mutex::new(Vec::new()),
            fail_once: AtomicBool::new(false),
            failure: Mutex::new(None),
            worker: Mutex::new(None),
        }
    }
    fn matching(&self, resource: &str) -> Vec<Value> {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .filter(|line| line[F::Resource.as_token()] == resource)
            .cloned()
            .collect()
    }
}

impl ExportCalls for Sink {
    fn streams(&self) -> &[u8] {
        CARRIES
    }
    fn routes(&self) -> &[Route] {
        &[]
    }
    fn deliver(&self, stream: u8, line: Vec<u8>, _: Box<dyn Send>) -> Delivered {
        assert_eq!(stream, ExportStream::Events as u8);
        let line: Value = serde_json::from_slice(&line).unwrap();
        if let Some(resource) = line[F::Resource.as_token()].as_str() {
            assert!(
                !AUDIT_LOG
                    .list_filtered(FIRST_PAGE, ONE_RECORD, None, Some(resource))
                    .is_empty(),
                "the ring is visible before the export callback"
            );
        }
        let fails = line[F::Resource.as_token()] == FIRST_RESOURCE
            && self.fail_once.swap(false, Ordering::SeqCst);
        self.lines.lock().unwrap().push(line);
        if fails {
            let (done, release) = self.failure.lock().unwrap().take().unwrap();
            *self.worker.lock().unwrap() = Some(std::thread::spawn(move || {
                release.recv_timeout(CONTROL_TIMEOUT).unwrap();

                record_plugin_refusal(
                    PluginRefusal::Op,
                    Kind::Export.root(),
                    FAILURE_INSTANCE,
                    FAILURE_CODE,
                );
                done.send(()).unwrap();
            }));
        }
        Delivered::Queued
    }
    fn scrape(&self, _: &[Family]) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }
    fn status(&self) -> Option<Vec<u8>> {
        None
    }
    fn serve(&self, _: &ServeRequest<'_>) -> Result<Served, String> {
        Err("fixture is push-only".into())
    }
}

struct Axis {
    full: Arc<Sink>,
    narrow: Arc<Sink>,
    logs: Arc<Sink>,
}

impl ExportAxis for Axis {
    fn probe(&self, module: &str, _: &str, _: &Value) -> Option<Probed> {
        (module == MODULE).then(|| (Some(CARRIES.to_vec()), Vec::new()))
    }
    fn check(&self, module: &str, _: u32, _: &[(String, &Value)]) -> Option<Vec<String>> {
        (module == MODULE).then(Vec::new)
    }
    fn open(&self, module: &str, label: &str, _: &Value) -> Result<Arc<dyn ExportCalls>, String> {
        assert_eq!(module, MODULE);
        let name = label.rsplit('.').next().unwrap();
        Ok(match name {
            FULL => self.full.clone(),
            NARROW => self.narrow.clone(),
            LOGS_ONLY => self.logs.clone(),
            _ => panic!("unexpected fixture instance"),
        })
    }
    fn linked(&self, module: &str) -> bool {
        module == MODULE
    }
    fn first_party(&self, module: &str) -> bool {
        module == MODULE
    }
}

fn definition(stream: ExportStream, fields: Option<&[F]>) -> ExportDefCfg {
    ExportDefCfg {
        module: MODULE.into(),
        streams: Some(vec![stream.as_token().into()]),
        fields: fields.map(|fields| fields.iter().map(|field| field.as_token().into()).collect()),
        durable: false,
        settings: serde_json::Map::new(),
    }
}

#[test]
fn accepted_events_project_once_and_async_export_failures_do_not_feed_back() {
    let axis: &'static Axis = Box::leak(Box::new(Axis {
        full: Arc::new(Sink::new()),
        narrow: Arc::new(Sink::new()),
        logs: Arc::new(Sink::new()),
    }));
    publish_root_rows(RootInstall {
        export_axis: Some(axis),
        ..RootInstall::default()
    });
    let mut defs = ExportDefs::new();
    defs.insert(FULL.into(), definition(ExportStream::Events, None));
    defs.insert(
        NARROW.into(),
        definition(
            ExportStream::Events,
            Some(ExportStream::Events.pinned_fields()),
        ),
    );
    defs.insert(LOGS_ONLY.into(), definition(ExportStream::Logs, None));
    let mut errors = Vec::new();
    let config = resolve_export(&defs, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
    busbar_kernel::export::plugin::open(&config).unwrap();
    let store = Arc::new(Durable::default());
    let app = busbar_kernel_testkit::test_support::TestApp::new()
        .governance(Arc::new(GovState::new(store.clone(), None).unwrap()))
        .build();
    busbar_kernel::boot::hydrate_all(&app).unwrap();
    busbar_kernel::export::plugin::start().unwrap();

    let (done, finished) = mpsc::channel();
    let (release, released) = mpsc::channel();
    *axis.full.failure.lock().unwrap() = Some((done, released));
    axis.full.fail_once.store(true, Ordering::SeqCst);
    emit_admin_hostless_now(ACTION, FIRST_RESOURCE, OUTCOME_APPLIED, PRINCIPAL);
    let first = axis.full.matching(FIRST_RESOURCE);
    assert_eq!(
        first.len(),
        ONE_RECORD,
        "one accepted mutation is exported once"
    );
    let first = &first[FIRST_PAGE];
    assert_eq!(first[F::Kind.as_token()], ACTION);
    assert_eq!(first[F::Actor.as_token()], PRINCIPAL);
    assert_eq!(first[F::Outcome.as_token()], OUTCOME_APPLIED);
    {
        let narrow = axis.narrow.lines.lock().unwrap();
        let narrow = narrow.last().unwrap();
        assert_eq!(narrow[F::Seq.as_token()], first[F::Seq.as_token()]);
        assert_eq!(narrow[F::Ts.as_token()], first[F::Ts.as_token()]);
        assert_eq!(
            narrow[F::PrevHash.as_token()],
            first[F::PrevHash.as_token()]
        );
        for field in [F::Kind, F::Actor, F::Resource, F::Outcome] {
            assert!(narrow.get(field.as_token()).is_none());
        }
    }
    assert!(axis.logs.lines.lock().unwrap().is_empty());
    store.down.store(true, Ordering::SeqCst);
    release.send(()).unwrap();
    finished.recv_timeout(CONTROL_TIMEOUT).unwrap();
    axis.full
        .worker
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .join()
        .unwrap();
    let failure_resource =
        plugin_refusal_resource(Kind::Export.root(), FAILURE_INSTANCE, FAILURE_CODE);
    assert!(AUDIT_LOG
        .list_filtered(FIRST_PAGE, ONE_RECORD, None, Some(&failure_resource))
        .is_empty());
    assert!(axis.full.matching(&failure_resource).is_empty());
    store.down.store(false, Ordering::SeqCst);
    emit_admin_hostless_now(
        ACTION,
        FAILURE_RECOVERY_RESOURCE,
        OUTCOME_APPLIED,
        PRINCIPAL,
    );
    assert_eq!(
        AUDIT_LOG
            .list_filtered(FIRST_PAGE, ONE_RECORD, None, Some(&failure_resource))
            .len(),
        ONE_RECORD,
        "the asynchronous export refusal remains in the audit chain"
    );
    let failure = AUDIT_LOG.list_filtered(FIRST_PAGE, ONE_RECORD, None, Some(&failure_resource));
    assert!(
        store.rows.lock().unwrap().iter().any(|row| {
            row.kind == busbar_kernel::store::plane_view::KIND_AUDIT
                && row.seq == failure[FIRST_PAGE].seq
        }),
        "the asynchronous refusal is durably appended"
    );
    assert!(axis.full.matching(&failure_resource).is_empty());

    emit_admin_hostless_now(
        PluginRefusal::Op.action(),
        &failure_resource,
        OUTCOME_APPLIED,
        PRINCIPAL,
    );
    assert_eq!(axis.full.matching(&failure_resource).len(), ONE_RECORD);
    let auth_resource = plugin_refusal_resource(Kind::Auth.root(), FAILURE_INSTANCE, FAILURE_CODE);
    record_plugin_refusal(
        PluginRefusal::Op,
        Kind::Auth.root(),
        FAILURE_INSTANCE,
        FAILURE_CODE,
    );
    assert_eq!(axis.full.matching(&auth_resource).len(), ONE_RECORD);

    store.down.store(true, Ordering::SeqCst);
    emit_admin_hostless_now(ACTION, QUEUED_RESOURCE, OUTCOME_APPLIED, PRINCIPAL);
    assert!(axis.full.matching(QUEUED_RESOURCE).is_empty());
    assert!(AUDIT_LOG
        .list_filtered(FIRST_PAGE, ONE_RECORD, None, Some(QUEUED_RESOURCE))
        .is_empty());
    store.down.store(false, Ordering::SeqCst);
    emit_admin_hostless_now(ACTION, RECOVERY_RESOURCE, OUTCOME_APPLIED, PRINCIPAL);
    assert_eq!(axis.full.matching(QUEUED_RESOURCE).len(), ONE_RECORD);
    assert_eq!(axis.full.matching(RECOVERY_RESOURCE).len(), ONE_RECORD);
    let queued = axis.full.matching(QUEUED_RESOURCE).pop().unwrap();
    let recovered = axis.full.matching(RECOVERY_RESOURCE).pop().unwrap();
    assert_eq!(
        recovered[F::Seq.as_token()].as_u64(),
        queued[F::Seq.as_token()].as_u64().map(|seq| seq + 1)
    );
    let before_restore = axis.full.lines.lock().unwrap().clone();
    busbar_kernel::boot::hydrate_all(&app).unwrap();
    assert_eq!(
        *axis.full.lines.lock().unwrap(),
        before_restore,
        "restoring accepted records does not re-export them"
    );
}
