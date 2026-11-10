// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::dispatch::{load_linked, Bind, ConnTable, DispatchConfig, LinkedRow, NoSink};
use busbar_contract::abi::mechanism::call::{AbiStr, Op, RawOutcome};
use busbar_contract::abi::mechanism::door::{Door, DoorParts, Statement};
use busbar_contract::abi::mechanism::lifecycle::{OpenIn, OpenOut, OpsHead};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::mechanism::{KindCode, DOOR_MAGIC, MECHANISM_VERSION};
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::plugin::TestKernelSeal;
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};
use std::sync::{Condvar, OnceLock};
use tokio::sync::Notify;

#[derive(Default)]
struct Stats {
    allocated: AtomicUsize,
    opened: AtomicUsize,
    closed: AtomicUsize,
    ready: AtomicUsize,
    fail_open: AtomicBool,
    refuse_open: AtomicBool,
    bad_metadata: AtomicBool,
    fail_ready: AtomicBool,
    target_effects: AtomicUsize,
    short: AtomicUsize,
    bootstrap_calls: AtomicUsize,
    fences: AtomicUsize,
    hold: AtomicBool,
    release: Mutex<bool>,
    released: Condvar,
    entered: Notify,
    closed_note: Notify,
    secret: Mutex<Vec<u8>>,
    legacy: bool,
}
impl Stats {
    fn release(&self) {
        *self.release.lock().unwrap() = true;
        self.released.notify_all();
    }
}
struct ReleaseOnDrop(Arc<Stats>);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}
fn registry() -> &'static Mutex<HashMap<u64, Arc<Stats>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<u64, Arc<Stats>>>> = OnceLock::new();
    REGISTRY.get_or_init(Mutex::default)
}
type HeldReply = (zeroize::Zeroizing<Vec<u8>>, zeroize::Zeroizing<Vec<u8>>);
struct Native {
    stats: Arc<Stats>,
    replies: Mutex<HashMap<Ticket, HeldReply>>,
}
fn info() -> owned::BackendInfo {
    owned::BackendInfo {
        dataset: owned::DatasetId([1; 16]),
        atomic_domain: [2; 16],
        clock_authority: [3; 16],
        physical_version: 1,
        durability: owned::Durability::Ephemeral,
    }
}
fn source() -> native::SourceIdentity {
    native::SourceIdentity {
        native_anchor: [4; 32],
        dataset: owned::DatasetId([9; 16]),
        format: Some(native::Format {
            owner: [5; 16],
            physical: 1,
            logical: 1,
            codec: 1,
        }),
        catalogue_digest: [6; 32],
        layout_digest: [7; 32],
    }
}
fn recovery() -> native::RecoveryReady {
    native::RecoveryReady {
        upgrade: [4; 16],
        target: info().dataset,
        activation_receipt_digest: [8; 32],
        selector_digest: [9; 32],
    }
}
fn metadata_blob() -> Blob {
    static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
    let bytes = BYTES.get_or_init(|| {
        busbar_contract::abi::mechanism::extensions::encode(&[(
            metadata::EXTENSION,
            &metadata::encode(info()).unwrap(),
        )])
    });
    octets(bytes)
}
fn bounds() -> native::Bounds {
    native::Bounds {
        items: 128,
        bytes: 64 * 1024,
    }
}
fn response(request: &native::Request, state: &Native) -> native::Response {
    use native::{Request, Response};
    match request {
        Request::Inspect { .. } => Response::Inspected(native::Inspection {
            state: if state.stats.legacy {
                native::InspectionState::Legacy(
                    native::SourceReader::new(
                        native::SourceCodec::HistoricalV1,
                        native::DocumentSemantics::Historical,
                        [8; 32],
                    )
                    .unwrap(),
                )
            } else {
                native::InspectionState::Empty
            },
            source: state.stats.legacy.then(source),
            admission_marker: None,
            catalogue: vec![],
            capabilities: vec![
                native::NativeCapability::Snapshot,
                native::NativeCapability::PersistentFence,
                native::NativeCapability::Resume,
                native::NativeCapability::InactiveTarget,
                native::NativeCapability::CurrentOpen,
            ],
        }),
        Request::BeginOrResume {
            expected_source, ..
        } => Response::Begun(native::Upgrade {
            reference: native::UpgradeRef {
                id: [4; 16],
                authority: busbar_contract::Secret::new(vec![5; 32]),
            },
            source: expected_source.clone(),
            catalogue: vec![],
            snapshot: [6; 16],
            target: info(),
            native_step: 1,
        }),
        Request::Target { .. } => {
            state.stats.target_effects.fetch_add(1, Ordering::SeqCst);
            Response::Target(native::TargetBinding {
                upgrade: [4; 16],
                info: info(),
                binding: busbar_contract::Secret::new(vec![15; 4096]),
            })
        }
        Request::SourcePage {
            snapshot, family, ..
        } => Response::SourcePage(native::SourcePage {
            snapshot: *snapshot,
            family: *family,
            rows: vec![],
            next: None,
            source_digest: [10; 32],
            coverage_digest: [11; 32],
        }),
        Request::CheckFence { .. } => {
            let count = state.stats.fences.fetch_add(1, Ordering::SeqCst) + 1;
            Response::Fence(native::Fence {
                upgrade: [4; 16],
                source: source(),
                enforcement_digest: [12; 32],
                observation_digest: [count as u8; 32],
                snapshot: [6; 16],
            })
        }
        Request::Finish {
            activation_receipt, ..
        } => {
            if activation_receipt.phase == native::CompletionPhase::Activation {
                Response::RecoveryReady(recovery())
            } else {
                Response::ServingReady(native::ServingReady {
                    recovery: recovery(),
                    completed_checkpoint_digest: activation_receipt.checkpoint_value_digest,
                })
            }
        }
    }
}
extern "C" fn call(instance: *mut c_void, input: *const c_void, output: *mut c_void) -> RawOutcome {
    let mut outcome = Outcome::Ready;
    // SAFETY: this fixture is entered only through admitted complete ABI frames.
    unsafe {
        let head = &*input.cast::<busbar_contract::abi::mechanism::call::InHead>();
        match head.op {
            wire::slot::BOOTSTRAP => {
                let input = &*input.cast::<wire::BootstrapIn>();
                let out = &mut *output.cast::<wire::BootstrapOut>();
                assert!(!input.host.is_null(), "pre-open host tables are retained");
                let state = if instance.is_null() {
                    let settings: serde_json::Value = serde_json::from_slice(
                        std::slice::from_raw_parts(input.settings.ptr, input.settings.len),
                    )
                    .unwrap();
                    let stats = registry()
                        .lock()
                        .unwrap()
                        .get(&settings["id"].as_u64().unwrap())
                        .unwrap()
                        .clone();
                    stats.allocated.fetch_add(1, Ordering::SeqCst);
                    Box::into_raw(Box::new(Native {
                        stats,
                        replies: Mutex::default(),
                    }))
                } else {
                    instance.cast::<Native>()
                };
                out.instance = state.cast();
                let state = &*state;
                state.stats.bootstrap_calls.fetch_add(1, Ordering::SeqCst);
                if state.stats.hold.swap(false, Ordering::SeqCst) {
                    state.stats.entered.notify_one();
                    let mut released = state.stats.release.lock().unwrap();
                    while !*released {
                        released = state.stats.released.wait(released).unwrap();
                    }
                    if input.secrets_len != 0 {
                        let secret = &*input.secrets;
                        *state.stats.secret.lock().unwrap() =
                            std::slice::from_raw_parts(secret.ptr, secret.len).to_vec();
                    }
                }
                let bytes = std::slice::from_raw_parts(input.request.ptr, input.request.len);
                let mut replies = state.replies.lock().unwrap();
                let held = replies.entry(head.ticket).or_insert_with(|| {
                    let request = native::codec::decode_request(bytes, bounds()).unwrap();
                    let result: Result<native::Response, native::Error> =
                        Ok(response(&request, state));
                    let encoded = native::codec::encode_response(&result, bounds()).unwrap();
                    (
                        zeroize::Zeroizing::new(bytes.to_vec()),
                        zeroize::Zeroizing::new(encoded.expose(&TestKernelSeal).clone()),
                    )
                });
                assert_eq!(
                    held.0.as_slice(),
                    bytes,
                    "SHORT keeps the exact request and ticket"
                );
                if input.result.cap < held.1.len() {
                    out.needed = held.1.len() as u64;
                    state.stats.short.fetch_add(1, Ordering::SeqCst);
                    outcome = Outcome::Failed;
                } else {
                    std::ptr::copy_nonoverlapping(held.1.as_ptr(), input.result.ptr, held.1.len());
                    out.written = held.1.len() as u64;
                }
            }
            life::OPEN => {
                assert!(!instance.is_null(), "OPEN adopts its prepared instance");
                let state = &*instance.cast::<Native>();
                let input = &*input.cast::<OpenIn>();
                let extensions = std::slice::from_raw_parts(
                    input.head.extensions.ptr,
                    input.head.extensions.len,
                );
                let binding = busbar_contract::abi::mechanism::extensions::get(
                    extensions,
                    native::OPEN_BINDING,
                )
                .unwrap();
                native::codec::decode_open_binding(binding, bounds()).unwrap();
                state.stats.opened.fetch_add(1, Ordering::SeqCst);
                let out = &mut *output.cast::<OpenOut>();
                out.instance = instance;
                out.head.extensions = if state.stats.bad_metadata.load(Ordering::SeqCst) {
                    Blob::ZERO
                } else {
                    metadata_blob()
                };
                if state.stats.fail_open.swap(false, Ordering::SeqCst) {
                    outcome = Outcome::Failed;
                }
                if state.stats.refuse_open.load(Ordering::SeqCst) {
                    outcome = Outcome::Refused;
                }
            }
            life::READY => {
                let stats = &(&*instance.cast::<Native>()).stats;
                stats.ready.fetch_add(1, Ordering::SeqCst);
                if stats.fail_ready.swap(false, Ordering::SeqCst) {
                    outcome = Outcome::Failed;
                }
            }
            life::CLOSE => {
                let state = Box::from_raw(instance.cast::<Native>());
                state.stats.closed.fetch_add(1, Ordering::SeqCst);
                state.stats.closed_note.notify_one();
            }
            wire::slot::CLOCK => {
                let out = &mut *output.cast::<wire::ClockOut>();
                out.authority = info().clock_authority;
                out.observed_at = 100;
            }
            life::CANCEL | life::RELEASE | life::VALIDATE => {}
            _ => outcome = Outcome::Refused,
        }
        (*output.cast::<OutHead>()).outcome = RawOutcome::of(outcome);
    }
    RawOutcome::of(outcome)
}
extern "C" fn door() -> &'static Door {
    static DOOR: OnceLock<usize> = OnceLock::new();
    let address = *DOOR.get_or_init(|| {
        let op: Option<Op> = Some(call);
        let ops = Box::leak(Box::new(wire::Ops {
            head: OpsHead {
                size: std::mem::size_of::<wire::Ops>() as u32,
                slots: wire::TABLE_SLOTS,
                validate: op,
                open: op,
                refresh: op,
                retire: op,
                tick: op,
                drive: op,
                cancel: op,
                release: op,
                close: op,
            },
            read: op,
            scan: op,
            commit: op,
            clock: op,
            bootstrap: op,
        }));
        const REFS: &[AbiStr] = &[abi_str("password")];
        let statement = Box::leak(Box::new(Statement {
            size: std::mem::size_of::<Statement>() as u32,
            kind: KindCode::Store as u32,
            kind_abi: wire::ABI_VERSION,
            secret_refs: REFS.as_ptr(),
            secret_refs_len: REFS.len(),
            ..busbar_contract::abi::sdk::door::statement("prepared-native-test", "1.0.0", 32)
        }));
        // SAFETY: fixture metadata and complete table are immutable permanent allocations.
        Box::into_raw(Box::new(unsafe {
            Door::__from_parts(DoorParts {
                magic: DOOR_MAGIC,
                mechanism_version: MECHANISM_VERSION,
                size: std::mem::size_of::<Door>() as u32,
                kind: KindCode::Store as u32,
                kind_abi: wire::ABI_VERSION,
                statement,
                ops: std::ptr::from_ref(ops).cast(),
                ready: op,
                layout: wire::LAYOUT_FINGERPRINT,
            })
        })) as usize
    });
    // SAFETY: OnceLock retains the complete immutable fixture.
    unsafe { &*(address as *const Door) }
}
fn fixture(legacy: bool, hold: bool) -> (Arc<LoadedPrepared>, Arc<Stats>) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::SeqCst) + 1;
    let stats = Arc::new(Stats {
        legacy,
        ..Stats::default()
    });
    stats.hold.store(hold, Ordering::SeqCst);
    registry().lock().unwrap().insert(id, stats.clone());
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    let plugin = load_linked::<StoreV4>(
        &LinkedRow::of_kind::<StoreV4>(door as busbar_contract::abi::mechanism::door::DoorFn)
            .unwrap(),
        Bind {
            instance: format!("prepared-{id}").into(),
            max_inflight_cap: 32,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .unwrap();
    let settings =
        serde_json::to_vec(&serde_json::json!({"id":id,"password":"PREPARED_SECRET_CANARY"}))
            .unwrap();
    let prepared = LoadedPrepared::new(
        plugin,
        dispatcher,
        &settings,
        Limits {
            descriptor_bytes: 128 * 1024,
            output_items: 128,
            output_bytes: 64 * 1024,
            decode_bytes: 128 * 1024,
        },
    )
    .unwrap();
    (Arc::new(prepared), stats)
}
fn proof(phase: native::CompletionPhase) -> native::ActivationReceipt {
    native::ActivationReceipt {
        attempt: owned::AttemptId {
            dataset: info().dataset,
            writer: [2; 16],
            operation: [3; 16],
            writer_epoch: 1,
            execution_epoch: 1,
        },
        candidate_fingerprint: [4; 32],
        original_result: busbar_contract::Secret::new(vec![7]),
        checkpoint_address: native::completion_marker_address([4; 16]),
        checkpoint_value_digest: [5; 32],
        phase,
    }
}

#[tokio::test]
async fn prepared_upgrade_short_target_recovery_and_completion_use_one_native_instance() {
    let (prepared, stats) = fixture(true, false);
    assert_eq!(prepared.phase(), native::Phase::Bound);
    assert!(prepared.serving().is_err());
    assert!(prepared.open(native::OpenBinding::Empty).await.is_err());
    assert_eq!(stats.allocated.load(Ordering::SeqCst), 0);
    prepared
        .bootstrap(Arc::new(native::Request::Inspect { bounds: bounds() }))
        .await
        .unwrap();
    assert_eq!(prepared.phase(), native::Phase::Prepared);
    let begun = prepared
        .bootstrap(Arc::new(native::Request::BeginOrResume {
            expected_source: source(),
            route_digest: [1; 32],
            target_format: native::Format {
                owner: [2; 16],
                physical: 1,
                logical: 1,
                codec: 1,
            },
            operation_id: [3; 16],
        }))
        .await
        .unwrap();
    let native::Response::Begun(upgrade) = begun.as_ref() else {
        panic!("begun")
    };
    let target = prepared.target(upgrade.reference.clone()).await.unwrap();
    assert_eq!(target.upgrade_id(), upgrade.reference.id);
    assert_eq!(
        target.clock(info().dataset).await.unwrap().authority,
        info().clock_authority
    );
    assert_eq!(stats.target_effects.load(Ordering::SeqCst), 1);
    assert_eq!(stats.short.load(Ordering::SeqCst), 1);
    let mut observations = Vec::new();
    for _ in 0..2 {
        let reply = prepared
            .bootstrap(Arc::new(native::Request::CheckFence {
                upgrade: upgrade.reference.clone(),
            }))
            .await
            .unwrap();
        let native::Response::Fence(fence) = reply.as_ref() else {
            panic!("fence")
        };
        observations.push(fence.observation_digest);
    }
    assert_ne!(
        observations[0], observations[1],
        "fence checks are actual fresh native calls"
    );
    prepared
        .bootstrap(Arc::new(native::Request::Finish {
            upgrade: upgrade.reference.clone(),
            activation_receipt: proof(native::CompletionPhase::Activation),
        }))
        .await
        .unwrap();
    assert!(prepared.serving().is_err());
    let backend = prepared
        .open(native::OpenBinding::Recovery(recovery()))
        .await
        .unwrap();
    assert_eq!(prepared.phase(), native::Phase::RecoveryReady);
    assert_eq!(stats.ready.load(Ordering::SeqCst), 0);
    assert!(prepared.serving().is_err());
    stats.fail_ready.store(true, Ordering::SeqCst);
    let completed = Arc::new(native::Request::Finish {
        upgrade: upgrade.reference.clone(),
        activation_receipt: proof(native::CompletionPhase::Complete),
    });
    assert!(prepared.bootstrap(completed.clone()).await.is_err());
    assert!(prepared.serving().is_err());
    prepared.bootstrap(completed).await.unwrap();
    let serving = prepared.serving().unwrap();
    assert!(Arc::ptr_eq(&backend, &serving));
    assert_eq!(stats.opened.load(Ordering::SeqCst), 1);
    assert_eq!(stats.allocated.load(Ordering::SeqCst), 1);
    assert_eq!(stats.ready.load(Ordering::SeqCst), 2);
    drop(target);
    drop(backend);
    drop(serving);
    drop(prepared);
    assert_eq!(stats.closed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancelled_inspection_keeps_the_exact_ticket_and_protected_inputs_for_retry() {
    let (prepared, stats) = fixture(false, true);
    let _release = ReleaseOnDrop(stats.clone());
    let request = Arc::new(native::Request::Inspect { bounds: bounds() });
    let caller = prepared.clone();
    let original = request.clone();
    let task = tokio::spawn(async move { caller.bootstrap(original).await });
    tokio::time::timeout(Duration::from_secs(5), stats.entered.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(stats.closed.load(Ordering::SeqCst), 0);
    assert!(matches!(
        prepared
            .bootstrap(Arc::new(native::Request::Target {
                upgrade: native::UpgradeRef {
                    id: [4; 16],
                    authority: busbar_contract::Secret::new(vec![5; 32])
                }
            }))
            .await,
        Err(native::Error::Busy)
    ));
    stats.release();
    prepared.bootstrap(request).await.unwrap();
    assert_eq!(
        stats.bootstrap_calls.load(Ordering::SeqCst),
        1,
        "retry awaits the retained native call"
    );
    assert_eq!(
        stats.secret.lock().unwrap().as_slice(),
        b"PREPARED_SECRET_CANARY"
    );
    drop(prepared);
    assert_eq!(stats.closed.load(Ordering::SeqCst), 1);
    assert_eq!(stats.opened.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn dropping_a_prepared_owner_closes_only_after_the_native_inspection_retires() {
    let (prepared, stats) = fixture(false, true);
    let _release = ReleaseOnDrop(stats.clone());
    let caller = prepared.clone();
    let task = tokio::spawn(async move {
        caller
            .bootstrap(Arc::new(native::Request::Inspect { bounds: bounds() }))
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), stats.entered.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    drop(prepared);
    assert_eq!(stats.closed.load(Ordering::SeqCst), 0);
    stats.release();
    tokio::time::timeout(Duration::from_secs(5), stats.closed_note.notified())
        .await
        .unwrap();
    assert_eq!(stats.closed.load(Ordering::SeqCst), 1);
    assert_eq!(
        stats.secret.lock().unwrap().as_slice(),
        b"PREPARED_SECRET_CANARY"
    );
}

#[tokio::test]
async fn transient_open_retries_same_prepared_instance_after_retirement() {
    let (prepared, stats) = fixture(false, false);
    prepared
        .bootstrap(Arc::new(native::Request::Inspect { bounds: bounds() }))
        .await
        .unwrap();
    stats.fail_open.store(true, Ordering::SeqCst);
    assert!(prepared.open(native::OpenBinding::Empty).await.is_err());
    assert!(prepared.serving().is_err());
    prepared.open(native::OpenBinding::Empty).await.unwrap();
    assert_eq!(stats.opened.load(Ordering::SeqCst), 2);
    assert_eq!(stats.allocated.load(Ordering::SeqCst), 1);
    assert_eq!(stats.ready.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn failed_ready_retries_ready_without_reopening_the_validated_backend() {
    let (prepared, stats) = fixture(false, false);
    prepared
        .bootstrap(Arc::new(native::Request::Inspect { bounds: bounds() }))
        .await
        .unwrap();
    stats.fail_ready.store(true, Ordering::SeqCst);
    assert!(prepared.open(native::OpenBinding::Empty).await.is_err());
    assert!(prepared.serving().is_err());
    let backend = prepared.open(native::OpenBinding::Empty).await.unwrap();
    assert!(Arc::ptr_eq(&backend, &prepared.serving().unwrap()));
    assert_eq!(stats.opened.load(Ordering::SeqCst), 1);
    assert_eq!(stats.ready.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn refused_open_and_success_without_validated_metadata_are_never_reopened() {
    for invalid_metadata in [false, true] {
        let (prepared, stats) = fixture(false, false);
        prepared
            .bootstrap(Arc::new(native::Request::Inspect { bounds: bounds() }))
            .await
            .unwrap();
        stats.bad_metadata.store(invalid_metadata, Ordering::SeqCst);
        stats.refuse_open.store(!invalid_metadata, Ordering::SeqCst);
        assert!(prepared.open(native::OpenBinding::Empty).await.is_err());
        assert!(prepared.open(native::OpenBinding::Empty).await.is_err());
        assert!(prepared.serving().is_err());
        assert_eq!(stats.opened.load(Ordering::SeqCst), 1);
        assert_eq!(stats.ready.load(Ordering::SeqCst), 0);
    }
}
