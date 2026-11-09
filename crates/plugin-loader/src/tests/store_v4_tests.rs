// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::mechanism::call::RawOutcome;

fn limits() -> Limits {
    Limits {
        descriptor_bytes: 4096,
        output_items: 4096,
        output_bytes: 2 * 1024 * 1024,
        decode_bytes: 4 * 1024 * 1024,
    }
}
fn read_request(source: Arc<owned::Read>) -> ReadRequest {
    ReadRequest {
        source: sdk::Read::new(source, limits().descriptor_bytes).unwrap(),
        items: Vec::new(),
        bytes: zeroize::Zeroizing::new(Vec::new()),
    }
}
fn ready<O: OutFrame>(mut out: O) -> O {
    // SAFETY: OutFrame leads with an initialized OutHead.
    unsafe {
        (*std::ptr::from_mut(&mut out).cast::<OutHead>()).outcome = RawOutcome::of(Outcome::Ready);
    }
    out
}

#[test]
fn lent_read_keeps_source_after_caller_ownership_is_dropped() {
    let source = Arc::new(owned::Read {
        dataset: owned::DatasetId([1; 16]),
        addresses: vec![owned::Address {
            namespace: [2; 16],
            key: b"retained".to_vec(),
        }],
        time: None,
    });
    let weak = Arc::downgrade(&source);
    let retained = Arc::new(Retained(UnsafeCell::new(read_request(source)), None));
    let frame = retained.frame();
    let lent = retained.clone() as Lent;
    drop(retained);
    assert!(weak.upgrade().is_some());
    // SAFETY: the erased lent owner retains descriptors and source after caller drop.
    let key = unsafe { (*frame.input.addresses).key };
    assert_eq!(
        unsafe { std::slice::from_raw_parts(key.ptr, key.len) },
        b"retained"
    );
    drop(lent);
    assert!(weak.upgrade().is_none());
}

#[test]
fn read_decodes_short_then_owned_values_and_checks_clock_authority() {
    let source = Arc::new(owned::Read {
        dataset: owned::DatasetId([1; 16]),
        addresses: vec![owned::Address {
            namespace: [2; 16],
            key: vec![],
        }],
        time: None,
    });
    let mut request = read_request(source);
    let mut frame = request.frame();
    frame.out.head.outcome = RawOutcome::of(Outcome::Failed);
    frame.out.needed_items = 1;
    frame.out.needed_bytes = 3;
    assert!(matches!(
        request.decode(Outcome::Failed, &frame, limits().decode_bytes, [3; 16]),
        Err(ResponseError::Short {
            needed_items: 1,
            needed_bytes: 3
        })
    ));
    request.grow(1, 3, limits()).unwrap();
    let mut frame = request.frame();
    request.bytes.copy_from_slice(b"abc");
    request.items[0] = wire::ReadValue {
        found: wire::VALUE_FOUND,
        _reserved: 0,
        value: Blob {
            ptr: request.bytes.as_ptr(),
            len: 3,
            fmt: BLOB_OCTETS,
            flags: BLOB_SECRET,
        },
    };
    frame.out = ready(frame.out);
    frame.out.code = wire::READ_VALUES;
    frame.out.authority = [3; 16];
    frame.out.items_written = 1;
    frame.out.bytes_written = 3;
    let value = request
        .decode(Outcome::Ready, &frame, limits().decode_bytes, [3; 16])
        .unwrap();
    match value {
        owned::ReadResult::Values { values, .. } => {
            assert_eq!(
                values[0].as_ref().unwrap(),
                &busbar_contract::redacted::Secret::new(b"abc".to_vec())
            )
        }
        _ => panic!("expected values"),
    }
    assert!(matches!(
        request.decode(Outcome::Ready, &frame, limits().decode_bytes, [4; 16]),
        Err(ResponseError::Malformed)
    ));
}

#[test]
fn growth_uses_explicit_host_limits_and_preserves_immutable_input() {
    let source = Arc::new(owned::Read {
        dataset: owned::DatasetId([1; 16]),
        addresses: vec![],
        time: None,
    });
    let mut request = read_request(source);
    let before = request.frame().input;
    request.grow(1024, 1024 * 1024, limits()).unwrap();
    let after = request.frame().input;
    assert_eq!(before.dataset, after.dataset);
    assert_eq!(before.addresses, after.addresses);
    assert_eq!(before.addresses_len, after.addresses_len);
    assert!(request.bytes.iter().all(|byte| *byte == 0));
    assert!(request
        .items
        .iter()
        .all(|item| item.value.ptr.is_null() && item.found == 0));
    assert!(request.grow(4097, 0, limits()).is_err());
    assert!(request.grow(u64::MAX, u64::MAX, limits()).is_err());
    assert!(request.grow(1024, 1024 * 1024, limits()).is_err());
}

#[test]
fn metadata_requires_one_complete_named_extension() {
    let info = owned::BackendInfo {
        dataset: owned::DatasetId([1; 16]),
        atomic_domain: [2; 16],
        clock_authority: [3; 16],
        physical_version: 1,
        durability: owned::Durability::Local,
    };
    let metadata = metadata::encode(info).unwrap();
    let bytes =
        busbar_contract::abi::mechanism::extensions::encode(&[(metadata::EXTENSION, &metadata)]);
    assert_eq!(instance_metadata(octets(&bytes)).unwrap(), info);
    assert!(instance_metadata(octets(&metadata)).is_err());
    let duplicate = busbar_contract::abi::mechanism::extensions::encode(&[
        (metadata::EXTENSION, &metadata),
        (metadata::EXTENSION, &metadata),
    ]);
    assert!(instance_metadata(octets(&duplicate)).is_err());
    let mut trailing = bytes;
    trailing.push(1);
    assert!(instance_metadata(octets(&trailing)).is_err());
}

#[test]
fn malformed_commit_is_unknown_and_never_refused() {
    assert_eq!(classify(ResponseError::Malformed, true), Failure::Unknown);
    assert_eq!(classify(ResponseError::Pending, true), Failure::Unknown);
    assert_eq!(classify(ResponseError::Budget, true), Failure::Unknown);
    assert_eq!(
        classify(ResponseError::Failure(Failure::Refused), true),
        Failure::Refused
    );
}

#[test]
fn open_secrets_are_removed_from_settings_and_retained_separately() {
    let lent = OpenLent::new(
        &["password".to_string()],
        br#"{"password":"secret","other":1}"#,
    );
    assert!(!String::from_utf8_lossy(&lent.settings).contains("secret"));
    assert_eq!(lent.blobs.len(), 1);
    assert_eq!(&*lent._secrets[0], b"secret");
    assert_eq!(lent.blobs[0].flags, BLOB_SECRET);
}

mod linked {
    use super::*;
    use crate::dispatch::{load_linked, Bind, ConnTable, DispatchConfig, LinkedRow, NoSink};
    use busbar_contract::abi::mechanism::call::Op;
    use busbar_contract::abi::mechanism::door::{Door, DoorParts, Statement};
    use busbar_contract::abi::mechanism::lifecycle::{OpenOut, OpsHead};
    use busbar_contract::abi::mechanism::{KindCode, DOOR_MAGIC, MECHANISM_VERSION};
    use std::ffi::c_void;
    use std::sync::{Condvar, Mutex, OnceLock};

    type ReadGateState = (bool, bool, Option<Vec<u8>>, bool);
    static GATE: (Mutex<ReadGateState>, Condvar) =
        (Mutex::new((false, false, None, false)), Condvar::new());

    static OPEN_GATE: (Mutex<(bool, bool, bool)>, Condvar) =
        (Mutex::new((false, false, false)), Condvar::new());

    fn info() -> owned::BackendInfo {
        owned::BackendInfo {
            dataset: owned::DatasetId([1; 16]),
            atomic_domain: [2; 16],
            clock_authority: [3; 16],
            physical_version: 1,
            durability: owned::Durability::Ephemeral,
        }
    }
    fn extension() -> &'static [u8] {
        static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
        BYTES.get_or_init(|| {
            busbar_contract::abi::mechanism::extensions::encode(&[(
                metadata::EXTENSION,
                &metadata::encode(info()).unwrap(),
            )])
        })
    }
    extern "C" fn call(
        instance: *mut c_void,
        input: *const c_void,
        output: *mut c_void,
    ) -> RawOutcome {
        // SAFETY: this linked fixture receives validated, live dispatcher frames.
        unsafe {
            let slot = (*input.cast::<busbar_contract::abi::mechanism::call::InHead>()).op;
            let mut outcome = Outcome::Ready;
            match slot {
                life::OPEN => {
                    let out = &mut *output.cast::<OpenOut>();
                    let input =
                        &*input.cast::<busbar_contract::abi::mechanism::lifecycle::OpenIn>();
                    let settings =
                        std::slice::from_raw_parts(input.settings.ptr, input.settings.len);
                    if settings == br#"{"openhold":true}"# {
                        let mut state = OPEN_GATE.0.lock().unwrap();
                        state.0 = true;
                        OPEN_GATE.1.notify_all();
                        while !state.1 {
                            state = OPEN_GATE.1.wait(state).unwrap();
                        }
                    }
                    out.instance = if settings == br#"{"openhold":true}"# {
                        std::ptr::without_provenance_mut::<c_void>(3)
                    } else if settings == br#"{"hold":true}"# {
                        std::ptr::without_provenance_mut::<c_void>(2)
                    } else {
                        std::ptr::dangling_mut::<u8>().cast()
                    };
                    out.head.extensions = octets(extension());
                }
                life::CLOSE if instance as usize == 3 => {
                    let mut state = OPEN_GATE.0.lock().unwrap();
                    state.2 = true;
                    OPEN_GATE.1.notify_all();
                }
                life::CLOSE if instance as usize == 2 => {
                    let mut state = GATE.0.lock().unwrap();
                    assert!(state.2.is_some(), "closed before native crossing finished");
                    state.3 = true;
                    GATE.1.notify_all();
                }
                wire::slot::READ => {
                    let input = &*input.cast::<wire::ReadIn>();
                    let out = &mut *output.cast::<wire::ReadOut>();
                    if input.addresses_len == 1 && (*input.addresses).key.len == 4 {
                        let mut state = GATE.0.lock().unwrap();
                        state.0 = true;
                        GATE.1.notify_all();
                        while !state.1 {
                            state = GATE.1.wait(state).unwrap();
                        }
                        let key = (*input.addresses).key;
                        state.2 = Some(std::slice::from_raw_parts(key.ptr, key.len).to_vec());
                        GATE.1.notify_all();
                    }
                    if input.values.items_cap < input.addresses_len {
                        outcome = Outcome::Failed;
                        out.needed_items = input.addresses_len as u64;
                    } else {
                        out.code = wire::READ_VALUES;
                        out.authority = info().clock_authority;
                        out.items_written = input.addresses_len as u64;
                        for index in 0..input.addresses_len {
                            input.values.items.add(index).write(wire::ReadValue {
                                found: wire::VALUE_ABSENT,
                                _reserved: 0,
                                value: Blob::ABSENT,
                            });
                        }
                    }
                }
                wire::slot::SCAN => {
                    let out = &mut *output.cast::<wire::ScanOut>();
                    out.code = wire::SCAN_PAGE;
                    out.continuation = wire::SCAN_EXHAUSTED;
                    out.generation = 1;
                }
                wire::slot::COMMIT => {
                    let input = &*input.cast::<wire::CommitIn>();
                    let out = &mut *output.cast::<wire::CommitOut>();
                    // First crossing may have committed: its response buffer is short.
                    if input.result.cap == 0 {
                        outcome = Outcome::Failed;
                        out.needed = 3;
                    } else {
                        outcome = Outcome::Refused;
                    }
                }
                wire::slot::CLOCK => {
                    let out = &mut *output.cast::<wire::ClockOut>();
                    out.authority = info().clock_authority;
                    out.observed_at = 123;
                }
                _ => {}
            }
            (*output.cast::<OutHead>()).outcome = RawOutcome::of(outcome);
            RawOutcome::of(outcome)
        }
    }
    extern "C" fn door() -> &'static Door {
        static DOOR: OnceLock<usize> = OnceLock::new();
        let ptr = *DOOR.get_or_init(|| {
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
            let statement = Box::leak(Box::new(Statement {
                size: std::mem::size_of::<Statement>() as u32,
                kind: KindCode::Store as u32,
                kind_abi: wire::ABI_VERSION,
                ..busbar_contract::abi::sdk::door::statement("primitive-loader-test", "1.0.0", 32)
            }));
            // SAFETY: all metadata and tables are complete permanent allocations.
            Box::into_raw(Box::new(unsafe {
                Door::__from_parts(DoorParts {
                    magic: DOOR_MAGIC,
                    mechanism_version: MECHANISM_VERSION,
                    size: std::mem::size_of::<Door>() as u32,
                    kind: KindCode::Store as u32,
                    kind_abi: wire::ABI_VERSION,
                    statement,
                    ops: std::ptr::from_ref(ops).cast(),
                    ready: Some(call),
                    layout: wire::LAYOUT_FINGERPRINT,
                })
            })) as usize
        });
        // SAFETY: the OnceLock permanently retains the immutable descriptor allocation.
        unsafe { &*(ptr as *const Door) }
    }

    fn axis() -> DoorPersistenceAxis {
        DoorPersistenceAxis {
            dispatcher: Arc::new(Dispatcher::new(
                DispatchConfig::default(),
                busbar_contract::services::test_caller_binding(),
            )),
            logs: crate::dispatch::PluginLogConfig::from_words(
                None,
                None,
                &Default::default(),
                None,
                None,
            )
            .unwrap(),
            conns: ConnTable::NoNeeds,
            limits: limits(),
        }
    }

    #[tokio::test]
    async fn axis_opens_linked_v4_and_exposes_instance_metadata() {
        use owned::axis::{PersistenceAxis, StoreDoor};
        let backend = axis()
            .open(StoreDoor::Linked(door), "primitive-axis", b"{}")
            .await
            .unwrap();
        assert_eq!(backend.info(), info());
        assert_eq!(
            backend.clock(info().dataset).await.unwrap().unix_seconds,
            123
        );
    }

    #[tokio::test]
    async fn axis_rejects_v3_before_any_lifecycle_or_business_crossing() {
        use owned::axis::{PersistenceAxis, StoreDoor};
        use std::sync::atomic::{AtomicUsize, Ordering};
        static CROSSED: AtomicUsize = AtomicUsize::new(0);
        extern "C" fn old_call(_: *mut c_void, _: *const c_void, _: *mut c_void) -> RawOutcome {
            CROSSED.fetch_add(1, Ordering::SeqCst);
            RawOutcome::of(Outcome::Refused)
        }
        extern "C" fn old_door() -> &'static Door {
            static DOOR: OnceLock<usize> = OnceLock::new();
            let ptr = *DOOR.get_or_init(|| {
                let ops = crate::retired_store_fixture::table_with(old_call);
                let statement = Box::leak(Box::new(Statement {
                    size: std::mem::size_of::<Statement>() as u32,
                    kind: KindCode::Store as u32,
                    kind_abi: 3,
                    ..busbar_contract::abi::sdk::door::statement("v3-axis-refusal", "1.0.0", 32)
                }));
                // SAFETY: complete v3 tables and immutable metadata live permanently.
                Box::into_raw(Box::new(unsafe {
                    Door::__from_parts(DoorParts {
                        magic: DOOR_MAGIC,
                        mechanism_version: MECHANISM_VERSION,
                        size: std::mem::size_of::<Door>() as u32,
                        kind: KindCode::Store as u32,
                        kind_abi: 3,
                        statement,
                        ops,
                        ready: Some(old_call),
                        layout: crate::retired_store_fixture::LAYOUT,
                    })
                })) as usize
            });
            // SAFETY: OnceLock retains the permanent immutable door allocation.
            unsafe { &*(ptr as *const Door) }
        }
        let result = axis()
            .open(StoreDoor::Linked(old_door), "old-store", b"{}")
            .await;
        assert!(result.is_err(), "v4 selection admitted a v3 door");
        assert_eq!(CROSSED.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cancelled_open_closes_after_native_open_finishes() {
        use owned::axis::{PersistenceAxis, StoreDoor};
        let task = tokio::spawn(async move {
            axis()
                .open(
                    StoreDoor::Linked(door),
                    "v4-open-cancel-test",
                    br#"{"openhold":true}"#,
                )
                .await
                .map(|_| ())
        });
        tokio::task::yield_now().await;
        {
            let state = OPEN_GATE.0.lock().unwrap();
            let (_state, timeout) = OPEN_GATE
                .1
                .wait_timeout_while(state, Duration::from_secs(5), |state| !state.0)
                .unwrap();
            assert!(!timeout.timed_out(), "native open never entered");
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let mut state = OPEN_GATE.0.lock().unwrap();
        assert!(
            !state.2,
            "native instance closed while OPEN was still running"
        );
        state.1 = true;
        OPEN_GATE.1.notify_all();
        let (_state, timeout) = OPEN_GATE
            .1
            .wait_timeout_while(state, Duration::from_secs(5), |state| !state.2)
            .unwrap();
        assert!(
            !timeout.timed_out(),
            "cancelled OPEN's native instance was not closed"
        );
    }
    #[tokio::test]
    async fn dropped_read_future_keeps_native_descriptors_and_source_alive() {
        let dispatcher = Arc::new(Dispatcher::new(
            DispatchConfig::default(),
            busbar_contract::services::test_caller_binding(),
        ));
        extern "C" fn raw_door() -> *const Door {
            door()
        }
        // SAFETY: the fixture statement is permanent checked metadata.
        let statement =
            unsafe { busbar_contract::abi::mechanism::rendering::render(&*door().statement()) }
                .unwrap();
        let row = LinkedRow {
            statement,
            door: raw_door,
        };
        let plugin = load_linked::<StoreV4>(
            &row,
            Bind {
                instance: Arc::from("v4-cancel-test"),
                max_inflight_cap: 32,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::NoNeeds,
            },
        )
        .unwrap();
        let backend = Arc::new(
            LoadedPersistence::open(plugin, dispatcher, br#"{"hold":true}"#, limits())
                .await
                .unwrap(),
        );
        let source = Arc::new(owned::Read {
            dataset: info().dataset,
            addresses: vec![owned::Address {
                namespace: [4; 16],
                key: b"held".to_vec(),
            }],
            time: None,
        });
        let weak = Arc::downgrade(&source);
        let task = tokio::spawn({
            let backend = backend.clone();
            async move { backend.read(source).await }
        });
        tokio::task::yield_now().await;
        {
            let state = GATE.0.lock().unwrap();
            let (_state, timeout) = GATE
                .1
                .wait_timeout_while(state, Duration::from_secs(5), |state| !state.0)
                .unwrap();
            assert!(!timeout.timed_out(), "native read never entered");
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(
            weak.upgrade().is_some(),
            "dispatcher must retain the dropped caller's source"
        );
        drop(backend);
        let mut state = GATE.0.lock().unwrap();
        assert!(
            !state.3,
            "caller cancellation must not close an active native instance"
        );
        state.1 = true;
        GATE.1.notify_all();
        let (state, timeout) = GATE
            .1
            .wait_timeout_while(state, Duration::from_secs(5), |state| !state.3)
            .unwrap();
        assert!(!timeout.timed_out(), "native read did not finish");
        assert_eq!(state.2.as_deref(), Some(b"held".as_slice()));
        assert!(
            weak.upgrade().is_none(),
            "final native owner must retire the source before closing"
        );
    }
    #[tokio::test]
    async fn async_binding_opens_readies_retries_and_preserves_commit_uncertainty() {
        let dispatcher = Arc::new(Dispatcher::new(
            DispatchConfig::default(),
            busbar_contract::services::test_caller_binding(),
        ));
        extern "C" fn raw_door() -> *const Door {
            door()
        }
        // SAFETY: the fixture statement is permanent checked metadata.
        let statement =
            unsafe { busbar_contract::abi::mechanism::rendering::render(&*door().statement()) }
                .unwrap();
        let row = LinkedRow {
            statement,
            door: raw_door,
        };
        let plugin = load_linked::<StoreV4>(
            &row,
            Bind {
                instance: Arc::from("v4-test"),
                max_inflight_cap: 32,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::NoNeeds,
            },
        )
        .unwrap();
        let backend = LoadedPersistence::open(plugin, dispatcher, b"{}", limits())
            .await
            .unwrap();
        assert_eq!(backend.info(), info());
        let read = backend
            .read(Arc::new(owned::Read {
                dataset: info().dataset,
                addresses: vec![owned::Address {
                    namespace: [4; 16],
                    key: b"key".to_vec(),
                }],
                time: None,
            }))
            .await
            .unwrap();
        assert!(
            matches!(read, owned::ReadResult::Values { values, .. } if values.len()==1 && values[0].is_none())
        );
        let page = backend
            .scan(Arc::new(owned::Scan {
                dataset: info().dataset,
                namespace: owned::NamespaceId([4; 16]),
                prefix: vec![],
                after: None,
                generation: None,
                allow_change: false,
                max_items: 10,
                max_bytes: 100,
            }))
            .await
            .unwrap();
        assert!(page.rows.is_empty() && page.next.is_none());
        assert_eq!(
            backend.clock(info().dataset).await.unwrap().unix_seconds,
            123
        );
        assert_eq!(
            backend.clock(owned::DatasetId([8; 16])).await,
            Err(Failure::Refused)
        );
        let candidate = owned::PreparedCandidate::new(owned::Candidate {
            id: owned::AttemptId {
                dataset: info().dataset,
                writer_epoch: 1,
                writer: [5; 16],
                execution_epoch: 1,
                operation: [6; 16],
            },
            codec: owned::CANDIDATE_VERSION,
            predicates: vec![],
            mutations: vec![owned::Mutation::Delete(owned::Address {
                namespace: [4; 16],
                key: b"key".to_vec(),
            })],
            time: None,
            result: busbar_contract::redacted::Secret::new(vec![]),
        })
        .unwrap();
        assert!(matches!(
            backend.commit(candidate).await,
            Err(Failure::Unknown)
        ));
    }
}

#[test]
fn commit_keeps_exact_candidate_on_growth_and_rejects_changed_receipt_bytes() {
    let candidate = owned::PreparedCandidate::new(owned::Candidate {
        id: owned::AttemptId {
            dataset: owned::DatasetId([1; 16]),
            writer_epoch: 1,
            writer: [2; 16],
            execution_epoch: 1,
            operation: [3; 16],
        },
        codec: owned::CANDIDATE_VERSION,
        predicates: vec![],
        mutations: vec![owned::Mutation::Delete(owned::Address {
            namespace: [4; 16],
            key: b"key".to_vec(),
        })],
        time: None,
        result: busbar_contract::redacted::Secret::new(b"abc".to_vec()),
    })
    .unwrap();
    let mut request = CommitRequest {
        source: sdk::Commit::new(&candidate, limits().descriptor_bytes).unwrap(),
        original: candidate,
        bytes: zeroize::Zeroizing::new(Vec::new()),
    };
    let before = request.frame().input.candidate;
    request.grow(0, 3, limits()).unwrap();
    let mut frame = request.frame();
    assert_eq!(before.mutations, frame.input.candidate.mutations);
    assert_eq!(before.result.ptr, frame.input.candidate.result.ptr);
    assert_eq!(before.id.operation, frame.input.candidate.id.operation);
    request.bytes.copy_from_slice(b"abc");
    frame.out = ready(frame.out);
    frame.out.code = wire::COMMIT_APPLIED;
    frame.out.authority = [5; 16];
    frame.out.written = 3;
    assert!(matches!(
        request.decode(Outcome::Ready, &frame, limits().decode_bytes, [5; 16]),
        Ok(owned::Decision::Applied(_))
    ));
    request.bytes.copy_from_slice(b"bad");
    assert!(matches!(
        request.decode(Outcome::Ready, &frame, limits().decode_bytes, [5; 16]),
        Err(ResponseError::Malformed)
    ));
}

#[test]
fn fitting_read_buffers_are_presized_p29_performance_0() {
    let items = presized(3, limits(), 0u64);
    assert_eq!(
        items.len(),
        3,
        "a 3-address read must start with 3 descriptors"
    );
    let bytes = presized_bytes(3 * INITIAL_VALUE_BYTES, limits());
    assert_eq!(bytes.len(), 3 * INITIAL_VALUE_BYTES);
    assert!(presized_bytes(usize::MAX, limits()).len() <= limits().output_bytes);
}
