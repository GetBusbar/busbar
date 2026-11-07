// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::abi::mechanism::call::{Blob, InHead, OutHead, BLOB_OCTETS, FLAG_RESUME};
use crate::abi::mechanism::lifecycle::{
    self as lc, CancelIn, CancelOut, OpenIn, OpenOut, ReleaseIn,
};
use crate::abi::sdk::door::{blank_in, blank_out};
use crate::redacted::Secret;
use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};

crate::own_seal!(Own);
static COMMITS: AtomicUsize = AtomicUsize::new(0);
static READS: AtomicUsize = AtomicUsize::new(0);
static SCANS: AtomicUsize = AtomicUsize::new(0);
static BOOTSTRAPS: AtomicUsize = AtomicUsize::new(0);
struct Fake {
    owner: Own,
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
fn observation() -> owned::ClockObservation {
    owned::ClockObservation {
        authority: [3; 16],
        unix_seconds: 41,
    }
}
impl Backend for Fake {
    type Owner = Own;
    fn owner(&self) -> &Own {
        &self.owner
    }
    fn input_budget(&self) -> usize {
        1_048_576
    }
    fn validate(_: &[u8]) -> Result<(), String> {
        Ok(())
    }
    fn open(_: &[u8], _: &[&[u8]], _: Option<Host>) -> Result<Self, String> {
        Ok(Self { owner: Own::here() })
    }
    fn connect(&self, _: &mut Op<'_>) -> Step<Result<(), String>> {
        Step::Ready(Ok(()))
    }
    fn connect_prepared(
        &self,
        _: &mut Op<'_>,
        binding: &crate::persistence::lifecycle::OpenBinding,
    ) -> Step<Result<(), String>> {
        Step::Ready(
            if matches!(binding, crate::persistence::lifecycle::OpenBinding::Empty) {
                Ok(())
            } else {
                Err("fixture binding mismatch".into())
            },
        )
    }
    fn bootstrap(
        &self,
        op: &mut Op<'_>,
        request: &crate::persistence::lifecycle::Request<Self::Owner>,
    ) -> Step<
        Result<
            crate::persistence::lifecycle::Response<Self::Owner>,
            crate::persistence::lifecycle::Error,
        >,
    > {
        use crate::persistence::lifecycle::{
            Error, Inspection, InspectionState, NativeCapability, Request, Response,
        };
        BOOTSTRAPS.fetch_add(1, Ordering::SeqCst);
        if !matches!(request, Request::Inspect { .. }) {
            return Step::Ready(Err(Error::MissingCapability));
        }
        if !op.resuming() {
            op.park(17u8);
            return Step::Pending { wake_at_ns: 1 };
        }
        assert_eq!(op.resume::<u8>(), Some(17));
        Step::Ready(Ok(Response::Inspected(Inspection {
            state: InspectionState::Empty,
            source: None,
            admission_marker: None,
            catalogue: vec![],
            capabilities: vec![NativeCapability::CurrentOpen],
        })))
    }
    fn info(&self) -> owned::BackendInfo {
        info()
    }
    fn read(
        &self,
        op: &mut Op<'_>,
        source: &owned::Read,
    ) -> Step<Result<owned::ReadResult<Own>, owned::Failure>> {
        READS.fetch_add(1, Ordering::SeqCst);
        let pointer = source.addresses[0].key.as_ptr() as usize;
        if !op.resuming() {
            op.park(pointer);
            return Step::Pending { wake_at_ns: 1 };
        }
        assert_eq!(op.resume::<usize>(), Some(pointer));
        Step::Ready(Ok(owned::ReadResult::Values {
            observed_at: observation(),
            values: vec![Some(Secret::held(b"value".to_vec()))],
        }))
    }
    fn scan(
        &self,
        _: &mut Op<'_>,
        source: &owned::Scan,
    ) -> Step<Result<owned::Page<Own>, owned::Failure>> {
        SCANS.fetch_add(1, Ordering::SeqCst);
        assert_eq!(source.prefix, b"k");
        assert_eq!(source.after.as_deref(), Some(b"k0".as_slice()));
        Step::Ready(Ok(owned::Page {
            generation: 7,
            rows: vec![(
                owned::Address {
                    namespace: source.namespace.0,
                    key: b"k1".to_vec(),
                },
                Secret::held(vec![8]),
            )],
            next: Some(b"k1".to_vec()),
        }))
    }
    fn commit(
        &self,
        op: &mut Op<'_>,
        source: &owned::PreparedCandidate<Own>,
    ) -> Step<Result<Committed<Own>, owned::Failure>> {
        let pointer = source.candidate().result.expose_own(self.owner()).as_ptr() as usize;
        if !op.resuming() {
            op.park(pointer);
            return Step::Pending { wake_at_ns: 1 };
        }
        assert_eq!(op.resume::<usize>(), Some(pointer));
        COMMITS.fetch_add(1, Ordering::SeqCst);
        let result = b"original-result".to_vec();
        crate::abi::sdk::secret_bytes::watch(&result);
        Step::Ready(Ok(Committed {
            observed_at: observation(),
            decision: owned::Decision::Applied(Secret::held(result)),
        }))
    }
    fn clock(
        &self,
        _: &mut Op<'_>,
        _: owned::DatasetId,
    ) -> Step<Result<owned::ClockObservation, owned::Failure>> {
        Step::Ready(Ok(observation()))
    }
}
crate::store_v4_door!(Fake, "test-primitive", "0", 8);

fn head<T>(slot: u32, ticket: Ticket) -> InHead {
    let mut head: InHead = blank_in::<wire::ClockIn>().head;
    head.size = std::mem::size_of::<T>() as u32;
    head.op = slot;
    head.ticket = ticket;
    head
}
fn call<I, O>(
    op: Option<crate::abi::mechanism::call::Op>,
    instance: *mut c_void,
    input: &I,
    out: &mut O,
) -> Outcome {
    // SAFETY: every output used here has a leading OutHead.
    unsafe {
        (*core::ptr::from_mut(out).cast::<OutHead>()).size = std::mem::size_of::<O>() as u32;
    }
    // SAFETY: callers select the exact table slot and retain matching initialized loans.
    unsafe {
        op.unwrap()(
            instance,
            core::ptr::from_ref(input).cast(),
            core::ptr::from_mut(out).cast(),
        )
        .outcome()
    }
}
fn table() -> &'static wire::Ops {
    // SAFETY: generated door's table is the declared v4 table.
    unsafe { &*door().ops().cast::<wire::Ops>() }
}
#[test]
fn v4_native_pending_short_retry_metadata_and_cancel() {
    let door = door();
    assert_eq!(door.kind_abi(), 3);
    assert_eq!(door.layout(), wire::LAYOUT_FINGERPRINT);
    assert_eq!(table().head.slots, wire::TABLE_SLOTS);
    // SAFETY: generated statement is static and initialized.
    let statement = unsafe { &*door.statement() };
    assert_eq!(statement.kind_abi, 3);
    assert!(statement.kind_tail().is_null());
    assert_eq!(<crate::abi::store::v4::Ops as KindOps>::ABI_VERSION, 3);
    assert_eq!(
        <crate::abi::store::v4::Ops as KindOps>::LAYOUT_FINGERPRINT,
        crate::abi::store::LAYOUT_FINGERPRINT
    );
    let mut open: OpenIn = blank_in();
    open.head = head::<OpenIn>(lc::slot::OPEN, Ticket::NONE);
    let mut opened: OpenOut = blank_out();
    assert_eq!(
        call(table().head.open, core::ptr::null_mut(), &open, &mut opened),
        Outcome::Ready
    );
    assert_ne!(opened.head.lease, 0);
    // SAFETY: OPEN's real metadata lease remains held here.
    let extension = unsafe {
        core::slice::from_raw_parts(opened.head.extensions.ptr, opened.head.extensions.len)
    };
    assert_eq!(
        metadata::decode(
            crate::abi::mechanism::extensions::get(extension, metadata::EXTENSION).unwrap()
        )
        .unwrap(),
        info()
    );
    let mut release: ReleaseIn = blank_in();
    release.head = head::<ReleaseIn>(lc::slot::RELEASE, Ticket::NONE);
    release.lease = opened.head.lease;
    assert_eq!(
        call(
            table().head.release,
            opened.instance,
            &release,
            &mut blank_out::<OutHead>()
        ),
        Outcome::Ready
    );

    // Nonempty selectors are copied by the native decoder. Encoding must bind to
    // that retained copy while response decoding still binds to the caller's loan.
    let source = owned::Scan {
        dataset: info().dataset,
        namespace: owned::NamespaceId([8; 16]),
        prefix: b"k".to_vec(),
        after: Some(b"k0".to_vec()),
        generation: Some(7),
        allow_change: false,
        max_items: 1,
        max_bytes: 100,
    };
    let mut scan = crate::abi::sdk::store::v4::scan(
        &source,
        head::<wire::ScanIn>(
            wire::slot::SCAN,
            Ticket {
                slot: 0,
                generation: 1,
            },
        ),
        wire::HostRows {
            items: core::ptr::null_mut(),
            items_cap: 0,
            bytes: crate::abi::store::HostBuf {
                ptr: core::ptr::null_mut(),
                cap: 0,
            },
        },
    );
    let mut scanned: wire::ScanOut = blank_out();
    assert_eq!(
        call(table().scan, opened.instance, &scan, &mut scanned),
        Outcome::Failed
    );
    assert_eq!((scanned.needed_items, scanned.needed_bytes), (1, 5));
    assert_eq!(SCANS.load(Ordering::SeqCst), 1);
    let mut rows = [wire::ScanRow {
        key: wire::Bytes {
            ptr: core::ptr::null(),
            len: 0,
        },
        value: Blob::ABSENT,
    }];
    let mut bytes = [0; 5];
    scan.rows = wire::HostRows {
        items: rows.as_mut_ptr(),
        items_cap: rows.len(),
        bytes: crate::abi::store::HostBuf {
            ptr: bytes.as_mut_ptr(),
            cap: bytes.len(),
        },
    };
    let original_after = scan.after;
    scan.after = wire::Bytes {
        ptr: b"k9".as_ptr(),
        len: 2,
    };
    assert_eq!(
        call(table().scan, opened.instance, &scan, &mut scanned),
        Outcome::Refused
    );
    scan.after = original_after;
    assert_eq!(
        call(table().scan, opened.instance, &scan, &mut scanned),
        Outcome::Ready
    );
    assert_eq!(SCANS.load(Ordering::SeqCst), 1);
    let page = crate::abi::sdk::store::v4::response::scan(
        Outcome::Ready,
        &source,
        &scan,
        &scanned,
        &rows,
        &bytes,
        1024,
    )
    .unwrap();
    assert_eq!(page.rows[0].0.key, b"k1");
    assert_eq!(page.next.as_deref(), Some(b"k1".as_slice()));

    let ticket = Ticket {
        slot: 3,
        generation: 1,
    };
    let mut input: wire::CommitIn = blank_in();
    input.head = head::<wire::CommitIn>(wire::slot::COMMIT, ticket);
    input.candidate.id = wire::AttemptId {
        dataset: [1; 16],
        writer: [4; 16],
        operation: [5; 16],
        writer_epoch: 1,
        execution_epoch: 1,
    };
    input.candidate.codec = wire::CODEC_VERSION;
    input.candidate.result = Blob {
        ptr: b"candidate-result".as_ptr(),
        len: 16,
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    let mutation = wire::Mutation {
        address: wire::Address {
            namespace: [8; 16],
            key: wire::Bytes {
                ptr: b"key".as_ptr(),
                len: 3,
            },
        },
        tag: wire::MUTATION_DELETE,
        _reserved: 0,
        exact_length: 0,
        value: Blob::ABSENT,
    };
    input.candidate.mutations = &mutation;
    input.candidate.mutations_len = 1;
    let mut output: wire::CommitOut = blank_out();
    assert_eq!(
        call(table().commit, opened.instance, &input, &mut output),
        Outcome::Pending
    );
    input.head.flags |= FLAG_RESUME;
    assert_eq!(
        call(table().commit, opened.instance, &input, &mut output),
        Outcome::Failed
    );
    assert_eq!(output.needed, 15);
    assert_eq!(COMMITS.load(Ordering::SeqCst), 1);
    input.candidate.result = Blob {
        ptr: b"changed".as_ptr(),
        len: 7,
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    input.head.flags = 0;
    assert_eq!(
        call(table().commit, opened.instance, &input, &mut output),
        Outcome::Refused
    );
    assert_eq!(COMMITS.load(Ordering::SeqCst), 1);
    input.candidate.result = Blob {
        ptr: b"candidate-result".as_ptr(),
        len: 16,
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    let mut bytes = [0; 15];
    input.head.flags = 0;
    input.result = crate::abi::store::HostBuf {
        ptr: bytes.as_mut_ptr(),
        cap: bytes.len(),
    };
    assert_eq!(
        call(table().commit, opened.instance, &input, &mut output),
        Outcome::Ready
    );
    assert_eq!(output.observed_at, 41);
    assert_eq!(output.authority, [3; 16]);
    assert_eq!(&bytes, b"original-result");
    assert_eq!(COMMITS.load(Ordering::SeqCst), 1);

    let address = wire::Address {
        namespace: [8; 16],
        key: wire::Bytes {
            ptr: b"key".as_ptr(),
            len: 3,
        },
    };
    let mut read: wire::ReadIn = blank_in();
    read.head = head::<wire::ReadIn>(
        wire::slot::READ,
        Ticket {
            slot: 4,
            generation: 1,
        },
    );
    read.dataset = [1; 16];
    read.addresses = &address;
    read.addresses_len = 1;
    let mut read_out: wire::ReadOut = blank_out();
    assert_eq!(
        call(table().read, opened.instance, &read, &mut read_out),
        Outcome::Pending
    );
    read.head.flags |= FLAG_RESUME;
    assert_eq!(
        call(table().read, opened.instance, &read, &mut read_out),
        Outcome::Failed
    );
    assert_eq!(READS.load(Ordering::SeqCst), 2);
    let mut values = [wire::ReadValue {
        found: 0,
        _reserved: 0,
        value: Blob::ABSENT,
    }];
    let mut value_bytes = [0; 5];
    read.head.flags = 0;
    read.values = wire::HostValues {
        items: values.as_mut_ptr(),
        items_cap: 1,
        bytes: crate::abi::store::HostBuf {
            ptr: value_bytes.as_mut_ptr(),
            cap: 5,
        },
    };
    assert_eq!(
        call(table().read, opened.instance, &read, &mut read_out),
        Outcome::Ready
    );
    assert_eq!(&value_bytes, b"value");
    assert_eq!(READS.load(Ordering::SeqCst), 2);
    // Cancellation retires the exact pending request through the existing ticket path.
    // SAFETY: decoder-watched initialized allocations stay in this thread until cancellation.
    let probe = unsafe { crate::alloc_counter::InitializedPayloadProbe::start().unwrap() };
    input.head = head::<wire::CommitIn>(
        wire::slot::COMMIT,
        Ticket {
            slot: 5,
            generation: 1,
        },
    );
    assert_eq!(
        call(table().commit, opened.instance, &input, &mut output),
        Outcome::Pending
    );
    let mut cancel: CancelIn = blank_in();
    cancel.head = head::<CancelIn>(lc::slot::CANCEL, Ticket::NONE);
    cancel.ticket = input.head.ticket;
    let mut cancelled: CancelOut = blank_out();
    assert_eq!(
        call(
            table().head.cancel,
            opened.instance,
            &cancel,
            &mut cancelled
        ),
        Outcome::Ready
    );
    assert_eq!(cancelled.disposition, crate::abi::store::CANCEL_UNKNOWN);
    let observed = probe.finish();
    assert!(!observed.reentered);
    assert!(!observed.payloads.is_empty());
    for payload in observed.payloads {
        assert!(payload.freed);
        assert!(!payload.reallocated);
        #[cfg(target_os = "linux")]
        assert!(payload.wiped);
    }
    input.head.flags = FLAG_RESUME;
    assert_eq!(
        call(table().commit, opened.instance, &input, &mut output),
        Outcome::Fault
    );
    assert_eq!(COMMITS.load(Ordering::SeqCst), 1);
    // A completed short reply also retires its candidate and original result on cancel.
    // SAFETY: watched initialized allocations remain on this thread through cancellation.
    let probe = unsafe { crate::alloc_counter::InitializedPayloadProbe::start().unwrap() };
    input.head = head::<wire::CommitIn>(
        wire::slot::COMMIT,
        Ticket {
            slot: 6,
            generation: 1,
        },
    );
    input.result = crate::abi::store::HostBuf {
        ptr: core::ptr::null_mut(),
        cap: 0,
    };
    assert_eq!(
        call(table().commit, opened.instance, &input, &mut output),
        Outcome::Pending
    );
    input.head.flags = FLAG_RESUME;
    assert_eq!(
        call(table().commit, opened.instance, &input, &mut output),
        Outcome::Failed
    );
    assert_eq!(COMMITS.load(Ordering::SeqCst), 2);
    cancel.ticket = input.head.ticket;
    assert_eq!(
        call(
            table().head.cancel,
            opened.instance,
            &cancel,
            &mut cancelled
        ),
        Outcome::Ready
    );
    let observed = probe.finish();
    assert!(!observed.reentered);
    assert_eq!(observed.payloads.len(), 2);
    for payload in observed.payloads {
        assert!(payload.freed);
        assert!(!payload.reallocated);
        #[cfg(target_os = "linux")]
        assert!(payload.wiped);
    }
    let mut close: InHead = head::<InHead>(lc::slot::CLOSE, Ticket::NONE);
    close.size = std::mem::size_of::<InHead>() as u32;
    assert_eq!(
        call(
            table().head.close,
            opened.instance,
            &close,
            &mut blank_out::<OutHead>()
        ),
        Outcome::Ready
    );
}

#[test]
fn bootstrap_pending_short_and_prepared_open_retain_exactly_one_instance() {
    use crate::abi::sdk::store::v4::bootstrap::{Bootstrap, OpenBindingBytes};
    use crate::persistence::lifecycle::{self as native, OpenBinding, Request, Response};
    let bounds = native::Bounds {
        items: 64,
        bytes: 1_048_576,
    };
    let request = Bootstrap::new(std::sync::Arc::new(Request::Inspect { bounds }), bounds).unwrap();
    let changed = Bootstrap::new(
        std::sync::Arc::new(Request::Inspect {
            bounds: native::Bounds {
                items: 63,
                ..bounds
            },
        }),
        bounds,
    )
    .unwrap();
    let ticket = Ticket {
        slot: 17,
        generation: 1,
    };
    let mut input: wire::BootstrapIn = blank_in();
    input.head = head::<wire::BootstrapIn>(wire::slot::BOOTSTRAP, ticket);
    input.request = request.blob();
    let mut output: wire::BootstrapOut = blank_out();
    assert_eq!(
        call(
            table().bootstrap,
            core::ptr::null_mut(),
            &input,
            &mut output
        ),
        Outcome::Pending
    );
    let instance = output.instance;
    assert!(!instance.is_null());
    assert_eq!(BOOTSTRAPS.load(Ordering::SeqCst), 1);
    input.head.flags = FLAG_RESUME;
    input.request = changed.blob();
    assert_eq!(
        call(table().bootstrap, instance, &input, &mut output),
        Outcome::Fault
    );
    assert_eq!(output.instance, instance);
    input.request = request.blob();
    assert_eq!(
        call(table().bootstrap, instance, &input, &mut output),
        Outcome::Failed
    );
    assert_eq!(output.instance, instance);
    assert!(output.needed > 0);
    assert_eq!(BOOTSTRAPS.load(Ordering::SeqCst), 2);
    let mut bytes = vec![0; output.needed as usize];
    input.head.flags = 0;
    input.result = crate::abi::store::HostBuf {
        ptr: bytes.as_mut_ptr(),
        cap: bytes.len(),
    };
    assert_eq!(
        call(table().bootstrap, instance, &input, &mut output),
        Outcome::Ready
    );
    assert_eq!(output.instance, instance);
    assert_eq!(BOOTSTRAPS.load(Ordering::SeqCst), 2);
    assert!(matches!(
        native::codec::decode_response(&bytes[..output.written as usize], bounds),
        Ok(Response::Inspected(_))
    ));
    let binding = OpenBindingBytes::new(OpenBinding::Empty, bounds).unwrap();
    let mut open: OpenIn = blank_in();
    open.head = head::<OpenIn>(lc::slot::OPEN, Ticket::NONE);
    open.head.extensions = binding.extensions();
    open.generation = 1;
    let mut opened: OpenOut = blank_out();
    assert_eq!(
        call(table().head.open, instance, &open, &mut opened),
        Outcome::Fault
    );
    assert_eq!(
        opened.instance, instance,
        "failed prepared OPEN remains disposable"
    );
    open.generation = 0;
    assert_eq!(
        call(table().head.open, instance, &open, &mut opened),
        Outcome::Ready
    );
    assert_eq!(
        opened.instance, instance,
        "OPEN adopts the native inspection instance"
    );
    let close = head::<InHead>(lc::slot::CLOSE, Ticket::NONE);
    let mut out: OutHead = blank_out();
    assert_eq!(
        call(table().head.close, instance, &close, &mut out),
        Outcome::Ready
    );
}
