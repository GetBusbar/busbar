// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;

#[test]
fn red_a_snapshot_length_over_the_byte_cap_is_refused_before_any_copy() {
    crate::dispatch_tests::assert_child_passes(
        "red_a_snapshot_length_over_the_byte_cap_is_refused_before_any_copy",
        "a snapshot length over the byte cap was copied",
        oversize_snapshot_lengths_child,
    );
}

fn oversize_snapshot_lengths_child() {
    use busbar_contract::abi::plane::PlaneSnapshot;
    let b = [b'a'; 8];
    let over = u32::MAX as usize + 1;
    let snap = || {
        // SAFETY: a `PlaneSnapshot` is plain C data (integers, raw pointers); all-zero is valid.
        let mut s: PlaneSnapshot = unsafe { std::mem::zeroed() };
        s.size = std::mem::size_of::<PlaneSnapshot>() as u32;
        s.generation = 1;
        s
    };
    let fine = snap();
    assert!(
        copy_snapshot(&fine, 0).is_some(),
        "a snapshot within every cap copies"
    );
    let mut audience = snap();
    audience.audience = AbiStr {
        ptr: b.as_ptr(),
        len: over,
    };
    assert!(
        copy_snapshot(&audience, 0).is_none(),
        "an audience over the cap"
    );
    let mut openapi = snap();
    openapi.openapi = Blob {
        ptr: b.as_ptr(),
        len: over,
        fmt: 0,
        flags: 0,
    };
    assert!(
        copy_snapshot(&openapi, 0).is_none(),
        "an openapi over the cap"
    );
    let mut facts = snap();
    facts.resource_facts = Blob {
        ptr: b.as_ptr(),
        len: over,
        fmt: 0,
        flags: 0,
    };
    assert!(
        copy_snapshot(&facts, 0).is_none(),
        "resource facts over the cap"
    );
}

/// A probe door double's park: armed, the next bind notes it entered and waits for the release (at
/// most thirty seconds, so a test that never releases fails rather than hangs).
#[derive(Default)]
struct Gate {
    armed: AtomicBool,
    entered: AtomicBool,
    released: AtomicBool,
}

impl Gate {
    fn park(&self) {
        if !self.armed.swap(false, Ordering::SeqCst) {
            return;
        }
        self.entered.store(true, Ordering::SeqCst);
        let since = Instant::now();
        while !self.released.load(Ordering::SeqCst) && since.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn entered_within(&self, wait: Duration) -> bool {
        let since = Instant::now();
        while !self.entered.load(Ordering::SeqCst) {
            if since.elapsed() > wait {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        true
    }
}

#[test]
fn red_a_probe_is_bound_and_opened_with_the_probes_lock_let_go() {
    let gate = Arc::new(Gate::default());
    let parks = Arc::clone(&gate);
    let inner = linked_probe(crate::plane_door_plugin::door, "the-probe");
    let bind: ProbeBind = Arc::new(move || {
        parks.park();
        inner()
    });
    let reg = registration(bind).expect("the plane registers");
    gate.armed.store(true, Ordering::SeqCst);
    let (parked, second) = std::thread::scope(|s| {
        let first = Arc::clone(&reg.facing);
        let one = s.spawn(move || first(b"", b"", Some("https://one.example"), &[]).is_ok());
        let parked = gate.entered_within(Duration::from_secs(10));
        let (tx, rx) = std::sync::mpsc::channel();
        let other = Arc::clone(&reg.facing);
        s.spawn(move || {
            let _ = tx.send(other(b"", b"", Some("https://two.example"), &[]).is_ok());
        });
        let second = rx.recv_timeout(Duration::from_secs(5));

        gate.released.store(true, Ordering::SeqCst);
        let _ = one.join();
        (parked, second)
    });
    assert!(parked, "the first facing never reached the probe's bind");
    assert!(
        second.is_ok(),
        "a facing blocked while another URL's probe was in its door: the probes' lock was held \
         across plugin code"
    );
}

#[test]
fn a_linked_plane_registry_row_binds_no_probe_until_its_section_is_judged() {
    use std::sync::atomic::AtomicUsize;
    let door = crate::plane_door_plugin::door;
    let binds = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&binds);
    let inner = linked_probe(door, "the-probe");
    let bind: ProbeBind = Arc::new(move || {
        counted.fetch_add(1, Ordering::SeqCst);
        inner()
    });
    let candidate = crate::boot::Candidate::linked(door).expect("a linked door states itself");
    let reg = stated_registration(&candidate, bind).expect("the plane registers");
    assert_eq!(
        binds.load(Ordering::SeqCst),
        0,
        "registering a linked plane's row bound a probe instance of it"
    );
    let bound = registration(linked_probe(door, "the-probe")).expect("the plane binds");
    assert_eq!(
        reg.key, bound.key,
        "the stated row names the plane its bind does"
    );
    assert_eq!(reg.section, bound.section);
    assert_eq!(reg.owns, bound.owns);
    assert_eq!(reg.consumes, bound.consumes);
    assert_eq!(reg.requires, bound.requires);
    assert_eq!(reg.dialects, bound.dialects);
    assert_eq!(reg.admin_routes.len(), bound.admin_routes.len());
    let _ = (reg.validate)(b"");
    let _ = (reg.validate)(b"");
    assert_eq!(
        binds.load(Ordering::SeqCst),
        1,
        "judging its section binds the one probe that answers every judge"
    );
}

#[test]
fn concurrent_facing_owns_its_probe_until_completion_then_closes_the_spare() {
    let gate = Arc::new(Gate::default());
    let parks = Arc::clone(&gate);
    let held = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = Arc::clone(&held);
    let inner = linked_probe(crate::plane_door_plugin::door, "concurrent-probe");
    let bind: ProbeBind = Arc::new(move || {
        let p = inner()?;
        observed.lock().unwrap().push(Arc::clone(&p.inner));
        parks.park();
        Ok(p)
    });
    let reg = registration(bind).unwrap();
    gate.armed.store(true, Ordering::SeqCst);
    let (parked, second, first) = std::thread::scope(|s| {
        let facing = Arc::clone(&reg.facing);
        let first = s.spawn(move || facing(b"{}", b"", Some("https://one.example"), &[]));
        let parked = gate.entered_within(Duration::from_secs(10));
        let facing = Arc::clone(&reg.facing);
        let (tx, rx) = std::sync::mpsc::channel();
        s.spawn(move || {
            let _ = tx.send(facing(b"{}", b"", Some("https://two.example"), &[]));
        });
        let second = rx.recv_timeout(Duration::from_secs(5));
        gate.released.store(true, Ordering::SeqCst);
        (parked, second, first.join())
    });
    assert!(parked);
    let second = second
        .expect("second input runs without the first's lock")
        .unwrap();
    let first = first.unwrap().unwrap();
    assert_eq!(first.claims, second.claims);
    {
        let observed = held.lock().unwrap();
        assert!(
            observed[1].is_open(),
            "late completion remains the cached probe"
        );
        assert!(!observed[2].is_open(), "displaced completed probe closed");
    }
    drop(reg);
    assert!(held.lock().unwrap().iter().all(|p| !p.is_open()));
}

extern "C" fn refusing_probe_open(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> busbar_contract::abi::mechanism::call::RawOutcome {
    // SAFETY: this entry occupies the plane OPEN slot and the host lends its typed input.
    let input_ref = unsafe { &*input.cast::<PlaneOpenIn>() };
    if input_ref.open.settings.len == b"refuse-open".len() {
        return busbar_contract::abi::mechanism::call::RawOutcome::of(Outcome::Refused);
    }
    // SAFETY: the fixture's immutable table has this plane's exact shape.
    let ops = unsafe { &*crate::plane_door_plugin::door().ops().cast::<plane::Ops>() };
    // SAFETY: forward the same OPEN instance and complete host frames to their original
    // SDK slot; all nested loans remain live for this same-thread crossing.
    unsafe { ops.head.open.unwrap()(instance, input, out) }
}

extern "C" fn refusing_probe_refresh(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> busbar_contract::abi::mechanism::call::RawOutcome {
    // SAFETY: this entry occupies REFRESH; the host lends its typed input.
    let input_ref = unsafe { &*input.cast::<RefreshIn>() };
    if input_ref.settings.len == b"refuse-refresh".len() {
        return busbar_contract::abi::mechanism::call::RawOutcome::of(Outcome::Refused);
    }
    let mut forwarded = *input_ref;
    if input_ref.settings.len == b"park-refresh".len() {
        REFRESH_GATE.park();
        // This is the wrapper's synchronization marker, not MCP configuration.
        // The actual product receives the same valid empty settings as the
        // adjacent unparked probe, so only its ownership lifetime differs.
        forwarded.settings = Blob {
            ptr: b"{}".as_ptr(),
            len: 2,
            fmt: busbar_contract::abi::mechanism::call::BLOB_JSON,
            flags: 0,
        };
    }
    // SAFETY: the fixture's immutable table has this plane's exact shape.
    let ops = unsafe { &*crate::plane_door_plugin::door().ops().cast::<plane::Ops>() };
    // SAFETY: forward the same instance, head, generation, and secret loans. The
    // copied REFRESH frame and its static settings remain live for the crossing.
    unsafe { ops.head.refresh.unwrap()(instance, std::ptr::from_ref(&forwarded).cast(), out) }
}

static REFRESH_GATE: std::sync::LazyLock<Gate> = std::sync::LazyLock::new(Gate::default);

#[test]
fn an_open_probe_in_refresh_is_not_closed_by_a_concurrent_same_input() {
    let held = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = Arc::clone(&held);
    let inner = linked_probe(refusing_probe_door, "in-use-probe");
    let bind: ProbeBind = Arc::new(move || {
        let p = inner()?;
        observed.lock().unwrap().push(Arc::clone(&p.inner));
        Ok(p)
    });
    let reg = registration(bind).unwrap();
    let original = (reg.facing)(b"{}", b"", None, &[]).unwrap();
    REFRESH_GATE.armed.store(true, Ordering::SeqCst);
    let (parked, second, both_open, first) = std::thread::scope(|s| {
        let facing = Arc::clone(&reg.facing);
        let first = s.spawn(move || facing(b"park-refresh", b"", None, &[]));
        let parked = REFRESH_GATE.entered_within(Duration::from_secs(10));
        let facing = Arc::clone(&reg.facing);
        let (tx, rx) = std::sync::mpsc::channel();
        s.spawn(move || {
            let _ = tx.send(facing(b"{}", b"", None, &[]));
        });
        let second = rx.recv_timeout(Duration::from_secs(5));
        let both_open = {
            let observed = held.lock().unwrap();
            observed.len() == 3 && observed[1].is_open() && observed[2].is_open()
        };
        REFRESH_GATE.released.store(true, Ordering::SeqCst);
        (parked, second, both_open, first.join())
    });
    assert!(parked);
    assert_eq!(
        second.expect("a different owner can finish").unwrap(),
        original
    );
    assert!(
        both_open,
        "in-use owner was not closed or borrowed by the second call"
    );
    assert_eq!(first.unwrap().unwrap(), original);
    assert!(held.lock().unwrap()[1].is_open());
    assert!(
        !held.lock().unwrap()[2].is_open(),
        "displaced spare closed only after first completed"
    );
    drop(reg);
    assert!(held.lock().unwrap().iter().all(|p| !p.is_open()));
}

fn copied_declaration(blob: &[u8], token: &str, flags: u32) -> PlaneFacts {
    use crate::dispatch::Kind;
    use busbar_contract::abi::mechanism::door::{
        KindTailHead, Section, Statement, SECTION_DECLARING,
    };
    use busbar_contract::abi::plane::{
        PinMechanism, TrustKey, INGRESS_REQUEST_RESPONSE, TRUST_PIN,
    };
    let text = |s: &str| AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    };
    let section = Section {
        name: text("declared"),
        flags: SECTION_DECLARING,
        _reserved: 0,
    };
    let mechanism = PinMechanism {
        token: text(token),
        flags,
        _reserved: 0,
    };
    let key = TrustKey {
        key: text("anchor"),
        role: TRUST_PIN,
        flags: 0,
        default: AbiStr::ZERO,
        mechanisms: &mechanism,
        mechanisms_len: 1,
    };
    let tail = PlaneTail {
        head: KindTailHead {
            size: std::mem::size_of::<PlaneTail>() as u32,
            _reserved: 0,
        },
        ingress: INGRESS_REQUEST_RESPONSE,
        admin_openapi: Blob {
            ptr: blob.as_ptr(),
            len: blob.len(),
            fmt: busbar_contract::abi::mechanism::call::BLOB_JSON,
            flags: 0,
        },
        trust_keys: &key,
        trust_keys_len: 1,
        ..PlaneTail::ZERO
    };
    // SAFETY: Statement is plain C data; all pointer-bearing data above outlives context's copy.
    let mut statement: Statement = unsafe { std::mem::zeroed() };
    statement.sections = &section;
    statement.sections_len = 1;
    statement.kind_tail = &tail.head;
    let context = Plane::context(&statement).unwrap().unwrap();
    context.downcast_ref::<PlaneFacts>().unwrap().clone()
}

#[test]
fn repeated_declarations_share_host_owned_blobs_and_mechanisms() {
    use busbar_contract::abi::plane::{MECHANISM_PEER_KEY, MECHANISM_ROOT};
    let mut bytes = br#"{"paths":{}}"#.to_vec();
    let mut token = String::from("retained-anchor");
    let first = copied_declaration(&bytes, &token, MECHANISM_ROOT);
    let second = copied_declaration(&bytes, &token, MECHANISM_ROOT);
    let a = first.served.admin_openapi.unwrap();
    let b = second.served.admin_openapi.unwrap();
    assert_eq!(a, bytes);
    assert_ne!(a.as_ptr(), bytes.as_ptr(), "declaration owns a host copy");
    assert!(
        std::ptr::eq(a, b),
        "repeated bytes reuse their permanent allocation"
    );
    let m = first.declared.trust_keys[0].mechanisms;
    assert_eq!(m, second.declared.trust_keys[0].mechanisms);
    assert!(std::ptr::eq(m, second.declared.trust_keys[0].mechanisms));
    assert_ne!(m[0].token.as_ptr(), token.as_ptr());
    bytes.fill(b' ');
    token.clear();
    drop(bytes);
    drop(token);
    assert_eq!(a, br#"{"paths":{}}"#);
    assert_eq!(m[0].token, "retained-anchor");
    let changed = copied_declaration(
        br#"{"paths":{"/different":{}}}"#,
        "retained-anchor",
        MECHANISM_ROOT | MECHANISM_PEER_KEY,
    );
    assert_ne!(a, changed.served.admin_openapi.unwrap());
    assert_ne!(m, changed.declared.trust_keys[0].mechanisms);
    assert!(changed.declared.trust_keys[0].mechanisms[0].peer_key);
    let concurrent = std::thread::scope(|s| {
        let calls: Vec<_> = (0..4)
            .map(|_| {
                s.spawn(|| {
                    copied_declaration(
                        br#"{"concurrent":true}"#,
                        "concurrent-anchor",
                        MECHANISM_ROOT,
                    )
                })
            })
            .collect();
        calls
            .into_iter()
            .map(|call| call.join().unwrap())
            .collect::<Vec<_>>()
    });
    for facts in &concurrent[1..] {
        assert!(std::ptr::eq(
            concurrent[0].served.admin_openapi.unwrap(),
            facts.served.admin_openapi.unwrap()
        ));
        assert!(std::ptr::eq(
            concurrent[0].declared.trust_keys[0].mechanisms,
            facts.declared.trust_keys[0].mechanisms
        ));
    }
}

extern "C" fn refusing_probe_door() -> &'static busbar_contract::abi::mechanism::door::Door {
    use busbar_contract::abi::mechanism::door::{Door, DoorParts};
    let door = crate::plane_door_plugin::door();
    // SAFETY: the fixture states the plane kind's table.
    let mut ops = unsafe { *door.ops().cast::<plane::Ops>() };
    ops.head.open = Some(refusing_probe_open);
    ops.head.refresh = Some(refusing_probe_refresh);
    let ops = Box::leak(Box::new(ops));
    // SAFETY: only two entries changed, retaining their exact slot signatures and input lifetimes.
    Box::leak(Box::new(unsafe {
        Door::__from_parts(DoorParts {
            ops: std::ptr::from_ref(ops).cast(),
            ..door.parts()
        })
    }))
}

#[test]
fn refused_probe_attempts_close_and_retry_with_a_fresh_instance() {
    let held = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = Arc::clone(&held);
    let fail_bind = Arc::new(AtomicBool::new(false));
    let failures = Arc::clone(&fail_bind);
    let inner = linked_probe(refusing_probe_door, "refusing-probe");
    let bind: ProbeBind = Arc::new(move || {
        if failures.swap(false, Ordering::SeqCst) {
            return Err("fixture bind refused".into());
        }
        let p = inner()?;
        observed.lock().unwrap().push(Arc::clone(&p.inner));
        Ok(p)
    });
    let reg = registration(bind).unwrap();
    assert!((reg.facing)(b"refuse-open", b"", None, &[]).is_err());
    (reg.facing)(b"{}", b"", None, &[]).unwrap();
    assert_eq!(held.lock().unwrap().len(), 3, "refused OPEN was not reused");
    assert!((reg.facing)(b"refuse-refresh", b"", None, &[]).is_err());
    assert!(
        !held.lock().unwrap()[2].is_open(),
        "refused refresh's probe closed"
    );
    (reg.facing)(b"{}", b"", None, &[]).unwrap();
    fail_bind.store(true, Ordering::SeqCst);
    assert!((reg.facing)(b"{}", b"{}", None, &[]).is_err());
    assert!(
        !held.lock().unwrap()[3].is_open(),
        "changed input relinquished old probe before failed bind"
    );
    (reg.facing)(b"{}", b"{}", None, &[]).unwrap();
    drop(reg);
    assert!(held.lock().unwrap().iter().all(|p| !p.is_open()));
}
