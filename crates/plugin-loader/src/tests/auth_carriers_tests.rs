// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::auth_axis::AuthRows;
use crate::dispatch::{DispatchConfig, Dispatcher};
use crate::{LinkedPlugin, PluginRegistry};
use busbar_contract::abi::auth::{AuthPoints, EXT_CARRIERS};
use busbar_contract::abi::mechanism::door::{MarkWord, Statement};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::sdk::auth_door::{
    carrier, verify_tail, with_tail, Answer, Verdict, VerifiedIdentity, VerifyPlugin, VerifyView,
};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::Refusal;

struct Choice {
    variant: String,
    refreshed: AtomicBool,
}

impl VerifyPlugin for Choice {
    fn open_refusing(settings: &[u8], _: &[&[u8]]) -> Result<Self, Refusal> {
        Ok(Self {
            variant: serde_json::from_slice(settings)
                .map_err(|_| Refusal::failed("settings: expected a variant"))?,
            refreshed: AtomicBool::new(false),
        })
    }

    fn carriers(&self) -> Option<Vec<String>> {
        let refreshed = self.refreshed.load(Ordering::Acquire);
        let names = match self.variant.as_str() {
            "default" => return None,
            "second" => vec!["X-Second"],
            "bad-open" => vec!["x-undeclared"],
            "bad-refresh" if refreshed => vec!["x-undeclared"],
            "first" if refreshed => vec!["X-Second"],
            _ => vec!["X-First", "x-FIRST"],
        };
        Some(names.into_iter().map(str::to_string).collect())
    }

    fn verify(&self, request: &VerifyView<'_>) -> Answer {
        if request.method() == b"old-input" {
            let (lock, changed) = &VERIFY_GATE;
            let mut state = lock.lock().unwrap();
            state.0 = true;
            changed.notify_all();
            while !state.1 {
                state = changed.wait(state).unwrap();
            }
            return Verdict::Identity(VerifiedIdentity {
                subject: String::from_utf8(request.method().to_vec()).unwrap(),
                ..VerifiedIdentity::default()
            })
            .into();
        }
        Verdict::Pass.into()
    }

    fn reload(&self, _: &[u8], _: &[&[u8]]) -> Result<u64, Refusal> {
        if self.variant == "refused" {
            return Err(Refusal::refused("settings: retain the current variant"));
        }
        if self.variant == "failed" {
            return Err(Refusal::failed("settings: refresh failed"));
        }
        self.refreshed.store(true, Ordering::Release);
        Ok(0)
    }
}

mod choice {
    use super::*;

    const CARRIERS: &[MarkWord] = &[carrier("X-First"), carrier("x-second")];
    const TAIL: &busbar_contract::abi::auth::AuthTail = &verify_tail(0, AuthPoints::HEAD);

    busbar_contract::auth_verify_door!(
        Choice,
        with_tail(
            Statement {
                mark_words: CARRIERS.as_ptr(),
                mark_words_len: CARRIERS.len(),
                ..statement("carrier-choice", "1.0.0", 8)
            },
            TAIL
        )
    );
}

static VERIFY_GATE: (Mutex<(bool, bool)>, std::sync::Condvar) =
    (Mutex::new((false, false)), std::sync::Condvar::new());

fn rows() -> AuthRows {
    let registry = PluginRegistry::empty()
        .link(vec![LinkedPlugin::auth_door(
            "carrier-choice",
            choice::door,
        )])
        .expect("the linked door registers");
    AuthRows::new(
        Arc::new(registry),
        Arc::new(Dispatcher::new(DispatchConfig::default())),
    )
}

#[test]
fn opened_instances_select_their_own_carriers_and_refresh_preserves_owned_snapshots() {
    let rows = rows();
    let open = |variant: &str| {
        rows.open("carrier-choice", variant, &serde_json::json!(variant))
            .expect("the selected variant opens")
    };
    let first = open("first");
    let second = open("second");
    let default = open("default");
    assert_eq!(first.carriers(), ["x-first"]);
    assert_eq!(second.carriers(), ["x-second"]);
    assert_eq!(default.carriers(), ["x-first", "x-second"]);
    default.refresh().unwrap();
    assert_eq!(default.carriers(), ["x-first", "x-second"]);

    let opening_selection = first.carriers();
    first.refresh().expect("the refreshed variant is valid");
    assert_eq!(first.carriers(), ["x-second"]);
    assert_eq!(opening_selection, ["x-first"]);
    assert_eq!(second.carriers(), ["x-second"]);
}

#[test]
fn undeclared_open_carriers_refuse_and_invalid_refreshed_carriers_stop_new_verifies() {
    let rows = rows();
    assert!(rows
        .open("carrier-choice", "bad-open", &serde_json::json!("bad-open"))
        .is_err());
    let bad = rows
        .open(
            "carrier-choice",
            "bad-refresh",
            &serde_json::json!("bad-refresh"),
        )
        .unwrap();
    assert_eq!(
        bad.verify_now(&VerifyRequest::default()).unwrap().verified,
        Verified::Pass
    );
    assert!(bad.refresh().is_err());
    assert_eq!(bad.carriers(), ["x-first"]);
    assert_eq!(
        bad.verify_now(&VerifyRequest::default()).unwrap().verified,
        Verified::Failed
    );
    assert_eq!(
        bad.verify(VerifyRequest::default())
            .settled()
            .expect("invalid metadata refuses before scheduling")
            .verified,
        Verified::Failed
    );

    let refused = rows
        .open("carrier-choice", "refused", &serde_json::json!("refused"))
        .unwrap();
    assert!(refused.refresh().is_err());
    assert_eq!(refused.carriers(), ["x-first"]);
    assert_eq!(
        refused
            .verify_now(&VerifyRequest::default())
            .unwrap()
            .verified,
        Verified::Pass
    );
}

#[test]
fn malformed_carrier_metadata_is_rejected_without_echoing_its_value() {
    let facts = AuthFacts {
        carriers: vec!["x-first".into(), "x-second".into()],
        ..AuthFacts::default()
    };
    for value in [
        &b"[\"x-undeclared-secret-canary\"]"[..],
        b"[1]",
        b"{}",
        b"[",
    ] {
        let bytes = extensions::encode(&[(EXT_CARRIERS, value)]);
        let error = instance_carriers(blob(&bytes, BLOB_OCTETS, 0), &[], &facts)
            .expect_err("invalid carrier selection is refused");
        assert!(!error.contains("secret-canary"));
    }
    let value = b"[\"X-FIRST\",\"x-first\"]";
    let repeated = extensions::encode(&[(EXT_CARRIERS, value), (EXT_CARRIERS, value)]);
    assert!(instance_carriers(blob(&repeated, BLOB_OCTETS, 0), &[], &facts).is_err());
    let mut truncated = extensions::encode(&[(EXT_CARRIERS, value)]);
    truncated.pop();
    assert!(instance_carriers(blob(&truncated, BLOB_OCTETS, 0), &[], &facts).is_err());
    let bytes = extensions::encode(&[("future-metadata", b"ignored"), (EXT_CARRIERS, value)]);
    assert_eq!(
        instance_carriers(blob(&bytes, BLOB_OCTETS, 0), &[], &facts).unwrap(),
        ["x-first"]
    );
    assert!(instance_carriers(blob(&bytes, BLOB_JSON, 0), &[], &facts).is_err());
    let unrelated = extensions::encode(&[("future-metadata", b"ignored")]);
    assert_eq!(
        instance_carriers(
            blob(&unrelated, BLOB_OCTETS, 0),
            &["x-second".into()],
            &facts
        )
        .unwrap(),
        ["x-second"]
    );
}

#[test]
fn admitted_verify_keeps_its_input_while_refresh_publishes_a_new_selection() {
    let rows = rows();
    let calls = rows
        .open("carrier-choice", "concurrent", &serde_json::json!("first"))
        .unwrap();
    let opening = calls.carriers();
    std::thread::scope(|scope| {
        let old = scope.spawn(|| {
            calls
                .verify_now(&VerifyRequest {
                    method: "old-input".into(),
                    ..VerifyRequest::default()
                })
                .unwrap()
        });
        let (lock, changed) = &VERIFY_GATE;
        let mut state = lock.lock().unwrap();
        while !state.0 {
            state = changed.wait(state).unwrap();
        }
        drop(state);
        let refreshed = calls.refresh();
        // Release the crossing even if the refresh assertion below fails.
        lock.lock().unwrap().1 = true;
        changed.notify_all();
        refreshed.unwrap();
        assert_eq!(calls.carriers(), ["x-second"]);
        assert_eq!(opening, ["x-first"]);
        assert!(matches!(old.join().unwrap().verified,
            Verified::Identity(ref identity) if identity.subject == "old-input"));
    });
}

// Wrap the real SDK table to observe lease custody and CLOSE, and to emulate foreign metadata.
// Choice's SDK still owns every instance and lease, so the wrappers exercise the real seam.
mod observed {
    use super::*;
    use busbar_contract::abi::auth::Ops;
    use busbar_contract::abi::mechanism::call::{OutHead, RawOutcome};
    use busbar_contract::abi::mechanism::door::{Door, DoorFn, DoorParts};
    use busbar_contract::abi::mechanism::lifecycle::{OpenIn, OpenOut, ReleaseIn};
    use std::ffi::c_void;

    pub static RELEASES: AtomicU64 = AtomicU64::new(0);
    pub static CLOSES: AtomicU64 = AtomicU64::new(0);
    pub static LIVE: AtomicU64 = AtomicU64::new(0);

    fn parts() -> DoorParts {
        // SAFETY: the SDK door has static complete storage.
        unsafe { Door::read_parts(choice::door()) }
    }

    fn base() -> &'static Ops {
        // SAFETY: the SDK door states an auth table with static storage.
        unsafe { &*parts().ops.cast::<Ops>() }
    }

    fn metadata(settings: Blob, refreshed: bool) -> Option<&'static [u8]> {
        static MALFORMED: std::sync::LazyLock<Vec<u8>> =
            std::sync::LazyLock::new(|| extensions::encode(&[(EXT_CARRIERS, b"[")]));
        static DUPLICATE: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
            extensions::encode(&[
                (EXT_CARRIERS, b"[\"x-first\"]"),
                (EXT_CARRIERS, b"[\"x-second\"]"),
            ])
        });
        // SAFETY: the host lends settings throughout this lifecycle crossing.
        let settings = unsafe { crate::dispatch::plugin::blob_bytes(settings) };
        match settings {
            b"\"malformed-open\"" => Some(MALFORMED.as_slice()),
            b"\"duplicate-open\"" => Some(DUPLICATE.as_slice()),
            b"\"malformed-refresh\"" if refreshed => Some(MALFORMED.as_slice()),
            _ => None,
        }
    }

    extern "C" fn open_slot(
        instance: *mut c_void,
        input: *const c_void,
        output: *mut c_void,
    ) -> RawOutcome {
        let result = base().head.open.unwrap()(instance, input, output);
        if result.outcome() == Outcome::Ready {
            LIVE.fetch_add(1, Ordering::SeqCst);
            // SAFETY: OPEN supplies these live complete frames. Retain the real SDK lease;
            // only the extension bytes are replaced with static fixture data.
            unsafe {
                if let Some(bytes) = metadata((*input.cast::<OpenIn>()).settings, false) {
                    (*output.cast::<OpenOut>()).head.extensions = blob(bytes, BLOB_OCTETS, 0);
                }
            }
        }
        result
    }

    extern "C" fn refresh_slot(
        instance: *mut c_void,
        input: *const c_void,
        output: *mut c_void,
    ) -> RawOutcome {
        // REFRESH is ticket-less: PENDING is a host-judged FAULT and must quarantine admission.
        // SAFETY: the host lends a complete RefreshIn for this crossing.
        let settings = unsafe { (*input.cast::<RefreshIn>()).settings };
        if unsafe { crate::dispatch::plugin::blob_bytes(settings) } == b"\"pending-refresh\"" {
            // SAFETY: the host lends a complete mutable OutHead.
            unsafe {
                (*output.cast::<OutHead>()).outcome = RawOutcome::of(Outcome::Pending);
            }
            return RawOutcome::of(Outcome::Pending);
        }
        let result = base().head.refresh.unwrap()(instance, input, output);
        if result.outcome() == Outcome::Ready {
            // SAFETY: REFRESH supplies these live complete frames, as OPEN above.
            unsafe {
                if let Some(bytes) = metadata((*input.cast::<RefreshIn>()).settings, true) {
                    (*output.cast::<OutHead>()).extensions = blob(bytes, BLOB_OCTETS, 0);
                }
            }
        }
        result
    }

    extern "C" fn release_slot(
        instance: *mut c_void,
        input: *const c_void,
        output: *mut c_void,
    ) -> RawOutcome {
        // SAFETY: RELEASE's input is a live ReleaseIn.
        let lease = unsafe { (*input.cast::<ReleaseIn>()).lease };
        let result = base().head.release.unwrap()(instance, input, output);
        if lease != 0 && result.outcome() == Outcome::Ready {
            RELEASES.fetch_add(1, Ordering::SeqCst);
        }
        result
    }

    extern "C" fn close_slot(
        instance: *mut c_void,
        input: *const c_void,
        output: *mut c_void,
    ) -> RawOutcome {
        CLOSES.fetch_add(1, Ordering::SeqCst);
        LIVE.fetch_sub(1, Ordering::SeqCst);
        base().head.close.unwrap()(instance, input, output)
    }

    extern "C" fn refused_ready(
        _: *mut c_void,
        _: *const c_void,
        output: *mut c_void,
    ) -> RawOutcome {
        // SAFETY: READY's output begins with a live OutHead.
        unsafe {
            (*output.cast::<OutHead>()).outcome = RawOutcome::of(Outcome::Refused);
        }
        RawOutcome::of(Outcome::Refused)
    }

    fn wrapped(refuse_ready: bool) -> Door {
        let mut ops = *base();
        ops.head.open = Some(open_slot);
        ops.head.refresh = Some(refresh_slot);
        ops.head.release = Some(release_slot);
        ops.head.close = Some(close_slot);
        let mut parts = parts();
        parts.ops = std::ptr::from_ref(Box::leak(Box::new(ops))).cast();
        if refuse_ready {
            parts.ready = Some(refused_ready);
        }
        // SAFETY: the original static Statement and copied table retain their SDK contract;
        // wrappers preserve SDK instance ownership, mirror outcomes, and return its leases.
        unsafe { Door::__from_parts(parts) }
    }

    pub extern "C" fn door() -> &'static Door {
        static DOOR: std::sync::OnceLock<Door> = std::sync::OnceLock::new();
        DOOR.get_or_init(|| wrapped(false))
    }

    pub extern "C" fn ready_failure_door() -> &'static Door {
        static DOOR: std::sync::OnceLock<Door> = std::sync::OnceLock::new();
        DOOR.get_or_init(|| wrapped(true))
    }

    pub fn open(door: DoorFn, variant: &str) -> Result<AuthInstance, String> {
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let sink = AuthSink::new("observed");
        let plugin = crate::dispatch::load_linked::<Auth>(
            &crate::dispatch::LinkedRow::of(door).unwrap(),
            crate::dispatch::Bind {
                instance: "observed".into(),
                max_inflight_cap: 8,
                sink: sink.bind(),
                dispatcher: dispatcher.adopter(),
                conns: crate::dispatch::ConnTable::NoNeeds,
            },
        )
        .unwrap();
        AuthInstance::open(
            plugin,
            sink,
            dispatcher,
            "observed",
            &serde_json::to_vec(variant).unwrap(),
            vec![b"wipe-on-refusal".to_vec()],
        )
    }
}

#[test]
fn rejected_open_metadata_and_ready_failure_release_then_close_once_and_refresh_releases() {
    use observed::{CLOSES, LIVE, RELEASES};
    for variant in ["bad-open", "malformed-open", "duplicate-open"] {
        let releases = RELEASES.load(Ordering::SeqCst);
        let closes = CLOSES.load(Ordering::SeqCst);
        assert!(observed::open(observed::door, variant).is_err());
        assert_eq!(RELEASES.load(Ordering::SeqCst), releases + 1);
        assert_eq!(CLOSES.load(Ordering::SeqCst), closes + 1);
        assert_eq!(LIVE.load(Ordering::SeqCst), 0);
    }
    let closes = CLOSES.load(Ordering::SeqCst);
    let releases = RELEASES.load(Ordering::SeqCst);
    assert!(observed::open(observed::ready_failure_door, "first").is_err());
    assert_eq!(RELEASES.load(Ordering::SeqCst), releases + 1);
    assert_eq!(CLOSES.load(Ordering::SeqCst), closes + 1);
    assert_eq!(LIVE.load(Ordering::SeqCst), 0);

    let calls = observed::open(observed::door, "malformed-refresh").unwrap();
    let releases = RELEASES.load(Ordering::SeqCst);
    assert!(calls.refresh().is_err());
    assert_eq!(RELEASES.load(Ordering::SeqCst), releases + 1);
    assert_eq!(
        calls
            .verify_now(&VerifyRequest::default())
            .unwrap()
            .verified,
        Verified::Failed
    );
    assert_eq!(
        calls
            .verify(VerifyRequest::default())
            .settled()
            .unwrap()
            .verified,
        Verified::Failed
    );
    let instance = calls.instance();
    close(calls.plugin());
    drop(calls);
    assert!(instance.upgrade().is_none());
    assert_eq!(LIVE.load(Ordering::SeqCst), 0);

    for variant in ["first", "refused", "failed", "pending-refresh"] {
        let calls = observed::open(observed::door, variant).unwrap();
        let releases = RELEASES.load(Ordering::SeqCst);
        let refreshed = calls.refresh();
        match variant {
            "first" => {
                refreshed.unwrap();
                assert_eq!(calls.carriers(), ["x-second"]);
                assert_eq!(RELEASES.load(Ordering::SeqCst), releases + 1);
            }
            _ => {
                assert!(refreshed.is_err());
                assert_eq!(calls.carriers(), ["x-first"]);
                assert_eq!(RELEASES.load(Ordering::SeqCst), releases);
            }
        }
        assert_eq!(
            calls
                .verify_now(&VerifyRequest::default())
                .unwrap()
                .verified,
            if variant == "pending-refresh" {
                Verified::Failed
            } else {
                Verified::Pass
            }
        );
        close(calls.plugin());
        let instance = calls.instance();
        drop(calls);
        assert!(instance.upgrade().is_none());
        assert_eq!(LIVE.load(Ordering::SeqCst), 0);
    }
}
