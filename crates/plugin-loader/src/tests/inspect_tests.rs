// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DES-443 r3 §6: describe-only inspection opens each image at most once, unloads or pins it, never leaves it
//! resident, answers hits without a slot, and refuses a busy slot, the cap and a passed deadline with a 503.

use super::*;

/// The inspect cache, slot and cap are process-wide: these tests take turns.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

fn image(lib: &str, name: &str, alias: &str) -> (Vec<u8>, SignedManifest) {
    let bytes = crate::test_host::cdylib_bytes(lib);
    let manifest = crate::pack_native::complete(
        &bytes,
        crate::sign::Manifest {
            name: name.into(),
            alias: alias.into(),
            kind: "store".into(),
            publisher: crate::test_host::TEST_PUBLISHER.into(),
            ..crate::sign::Manifest::default()
        },
        None,
    )
    .expect("the fixture packs");
    let signed = crate::test_host::test_sign(manifest, &bytes);
    (bytes, signed)
}

fn inspect(
    bytes: &[u8],
    manifest: &SignedManifest,
    trust: &TrustConfig,
) -> (Result<Described, Unanswered>, InspectOutcome) {
    let process = crate::test_host::shared_process().expect("process resources");
    describe(
        bytes,
        manifest,
        trust,
        &busbar_plugin_abi::host_side::host_vt::HOST,
        process.slots(),
        Box::new(|_| {}),
    )
}

/// Red first (A-F3 in the loader): inspecting an image leaves it neither resident nor reopened. Then: the trust
/// order (refused before any open), a busy slot and the cap (503, nothing opened), one open for fifty inspections,
/// the former_names re-check (F2), and hits that answer with the slot held (B-2), including a resident image
/// described in place (F1).
#[test]
fn an_image_is_opened_once_unloaded_and_then_answered_from_the_cache() {
    let _serial = serial();
    let (bytes, manifest) = image("native_schema_bomb", "native-schema-bomb", "schema-bomb");
    let sha256 = busbar_contract::crypto::sha256(&bytes);
    let trust = crate::test_host::test_trust("native-schema-bomb");

    let (answer, outcome) = inspect(&bytes, &manifest, &crate::test_host::test_trust("other"));
    assert!(matches!(
        answer.as_ref().err(),
        Some(Unanswered::Refused(_))
    ));
    assert_eq!((outcome.outcome, outcome.opened), (Outcome::Refused, false));
    assert_eq!(opens(&sha256), 0, "an untrusted image is never opened");

    let held = Slot::try_take([0; 32]).expect("the slot starts free");
    let (answer, outcome) = inspect(&bytes, &manifest, &trust);
    drop(held);
    assert!(
        matches!(answer.as_ref().err(), Some(Unanswered::Unavailable { text, retry_after_s }) if *retry_after_s == RETRY_AFTER_S && text.contains("another plugin inspection")),
        "a miss while the slot is held is a 503 at once: {:?}",
        answer.as_ref().err()
    );
    assert_eq!(outcome.reason.as_deref(), Some("busy"));
    assert_eq!(opens(&sha256), 0);

    let fakes: Vec<[u8; 32]> = (0..CAP_IMAGES)
        .map(|i| {
            let mut key = [0xEE; 32];
            key[0] = u8::try_from(i).expect("cap fits a byte");
            key
        })
        .collect();
    let mut prior = HashMap::new();
    {
        let mut cache = locked();
        for key in &fakes {
            if let Some(was) = cache.opened.insert(
                *key,
                Opened {
                    bytes: 1,
                    opens: 1,
                    pinned: false,
                    header_former: None,
                },
            ) {
                prior.insert(*key, was);
            }
        }
    }
    let (answer, outcome) = inspect(&bytes, &manifest, &trust);
    {
        let mut cache = locked();
        for key in &fakes {
            cache.opened.remove(key);
        }
        cache.opened.extend(prior);
    }
    assert!(
        matches!(answer.as_ref().err(), Some(Unanswered::Unavailable { text, .. }) if text.contains("restart clears it")),
        "a new image past the cap is a 503: {:?}",
        answer.as_ref().err()
    );
    assert_eq!(outcome.reason.as_deref(), Some("inspect-cap"));
    assert_eq!(opens(&sha256), 0);

    let (first, outcome) = inspect(&bytes, &manifest, &trust);
    let refused = match first {
        Err(Unanswered::Refused(refusal)) => refusal,
        other => panic!(
            "the bomb's D_SCHEMA is refused at describe: {:?}",
            other.err()
        ),
    };
    assert_eq!(outcome.outcome, Outcome::Unloaded, "{outcome:?}");
    assert!(outcome.opened);
    assert_eq!(opens(&sha256), 1);
    assert!(!pinned(&sha256));
    assert!(
        !crate::admit::is_resident(&sha256),
        "an inspected image is not left resident"
    );

    for _ in 0..50 {
        let (again, outcome) = inspect(&bytes, &manifest, &trust);
        assert_eq!(again.err(), Some(Unanswered::Refused(refused.clone())));
        assert_eq!((outcome.outcome, outcome.opened), (Outcome::Cached, false));
    }
    assert_eq!(opens(&sha256), 1, "fifty inspections open the image once");

    let mut reordered = manifest.clone();
    reordered.former_names = vec!["other-name".into(), "schema-bomb".into()];
    let reordered = crate::test_host::test_sign(reordered, &bytes);
    let (answer, outcome) = inspect(&bytes, &reordered, &trust);
    assert!(
        matches!(answer.as_ref().err(), Some(Unanswered::Refused(r)) if r.code == RefusalCode::DoorStampMismatch),
        "another former_names is checked against the header without reopening: {:?}",
        answer.as_ref().err()
    );
    assert!(!outcome.opened);
    assert_eq!(opens(&sha256), 1);

    let held = Slot::try_take([0; 32]).expect("the slot is free again");
    let (hit, outcome) = inspect(&bytes, &manifest, &trust);
    assert_eq!(hit.err(), Some(Unanswered::Refused(refused.clone())));
    assert_eq!(outcome.outcome, Outcome::Cached, "a hit takes no slot");

    locked()
        .answers
        .remove(&(sha256, manifest.former_names.join(",")));
    let admitted = crate::admit::admit_bytes(&bytes, &manifest, &trust).expect("the bomb installs");
    let (resident, outcome) = inspect(&bytes, &manifest, &trust);
    drop(held);
    assert_eq!(resident.err(), Some(Unanswered::Refused(refused)));
    assert_eq!(
        (outcome.outcome, outcome.opened),
        (Outcome::Cached, false),
        "an installed image is described in place, with no slot and no open (F1, B-2)"
    );
    assert_eq!(opens(&sha256), 1);
    drop(admitted);
}

/// An image whose describe registers a thread-exit destructor stays mapped after close: it is pinned, counted, and
/// still opened only once.
#[test]
fn an_image_that_pins_itself_is_counted_and_never_reopened() {
    let _serial = serial();
    let (bytes, manifest) = image("native_tls_pin", "native-tls-pin", "tls-pin");
    let sha256 = busbar_contract::crypto::sha256(&bytes);
    let trust = crate::test_host::test_trust("native-tls-pin");
    let (first, outcome) = inspect(&bytes, &manifest, &trust);
    let described = first.expect("the pinning fixture describes");
    assert!(described
        .schema
        .as_deref()
        .is_some_and(|s| s.contains("path")));
    if cfg!(target_env = "gnu") {
        assert_eq!(outcome.outcome, Outcome::Pinned, "{outcome:?}");
        assert!(pinned(&sha256));
    }
    for _ in 0..50 {
        let (again, outcome) = inspect(&bytes, &manifest, &trust);
        assert!(again.is_ok());
        assert_eq!(outcome.outcome, Outcome::Cached);
    }
    assert_eq!(opens(&sha256), 1, "a pinned image is never reopened");
    assert!(
        !crate::admit::is_resident(&sha256),
        "a pin is not a resident entry"
    );
}

fn refusal() -> Refusal {
    Refusal::new(RefusalCode::DescribeInvalid, "describe", "late", "on time")
}

fn finished(outcome: Outcome) -> (Result<Described, Unanswered>, InspectOutcome) {
    (
        Err(Unanswered::Refused(refusal())),
        InspectOutcome {
            sha256: [7; 32],
            opened: true,
            outcome,
            reason: None,
        },
    )
}

/// Past the deadline the request has gone: the inspect thread's outcome is reported `late`, with what it was.
#[test]
fn an_inspection_finished_after_its_deadline_is_reported_late() {
    let handoff = Handoff::default();
    assert!(handoff.wait(Duration::from_millis(5)).is_none());
    let (tx, rx) = std::sync::mpsc::channel();
    handoff.finish(
        finished(Outcome::Unloaded),
        Box::new(move |outcome| tx.send(outcome).expect("the test listens")),
    );
    let late = rx.try_recv().expect("a late completion is reported");
    assert_eq!(late.outcome, Outcome::Late);
    assert_eq!(late.reason.as_deref(), Some("unloaded"));
    assert_eq!(late.sha256, [7; 32]);
}

/// Within the deadline the request takes the answer, and nothing is reported late.
#[test]
fn an_inspection_answered_in_time_is_not_late() {
    let handoff = Arc::new(Handoff::default());
    let theirs = Arc::clone(&handoff);
    let (tx, rx) = std::sync::mpsc::channel::<InspectOutcome>();
    let thread = std::thread::spawn(move || {
        theirs.finish(
            finished(Outcome::Pinned),
            Box::new(move |outcome| tx.send(outcome).expect("the test listens")),
        );
    });
    let done = handoff
        .wait(Duration::from_secs(30))
        .expect("the answer arrives in time");
    thread.join().expect("the finisher ends");
    assert_eq!(done.1.outcome, Outcome::Pinned);
    assert!(rx.try_recv().is_err(), "nothing is reported late");
}

/// B-2: the cap's constants and text say a restart clears it.
#[test]
fn the_cap_is_32_images_or_4_gib_until_a_restart() {
    assert_eq!(CAP_IMAGES, 32);
    assert_eq!(CAP_BYTES, 4 * 1024 * 1024 * 1024);
}
