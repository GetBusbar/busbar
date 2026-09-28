// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel's host services: `clock.now`, and `dest.judge` over the one destination judge, with a
//! resolver the test answers by hand.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

/// A resolver that holds every resolution for the test to answer.
#[derive(Default)]
struct HandResolver {
    asked: AtomicUsize,
    held: Mutex<Vec<Resolved>>,
}

impl Resolve for HandResolver {
    fn resolve(&self, _host: &str, done: Resolved) {
        self.asked.fetch_add(1, Ordering::SeqCst);
        self.held.lock().unwrap().push(done);
    }
}

fn services(resolver: Arc<HandResolver>) -> KernelServices {
    let rules = DestRules {
        policy: GuardPolicy::default(),
        denylist: Arc::new(Denylist::new(&[], &[], false)),
    };
    KernelServices::new(HashMap::from([(0, rules)]), resolver)
}

fn verdict_now(r: Ran) -> Stored {
    match r {
        Ran::Now(s) => s,
        Ran::Later => panic!("the answer pended"),
    }
}

/// A later that records what it was answered.
fn recorder() -> (Arc<Mutex<Option<Stored>>>, Later) {
    let slot = Arc::new(Mutex::new(None));
    let mine = Arc::clone(&slot);
    (
        slot,
        Box::new(move |s| {
            *mine.lock().unwrap() = Some(s);
        }),
    )
}

#[test]
fn the_clock_reads_wall_time_and_a_monotonic_origin() {
    let s = services(Arc::default());
    let a = s.now();
    let b = s.now();
    assert!(a.wall_ns > 1_600_000_000_000_000_000);
    assert!(b.mono_ns >= a.mono_ns);
}

/// 1.5.5 REFUSAL TIMING: a refusal the name decides answers at once, before any resolution, with the
/// verdict the one judge gives.
#[test]
fn dest_judge_refuses_what_the_name_decides_at_once() {
    let r = Arc::new(HandResolver::default());
    let s = services(Arc::clone(&r));
    for (dest, want) in [
        (
            "https://169.254.169.254/latest/meta-data/",
            svc::DEST_METADATA,
        ),
        ("https://metadata.google.internal/", svc::DEST_METADATA),
        ("https://[fd00:ec2::254]/", svc::DEST_METADATA),
        ("https://0x7f000001/", svc::DEST_OBFUSCATED),
        ("ftp://files.example/", svc::DEST_SCHEME),
        ("https://10.0.0.7/", svc::DEST_INTERNAL),
        ("https://93.184.216.34/", svc::DEST_ALLOWED),
    ] {
        let (_, later) = recorder();
        let got = verdict_now(s.dest_judge(dest, 0, true, Some(later)));
        assert_eq!(
            (got.outcome, got.value),
            (Stored::ready(0).outcome, want),
            "{dest}"
        );
    }
    assert_eq!(r.asked.load(Ordering::SeqCst), 0);
}

/// Asked to resolve, a name pends and the address judgement decides the answer; not asked, the
/// name's own judgement is the verdict and nothing resolves.
#[test]
fn dest_judge_resolves_only_when_asked_and_judges_what_answered() {
    let r = Arc::new(HandResolver::default());
    let s = services(Arc::clone(&r));
    let (slot, later) = recorder();
    assert!(matches!(
        s.dest_judge("https://api.example.com/v1", 0, true, Some(later)),
        Ran::Later
    ));
    let done = r.held.lock().unwrap().pop().unwrap();
    done(Ok(vec!["10.1.2.3".parse().unwrap()]));
    assert_eq!(
        slot.lock().unwrap().as_ref().unwrap().value,
        svc::DEST_INTERNAL
    );

    let (slot, later) = recorder();
    assert!(matches!(
        s.dest_judge("https://api.example.com/v1", 0, true, Some(later)),
        Ran::Later
    ));
    let done = r.held.lock().unwrap().pop().unwrap();
    done(Err("NXDOMAIN".into()));
    assert_eq!(
        slot.lock().unwrap().as_ref().unwrap().value,
        svc::DEST_UNRESOLVABLE
    );

    let (_, later) = recorder();
    let got = verdict_now(s.dest_judge("https://api.example.com/v1", 0, false, Some(later)));
    assert_eq!(got.value, svc::DEST_ALLOWED);
    assert_eq!(r.asked.load(Ordering::SeqCst), 2);
}

#[test]
fn an_egress_class_the_kernel_did_not_map_is_refused() {
    let s = services(Arc::default());
    let (_, later) = recorder();
    let got = verdict_now(s.dest_judge("https://a.example/", 7, true, Some(later)));
    assert_eq!(got, Stored::refused("no such egress class"));
}
