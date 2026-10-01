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

/// Every loopback and private SPELLING is refused without resolving, for a class without private
/// addressing: `?`, `#` and `\` end the authority, a trailing root dot and a percent-encoded name are
/// read the way the dialling stack reads them. RED on the reader that ended the authority only at
/// `/`, which judged each of these an unresolved name and allowed it.
#[test]
fn dest_judge_refuses_every_loopback_spelling_without_resolving() {
    let r = Arc::new(HandResolver::default());
    let s = services(Arc::clone(&r));
    for dest in [
        "https://127.0.0.1?x",
        "https://localhost#a",
        "https://127.0.0.1./",
        "https://%6c%6fcalhost/",
        "https://10.0.0.5\\x/",
    ] {
        let (_, later) = recorder();
        let got = verdict_now(s.dest_judge(dest, 0, false, Some(later)));
        assert_eq!(
            (got.outcome, got.value),
            (Stored::ready(0).outcome, svc::DEST_INTERNAL),
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

/// THE JUDGE A DIAL READS: the address it answers is exactly the one the judgement pinned. A name
/// pends and the pin arrives with the answer; an IP literal is its own pin and asks no resolver; a
/// refusal the name decides answers at once; an answered address the rules refuse is refused with
/// the verdict `dest.judge` gives.
#[test]
fn judge_dial_answers_the_pinned_address_the_verdict_judged() {
    let r = Arc::new(HandResolver::default());
    let s = services(Arc::clone(&r));
    let pinned = Arc::new(Mutex::new(None));
    let got = Arc::clone(&pinned);
    let now = s.judge_dial(
        "api.example.com:8443",
        0,
        Box::new(move |v| *got.lock().unwrap() = Some(v)),
    );
    assert_eq!(now, None, "a name pends");
    let done = r.held.lock().unwrap().pop().unwrap();
    done(Ok(vec![
        "93.184.216.34".parse().unwrap(),
        "93.184.216.35".parse().unwrap(),
    ]));
    assert_eq!(
        *pinned.lock().unwrap(),
        Some(Ok("93.184.216.34:8443".parse().unwrap())),
        "the first admissible address, at the named port"
    );

    let got = s.judge_dial("93.184.216.34:443", 0, Box::new(|_| panic!("no pend")));
    assert_eq!(got, Some(Ok("93.184.216.34:443".parse().unwrap())));
    let got = s.judge_dial(
        "metadata.google.internal:80",
        0,
        Box::new(|_| panic!("no pend")),
    );
    assert_eq!(got, Some(Err(svc::DEST_METADATA)));
    assert_eq!(
        r.asked.load(Ordering::SeqCst),
        1,
        "only the name asked the resolver"
    );

    let refused = Arc::new(Mutex::new(None));
    let got = Arc::clone(&refused);
    assert_eq!(
        s.judge_dial(
            "rebind.example:80",
            0,
            Box::new(move |v| *got.lock().unwrap() = Some(v))
        ),
        None
    );
    let done = r.held.lock().unwrap().pop().unwrap();
    done(Ok(vec!["169.254.169.254".parse().unwrap()]));
    assert_eq!(*refused.lock().unwrap(), Some(Err(svc::DEST_METADATA)));
    assert_eq!(
        s.judge_dial("a.example:1", 7, Box::new(|_| {})),
        Some(Err(svc::DEST_NO_HOST)),
        "an unmapped class dials nothing"
    );
}

fn services_under(resolver: Arc<HandResolver>, denylist: Denylist) -> KernelServices {
    let rules = DestRules {
        policy: GuardPolicy::default(),
        denylist: Arc::new(denylist),
    };
    KernelServices::new(HashMap::from([(0, rules)]), resolver)
}

/// 1.5.5's OVERRIDES, ON THE ONE JUDGE: under `security.allow_all_metadata` the metadata guard is
/// off for `dest.judge` and for the connector's dial alike (both are `judge_dial`): a metadata
/// literal is admitted and pinned, a metadata name is resolved and its metadata answer pinned.
/// RED on the judge that lifted only the denylist and kept the address guard's own metadata refusal.
#[test]
fn allow_all_metadata_admits_metadata_on_the_dial_and_on_dest_judge() {
    let r = Arc::new(HandResolver::default());
    let s = services_under(Arc::clone(&r), Denylist::new(&[], &[], true));
    let imds: SocketAddr = "169.254.169.254:80".parse().unwrap();
    assert_eq!(
        s.judge_dial("169.254.169.254:80", 0, Box::new(|_| {})),
        Some(Ok(imds))
    );
    let (_, later) = recorder();
    let got = verdict_now(s.dest_judge("https://169.254.169.254/latest", 0, true, Some(later)));
    assert_eq!(got.value, svc::DEST_ALLOWED);

    let pinned = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&pinned);
    assert!(s
        .judge_dial(
            "metadata.google.internal:80",
            0,
            Box::new(move |v| *slot.lock().unwrap() = Some(v)),
        )
        .is_none());
    let done = r.held.lock().unwrap().pop().expect("the name was resolved");
    done(Ok(vec![imds.ip()]));
    assert_eq!(*pinned.lock().unwrap(), Some(Ok(imds)));
}

/// A CARVE-OUT lifts exactly what it names: `allow_metadata_hosts: [169.254.169.254]` admits that
/// address (literal, or answered for a name) and nothing else on the list.
#[test]
fn a_metadata_carve_out_admits_only_what_it_names() {
    let r = Arc::new(HandResolver::default());
    let s = services_under(
        Arc::clone(&r),
        Denylist::new(&[], &["169.254.169.254".to_string()], false),
    );
    assert_eq!(
        s.judge_dial("169.254.169.254:80", 0, Box::new(|_| {})),
        Some(Ok("169.254.169.254:80".parse().unwrap()))
    );
    assert_eq!(
        s.judge_dial("100.100.100.200:80", 0, Box::new(|_| {})),
        Some(Err(svc::DEST_METADATA))
    );
    let pinned = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&pinned);
    assert!(s
        .judge_dial("rebind.example:80", 0, Box::new(move |v| *slot.lock().unwrap() = Some(v)))
        .is_none());
    let done = r.held.lock().unwrap().pop().expect("resolved");
    done(Ok(vec!["100.100.100.200".parse().unwrap()]));
    assert_eq!(*pinned.lock().unwrap(), Some(Err(svc::DEST_METADATA)));
}

/// With no override nothing changes: metadata is refused on the dial, by literal and by answer.
#[test]
fn without_an_override_metadata_stays_refused_on_the_dial() {
    let r = Arc::new(HandResolver::default());
    let s = services(Arc::clone(&r));
    assert_eq!(
        s.judge_dial("169.254.169.254:80", 0, Box::new(|_| {})),
        Some(Err(svc::DEST_METADATA))
    );
    let pinned = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&pinned);
    assert!(s
        .judge_dial("rebind.example:80", 0, Box::new(move |v| *slot.lock().unwrap() = Some(v)))
        .is_none());
    let done = r.held.lock().unwrap().pop().expect("resolved");
    done(Ok(vec!["169.254.169.254".parse().unwrap()]));
    assert_eq!(*pinned.lock().unwrap(), Some(Err(svc::DEST_METADATA)));
}

/// RULING A ON THE DIAL: every resolved address is judged by the same lists the configuration check
/// reads, operator-blocked addresses included. A name answering an address in
/// `security.blocked_metadata_hosts` is refused on the dial, exactly as the literal is.
#[test]
fn an_operator_blocked_answer_is_refused_on_the_dial() {
    let r = Arc::new(HandResolver::default());
    let s = services_under(
        Arc::clone(&r),
        Denylist::new(&["93.184.216.34".to_string()], &[], false),
    );
    assert_eq!(
        s.judge_dial("93.184.216.34:443", 0, Box::new(|_| {})),
        Some(Err(svc::DEST_METADATA))
    );
    let pinned = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&pinned);
    assert!(s
        .judge_dial("blocked.example:443", 0, Box::new(move |v| *slot.lock().unwrap() = Some(v)))
        .is_none());
    let done = r.held.lock().unwrap().pop().expect("resolved");
    done(Ok(vec!["93.184.216.34".parse().unwrap()]));
    assert_eq!(*pinned.lock().unwrap(), Some(Err(svc::DEST_METADATA)));
}
