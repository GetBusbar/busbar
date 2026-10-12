// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `dest.judge` AND THE DIAL, THROUGH THE KERNEL, OVER THE ONE GUARD (OWNER ruling DESTINATION
//! GUARD): the kernel's host services with the deployment's judge installed, as the root installs
//! it, and a resolver the test answers by hand. These held the kernel's own rules before; the rules
//! are the guard's now, and the kernel only asks.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::abi::host::service as svc;
use busbar_contract::services::{HostServices, Later, Ran, Stored};
use busbar_kernel::config::Destinations;
use busbar_kernel::host_services::KernelServices;

use crate::guard::{Guard, Resolve, Resolved};
use crate::process::GuardJudge;

/// The provider class, the one class the 1.5.5 carve-outs speak for.
const P: u32 = busbar_contract::abi::host::conn::connector::EGRESS_PROVIDER;

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

/// The kernel's services judging by the guard `d` states, over `resolver`.
fn services(resolver: Arc<HandResolver>, d: Destinations) -> KernelServices {
    let d = Destinations {
        block_private_addresses: true,
        ..d
    };
    let guard = Guard::from_config(&d).expect("a valid guard");
    KernelServices::new().with_dest_judge(Arc::new(GuardJudge::new(guard, resolver)))
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

/// 1.5.5 REFUSAL TIMING: a refusal the name decides answers at once, before any resolution, with the
/// verdict the one judge gives.
#[test]
fn dest_judge_refuses_what_the_name_decides_at_once() {
    let r = Arc::new(HandResolver::default());
    let s = services(Arc::clone(&r), Destinations::default());
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
        let got = verdict_now(s.dest_judge(dest, 0, svc::DEST_RESOLVE, Some(later)));
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
    let s = services(Arc::clone(&r), Destinations::default());
    for dest in [
        "https://127.0.0.1?x",
        "https://localhost#a",
        "https://127.0.0.1./",
        "https://%6c%6fcalhost/",
        "https://10.0.0.5\\x/",
    ] {
        let (_, later) = recorder();
        let got = verdict_now(s.dest_judge(dest, 0, 0, Some(later)));
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
    let s = services(Arc::clone(&r), Destinations::default());
    let (slot, later) = recorder();
    assert!(matches!(
        s.dest_judge(
            "https://api.example.com/v1",
            0,
            svc::DEST_RESOLVE,
            Some(later)
        ),
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
        s.dest_judge(
            "https://api.example.com/v1",
            0,
            svc::DEST_RESOLVE,
            Some(later)
        ),
        Ran::Later
    ));
    let done = r.held.lock().unwrap().pop().unwrap();
    done(Err("NXDOMAIN".into()));
    assert_eq!(
        slot.lock().unwrap().as_ref().unwrap().value,
        svc::DEST_UNRESOLVABLE
    );

    let (_, later) = recorder();
    let got = verdict_now(s.dest_judge("https://api.example.com/v1", 0, 0, Some(later)));
    assert_eq!(got.value, svc::DEST_ALLOWED);
    assert_eq!(r.asked.load(Ordering::SeqCst), 2);
}

/// The addresses a stored `dest.judge` answer names: each span's key, as text.
fn addresses(s: &Stored) -> Vec<String> {
    s.spans
        .iter()
        .map(|sp| {
            assert_eq!(sp.value.len, 0, "an address span carries no value");
            let at = sp.key.offset as usize;
            String::from_utf8(s.bytes[at..at + sp.key.len as usize].to_vec()).unwrap()
        })
        .collect()
}

/// THE JUDGED ADDRESSES (ARCHITECT DEST-PIN 2026-10-01): asked to resolve and admitted, `dest.judge`
/// writes every address its one judgement judged, one span each, the pin first, from the SAME
/// resolution (no second lookup); an IP literal names itself; a refusal and a judgement that did
/// not resolve name none. RED on the judge that answered the verdict alone.
#[test]
fn dest_judge_writes_the_addresses_it_judged() {
    let r = Arc::new(HandResolver::default());
    let s = services(Arc::clone(&r), Destinations::default());
    let (slot, later) = recorder();
    assert!(matches!(
        s.dest_judge(
            "https://push.example.com/hook",
            0,
            svc::DEST_RESOLVE,
            Some(later)
        ),
        Ran::Later
    ));
    let done = r.held.lock().unwrap().pop().unwrap();
    done(Ok(vec![
        "93.184.216.34".parse().unwrap(),
        "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(),
    ]));
    let got = slot.lock().unwrap().take().unwrap();
    assert_eq!(got.value, svc::DEST_ALLOWED);
    assert_eq!(
        addresses(&got),
        ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]
    );
    assert_eq!(r.asked.load(Ordering::SeqCst), 1, "one resolution");

    let (_, later) = recorder();
    let got =
        verdict_now(s.dest_judge("https://93.184.216.34/x", 0, svc::DEST_RESOLVE, Some(later)));
    assert_eq!(
        (got.value, addresses(&got)),
        (svc::DEST_ALLOWED, vec!["93.184.216.34".to_owned()])
    );

    let (slot, later) = recorder();
    assert!(matches!(
        s.dest_judge(
            "https://mixed.example.com/",
            0,
            svc::DEST_RESOLVE,
            Some(later)
        ),
        Ran::Later
    ));
    let done = r.held.lock().unwrap().pop().unwrap();
    done(Ok(vec![
        "93.184.216.34".parse().unwrap(),
        "10.0.0.7".parse().unwrap(),
    ]));
    let got = slot.lock().unwrap().take().unwrap();
    assert_eq!(got.value, svc::DEST_INTERNAL);
    assert!(
        got.spans.is_empty() && got.bytes.is_empty(),
        "a refusal names none"
    );

    let (_, later) = recorder();
    let got = verdict_now(s.dest_judge("https://push.example.com/", 0, 0, Some(later)));
    assert!(got.spans.is_empty(), "not asked to resolve, none");
}

#[test]
fn an_egress_class_the_guard_does_not_know_is_refused() {
    let s = services(Arc::default(), Destinations::default());
    let (_, later) = recorder();
    let got = verdict_now(s.dest_judge("https://a.example/", 7, svc::DEST_RESOLVE, Some(later)));
    assert_eq!(got.value, svc::DEST_NO_HOST);
}

/// THE JUDGE A DIAL READS: the address it answers is exactly the one the judgement pinned. A name
/// pends and the pin arrives with the answer; an IP literal is its own pin and asks no resolver; a
/// refusal the name decides answers at once; an answered address the rules refuse is refused with
/// the verdict `dest.judge` gives.
#[test]
fn judge_dial_answers_the_pinned_address_the_verdict_judged() {
    let r = Arc::new(HandResolver::default());
    let s = services(Arc::clone(&r), Destinations::default());
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

/// 1.5.5's OVERRIDES, ON THE ONE JUDGE: under `security.allow_all_metadata` the metadata guard is
/// off for `dest.judge` and for the connector's dial alike (both are `judge_dial`): a metadata
/// literal is admitted and pinned, a metadata name is resolved and its metadata answer pinned.
/// RED on the judge that lifted only the denylist and kept the address guard's own metadata refusal.
/// The overrides are a provider dial's only (ARCHITECT ruling on #413): every other class refuses.
#[test]
fn allow_all_metadata_admits_metadata_on_the_dial_and_on_dest_judge() {
    let r = Arc::new(HandResolver::default());
    let s = services(
        Arc::clone(&r),
        Destinations {
            allow_all_metadata: true,
            ..Destinations::default()
        },
    );
    let imds: SocketAddr = "169.254.169.254:80".parse().unwrap();
    assert_eq!(
        s.judge_dial("169.254.169.254:80", P, Box::new(|_| {})),
        Some(Ok(imds))
    );
    for class in [0, 2, 3, 4] {
        assert_eq!(
            s.judge_dial("169.254.169.254:80", class, Box::new(|_| {})),
            Some(Err(svc::DEST_METADATA)),
            "class {class}"
        );
    }
    let (_, later) = recorder();
    let got = verdict_now(s.dest_judge(
        "https://169.254.169.254/latest",
        P,
        svc::DEST_RESOLVE,
        Some(later),
    ));
    assert_eq!(got.value, svc::DEST_ALLOWED);

    let pinned = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&pinned);
    assert!(s
        .judge_dial(
            "metadata.google.internal:80",
            P,
            Box::new(move |v| *slot.lock().unwrap() = Some(v)),
        )
        .is_none());
    let done = r.held.lock().unwrap().pop().expect("the name was resolved");
    done(Ok(vec![imds.ip()]));
    assert_eq!(*pinned.lock().unwrap(), Some(Ok(imds)));
}

/// A CARVE-OUT lifts exactly what it names: `allow_metadata_hosts: [169.254.169.254]` admits that
/// address (literal, or answered for a name) and nothing else on the list, for a provider dial;
/// every other class refuses it.
#[test]
fn a_metadata_carve_out_admits_only_what_it_names() {
    let r = Arc::new(HandResolver::default());
    let s = services(
        Arc::clone(&r),
        Destinations {
            legacy_allow: vec!["169.254.169.254".to_string()],
            ..Destinations::default()
        },
    );
    assert_eq!(
        s.judge_dial("169.254.169.254:80", P, Box::new(|_| {})),
        Some(Ok("169.254.169.254:80".parse().unwrap()))
    );
    assert_eq!(
        s.judge_dial("169.254.169.254:80", 0, Box::new(|_| {})),
        Some(Err(svc::DEST_METADATA))
    );
    assert_eq!(
        s.judge_dial("100.100.100.200:80", P, Box::new(|_| {})),
        Some(Err(svc::DEST_METADATA))
    );
    let pinned = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&pinned);
    assert!(s
        .judge_dial(
            "rebind.example:80",
            P,
            Box::new(move |v| *slot.lock().unwrap() = Some(v))
        )
        .is_none());
    let done = r.held.lock().unwrap().pop().expect("resolved");
    done(Ok(vec!["100.100.100.200".parse().unwrap()]));
    assert_eq!(*pinned.lock().unwrap(), Some(Err(svc::DEST_METADATA)));
}

/// With no override nothing changes: metadata is refused on the dial, by literal and by answer.
#[test]
fn without_an_override_metadata_stays_refused_on_the_dial() {
    let r = Arc::new(HandResolver::default());
    let s = services(Arc::clone(&r), Destinations::default());
    assert_eq!(
        s.judge_dial("169.254.169.254:80", 0, Box::new(|_| {})),
        Some(Err(svc::DEST_METADATA))
    );
    let pinned = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&pinned);
    assert!(s
        .judge_dial(
            "rebind.example:80",
            0,
            Box::new(move |v| *slot.lock().unwrap() = Some(v))
        )
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
    let s = services(
        Arc::clone(&r),
        Destinations {
            blocked: vec!["93.184.216.34".to_string()],
            ..Destinations::default()
        },
    );
    assert_eq!(
        s.judge_dial("93.184.216.34:443", 0, Box::new(|_| {})),
        Some(Err(svc::DEST_METADATA))
    );
    let pinned = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&pinned);
    assert!(s
        .judge_dial(
            "blocked.example:443",
            0,
            Box::new(move |v| *slot.lock().unwrap() = Some(v))
        )
        .is_none());
    let done = r.held.lock().unwrap().pop().expect("resolved");
    done(Ok(vec!["93.184.216.34".parse().unwrap()]));
    assert_eq!(*pinned.lock().unwrap(), Some(Err(svc::DEST_METADATA)));
}

/// ASKED TO REFUSE PRIVATE REACH AND TO EXPLAIN (ARCHITECT ruling on a plane's guard words): under a
/// deployment that does NOT block private addresses, `DEST_REFUSE_PRIVATE` refuses a private
/// literal, a loopback name and a name answering a private address all the same; with
/// `DEST_EXPLAIN` a refusal an address decided names it (a cloud-metadata answer included), a
/// failed resolution names the resolver's reason, and a refusal the name alone decided names
/// nothing. Not asked to explain, nothing is written on a refusal.
#[test]
fn dest_judge_refuses_private_reach_when_asked_and_names_what_decided_it() {
    let r = Arc::new(HandResolver::default());
    let open = Destinations {
        block_private_addresses: false,
        ..Destinations::default()
    };
    let guard = Guard::from_config(&open).expect("a valid guard");
    let s = KernelServices::new().with_dest_judge(Arc::new(GuardJudge::new(
        guard,
        Arc::clone(&r) as Arc<dyn Resolve>,
    )));
    let strict = svc::DEST_RESOLVE | svc::DEST_REFUSE_PRIVATE | svc::DEST_EXPLAIN;
    let open_web = busbar_contract::abi::host::conn::connector::EGRESS_OPEN_WEB;
    // The deployment alone admits a private literal; the caller's flag refuses it, at once.
    for (flags, want) in [
        (svc::DEST_RESOLVE, svc::DEST_ALLOWED),
        (strict, svc::DEST_INTERNAL),
    ] {
        let (_, later) = recorder();
        let got = verdict_now(s.dest_judge("https://10.0.0.7/", open_web, flags, Some(later)));
        assert_eq!(got.value, want, "flags {flags}");
    }
    let (_, later) = recorder();
    let got = verdict_now(s.dest_judge("https://localhost/", open_web, strict, Some(later)));
    assert_eq!(got.value, svc::DEST_INTERNAL, "a loopback name");
    assert!(
        got.bytes.is_empty(),
        "the name alone decided it: nothing named"
    );
    // A name answering a private address, a metadata address, and no answer at all.
    let answered = |answer: Result<Vec<std::net::IpAddr>, String>, flags: u32| {
        let (slot, later) = recorder();
        assert!(matches!(
            s.dest_judge("https://card.example/", open_web, flags, Some(later)),
            Ran::Later
        ));
        let done = r.held.lock().unwrap().pop().expect("a resolution asked");
        done(answer);
        let got = slot.lock().unwrap().take().expect("answered");
        (got.value, String::from_utf8(got.bytes).expect("text"))
    };
    let private = vec![
        "93.184.216.34".parse().unwrap(),
        "10.1.2.3".parse().unwrap(),
    ];
    assert_eq!(
        answered(Ok(private.clone()), strict),
        (svc::DEST_INTERNAL, "10.1.2.3".to_string())
    );
    assert_eq!(
        answered(Ok(private), svc::DEST_RESOLVE | svc::DEST_REFUSE_PRIVATE),
        (svc::DEST_INTERNAL, String::new()),
        "not asked to explain, nothing is named"
    );
    assert_eq!(
        answered(Ok(vec!["169.254.169.254".parse().unwrap()]), strict),
        (svc::DEST_METADATA, "169.254.169.254".to_string())
    );
    assert_eq!(
        answered(Err("no such host".to_string()), strict),
        (svc::DEST_UNRESOLVABLE, "no such host".to_string())
    );
}

/// RED (SEAM-4f): the deployment's one judge, asked for a dial a need holds a PRIVATE REACH to
/// (`DestJudge::judge_reaching`), admits a private address (a literal, and a name's private answer)
/// in the provider class, which refuses both without it; a cloud-metadata address is refused either
/// way, a reach being a host entry, never an IP one.
#[test]
fn a_private_reach_admits_a_private_address_in_its_class_and_never_metadata() {
    use busbar_kernel::host_services::DestJudge;
    let resolver = Arc::new(HandResolver::default());
    let judge = GuardJudge::new(
        Guard::from_config(&Destinations {
            block_private_addresses: true,
            ..Destinations::default()
        })
        .expect("a valid guard"),
        resolver.clone(),
    );
    let never = || -> Box<dyn FnOnce(busbar_kernel::host_services::Admitted) + Send> {
        Box::new(|_| panic!("a literal answers at once"))
    };
    let private = "http://10.1.2.3:8080";
    assert!(matches!(
        judge.judge(private, P, false, never()),
        Some(Err(_))
    ));
    let admitted = judge.judge_reaching(private, P, never());
    assert_eq!(
        admitted.expect("at once").expect("admitted").0,
        "10.1.2.3:8080".parse::<SocketAddr>().unwrap()
    );
    let metadata = "http://169.254.169.254";
    assert!(matches!(
        judge.judge_reaching(metadata, P, never()),
        Some(Err(r)) if r.verdict == svc::DEST_METADATA
    ));
    // A name whose answer is private: admitted under the reach once it resolves.
    let got = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&got);
    assert!(judge
        .judge_reaching(
            "https://agent.internal",
            P,
            Box::new(move |v| *slot.lock().unwrap() = Some(v.map(|(at, _)| at))),
        )
        .is_none());
    let done = resolver.held.lock().unwrap().pop().expect("asked once");
    done(Ok(vec!["192.168.7.9".parse().unwrap()]));
    assert_eq!(
        got.lock().unwrap().take().expect("answered").ok(),
        Some("192.168.7.9:443".parse().unwrap())
    );
}
