// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Destination matrices against the actual connector guard and host dispatcher.
use busbar_contract::abi::host::conn::connector::{
    EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::abi::host::service::{
    DEST_ALLOWED, DEST_EXPLAIN, DEST_INTERNAL, DEST_METADATA, DEST_NO_HOST, DEST_OBFUSCATED,
    DEST_PLAINTEXT, DEST_REFUSE_PRIVATE, DEST_RESOLVE, DEST_SCHEME, DEST_UNRESOLVABLE,
};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::net::METADATA_HOSTS;
use busbar_contract::services::{HostServices, Later, Ran, Stored};
use busbar_core_connector::guard::{Guard, Resolve, Resolved};
use busbar_core_connector::process::GuardJudge;
use busbar_kernel::host_services::KernelServices as Host;
use std::sync::{mpsc, Arc};
use std::time::Duration;
const UNTICKETED: &str = "a service that may pend is callable only inside a ticketed op";
// Only the external resolver is controlled; all policy and host answers are production.
struct Names;
impl Resolve for Names {
    fn resolve(&self, host: &str, done: Resolved) {
        let answer = match host {
            "vendor.example" => Ok(vec![
                "93.184.215.14".parse().unwrap(),
                "1.1.1.1".parse().unwrap(),
            ]),
            "inner.example" => Ok(vec!["10.1.2.3".parse().unwrap()]),
            "empty.example" => Ok(vec![]),
            _ => Err("NXDOMAIN".into()),
        };
        std::thread::spawn(move || done(answer));
    }
}
fn host() -> Host {
    Host::new().with_dest_judge(Arc::new(GuardJudge::new(Guard::default(), Arc::new(Names))))
}
fn later() -> (Later, mpsc::Receiver<Stored>) {
    let (tx, rx) = mpsc::channel();
    (
        Box::new(move |s| {
            let _ = tx.send(s);
        }),
        rx,
    )
}

fn answer(r: Ran, rx: &mpsc::Receiver<Stored>) -> Stored {
    match r {
        Ran::Now(s) => s,
        Ran::Later => rx
            .recv_timeout(Duration::from_secs(10))
            .expect("a pended service answers"),
    }
}

fn judged(h: &Host, dest: &str, class: u32, flags: u32) -> Stored {
    match h.dest_judge(dest, class, flags, None) {
        Ran::Now(s) => s,
        Ran::Later => panic!("`{dest}`: a ticket-less judgement pended"),
    }
}

fn keys(s: &Stored) -> Vec<String> {
    s.spans
        .iter()
        .map(|sp| {
            let (at, len) = (sp.key.offset as usize, sp.key.len as usize);
            String::from_utf8_lossy(&s.bytes[at..at + len]).into_owned()
        })
        .collect()
}

#[test]
fn dest_judge_answers_the_owner_default_guard_without_resolving() {
    let h = host();
    let metadata = format!("https://{}/", METADATA_HOSTS[0]);
    let open = EGRESS_OPEN_WEB;
    let infra = EGRESS_OPERATOR_INFRASTRUCTURE;
    let strict = DEST_REFUSE_PRIVATE | DEST_EXPLAIN;
    for (dest, class, flags, verdict) in [
        ("https://vendor.example/agent", open, strict, DEST_ALLOWED),
        (
            "https://vendor.example/agent",
            infra,
            DEST_EXPLAIN,
            DEST_ALLOWED,
        ),
        ("HTTPS://vendor.example/", open, 0, DEST_ALLOWED),
        ("vendor.example:8443", open, 0, DEST_ALLOWED),
        ("http://vendor.example/", open, 0, DEST_PLAINTEXT),
        ("http://vendor.example/", infra, 0, DEST_ALLOWED),
        ("ftp://vendor.example/", open, 0, DEST_SCHEME),
        ("https://user@vendor.example/", open, 0, DEST_NO_HOST),
        ("", open, 0, DEST_NO_HOST),
        (
            "https://vendor.example/",
            EGRESS_LOOPBACK_ALLOWED + 1,
            0,
            DEST_NO_HOST,
        ),
        (metadata.as_str(), infra, 0, DEST_METADATA),
        ("https://169.254.169.254/latest", infra, 0, DEST_METADATA),
        ("https://10.0.0.7/", open, 0, DEST_INTERNAL),
        ("https://10.0.0.7/", infra, 0, DEST_ALLOWED),
        (
            "https://10.0.0.7/",
            infra,
            DEST_REFUSE_PRIVATE,
            DEST_INTERNAL,
        ),
        (
            "https://127.0.0.1/",
            EGRESS_LOOPBACK_ALLOWED,
            0,
            DEST_ALLOWED,
        ),
        (
            "http://127.0.0.1/",
            EGRESS_LOOPBACK_ALLOWED,
            0,
            DEST_ALLOWED,
        ),
        (
            "http://1.1.1.1/",
            EGRESS_LOOPBACK_ALLOWED,
            0,
            DEST_PLAINTEXT,
        ),
        (
            "https://10.0.0.7/",
            EGRESS_LOOPBACK_ALLOWED,
            0,
            DEST_INTERNAL,
        ),
        ("https://localhost/", open, 0, DEST_INTERNAL),
        ("https://localhost/", infra, 0, DEST_ALLOWED),
        ("https://0x7f000001/", open, 0, DEST_OBFUSCATED),
    ] {
        let s = judged(&h, dest, class, flags);
        assert_eq!(
            (s.outcome, s.value),
            (Outcome::Ready, verdict),
            "`{dest}` under class {class}, flags {flags}: {s:?}"
        );

        assert!(s.bytes.is_empty() && s.spans.is_empty(), "`{dest}`: {s:?}");
    }
}

#[test]
fn dest_judge_resolves_through_the_stated_answers_and_writes_what_it_judged() {
    let h = host();

    let (l, rx) = later();
    let s = answer(
        h.dest_judge("https://1.1.1.1/", EGRESS_OPEN_WEB, DEST_RESOLVE, Some(l)),
        &rx,
    );
    assert_eq!(
        (s.outcome, s.value),
        (Outcome::Ready, DEST_ALLOWED),
        "{s:?}"
    );
    assert_eq!(keys(&s), ["1.1.1.1"]);

    for dest in ["https://vendor.example/", "https://1.1.1.1/"] {
        let s = judged(&h, dest, EGRESS_OPEN_WEB, DEST_RESOLVE);
        assert_eq!(
            (s.outcome, s.error),
            (Outcome::Refused, UNTICKETED),
            "`{dest}`: {s:?}"
        );
    }

    let s = judged(&h, "https://localhost/", EGRESS_OPEN_WEB, DEST_RESOLVE);
    assert_eq!(
        (s.outcome, s.value),
        (Outcome::Ready, DEST_INTERNAL),
        "{s:?}"
    );
    for (dest, flags, verdict, written) in [
        (
            "https://vendor.example/",
            DEST_RESOLVE,
            DEST_ALLOWED,
            vec!["93.184.215.14", "1.1.1.1"],
        ),
        (
            "https://inner.example/",
            DEST_RESOLVE | DEST_EXPLAIN,
            DEST_INTERNAL,
            vec!["10.1.2.3"],
        ),
        (
            "https://inner.example/",
            DEST_RESOLVE,
            DEST_INTERNAL,
            vec![],
        ),
        (
            "https://empty.example/",
            DEST_RESOLVE,
            busbar_contract::abi::host::service::DEST_NO_ADDRESSES,
            vec![],
        ),
        (
            "https://unknown.example/",
            DEST_RESOLVE,
            DEST_UNRESOLVABLE,
            vec![],
        ),
    ] {
        let (l, rx) = later();
        let s = answer(h.dest_judge(dest, EGRESS_OPEN_WEB, flags, Some(l)), &rx);
        assert_eq!(
            (s.outcome, s.value),
            (Outcome::Ready, verdict),
            "`{dest}`: {s:?}"
        );
        assert_eq!(keys(&s), written, "`{dest}`: {s:?}");
    }
}
