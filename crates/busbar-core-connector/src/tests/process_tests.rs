// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE DIAL JUDGE: the deployment's one guard behind `DialJudge` and the kernel's `DestJudge`,

use std::time::Duration;

use super::*;

use busbar_contract::abi::host::conn::connector::{
    EGRESS_DEFAULT, EGRESS_OPERATOR_INFRASTRUCTURE, EGRESS_PROVIDER,
};
use busbar_contract::abi::host::service::DEST_METADATA;

use crate::guard::Resolved;

/// The node's own data port, as `own_ports` would read it off `listen`.
const OWN: u16 = 18_080;

const CLASSES: [u32; 5] = [
    EGRESS_DEFAULT,
    EGRESS_PROVIDER,
    EGRESS_OPERATOR_INFRASTRUCTURE,
    EGRESS_OPEN_WEB,
    EGRESS_LOOPBACK_ALLOWED,
];

/// A resolver answering from a fixed table, off the caller's thread.
struct Table(Vec<(&'static str, IpAddr)>);

impl Resolve for Table {
    fn resolve(&self, host: &str, done: Resolved) {
        let answer: Vec<IpAddr> = self
            .0
            .iter()
            .filter(|(n, _)| *n == host)
            .map(|(_, a)| *a)
            .collect();
        std::thread::spawn(move || {
            done(if answer.is_empty() {
                Err("NXDOMAIN".into())
            } else {
                Ok(answer)
            });
        });
    }
}

/// The deployment's judge over `allow` (block on), resolving `names`.
fn guard_judge(allow: &[&str], names: Vec<(&'static str, IpAddr)>) -> Arc<GuardJudge> {
    let d = Destinations {
        block_private_addresses: true,
        allow: allow.iter().map(|s| (*s).to_owned()).collect(),
        ..Destinations::default()
    };
    Arc::new(GuardJudge::new(
        Guard::from_config(&d).expect("valid"),
        Arc::new(Table(names)),
    ))
}

fn process_judge(allow: &[&str], names: Vec<(&'static str, IpAddr)>) -> Arc<dyn DialJudge> {
    judge(guard_judge(allow, names), &[OWN])
}

/// Judge `dest` under `class`, answering at once (a literal, or a refusal the name decides).
fn now(j: &Arc<dyn DialJudge>, dest: &str, class: u32) -> Result<SocketAddr, Verdict> {
    j.judge_dial(dest, class, Box::new(|_| panic!("a literal never pends")))
        .expect("answered at once")
}

/// Judge a name that must resolve: `None` at once, the pin or the refusal later.
fn pended(j: &Arc<dyn DialJudge>, dest: &str, class: u32) -> Result<SocketAddr, Verdict> {
    let (tx, rx) = std::sync::mpsc::channel();
    let at_once = j.judge_dial(
        dest,
        class,
        Box::new(move |v| {
            let _ = tx.send(v);
        }),
    );
    assert_eq!(at_once, None, "a name resolves off the caller's thread");
    rx.recv_timeout(Duration::from_secs(10))
        .expect("the judgement answered")
}

/// Every egress class a need may declare is judged by the one guard: a public address is judged

#[test]
fn every_egress_class_is_judged_by_the_one_guard() {
    let j = process_judge(&[], vec![]);
    for class in CLASSES {
        assert_eq!(
            now(&j, "93.184.216.34:443", class),
            Ok("93.184.216.34:443".parse().unwrap()),
            "class {class} judges a public address"
        );
    }
}

/// RED: under the default, the provider class and a request-data class (the default class,

#[test]
fn a_private_address_is_refused_for_providers_and_request_data_unless_allowlisted() {
    let strict = process_judge(&[], vec![]);
    let allowed = process_judge(&["10.0.0.0/8", "127.0.0.1"], vec![]);
    for class in crate::guard::PRIVATE_REFUSED_IN.iter().copied() {
        assert_eq!(
            now(&strict, "10.0.0.5:5432", class),
            Err(DEST_INTERNAL),
            "{class}"
        );
        assert_eq!(
            now(&strict, "127.0.0.1:6379", class),
            Err(DEST_INTERNAL),
            "{class}"
        );
        assert_eq!(
            now(&strict, "localhost:443", class),
            Err(DEST_INTERNAL),
            "{class}"
        );
        assert!(now(&allowed, "10.0.0.5:5432", class).is_ok(), "{class}");
        assert!(now(&allowed, "127.0.0.1:6379", class).is_ok(), "{class}");
    }
    let class = EGRESS_OPERATOR_INFRASTRUCTURE;
    assert!(now(&strict, "10.0.0.5:5432", class).is_ok(), "{class}");
    assert!(now(&strict, "127.0.0.1:6379", class).is_ok(), "{class}");
    for class in CLASSES {
        assert_eq!(
            now(&allowed, "169.254.169.254:80", class),
            Err(DEST_METADATA),
            "{class}"
        );
    }
}

/// RED: a name resolving to loopback is refused after its one resolution, before any socket; the

#[test]
fn a_name_resolving_to_loopback_is_refused_until_allowlisted() {
    let names = || vec![("db.internal", IpAddr::from([127, 0, 0, 1]))];
    let strict = process_judge(&[], names());
    assert_eq!(
        pended(&strict, "db.internal:5432", EGRESS_DEFAULT),
        Err(DEST_INTERNAL)
    );
    let allowed = process_judge(&["db.internal"], names());
    assert_eq!(
        pended(&allowed, "db.internal:5432", EGRESS_DEFAULT),
        Ok("127.0.0.1:5432".parse().unwrap())
    );
    assert_eq!(
        pended(&strict, "nowhere.test:1", EGRESS_PROVIDER),
        Err(DEST_UNRESOLVABLE)
    );
}

/// Loopback-allowed (its loopback allowlisted) dials loopback, but never the node's own ports,

#[test]
fn loopback_allowed_refuses_the_nodes_own_ports() {
    let names = vec![("localhost", IpAddr::from([127, 0, 0, 1]))];
    let j = process_judge(&["127.0.0.1", "::1", "localhost"], names);
    let c = EGRESS_LOOPBACK_ALLOWED;
    assert!(now(&j, "127.0.0.1:4318", c).is_ok());
    assert_eq!(now(&j, &format!("127.0.0.1:{OWN}"), c), Err(DEST_INTERNAL));
    assert_eq!(now(&j, &format!("[::1]:{OWN}"), c), Err(DEST_INTERNAL));

    assert!(now(
        &j,
        &format!("127.0.0.1:{OWN}"),
        EGRESS_OPERATOR_INFRASTRUCTURE
    )
    .is_ok());
    assert_eq!(
        pended(&j, &format!("localhost:{OWN}"), c),
        Err(DEST_INTERNAL)
    );
}

/// `dest.judge`'s arms through the same judge: a URL's scheme by class (open-web secure only,

#[test]
fn the_kernel_asks_the_same_judge() {
    let j = guard_judge(&["127.0.0.1", "10.1.2.3"], vec![]);
    assert_eq!(
        j.judge_name("http://93.184.216.34/x", EGRESS_OPEN_WEB, false),
        Err(DEST_PLAINTEXT)
    );
    assert_eq!(
        j.judge_name("http://93.184.216.34/x", EGRESS_DEFAULT, false),
        Ok(())
    );
    assert_eq!(
        j.judge_name("http://10.1.2.3/x", EGRESS_LOOPBACK_ALLOWED, false),
        Err(DEST_PLAINTEXT)
    );
    assert_eq!(
        j.judge_name("http://127.0.0.1:9/x", EGRESS_LOOPBACK_ALLOWED, false),
        Ok(())
    );
    assert_eq!(
        j.judge_name("ftp://93.184.216.34/", 0, false),
        Err(DEST_SCHEME)
    );
    assert_eq!(
        j.judge_name("https://u:p@93.184.216.34/", 0, false),
        Err(DEST_NO_HOST)
    );
    assert_eq!(
        j.judge_name("https://10.0.0.5/", 0, false),
        Err(DEST_INTERNAL)
    );
    let r = j
        .judge_answer("api.test", &["10.9.9.9".parse().unwrap()], EGRESS_DEFAULT)
        .unwrap_err();
    assert_eq!(r.verdict, DEST_INTERNAL);
    assert!(r.reason.contains("advanced.allow_destinations"), "{r}");
}

#[test]
fn the_nodes_own_ports_are_read_off_its_listen_addresses() {
    assert_eq!(
        own_ports(&["0.0.0.0:8080", "127.0.0.1:8081", "[::1]:9", "nowhere"]),
        vec![8080, 8081, 9]
    );
}

#[test]
fn recovered_listener_ports_replace_the_base_ports_for_immediate_judgements() {
    let j = process_judge(&["127.0.0.1", "::1"], vec![]);
    let class = EGRESS_LOOPBACK_ALLOWED;
    j.own_ports_applied(&own_ports(&["0.0.0.0:19080", "[::1]:19081"]));
    assert!(now(&j, &format!("127.0.0.1:{OWN}"), class).is_ok());
    for destination in ["127.0.0.1:19080", "[::1]:19081"] {
        assert_eq!(now(&j, destination, class), Err(DEST_INTERNAL));
    }
}

#[derive(Default)]
struct HeldResolution(std::sync::Mutex<Option<crate::guard::Resolved>>);

impl Resolve for HeldResolution {
    fn resolve(&self, _: &str, done: crate::guard::Resolved) {
        assert!(self.0.lock().unwrap().replace(done).is_none());
    }
}

#[test]
fn a_resolution_already_pending_uses_recovered_ports_and_calls_back_without_the_lock() {
    for (port, refused) in [(OWN, false), (19080, true), (19081, true)] {
        let resolver = Arc::new(HeldResolution::default());
        let destinations = Destinations {
            allow: vec!["localhost".into()],
            ..Destinations::default()
        };
        let j = judge(
            Arc::new(GuardJudge::new(
                Guard::from_config(&destinations).unwrap(),
                resolver.clone(),
            )),
            &[OWN],
        );
        let (tx, rx) = std::sync::mpsc::channel();
        let reentrant = Arc::clone(&j);
        assert_eq!(
            j.judge_dial_all(
                &format!("localhost:{port}"),
                EGRESS_LOOPBACK_ALLOWED,
                false,
                Box::new(move |answer, also| {
                    reentrant.own_ports_applied(&[19080, 19081]);
                    tx.send((answer, also)).unwrap();
                }),
            ),
            None
        );
        j.own_ports_applied(&[19080, 19081]);
        let done = resolver.0.lock().unwrap().take().unwrap();
        done(Ok(vec![
            "127.0.0.1".parse().unwrap(),
            "::1".parse().unwrap(),
        ]));
        let (answer, also) = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        if refused {
            assert_eq!(answer, Err(DEST_INTERNAL));
            assert!(also.is_empty(), "alternate loopback pins are protected too");
        } else {
            assert_eq!(answer, Ok(SocketAddr::from(([127, 0, 0, 1], OWN))));
            assert_eq!(also, vec![format!("[::1]:{OWN}").parse().unwrap()]);
        }
    }
}

/// A resolver recording every name it is asked, answering from a fixed table off the caller's
/// thread.
#[derive(Default)]
struct Asked {
    names: std::sync::Mutex<Vec<String>>,
    table: Vec<(&'static str, IpAddr)>,
}

impl Resolve for Asked {
    fn resolve(&self, host: &str, done: Resolved) {
        self.names.lock().unwrap().push(host.to_owned());
        Table(self.table.clone()).resolve(host, done);
    }
}

/// An IDN name 1.5.5 dialled: a bare non-ASCII name the guard admitted is resolved as its

#[test]
fn an_idn_name_is_resolved_as_its_punycode_name() {
    let public: IpAddr = "93.184.216.34".parse().unwrap();
    let asked = Arc::new(Asked {
        table: vec![
            ("xn--bcher-kva.example", public),
            ("Api.Example.COM", public),
        ],
        ..Asked::default()
    });
    let judge = judge(
        Arc::new(GuardJudge::new(
            Guard::default(),
            Arc::clone(&asked) as Arc<dyn Resolve>,
        )),
        &[OWN],
    );
    for (dest, name) in [
        ("b\u{fc}cher.example:443", "xn--bcher-kva.example"),
        ("B\u{dc}CHER.example:443", "xn--bcher-kva.example"),
        ("https://b\u{fc}cher.example/", "xn--bcher-kva.example"),
        ("Api.Example.COM:443", "Api.Example.COM"),
    ] {
        asked.names.lock().unwrap().clear();
        assert_eq!(
            pended(&judge, dest, EGRESS_PROVIDER),
            Ok(SocketAddr::new(public, 443)),
            "{dest}"
        );
        assert_eq!(
            *asked.names.lock().unwrap(),
            vec![name.to_owned()],
            "{dest}"
        );
    }
}
