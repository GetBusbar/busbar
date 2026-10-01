// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE DIAL JUDGE: the kernel's judge behind `DialJudge`, one rule set per egress class, the
//! node's own ports held off a loopback-allowed need.

use super::*;

// ── U2: THE KERNEL JUDGE BEHIND `DialJudge`, ONE RULE SET PER EGRESS CLASS ──

use busbar_contract::abi::host::service::{DEST_INTERNAL, DEST_METADATA};

/// The node's own data port, as `own_ports` would read it off `listen`.
const OWN: u16 = 18_080;

/// The process's judge over the deployment's rules: `blocked` an operator addition, `allowed` a
/// carve-out.
fn process_judge(blocked: &[&str], allowed: &[&str]) -> Arc<dyn DialJudge> {
    let owned = |l: &[&str]| l.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    judge(
        Arc::new(services(&owned(blocked), &owned(allowed), false)),
        &[OWN],
    )
}

/// Judge `dest` under `class`, answering at once (a literal, or a refusal the name decides).
fn now(j: &Arc<dyn DialJudge>, dest: &str, class: u32) -> Result<SocketAddr, Verdict> {
    j.judge_dial(dest, class, Box::new(|_| panic!("a literal never pends")))
        .expect("answered at once")
}

const CLASSES: [u32; 5] = [
    EGRESS_DEFAULT,
    EGRESS_PROVIDER,
    EGRESS_OPERATOR_INFRASTRUCTURE,
    EGRESS_OPEN_WEB,
    EGRESS_LOOPBACK_ALLOWED,
];

/// RED: every egress class a need may declare has its rules in the one judge: a public address is
/// judged and pinned under each, never refused as naming no usable host (the kernel's answer
/// for a class it holds no rules for).
#[test]
fn every_egress_class_is_judged_under_its_own_rules() {
    let j = process_judge(&[], &[]);
    for class in CLASSES {
        assert_eq!(
            now(&j, "93.184.216.34:443", class),
            Ok("93.184.216.34:443".parse().unwrap()),
            "class {class} judges a public address"
        );
    }
}

/// RED: the default class and `provider` refuse a host the operator blocked; an operator's
/// carve-out holds for them (1.5.5's provider posture), and private targets dial.
#[test]
fn provider_and_default_keep_the_deployments_metadata_rules() {
    let j = process_judge(&["imds.corp.example"], &[]);
    for class in [EGRESS_DEFAULT, EGRESS_PROVIDER] {
        assert_eq!(now(&j, "imds.corp.example:80", class), Err(DEST_METADATA));
        assert!(now(&j, "10.0.0.5:8000", class).is_ok(), "class {class}");
    }
}

/// RED: operator-infrastructure dials private and loopback targets, and refuses the cloud
/// metadata address even where the deployment carved it out for the provider class.
#[test]
fn operator_infrastructure_refuses_metadata_whatever_the_carve_outs() {
    let j = process_judge(&[], &["169.254.169.254"]);
    let c = EGRESS_OPERATOR_INFRASTRUCTURE;
    assert!(now(&j, "10.0.0.5:5432", c).is_ok());
    assert!(now(&j, "127.0.0.1:6379", c).is_ok());
    assert_eq!(now(&j, "169.254.169.254:80", c), Err(DEST_METADATA));
}

/// RED: open-web judges public destinations only: a private address, a loopback one and the
/// loopback name are refused as internal, before any resolution.
#[test]
fn open_web_refuses_private_and_loopback_destinations() {
    let j = process_judge(&[], &[]);
    let c = EGRESS_OPEN_WEB;
    assert_eq!(now(&j, "10.0.0.5:443", c), Err(DEST_INTERNAL));
    assert_eq!(now(&j, "127.0.0.1:443", c), Err(DEST_INTERNAL));
    assert_eq!(now(&j, "localhost:443", c), Err(DEST_INTERNAL));
}

/// RED: loopback-allowed dials loopback, but never the node's own ports, answered at once for a
/// literal and after resolution for a name.
#[test]
fn loopback_allowed_refuses_the_nodes_own_ports() {
    let j = process_judge(&[], &[]);
    let c = EGRESS_LOOPBACK_ALLOWED;
    assert!(now(&j, "127.0.0.1:4318", c).is_ok());
    assert_eq!(now(&j, &format!("127.0.0.1:{OWN}"), c), Err(DEST_INTERNAL));
    assert_eq!(now(&j, &format!("[::1]:{OWN}"), c), Err(DEST_INTERNAL));
    // Another class may name that port: the rule is loopback-allowed's.
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
    rx.recv_timeout(std::time::Duration::from_secs(10))
        .expect("the judgement answered")
}

/// RED: a hostname is resolved and pinned by the kernel's judge, inside the judgement, and the
/// connector is handed the pinned address (no path regresses from "hostname refused" to
/// "hostname dialled" without a judgement).
#[test]
fn a_hostname_is_resolved_and_pinned_by_the_kernel_judge() {
    let j = process_judge(&[], &[]);
    let at = pended(&j, "localhost:5432", EGRESS_OPERATOR_INFRASTRUCTURE).expect("pinned");
    assert!(at.ip().is_loopback());
    assert_eq!(at.port(), 5432);
}

#[test]
fn the_nodes_own_ports_are_read_off_its_listen_addresses() {
    assert_eq!(
        own_ports(&["0.0.0.0:8080", "127.0.0.1:8081", "[::1]:9", "nowhere"]),
        vec![8080, 8081, 9]
    );
}
