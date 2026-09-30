// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;

use busbar_contract::abi::host::service as svc;

use super::*;

/// A kernel stand-in whose `dest.judge` answers READY, so an installed service is told apart from
/// the late refusal.
struct Judges;

impl HostServices for Judges {
    fn now(&self) -> Reading {
        Reading {
            wall_ns: 7,
            mono_ns: 7,
        }
    }
    fn dest_judge(&self, _: &str, _: u32, _: bool, _: Option<Later>) -> Ran {
        Ran::Now(Stored::ready(1))
    }
}

fn judged(s: &LateServices) -> Stored {
    match s.dest_judge("https://example.test/", 0, false, None) {
        Ran::Now(stored) => stored,
        Ran::Later => panic!("the late services never pend"),
    }
}

#[test]
fn a_service_called_before_the_install_answers_refused_and_never_panics() {
    let late = LateServices::new();
    assert_eq!(judged(&late), Stored::refused(NOT_INSTALLED));
    let a = late.now();
    let b = late.now();
    assert!(a.wall_ns > 1_600_000_000_000_000_000, "the system clock");
    assert!(b.mono_ns >= a.mono_ns);
}

#[test]
fn the_installed_services_answer_and_a_second_install_is_refused() {
    let late = LateServices::new();
    late.install(Arc::new(Judges)).expect("the first install");
    assert_eq!(
        judged(&late),
        Stored::ready(1),
        "the installed services answer"
    );
    assert_eq!(late.now().wall_ns, 7);
    assert_eq!(
        late.install(Arc::new(Judges)),
        Err(AlreadyInstalled),
        "a second install is refused"
    );
    assert!(late.is_installed());
}

fn kernel(blocked: &[&str], allow_all: bool) -> KernelServices {
    let blocked: Vec<String> = blocked.iter().map(|h| (*h).to_string()).collect();
    KernelServices::new(
        HashMap::from([(
            DEFAULT_EGRESS_CLASS,
            default_egress_rules(&blocked, &[], allow_all),
        )]),
        Arc::new(SystemResolver),
    )
}

fn verdict(s: &dyn HostServices, dest: &str, class: u32) -> Stored {
    match s.dest_judge(dest, class, false, None) {
        Ran::Now(stored) => stored,
        Ran::Later => panic!("an unresolved judgement answers at once"),
    }
}

/// The default egress class is the deployment's `security` section: the metadata denylist with the
/// operator's additions and override; a class the kernel did not map is refused.
#[test]
fn the_default_egress_class_is_the_deployments_security_stance() {
    let late = LateServices::new();
    late.install(Arc::new(kernel(&["metadata.corp.example"], false)))
        .expect("the install");
    let judged = |dest| verdict(late.as_ref(), dest, DEFAULT_EGRESS_CLASS).value;
    assert_eq!(
        judged("https://169.254.169.254/latest/meta-data/"),
        svc::DEST_METADATA
    );
    assert_eq!(
        judged("https://metadata.corp.example/"),
        svc::DEST_METADATA,
        "the operator's own addition to the denylist"
    );
    assert_eq!(judged("https://10.0.0.7/"), svc::DEST_INTERNAL);
    assert_eq!(judged("http://93.184.216.34/"), svc::DEST_ALLOWED);
    assert_eq!(
        verdict(late.as_ref(), "https://93.184.216.34/", 9).outcome,
        busbar_contract::abi::mechanism::call::Outcome::Refused,
        "an unmapped class is refused"
    );
    let open = kernel(&[], true);
    assert_eq!(
        verdict(&open, "https://169.254.169.254/", DEFAULT_EGRESS_CLASS).value,
        svc::DEST_ALLOWED,
        "allow_all_metadata turns the metadata guard off"
    );
}
