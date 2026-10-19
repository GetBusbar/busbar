// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `egress/trust/mod.rs` — the destinations seam the composition root installs with the
//! connector's one destination guard behind it.

use std::net::IpAddr;
use std::sync::Mutex;

use super::*;
use crate::host_services::{Admitted, DestRefusal};

/// A guard that records every destinations commit raised to it and judges nothing.
#[derive(Default)]
struct Recording(Mutex<Vec<Vec<String>>>);

impl DestJudge for Recording {
    fn judge_name(&self, _: &str, _: u32, _: bool) -> Result<(), u64> {
        Err(busbar_contract::abi::host::service::DEST_NO_HOST)
    }
    fn judge(
        &self,
        _: &str,
        _: u32,
        _: bool,
        _: Box<dyn FnOnce(Admitted) + Send>,
    ) -> Option<Admitted> {
        Some(Err(busbar_contract::abi::host::service::DEST_NO_HOST.into()))
    }
    fn judge_answer(&self, host: &str, _: &[IpAddr], _: u32) -> Result<(), DestRefusal> {
        Err(DestRefusal {
            verdict: busbar_contract::abi::host::service::DEST_NO_HOST,
            reason: format!("{host}: judged nothing"),
        })
    }
    fn destinations_applied(&self, d: &Destinations) {
        self.0.lock().unwrap().push(d.allow.clone());
    }
}

fn destinations(allow: &[&str]) -> Destinations {
    Destinations {
        allow: allow.iter().map(|s| (*s).to_owned()).collect(),
        ..Destinations::default()
    }
}

/// The root's capability raises every commit to the guard behind it, exactly what was committed,
/// in order; it decides nothing itself.
#[test]
fn the_guarded_seam_raises_every_commit_to_the_guard_behind_it() {
    let guard = Arc::new(Recording::default());
    let seam = GuardedEgressTrust(guard.clone());
    seam.destinations_applied(&destinations(&["10.0.0.0/8"]));
    seam.destinations_applied(&destinations(&[]));
    assert_eq!(
        *guard.0.lock().unwrap(),
        vec![vec!["10.0.0.0/8".to_owned()], Vec::new()]
    );
}

/// The pass-through has no guard behind it: a commit raised to it is heard by nobody, and the
/// install reads back the capability the composition root installed (first install wins).
#[test]
fn the_composition_root_install_hands_the_installed_capability_back() {
    const MARK: &str = "commit-raised-by-the-install-test.internal";
    PassThroughEgressTrust.destinations_applied(&destinations(&[MARK]));
    let guard = Arc::new(Recording::default());
    install_egress_trust_host(Arc::new(GuardedEgressTrust(guard.clone())));
    assert!(egress_trust_host().is_some(), "the install reads back");
    destinations_applied(&destinations(&[MARK]));
    // This test binary's one install is this one (nothing else in the kernel's suite installs the
    // seam), so the commit reached the guard behind it. Other tests' config commits may reach it
    // too, so the assertion looks for this one by its mark.
    assert!(
        guard.0.lock().unwrap().contains(&vec![MARK.to_owned()]),
        "the commit reached the installed guard"
    );
}
