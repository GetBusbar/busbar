// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn clone_resets_observation_and_does_not_change_prior_generation() {
    let prior = PlaneRefreshReport::default();
    prior.begin();
    prior.record("plane", "section", 7, None);
    prior.finish();
    let next = prior.clone();
    assert_eq!(next.snapshot(), RefreshSnapshot::default());
    next.begin();
    assert_eq!(next.snapshot().phase, "observing");
    next.record("plane", "section", 7, Some(RefreshFailure::BootstrapHeld));
    let observing = next.snapshot();
    assert_eq!(observing.phase, "observing");
    assert_eq!(observing.planes[0].generation, 7);
    assert_eq!(observing.planes[0].outcome, "retained");
    assert_eq!(
        observing.restart_sections().collect::<Vec<_>>(),
        ["section"]
    );
    next.finish();
    assert_eq!(next.snapshot().phase, "observed");
    assert_eq!(prior.snapshot().planes[0].outcome, "installed");
    assert_eq!(prior.snapshot().phase, "observed");
}

#[test]
fn generic_failure_does_not_invent_a_restart_remedy() {
    let report = PlaneRefreshReport::default();
    assert_eq!(report.snapshot().phase, "unobserved");
    report.begin();
    report.record("plane", "section", 3, Some(RefreshFailure::RefreshFailed));
    report.finish();
    assert_eq!(report.snapshot().planes[0].outcome, "retained");
    assert_eq!(report.snapshot().restart_sections().count(), 0);
}
