// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The inbound host-capability seam: default grants nothing; a host grants a capability by overriding
//! its method; and the seam stays neutral (opaque bytes in, opaque bytes out).

use super::*;

/// A host that grants nothing (the default surface) — every capability is `NotGranted`.
struct UngrantedHost;
impl PlaneHost for UngrantedHost {}

/// A host that grants exactly one capability (`metrics_emit`), echoing the opaque request back.
struct MetricsOnlyHost;
impl PlaneHost for MetricsOnlyHost {
    fn metrics_emit(&self, req: &[u8]) -> HostCallResult {
        Ok(req.to_vec())
    }
}

#[test]
fn the_default_host_grants_no_capability() {
    let h = UngrantedHost;
    assert_eq!(h.govern_admit(b"x"), Err(HostCallError::NotGranted));
    assert_eq!(h.meter_charge(b"x"), Err(HostCallError::NotGranted));
    assert_eq!(h.journal_append(b"x"), Err(HostCallError::NotGranted));
    assert_eq!(h.egress_open(b"x"), Err(HostCallError::NotGranted));
    assert_eq!(h.metrics_emit(b"x"), Err(HostCallError::NotGranted));
    assert_eq!(h.clock_now(b"x"), Err(HostCallError::NotGranted));
}

#[test]
fn granting_a_capability_means_overriding_its_method_and_nothing_else_leaks_through() {
    let h = MetricsOnlyHost;
    // The one granted capability responds...
    assert_eq!(h.metrics_emit(b"hello"), Ok(b"hello".to_vec()));
    // ...and every other capability stays not-granted (absent = not granted).
    assert_eq!(h.govern_admit(b"hello"), Err(HostCallError::NotGranted));
    assert_eq!(h.egress_open(b"hello"), Err(HostCallError::NotGranted));
}

#[test]
fn the_seam_is_neutral_opaque_bytes_in_opaque_bytes_out() {
    // The host never interprets the plane's payload; it routes by capability and returns bytes.
    let h = MetricsOnlyHost;
    let opaque = &[0u8, 255, 7, 42];
    assert_eq!(h.metrics_emit(opaque), Ok(opaque.to_vec()));
}

#[test]
fn a_host_can_be_used_behind_a_dyn_reference() {
    // A plane holds `&dyn PlaneHost` (or Arc<dyn PlaneHost>) — object safety is required.
    let h: &dyn PlaneHost = &UngrantedHost;
    assert_eq!(h.tasks_op(b""), Err(HostCallError::NotGranted));
}
