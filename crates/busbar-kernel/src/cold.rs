// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COLD MODULE (LINT-RULES LR-167): the cold code the kernel's request-path modules need,
//! called out of line: refusal text, spelled only when a request, a unit or a definition is
//! refused, and the first-sight paths that key a name once and then share it. Every fn is
//! `#[cold]` or `#[inline(never)]`; none holds a loop or sweeps request data (BP17). Each section
//! is named for the request-path module it serves.

// --- plane_driver (door, registry, serve, dispatch, slots, needs, route_tables, timing, authenticated_route) ---

/// `plane_driver::slots`: a plane's runtime slot key, `<plane_key>:runtime`, composed and leaked
/// once per plane key, on its first lookup; the caller interns it.
#[cold]
pub(crate) fn runtime_slot_key_first(plane_key: &str) -> &'static str {
    format!("{plane_key}:runtime").leak()
}

/// `plane_driver::route_tables`: a configured pool's queue-depth slot, keyed once, on its first
/// queued request.
#[cold]
pub(crate) fn first_queued_depth(
    queued: &mut foldhash::HashMap<String, u64>,
    pool: &str,
    depth: u64,
) {
    queued.insert(pool.to_owned(), depth);
}

/// `plane_driver::timing`: an attempt's start, read only when tracing enables its span (a
/// disabled span reads no clock).
#[inline(never)]
pub(crate) fn traced_start() -> std::time::Instant {
    std::time::Instant::now()
}

/// `plane_driver::timing`: the wall interval since a traced attempt's `start`, read only at a
/// boundary its enabled span records.
#[inline(never)]
pub(crate) fn traced_since(start: std::time::Instant) -> std::time::Duration {
    start.elapsed()
}

/// `plane_driver::authenticated_route`: whether a failed route lookup's deadline had passed, read
/// only to name the failure's cause (`DeadlineExceeded` or `PlanePanic`).
#[cold]
pub(crate) fn lookup_deadline_passed(
    calls: &dyn busbar_contract::plane_calls::PlaneCalls,
    deadline_ns: u64,
) -> bool {
    calls.now_ns() >= deadline_ns
}

/// `plane_driver::serve`: an audited served route's audit action (`<kind>.<verb>`) and resource
/// (`<kind>:<name>`), spelled only when the plane reports the route's write applied or rejected.
#[cold]
pub(crate) fn served_audit_names(kind: &str, verb: &str, name: &str) -> (String, String) {
    (format!("{kind}.{verb}"), format!("{kind}:{name}"))
}
