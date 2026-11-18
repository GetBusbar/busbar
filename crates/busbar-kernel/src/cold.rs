// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COLD MODULE (LINT-RULES LR-167): the cold code the kernel's request-path modules need,
//! called out of line: refusal text, spelled only when a request, a unit or a definition is
//! refused, and the first-sight paths that key a name once and then share it. Every fn is
//! `#[cold]` or `#[inline(never)]`; none holds a loop or sweeps request data (BP17). Each section
//! is named for the request-path module it serves.

// --- hooks::text_cut ---

/// `hooks::text_cut`: a plugin's name, keyed once on its first cut text and shared from then on.
#[cold]
pub(crate) fn first_text_cut(
    warned: &mut foldhash::HashMap<std::sync::Arc<str>, u8>,
    plugin: &str,
    bits: u8,
) -> std::sync::Arc<str> {
    let name: std::sync::Arc<str> = std::sync::Arc::from(plugin);
    warned.insert(std::sync::Arc::clone(&name), bits);
    name
}

// Sections as submodules (cold/<section>.rs), so the slices that fill them do not collide.
pub(crate) mod auth;
pub(crate) mod far_end;
pub(crate) mod governance;
pub(crate) mod host;
// --- plane_driver::far_end ---

/// `plane_driver::far_end`: a provider's credential refusal, keyed once, on its first refusal.
#[cold]
pub(crate) fn far_end_first_refusal(
    last: &mut foldhash::HashMap<String, busbar_contract::conn::ConnError>,
    provider: &str,
    err: busbar_contract::conn::ConnError,
) {
    last.insert(provider.to_owned(), err);
}

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

// --- plane_driver ---

impl crate::plane_driver::DriverConfig {
    /// The status a refusal renders under: the plane's own row for its dialect and reason, else its
    /// any-dialect row, else the kernel's choice. Looked up only when a unit is refused.
    #[cold]
    pub fn status(&self, dialect: u32, reason: busbar_contract::caps::ReasonCode) -> u32 {
        use busbar_contract::abi::plane::{reason_code, REFUSAL_ANY_DIALECT};
        let code = reason_code(reason);
        let row = |d: u32| {
            self.refusal_statuses
                .iter()
                .find(|r| r.dialect == d && r.reason == code)
                .map(|r| r.status)
        };
        row(dialect)
            .or_else(|| row(REFUSAL_ANY_DIALECT))
            .unwrap_or_else(|| (self.status_of)(reason))
    }
}

/// `plane_driver`: the audit resource of a settled unit whose provider's final usage went unbilled.
#[cold]
pub(crate) fn usage_unread_resource(unit: u64, reason: &str) -> String {
    format!("unit:{unit} reason:{reason}")
}

/// `plane_driver`: one span of a plane's arena, copied out once into a rendered refusal's (or a
/// catalog's) owned head; a span outside the arena is empty.
#[inline(never)]
pub(crate) fn rendered_span(
    arena: &[u8],
    s: busbar_contract::abi::mechanism::call::Span,
) -> Vec<u8> {
    let start = s.offset as usize;
    arena
        .get(start..start.saturating_add(s.len as usize))
        .unwrap_or_default()
        .to_vec()
}

/// `plane_driver`: bytes as owned text, lossily, for the DEBUG `request finished` summary only.
#[cold]
pub(crate) fn lossy_owned(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `plane_driver`: a rendered refusal's body as the frame its encode answers with.
#[cold]
pub(crate) fn refusal_frame(body: &[u8]) -> std::sync::Arc<[u8]> {
    std::sync::Arc::from(body)
}

// --- plane_driver::port_hooks ---

/// `plane_driver::port_hooks`: a route-policy rejection counter's `status` label, spelled once per
/// decider and status, on that status's first rejection (the counter is kept from then on).
#[cold]
pub(crate) fn route_policy_status_label(status: u16) -> String {
    format!("{status}")
}

// --- plane_driver::money ---

/// `plane_driver::money::native_admission`: a refused selected startup transfer, as the text the
/// response confirmation reports.
#[cold]
pub(crate) fn selected_startup_refusal(error: &impl std::fmt::Debug) -> String {
    format!("selected startup terminal transfer refused: {error:?}")
}

// --- plane_driver::port_auth, plane_driver::port_serve ---

/// `plane_driver::port_auth::plain_refusal`: core's own rendering of a refusal (the status, its
/// text as `text/plain`, the end), spelled only when the plane cannot render it.
#[cold]
pub(crate) fn plain_refusal_items(
    refusal: &crate::refusal::ClientRefusal,
) -> Vec<crate::plane_driver::port_session::ToClient> {
    use crate::plane_driver::port_session::ToClient;
    vec![
        ToClient::Head {
            status: refusal.status,
            fields: vec![(
                b"content-type".to_vec(),
                b"text/plain; charset=utf-8".to_vec(),
            )],
        },
        ToClient::Body(refusal.text.as_bytes().to_vec()),
        ToClient::End,
    ]
}

/// `plane_driver::port_serve`: the `retry-after` field an exhausted session's refusal head gets.
#[cold]
pub(crate) fn retry_after_field(name: &[u8], wait: u32) -> (Vec<u8>, Vec<u8>) {
    (name.to_vec(), format!("{wait}").into_bytes())
}
