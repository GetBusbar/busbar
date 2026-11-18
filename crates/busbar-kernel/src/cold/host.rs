// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! The host section: cold code for every busbar-kernel request-path module outside auth/.

// --- host_services: refusal text and rare first-sight paths of crate::host_services ---

/// A destination guard's refusal sentence for `host` (`DestJudge::judge_host`).
#[cold]
pub(crate) fn services_host_refused(host: &str) -> String {
    format!("host `{host}` was refused by the destination guard")
}

/// An admission refused: the instance declares a kernel-reserved record kind.
#[cold]
pub(crate) fn services_kind_reserved(
    instance: &str,
    kind: &str,
) -> crate::host_services::AdmitRefused {
    crate::host_services::AdmitRefused::KindReserved {
        instance: instance.to_owned(),
        kind: kind.to_owned(),
    }
}

/// An admission refused: a cold record bootstrap grant holds the instance.
#[cold]
pub(crate) fn services_bootstrap_held(instance: &str) -> crate::host_services::AdmitRefused {
    crate::host_services::AdmitRefused::BootstrapHeld {
        instance: instance.to_owned(),
    }
}

/// An admission refused: another instance holds the signing domain.
#[cold]
pub(crate) fn services_domain_held(
    domain: &str,
    held_by: &str,
    asked_by: &str,
) -> crate::host_services::AdmitRefused {
    crate::host_services::AdmitRefused::DomainHeld {
        domain: domain.to_owned(),
        held_by: held_by.to_owned(),
        asked_by: asked_by.to_owned(),
    }
}

/// An admission refused: an admitted instance tried to change its ticket prefix.
#[cold]
pub(crate) fn services_ticket_prefix_changed(
    instance: &str,
    prefix: &str,
) -> crate::host_services::AdmitRefused {
    crate::host_services::AdmitRefused::TicketPrefixChanged {
        instance: instance.to_owned(),
        prefix: prefix.to_owned(),
    }
}

/// An admission refused: another instance holds the ticket prefix.
#[cold]
pub(crate) fn services_ticket_prefix_held(
    prefix: &str,
    held_by: &str,
    asked_by: &str,
) -> crate::host_services::AdmitRefused {
    crate::host_services::AdmitRefused::TicketPrefixHeld {
        prefix: prefix.to_owned(),
        held_by: held_by.to_owned(),
        asked_by: asked_by.to_owned(),
    }
}

/// A demotion row's key: spelled for an admission replay, an operator trust decision, or a
/// sighting that changes trust state (`crate::host_services::demotion_key`).
#[cold]
pub(crate) fn services_demotion_key(instance: &str, counterparty: &str) -> String {
    format!(
        "{instance}{}{counterparty}",
        crate::host_services::DEMOTION_SEP
    )
}

/// An opened instance's caller-binding store handle, bound once, at its first session.
#[cold]
pub(crate) fn services_caller_rows(
    store: std::sync::Arc<crate::persistence::facade::CoreStore>,
    instance: &str,
    schema: &str,
) -> Result<crate::persistence::scoped::ScopedStore, crate::persistence::scoped::Error> {
    crate::persistence::scoped::ScopedStore::host_private(store, instance, [schema.to_owned()])
}

/// The one-time durable binding row of a principal seen for the first time: absent, then put.
#[cold]
pub(crate) fn services_caller_binding(
    op: crate::persistence::scoped::Op,
    schema: &str,
    principal: &str,
    proposed: &str,
) -> crate::persistence::scoped::Request {
    use crate::persistence::scoped::{Expected, Mutation, Predicate, Request};
    Request {
        op,
        predicates: vec![Predicate {
            schema: schema.to_owned(),
            key: principal.as_bytes().to_vec(),
            expected: Expected::Absent,
        }],
        mutations: vec![Mutation::Put {
            schema: schema.to_owned(),
            key: principal.as_bytes().to_vec(),
            value: busbar_contract::Secret::new(proposed.as_bytes().to_vec()),
        }],
    }
}

// --- inbound: refusal text and refusal copies of crate::inbound ---

/// A refused request's target (`path?query`), rendered once into its refusal.
#[cold]
pub(crate) fn inbound_path_and_query(target: &str, query: Option<&str>) -> String {
    match query {
        Some(query) => format!("{target}?{query}"),
        None => target.to_owned(),
    }
}

/// A refusal response copied once into its owned wire refusal (`Refusal::of`).
#[cold]
pub(crate) fn inbound_refusal_of(resp: axum::response::Response) -> crate::inbound::Refusal {
    use futures::FutureExt as _;
    use http_body_util::BodyExt as _;
    let (parts, body) = resp.into_parts();
    let body = body
        .collect()
        .now_or_never()
        .and_then(Result::ok)
        .map(|c| c.to_bytes().to_vec())
        .unwrap_or_default();
    let fields = parts
        .headers
        .iter()
        .map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec()))
        .collect();
    crate::inbound::Refusal {
        status: u32::from(parts.status.as_u16()),
        fields,
        body,
    }
}

/// A unit refusal's rendered bytes moved into its wire refusal: each field name must be text.
#[cold]
pub(crate) fn inbound_unit_refusal(
    rendered: crate::plane_driver::Rendered,
) -> Result<crate::inbound::Refusal, &'static str> {
    let crate::plane_driver::Rendered {
        status,
        fields: rendered_fields,
        body,
    } = rendered;
    let fields = rendered_fields
        .into_iter()
        .map(|(name, value)| {
            String::from_utf8(name)
                .map(|name| (name, value))
                .map_err(|_| "a unit refusal field name is not text")
        })
        .collect::<Result<_, _>>()?;
    Ok(crate::inbound::Refusal {
        status,
        fields,
        body,
    })
}

// --- ratelimit ---

/// The limiter's first sight of a principal in a window: key it once.
#[cold]
pub(crate) fn ratelimit_principal_key(principal: &str) -> String {
    principal.to_owned()
}

// --- telemetry ---

/// A thread's first emission into a counter chunk of its bank: build the chunk once.
#[cold]
pub(crate) fn telemetry_new_counter_chunk() -> Box<[std::sync::atomic::AtomicU64]> {
    (0..crate::telemetry::COUNTER_CHUNK)
        .map(|_| std::sync::atomic::AtomicU64::new(0))
        .collect()
}

/// A thread's first emission into a histogram chunk of its bank: build the chunk once.
#[cold]
pub(crate) fn telemetry_new_hist_chunk() -> crate::telemetry::HistChunk {
    (0..crate::telemetry::HIST_CHUNK)
        .map(|_| std::sync::Mutex::new(Vec::new()))
        .collect()
}

/// Keep an unbanked label set's counter handle, once the process recorder is installed (before
/// that a handle is the no-op one, so it is not kept).
#[inline(never)]
pub(crate) fn telemetry_keep_counter(
    cache: &crate::telemetry::Handles<crate::telemetry::LabelMap<metrics::Counter>>,
    first: &str,
    second: &str,
    counter: metrics::Counter,
) {
    if crate::snapshot::recorder_installed() {
        cache
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .entry(Box::from(first))
            .or_default()
            .insert(Box::from(second), counter);
    }
}

/// The first unbanked breaker trip for `(pool, lane)`: register its counter and keep the handle.
#[cold]
pub(crate) fn telemetry_breaker_trip_first(pool_label: &str, lane_label: &str) {
    let counter = metrics::counter!(
        crate::snapshot::BREAKER_TRIPS_TOTAL,
        "pool" => pool_label.to_owned(),
        "lane" => lane_label.to_owned()
    );
    counter.increment(1);
    telemetry_keep_counter(
        &crate::telemetry::UNBANKED_BREAKER_TRIPS,
        pool_label,
        lane_label,
        counter,
    );
}

/// The first `busbar_unit_refusals_total` for `(instance, reason)`: register its counter and keep
/// the handle.
#[cold]
pub(crate) fn telemetry_unit_refusal_first(instance: &str, reason: &str) {
    let counter = metrics::counter!(
        crate::snapshot::UNIT_REFUSALS_TOTAL,
        "reason" => reason.to_owned(),
        "instance" => instance.to_owned()
    );
    counter.increment(1);
    telemetry_keep_counter(
        &crate::telemetry::UNBANKED_UNIT_REFUSALS,
        instance,
        reason,
        counter,
    );
}

/// The first unbanked failover for `(pool, reason)`: register its counter and keep the handle.
#[cold]
pub(crate) fn telemetry_failover_first(pool_label: &str, reason: &'static str) {
    let counter = metrics::counter!(
        crate::snapshot::FAILOVERS_TOTAL,
        "pool" => pool_label.to_owned(),
        "reason" => reason
    );
    counter.increment(1);
    if crate::snapshot::recorder_installed() {
        crate::telemetry::UNBANKED_FAILOVERS
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .entry(Box::from(pool_label))
            .or_default()
            .insert(reason, counter);
    }
}

/// The pool-depth gauge's first sight of a pool label: intern it once.
#[cold]
pub(crate) fn telemetry_pool_label(pool_label: &str) -> std::sync::Arc<str> {
    let mut held = crate::telemetry::POOL_LABELS
        .write()
        .unwrap_or_else(|p| p.into_inner());
    std::sync::Arc::clone(
        held.entry(Box::from(pool_label))
            .or_insert_with(|| std::sync::Arc::from(pool_label)),
    )
}

/// The first unbanked translation for `(from, to)`: register its counter and keep the handle.
#[cold]
pub(crate) fn telemetry_translation_first(from: &str, to: &str) {
    let counter = metrics::counter!(
        crate::snapshot::TRANSLATIONS_TOTAL,
        "from" => from.to_owned(),
        "to" => to.to_owned()
    );
    counter.increment(1);
    telemetry_keep_counter(&crate::telemetry::UNBANKED_TRANSLATIONS, from, to, counter);
}

/// The first unbanked upstream attempt for `(pool, lane)`: register its counter and keep the
/// handle.
#[cold]
pub(crate) fn telemetry_upstream_attempt_first(pool_label: &str, lane_label: &str) {
    let counter = metrics::counter!(
        crate::telemetry::UPSTREAM_ATTEMPTS_TOTAL,
        "pool" => pool_label.to_owned(),
        "lane" => lane_label.to_owned()
    );
    counter.increment(1);
    telemetry_keep_counter(
        &crate::telemetry::UNBANKED_ATTEMPTS,
        pool_label,
        lane_label,
        counter,
    );
}

/// The first unbanked upstream failure for `(pool, lane, disposition)`: register its counter and
/// keep the handle.
#[cold]
pub(crate) fn telemetry_upstream_failure_first(
    pool_label: &str,
    lane_label: &str,
    disposition: &'static str,
) {
    let counter = metrics::counter!(
        crate::telemetry::UPSTREAM_FAILURES_TOTAL,
        "pool" => pool_label.to_owned(),
        "lane" => lane_label.to_owned(),
        "disposition" => disposition
    );
    counter.increment(1);
    if crate::snapshot::recorder_installed() {
        crate::telemetry::UNBANKED_FAILURES
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .entry(Box::from(pool_label))
            .or_default()
            .entry(Box::from(lane_label))
            .or_default()
            .insert(disposition, counter);
    }
}

// --- router ---

/// A request panicked but the kernel's hook saw nothing (another hook replaced it): the 500's log
/// says so.
#[cold]
pub(crate) fn router_panic_unseen() -> (String, String) {
    (
        "<unknown: another panic hook replaced the kernel's>".to_owned(),
        String::new(),
    )
}

/// Where a request's panic happened, as `file:line:column`, for its log line.
#[cold]
pub(crate) fn router_panic_location(location: Option<&std::panic::Location<'_>>) -> String {
    location.map_or_else(
        || "<no location>".to_owned(),
        |l| format!("{}:{}:{}", l.file(), l.line(), l.column()),
    )
}

/// A request panic's captured backtrace text; empty when none was captured.
#[cold]
pub(crate) fn router_panic_backtrace(captured: &std::backtrace::Backtrace) -> String {
    if captured.status() == std::backtrace::BacktraceStatus::Captured {
        captured.to_string()
    } else {
        String::new()
    }
}

/// The overlay's row for an instance, made at its first queued write; acks keep it.
#[cold]
pub(crate) fn records_instance_row(instance: &str) -> std::sync::Arc<str> {
    std::sync::Arc::from(instance)
}

/// The overlay's row for a record kind, made at its first queued write; acks keep it.
#[cold]
pub(crate) fn records_kind_row(kind: &str) -> String {
    kind.to_owned()
}

/// The client-facing text of a limit refusal (a refused request), as the owned message its callers
/// carry.
#[cold]
pub(crate) fn ingress_refusal_text(text: &dyn std::fmt::Display) -> String {
    text.to_string()
}

/// The protected-resource metadata document's head fields: a discovery document clients fetch on
/// first sight and then cache for an hour (`max-age=3600`), never on a governed request.
#[cold]
pub(crate) fn ingress_metadata_fields() -> crate::plane_driver::HeadFields {
    vec![
        (b"cache-control".to_vec(), b"public, max-age=3600".to_vec()),
        (
            b"content-type".to_vec(),
            b"application/json; charset=utf-8".to_vec(),
        ),
    ]
}

// --- door and json ---

/// door: a verify refusal's message, rendered once on the refusal path.
#[cold]
pub(crate) fn door_refusal_message(refusal: &crate::door::VerifyRefusal) -> String {
    refusal.to_string()
}

/// door: the owned model name a `NoRate` refusal carries, copied once on the refusal path.
#[cold]
pub(crate) fn door_refused_name(name: &str) -> String {
    name.to_owned()
}

/// json: the log line for an unparseable body, rendered once on the error path.
#[cold]
pub(crate) fn json_parse_err_log(bytes_len: usize) -> String {
    format!("invalid JSON ({bytes_len} bytes)")
}
