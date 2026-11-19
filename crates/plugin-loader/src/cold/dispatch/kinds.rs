// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The cold code of `crate::dispatch::kinds`: load-time refusal text, the Statement facts each
//! kind copies out once at bind, a plane's registration built once at boot, and the plane snapshot
//! and facing copied out once per open or refresh.

use std::fmt::Display;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{AbiStr, Outcome};
use busbar_contract::abi::mechanism::door::{MetricFamily, Statement};
use busbar_contract::abi::plane::{self, PlaneSnapshot, PlaneTail};
use busbar_contract::abi::transport::{SettingDecl, StatusRow};
use busbar_contract::plane::{PinMechanismDecl, TrustKeyDecl, TrustRole};
use busbar_contract::plane_calls::{
    DialectFacts, DoorFacing, FacingProbe, InstanceDecl, PlaneRegistration, SectionJudge,
};
use busbar_contract::plugin_settings::sugar_words::{
    SECTION_CONSUMED, SECTION_DECLARING, SECTION_REQUIRED,
};
use busbar_contract::records::size_limits::Fault;
use busbar_contract::rendering::Unreadable;
use busbar_contract::route::Route;

use crate::dispatch::kinds::plane::{
    dialect_flags, kept, kept_blob, kept_mechanisms, listed, owned_blob, owned_str, NeedKeep,
    OwnedAdminRoute, OwnedClaim, OwnedSnapshot, ServedFacts,
};

// ---------------------------------------------------------------------------------------------
// Every kind

/// A load-time refusal, spelled once, when a Statement is refused.
#[cold]
pub(crate) fn refusal(text: &'static str) -> String {
    text.to_owned()
}

/// A loader or rendering refusal's text.
#[cold]
pub(crate) fn load_refusal<E: Display>(e: E) -> String {
    e.to_string()
}

/// A Statement string, copied out once, at bind.
#[cold]
pub(crate) fn statement_text(s: &str) -> String {
    s.to_owned()
}

/// A Statement list, copied out once, at bind.
#[cold]
pub(crate) fn statement_list<T: Copy>(list: &[T]) -> Vec<T> {
    list.to_vec()
}

/// The rule and field a kind tail breaks (`kind`: `export`, `transport`, `plane`).
#[cold]
pub(crate) fn tail_fault(kind: &str, f: Fault) -> String {
    format!("the {kind} tail breaks {:?} at {}", f.rule, f.field)
}

/// A Statement rendering that does not read back (`what`: `the auth Statement`, ...).
#[cold]
pub(crate) fn unreadable(what: &str, e: &Unreadable) -> String {
    format!(
        "{what} rendering does not read back: byte {} is not {}",
        e.at, e.what
    )
}

/// A Statement rendering of another kind than `want`.
#[cold]
pub(crate) fn rendering_kind(kind: u32, want: &str) -> String {
    format!("the Statement rendering states kind {kind}, not {want}")
}

// ---------------------------------------------------------------------------------------------
// auth

#[cold]
pub(crate) fn auth_carriers_over(max: usize) -> String {
    format!("the auth Statement states more than {max} carriers")
}

#[cold]
pub(crate) fn issued_twice(class: u32) -> String {
    format!("the auth Statement states issued-credential mark class {class} twice")
}

#[cold]
pub(crate) fn issued_missing(what: &str) -> String {
    format!("the issued-credential shape states no {what}")
}

#[cold]
pub(crate) fn issued_length(what: &str, word: &str, max: usize) -> String {
    format!("the issued-credential {what} {word:?} is not a decimal in 1..={max}")
}

#[cold]
pub(crate) fn issued_alphabet(what: &str, max: usize) -> String {
    format!(
        "the issued-credential {what} is not up to {max} distinct ASCII graphic \
         characters"
    )
}

#[cold]
pub(crate) fn issued_prefix(prefix: &str, id_len: usize) -> String {
    format!(
        "the issued-credential id prefix {prefix:?} is not ASCII graphic or leaves no room in a \
         {id_len}-character id"
    )
}

#[cold]
pub(crate) fn auth_tail_size(size: u32, frozen: usize) -> String {
    format!("an auth plugin states a {size}-byte tail, smaller than its frozen {frozen}")
}

#[cold]
pub(crate) fn auth_login_kind(kind: u32) -> String {
    format!("the auth tail's login kind {kind} disagrees with its login capability")
}

#[cold]
pub(crate) fn auth_inbound_points(points: u32, f: Fault) -> String {
    format!("the auth tail's inbound points {points:#x} are refused: {f:?}")
}

#[cold]
pub(crate) fn auth_operator(principal_len: usize) -> String {
    format!(
        "the auth tail's operator fact disagrees with its principal ({principal_len} bytes) or \
         capabilities"
    )
}

#[cold]
pub(crate) fn auth_credential_kinds(n: usize) -> String {
    format!("the auth tail states {n} credential kinds")
}

#[cold]
pub(crate) fn auth_credential_read(n: usize) -> String {
    format!(
        "the auth tail's credential-read fact disagrees with its {n} credential kinds or \
         capabilities"
    )
}

#[cold]
pub(crate) fn auth_styles(n: usize) -> String {
    format!("the auth tail states {n} styles")
}

#[cold]
pub(crate) fn auth_style_duplicated(name: &str) -> String {
    format!("auth style name {name:?} is empty or duplicated")
}

#[cold]
pub(crate) fn auth_style_refused(name: &str, flags: u32, points: u32, f: Fault) -> String {
    format!("auth style {name} is refused: flags {flags:#x}, points {points:#x}: {f:?}")
}

// ---------------------------------------------------------------------------------------------
// export

#[cold]
pub(crate) fn export_route_method(path: &str, method: &str) -> String {
    format!("the export route {path} names the method `{method}`")
}

/// An export's routes, copied out once, at bind.
#[cold]
pub(crate) fn export_routes(
    routes: &[busbar_contract::abi::export::Route],
) -> Result<Vec<Route>, String> {
    routes
        .iter()
        .map(crate::dispatch::kinds::export::route)
        .collect()
}

/// An export's metric families, copied out once, at bind.
#[cold]
pub(crate) fn export_families(
    declared: &[MetricFamily],
) -> Result<Vec<(String, u8, Vec<String>)>, String> {
    declared
        .iter()
        .map(crate::dispatch::kinds::export::family)
        .collect()
}

/// One metric family's label keys, copied out once, at bind; `None` when one is over-long.
#[cold]
pub(crate) fn export_label_keys(keys: &[AbiStr]) -> Option<Vec<String>> {
    keys.iter()
        .map(|k| crate::dispatch::kinds::export::owned(*k))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// hook

/// The hook tail states `value` for `what` (`class`, `prompt access`, `user access`).
#[cold]
pub(crate) fn hook_tail_states(what: &str, value: u32) -> String {
    format!("the hook tail states {what} {value}")
}

#[cold]
pub(crate) fn hook_route_method(path: &str) -> String {
    format!("the hook route {path} names an unsupported method")
}

#[cold]
pub(crate) fn hook_route_auth(path: &str) -> String {
    format!("the hook route {path} names an unsupported auth bar")
}

/// A hook's routes, copied out once, at bind.
#[cold]
pub(crate) fn hook_routes(
    routes: &[busbar_contract::abi::hook::Route],
) -> Result<Vec<Route>, String> {
    routes
        .iter()
        .map(crate::dispatch::kinds::hook::route)
        .collect()
}

// ---------------------------------------------------------------------------------------------
// transport

#[cold]
pub(crate) fn transport_overlong(field: &str) -> String {
    format!("the transport tail's {field} is longer than any string may be")
}

#[cold]
pub(crate) fn transport_not_utf8(field: &str) -> String {
    format!("the transport tail's {field} is not UTF-8")
}

/// A transport's tail names (`field`: `claim`, `composes_over`), interned once, at bind.
#[cold]
pub(crate) fn transport_names(list: &[AbiStr], field: &str) -> Result<Vec<&'static str>, String> {
    list.iter()
        .map(|s| crate::dispatch::kinds::transport::owned(*s, field))
        .collect()
}

/// A transport's settings keys, interned once, at bind.
#[cold]
pub(crate) fn transport_settings_keys(
    settings: &[SettingDecl],
) -> Result<Vec<&'static str>, String> {
    settings
        .iter()
        .map(|s| crate::dispatch::kinds::transport::owned(s.path, "settings"))
        .collect()
}

/// The claims whose row `pick` takes, in order, listed once, at bind.
#[cold]
pub(crate) fn transport_claims_where(
    claims: &[&'static str],
    rows: &[busbar_contract::abi::transport::Claim],
    pick: fn(&busbar_contract::abi::transport::Claim) -> bool,
) -> Vec<&'static str> {
    claims
        .iter()
        .zip(rows)
        .filter(|(_, row)| pick(row))
        .map(|(name, _)| *name)
        .collect()
}

/// Each claim row's final status numbering, read once, at bind.
#[cold]
pub(crate) fn transport_status_namespaces(
    rows: &[busbar_contract::abi::transport::Claim],
) -> Result<Vec<Option<Arc<str>>>, String> {
    rows.iter()
        .map(crate::dispatch::kinds::transport::status_namespace)
        .collect()
}

/// A transport's status table, copied out once, at bind.
#[cold]
pub(crate) fn transport_status_rows(status: &[StatusRow]) -> Vec<(u32, u32, u32)> {
    status.iter().map(|r| (r.claim, r.lo, r.hi)).collect()
}

// ---------------------------------------------------------------------------------------------
// plane

#[cold]
pub(crate) fn plane_sections_fault(f: Fault) -> String {
    format!("the plane's sections break {:?} at {}", f.rule, f.field)
}

#[cold]
pub(crate) fn plane_provider_keys(e: String) -> String {
    format!("the plane's provider keys are refused: {e}")
}

#[cold]
pub(crate) fn retired_trust_role(code: busbar_contract::diagnostic::Banner, key: &str) -> String {
    format!(
        "{code}: the plane declares trust key `{key}` with the retired role \
         TRUST_PRIVATE_REACH (4); one core setting, `advanced.allow_destinations`, governs \
         every private destination. Upgrade the plugin to a release built against busbar \
         1.6.0"
    )
}

#[cold]
pub(crate) fn plane_snapshot_refused(name: &str) -> String {
    format!("plane `{name}`'s snapshot did not pass the host's checks")
}

#[cold]
pub(crate) fn plane_refresh_failure(name: &str, outcome: Outcome, error: Option<&[u8]>) -> String {
    match error.filter(|e| !e.is_empty()) {
        Some(e) => format!(
            "plane `{name}` did not refresh: {:?}: {}",
            outcome,
            String::from_utf8_lossy(e)
        ),
        None => format!("plane `{name}` did not refresh: {outcome:?}"),
    }
}

/// A Statement blob, interned on its first sight for the process.
#[cold]
pub(crate) fn first_blob(
    blobs: &mut foldhash::HashSet<&'static [u8]>,
    bytes: &[u8],
) -> &'static [u8] {
    let kept: &'static [u8] = bytes.to_vec().leak();
    blobs.insert(kept);
    kept
}

/// The probe's instance name, shared once, at registration.
#[cfg(any(test, feature = "test-support"))]
#[cold]
pub(crate) fn shared_name(instance: &str) -> Arc<str> {
    Arc::from(instance)
}

/// A plane's Statement name, copied out once, at registration.
#[cold]
pub(crate) fn lossy_name(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

/// What a facing probe is keyed by, copied once per changed plane settings.
#[cold]
pub(crate) fn probe_key(
    url: &str,
    owned: &[u8],
    facts: &[DialectFacts],
) -> (String, Vec<u8>, Vec<DialectFacts>) {
    (url.to_owned(), owned.to_vec(), facts.to_vec())
}

/// The provider facts a plane's open is lent, built once per plane open.
#[cold]
pub(crate) fn plane_provider_facts(dialects: &[DialectFacts]) -> Vec<plane::ProviderFacts> {
    dialects
        .iter()
        .map(crate::dispatch::kinds::plane::provider)
        .collect()
}

/// A plane's facing, out of the snapshot its open or refresh published, once per plane settings.
#[cold]
pub(crate) fn plane_facing(snapshot: OwnedSnapshot, dialects: &[&'static str]) -> DoorFacing {
    let claims = snapshot
        .claims
        .into_iter()
        .map(|c| {
            let dialect = dialects
                .get(usize::from(c.refusal_dialect))
                .copied()
                .unwrap_or_default();
            (c.target, dialect)
        })
        .collect();
    DoorFacing {
        claims,
        admission: snapshot.audience.zip(snapshot.resource_metadata),
        listed: snapshot.listed,
    }
}

/// A plane snapshot string, copied out once per open or refresh.
#[cold]
pub(crate) fn snapshot_text(text: &str) -> String {
    text.to_owned()
}

/// A plane snapshot blob, copied out once per open or refresh.
#[cold]
pub(crate) fn snapshot_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}

/// A generation snapshot the host's checks passed, copied out once per open or refresh.
#[cold]
pub(crate) fn plane_snapshot(
    s: &PlaneSnapshot,
    claims: &[plane::Claim],
    routes: &[plane::AdminRoute],
    listed: &[AbiStr],
    spans: &[AbiStr],
) -> Option<OwnedSnapshot> {
    use busbar_contract::plane::codes::check_claim_target;
    let span_of = |i: usize| -> Option<String> {
        let name = spans.get(i).map_or(Some(String::new()), |n| {
            owned_str(*n).map(Option::unwrap_or_default)
        })?;
        name.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            .then_some(name)
    };
    let text = |a| owned_str(a)?.or(Some(String::new()));
    Some(OwnedSnapshot {
        generation: s.generation,
        claims: claims
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let target = text(c.target)?;
                check_claim_target(&target, c.flags).ok()?;
                Some(OwnedClaim {
                    verb: text(c.verb)?,
                    target,
                    carrier: text(c.carrier)?,
                    flags: c.flags,
                    refusal_dialect: c.refusal_dialect,
                    arrival_span: span_of(i)?,
                })
            })
            .collect::<Option<_>>()?,
        admin_routes: routes
            .iter()
            .map(|r| {
                Some(OwnedAdminRoute {
                    verb: text(r.verb)?,
                    target: text(r.target)?,
                    flags: r.flags,
                    audit_verb: text(r.audit_verb)?,
                })
            })
            .collect::<Option<_>>()?,
        openapi: owned_blob(s.openapi)?,
        audience: owned_str(s.audience)?,
        resource_metadata: owned_str(s.resource_metadata)?,
        resource_facts: owned_blob(s.resource_facts)?,
        listed: listed
            .iter()
            .map(|n| owned_str(*n).flatten())
            .collect::<Option<_>>()?,
    })
}

/// A plane's registration, built once, at boot: its served and declared facts copied into the
/// kernel's registry row beside its judge and facing probe.
#[cold]
pub(crate) fn plane_registration(
    key: &'static str,
    served: &ServedFacts,
    declared: &InstanceDecl,
    validate: SectionJudge,
    facing: FacingProbe,
) -> PlaneRegistration {
    let (label, subject_noun, admin_noun) = served.nouns;
    let refusal = served.caller_credential_refusal;
    PlaneRegistration {
        key,
        section: served.section,
        owns: served.owns.clone(),
        consumes: served.consumes.clone(),
        requires: served.requires.clone(),
        secret_refs: served.secret_refs.clone(),
        admin_routes: served.admin_routes.clone(),
        admin_openapi: served.admin_openapi,
        streaming_content_types: served.streaming_content_types.clone(),
        label,
        subject_noun,
        admin_noun,
        audit_kind: served.audit_kind,
        signing: declared.signing,
        dialects: served.dialects.clone(),
        dialect_flags: served.dialect_flags.clone(),
        scope_kinds: declared.scope_kinds.clone(),
        billable_classes: served
            .billable_classes
            .iter()
            .copied()
            .zip(served.billable_families.iter().copied())
            .collect(),
        class_parents: served.class_parents.clone(),
        fee_units: served.fee_units.clone(),
        record_kinds: declared.record_kinds.clone(),
        trust_keys: declared.trust_keys.clone(),
        caller_credential_refusal: (!refusal.is_empty()).then_some(refusal),
        fallback: served.fallback,
        provider_keys: served.provider_keys.clone(),
        validate,
        facing,
    }
}

/// What a plane tail declares for its instance's admission, copied out once, at bind.
#[cold]
pub(crate) fn plane_declared(t: &PlaneTail) -> InstanceDecl {
    let words = |p: *const AbiStr, n: usize| -> Vec<&'static str> {
        listed(p, n).into_iter().map(kept).collect()
    };
    let (domain, prefix) = (kept(t.signing_domain), kept(t.signing_kid_prefix));
    let trust_keys = listed(t.trust_keys, t.trust_keys_len)
        .into_iter()
        .map(|k| TrustKeyDecl {
            key: kept(k.key),
            role: match k.role {
                plane::TRUST_PIN => TrustRole::Pin,
                plane::TRUST_REVERIFY_TTL => TrustRole::ReverifyTtl,
                plane::TRUST_ITEM_APPROVALS => TrustRole::ItemApprovals,
                _ => TrustRole::RecoveryBackoff,
            },
            fingerprint: k.flags & plane::PIN_FINGERPRINT != 0,
            default: Some(kept(k.default)).filter(|d| !d.is_empty()),
            mechanisms: kept_mechanisms(
                listed(k.mechanisms, k.mechanisms_len)
                    .into_iter()
                    .map(|m| PinMechanismDecl {
                        token: kept(m.token),
                        root: m.flags & plane::MECHANISM_ROOT != 0,
                        peer_key: m.flags & plane::MECHANISM_PEER_KEY != 0,
                    })
                    .collect::<Vec<_>>(),
            ),
        })
        .collect();
    InstanceDecl {
        authenticated_route: t.flags & plane::TAIL_AUTHENTICATED_ROUTE != 0,
        conditional_records: false,
        conditional_records_optional: false,
        conditional_record_kinds: Vec::new(),
        label: Arc::default(),
        record_kinds: words(t.record_kinds, t.record_kinds_len),
        record_collections: Vec::new(),
        signing: (!domain.is_empty() && !prefix.is_empty()).then_some((domain, prefix)),
        scope_kinds: words(t.scope_kinds, t.scope_kinds_len),
        trust_keys,
        record_chains: listed(t.record_chains, t.record_chains_len),
        record_retentions: listed(t.record_retentions, t.record_retentions_len),
        ticket_prefix: None,
    }
}

/// What the composition root serves a plane instance by, copied out of its Statement once, at
/// bind (its provider keys are the caller's, read after).
#[cold]
pub(crate) fn plane_served(st: &Statement, tail: &PlaneTail) -> ServedFacts {
    let sections = listed(st.sections, st.sections_len);
    let admin_routes = listed(tail.admin_routes, tail.admin_routes_len);
    let streaming_content_types = listed(
        tail.streaming_content_types,
        tail.streaming_content_types_len,
    );
    ServedFacts {
        section: sections
            .iter()
            .find(|s| s.flags & SECTION_DECLARING != 0)
            .map_or("", |s| kept(s.name)),
        consumed: sections
            .iter()
            .filter(|s| s.flags & SECTION_CONSUMED != 0)
            .map(|s| kept(s.name))
            .collect(),
        owns: sections
            .iter()
            .filter(|s| s.flags & (SECTION_DECLARING | SECTION_CONSUMED) == 0)
            .map(|s| kept(s.name))
            .collect(),
        consumes: sections
            .iter()
            .filter(|s| s.flags & SECTION_CONSUMED != 0)
            .map(|s| kept(s.name))
            .collect(),
        requires: sections
            .iter()
            .filter(|s| s.flags & SECTION_REQUIRED != 0)
            .map(|s| kept(s.name))
            .collect(),
        secret_refs: listed(st.secret_refs, st.secret_refs_len)
            .into_iter()
            .map(kept)
            .collect(),
        admin_routes: admin_routes
            .into_iter()
            .map(|r| busbar_contract::plane_calls::StatedAdminRoute {
                verb: kept(r.verb),
                target: kept(r.target),
                flags: r.flags,
                audit_verb: kept(r.audit_verb),
            })
            .collect(),
        admin_openapi: (!tail.admin_openapi.ptr.is_null()).then(|| kept_blob(tail.admin_openapi)),
        op_classes: listed(tail.op_classes, tail.op_classes_len)
            .into_iter()
            .map(|c| kept(c.op))
            .collect(),
        audit_kind: kept(tail.audit_kind),
        billable_classes: listed(tail.billable_classes, tail.billable_classes_len)
            .into_iter()
            .map(|c| kept(c.class))
            .collect(),
        class_parents: {
            let classes = listed(tail.billable_classes, tail.billable_classes_len);
            listed(tail.class_parents, tail.class_parents_len)
                .into_iter()
                .map(|edge| busbar_contract::plane::ClassParent {
                    child: kept(classes[edge.child as usize].class),
                    parent: kept(classes[edge.parent as usize].class),
                })
                .collect()
        },
        route_cost: listed(tail.route_cost, tail.route_cost_len)
            .into_iter()
            .map(|term| (term.class, term.weight))
            .collect(),
        fee_units: listed(tail.fee_units, tail.fee_units_len)
            .into_iter()
            .map(kept)
            .collect(),
        streaming_content_types: streaming_content_types.into_iter().map(kept).collect(),
        metric_lanes: listed(tail.metric_lanes, tail.metric_lanes_len)
            .into_iter()
            .map(kept)
            .collect(),
        keeps: listed(st.needs, st.needs_len)
            .into_iter()
            .map(|n| NeedKeep {
                mode: n.keep_mode,
                kept: listed(n.keep_response_headers, n.keep_response_headers_len)
                    .into_iter()
                    .map(kept)
                    .collect(),
                denied: listed(n.deny_response_headers, n.deny_response_headers_len)
                    .into_iter()
                    .map(kept)
                    .collect(),
            })
            .collect(),
        need_auths: listed(st.needs, st.needs_len)
            .into_iter()
            .map(|n| (n.direction, kept(n.auth)))
            .collect(),
        need_targets: listed(st.needs, st.needs_len)
            .into_iter()
            .map(|n| kept(n.target_from))
            .collect(),
        need_trust: listed(st.needs, st.needs_len)
            .into_iter()
            .map(|n| kept(n.trust_from))
            .collect(),
        trust_keys: plane_declared(tail).trust_keys,
        need_transports: listed(st.needs, st.needs_len)
            .into_iter()
            .map(|n| kept(n.transport))
            .collect(),
        dialects: listed(tail.dialects, tail.dialects_len)
            .into_iter()
            .map(kept)
            .collect(),
        dialect_auth: listed(tail.dialect_auth, tail.dialect_auth_len)
            .into_iter()
            .map(|d| (d.dialect, kept(d.style), kept_blob(d.params)))
            .collect(),
        dialect_flags: dialect_flags(tail),
        nouns: (
            kept(tail.label),
            kept(tail.subject_noun),
            kept(tail.admin_noun),
        ),
        billable_families: listed(tail.billable_classes, tail.billable_classes_len)
            .into_iter()
            .map(|c| kept(c.family))
            .collect(),
        probes: tail.flags & busbar_contract::plane::codes::TAIL_PROBES != 0,
        fallback: tail.flags & busbar_contract::plane::codes::TAIL_FALLBACK != 0,
        caller_credential_refusal: kept(tail.caller_credential_refusal),
        tail_flags: tail.flags,
        stream_ceiling_secs: tail.stream_ceiling_secs,
        provider_keys: None,
    }
}
