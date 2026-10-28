// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KIND TAIL'S FACTS (`kind_tail_facts` in the rendering's format): every field of a kind's
//! Statement tail, so the signed manifest carries the tail itself and not only its size (ARCHITECT
//! ruling 2026-10-20, audit root#7 and loader#9). A reader that must not open the plugin reads a
//! dropped-in row's tail from its manifest ([`read_auth_tail`] for an auth row,
//! [`read_plane_cli_help`] for a plane's command-line help), and the admit comparison covers the
//! tail, so a manifest stating another tail than the door's refuses the load.
//!
//! THE FORMAT. The tail is read as this host's tail type by THE KIND TAIL GROWTH RULE (the plugin's
//! first `min(size, host)` bytes, the rest zero: a field the plugin predates renders absent), then
//! each field is rendered in declaration order with the rendering's own encodings (`u8`, `u32`,
//! `u64`, `str`, `blob`, `list`); an `f64` is its IEEE bits as a `u64`, and a byte list is a `str`.
//! The head and every padding field are not rendered, every pointer is followed and no address is
//! rendered. Each kind's tail is destructured whole, with no rest pattern: a field appended to a
//! tail does not compile until it is rendered here. A secret Statement states no tail fields, so
//! its facts are empty.
//!
//! ```text
//! store      durable_plane u8, fork_refusal u8
//! auth       caps u32, facts u32, login_kind u32, inbound_points u32,
//!            styles list of { name str, flags u32, points u32 },
//!            operator_principal str, credential_kinds list of str
//! hook       kind_class u32, prompt_access u32, user_access u32, infallible u8,
//!            requested_signals list of u32, routes list of { path str, method str, auth u32 }
//! export     streams str, routes list of { path str, method str, auth u32 }
//! plane      flags u32, ingress u32, dispatch_shape u32, answer_layout u32, scope str, label str,
//!            subject_noun str, admin_noun str, audit_kind str, signing_domain str,
//!            signing_kid_prefix str, cli_help str, dialects list of str,
//!            dialect_auth list of { dialect u32, flags u32, style str, params blob },
//!            scope_kinds list of str, op_classes list of { op str, name str },
//!            billable_classes list of { class str, family str },
//!            route_cost list of { class u32, weight f64 }, fee_units list of str,
//!            record_kinds list of str, egress_targets list of str,
//!            record_chains list of { kind u32, framing u32, flags u32 },
//!            trust_keys list of { key str, role u32, flags u32, default str,
//!                                 mechanisms list of { token str, flags u32 } },
//!            refusal_statuses list of { dialect u32, reason u32, status u32 },
//!            caller_credential_refusal str,
//!            admin_routes list of { verb str, target str, flags u32, audit_verb str },
//!            admin_openapi blob, stream_ceiling_secs u64, metric_lanes list of str
//! transport  role u32, framing u32, facts u32, handshake_max_steps u32, composes_over list of str,
//!            claim_rows list of { selector_forms str, egress_selector_forms str, facts list of str,
//!                                 status_namespace str, session u8, session_bound u8,
//!                                 unit0_trigger u8, status_at u8 },
//!            upgrades_to list of str, handoff_from str, handoff_to str, handoff_binding_fact str,
//!            handshake_frame_kind str, status_rows list of { claim u32, lo u32, hi u32, class u32 },
//!            settings list of { path str, kind u32, default str },
//!            fault_rows list of { claim u32, lo u32, hi u32, fault u32 }, frame_piece_size u32
//! ```

use core::mem::{size_of, MaybeUninit};
use core::ptr::{addr_of, copy_nonoverlapping};

use super::{items, In, Out, RenderError, Unreadable};
use crate::abi::mechanism::call::{AbiStr, Blob};
use crate::abi::mechanism::check::{self, Rule, HARD_MAX_BYTES};
use crate::abi::mechanism::door::KindTailHead;
use crate::abi::mechanism::KindCode;
use crate::abi::{auth, export, hook, plane, store, transport};

/// `p`'s tail as this host's `T`, by THE KIND TAIL GROWTH RULE: the plugin's first
/// `min(size, host)` bytes, the rest zero.
///
/// # Safety
///
/// `p` is non-NULL and points at plugin data of at least the size its head states; `T` is a
/// `#[repr(C)]` kind tail of plain integers, floats and pointers, so all-zero bytes are a valid `T`.
unsafe fn grown<T: Copy>(p: *const KindTailHead) -> T {
    // SAFETY: the caller's contract: a non-NULL tail leads with its head's `size`.
    let size = unsafe { addr_of!((*p).size).read_unaligned() } as usize;
    let n = size.min(size_of::<T>());
    let mut t = MaybeUninit::<T>::zeroed();
    // SAFETY: `n` is at most the plugin's stated size and at most `size_of::<T>()`; the rest of `t`
    // stays zero, a valid `T` (the caller's contract).
    unsafe {
        copy_nonoverlapping(p.cast::<u8>(), t.as_mut_ptr().cast::<u8>(), n);
        t.assume_init()
    }
}

/// A tail list, bounded before any slice is built over it: never NULL with a count, at most
/// [`check::STATEMENT_LIST_MAX`] entries, aligned for `X`.
///
/// # Safety
///
/// A non-NULL `ptr` with a count in bounds points at `len` live `X`s.
unsafe fn list<'a, X>(
    ptr: *const X,
    len: usize,
    field: &'static str,
) -> Result<&'a [X], RenderError> {
    check::listed(ptr, len, field).map_err(RenderError::Tail)?;
    check::bounded(ptr, len, field).map_err(RenderError::Tail)?;
    // SAFETY: the caller's contract, the bounds checked above.
    Ok(unsafe { items(ptr, len) })
}

/// A tail string, bounded before it is read: never NULL with a length, at most
/// [`HARD_MAX_BYTES`].
///
/// # Safety
///
/// A non-NULL `s.ptr` with a length in bounds points at `s.len` live bytes.
unsafe fn text(o: &mut Out, s: AbiStr, field: &'static str) -> Result<(), RenderError> {
    check::text(s, field).map_err(RenderError::Tail)?;
    if s.len as u64 > HARD_MAX_BYTES {
        return Err(RenderError::Tail(check::fault(Rule::OverMax, field)));
    }
    // SAFETY: the caller's contract, the bounds checked above.
    unsafe { o.str(s, field) }
}

/// A tail blob, bounded before it is read ([`check::blob`]).
///
/// # Safety
///
/// As [`text`], for `b`.
unsafe fn blob(o: &mut Out, b: Blob, field: &'static str) -> Result<(), RenderError> {
    check::blob(&b, field, field).map_err(RenderError::Tail)?;
    // SAFETY: the caller's contract, the bounds checked above.
    unsafe { o.blob(b, field) }
}

/// A tail list of strings.
///
/// # Safety
///
/// As [`list`] and [`text`].
unsafe fn texts(
    o: &mut Out,
    ptr: *const AbiStr,
    len: usize,
    field: &'static str,
) -> Result<(), RenderError> {
    // SAFETY (both): the caller's contract.
    let l = unsafe { list(ptr, len, field) }?;
    o.len(l.len(), field)?;
    for s in l {
        unsafe { text(o, *s, field) }?;
    }
    Ok(())
}

/// THE KIND TAIL'S FACTS of a Statement of `kind` whose tail is `p`, appended to `o` as one `bytes`
/// (`u32` length, then the facts). A NULL tail, and a secret's, has no facts.
///
/// # Safety
///
/// As [`super::render`]'s, for `p`.
pub(super) unsafe fn render(
    o: &mut Out,
    kind: u32,
    p: *const KindTailHead,
) -> Result<(), RenderError> {
    let mut facts = Out(Vec::new());
    if !p.is_null() {
        let f = &mut facts;
        // SAFETY (each arm): the caller's contract; each tail type is its kind's `#[repr(C)]` tail
        // of plain data, all-zero valid.
        unsafe {
            match KindCode::from_raw(kind) {
                Some(KindCode::Store) => store_tail(f, &grown(p)),
                Some(KindCode::Auth) => auth_tail(f, &grown(p))?,
                Some(KindCode::Hook) => hook_tail(f, &grown(p))?,
                Some(KindCode::Export) => export_tail(f, &grown(p))?,
                Some(KindCode::Plane) => plane_tail(f, &grown(p))?,
                Some(KindCode::Transport) => transport_tail(f, &grown(p))?,
                Some(KindCode::Secret) | None => {}
            }
        }
    }
    o.len(facts.0.len(), "kind_tail_facts")?;
    o.0.extend_from_slice(&facts.0);
    Ok(())
}

fn store_tail(o: &mut Out, t: &store::StoreTail) {
    let store::StoreTail {
        head: _,
        durable_plane,
        fork_refusal,
        _reserved: _,
    } = *t;
    o.u8(durable_plane);
    o.u8(fork_refusal);
}

/// # Safety
///
/// As [`render`]'s, for `t`'s lists and strings.
unsafe fn auth_tail(o: &mut Out, t: &auth::AuthTail) -> Result<(), RenderError> {
    let auth::AuthTail {
        head: _,
        caps,
        facts,
        login_kind,
        inbound_points,
        styles,
        styles_len,
        operator_principal,
        credential_kinds,
        credential_kinds_len,
    } = *t;
    o.u32(caps);
    o.u32(facts);
    o.u32(login_kind);
    o.u32(inbound_points);
    // SAFETY (every read below): the caller's contract; each list and string is bounded first.
    unsafe {
        let styles = list(styles, styles_len, "auth.styles")?;
        o.len(styles.len(), "auth.styles")?;
        for s in styles {
            let auth::StyleDecl {
                name,
                flags,
                points,
            } = *s;
            text(o, name, "auth.style.name")?;
            o.u32(flags);
            o.u32(points);
        }
        text(o, operator_principal, "auth.operator_principal")?;
        texts(
            o,
            credential_kinds,
            credential_kinds_len,
            "auth.credential_kinds",
        )
    }
}

/// # Safety
///
/// As [`render`]'s, for `t`'s lists and strings.
unsafe fn hook_tail(o: &mut Out, t: &hook::Tail) -> Result<(), RenderError> {
    let hook::Tail {
        head: _,
        kind_class,
        prompt_access,
        user_access,
        infallible,
        _reserved: _,
        requested_signals,
        requested_signals_len,
        routes,
        routes_len,
    } = *t;
    o.u32(kind_class);
    o.u32(prompt_access);
    o.u32(user_access);
    o.u8(infallible);
    // SAFETY (every read below): the caller's contract; each list and string is bounded first.
    unsafe {
        let signals = list(
            requested_signals,
            requested_signals_len,
            "hook.requested_signals",
        )?;
        o.len(signals.len(), "hook.requested_signals")?;
        for s in signals {
            o.u32(*s);
        }
        let routes = list(routes, routes_len, "hook.routes")?;
        o.len(routes.len(), "hook.routes")?;
        for r in routes {
            let hook::Route {
                path,
                method,
                auth: route_auth,
                _reserved: _,
            } = *r;
            text(o, path, "hook.route.path")?;
            text(o, method, "hook.route.method")?;
            o.u32(route_auth);
        }
    }
    Ok(())
}

/// # Safety
///
/// As [`render`]'s, for `t`'s lists and strings.
unsafe fn export_tail(o: &mut Out, t: &export::Tail) -> Result<(), RenderError> {
    let export::Tail {
        head: _,
        streams,
        streams_len,
        routes,
        routes_len,
    } = *t;
    // SAFETY (every read below): the caller's contract; each list and string is bounded first.
    unsafe {
        let streams = list(streams, streams_len, "export.streams")?;
        o.len(streams.len(), "export.streams")?;
        o.0.extend_from_slice(streams);
        let routes = list(routes, routes_len, "export.routes")?;
        o.len(routes.len(), "export.routes")?;
        for r in routes {
            let export::Route {
                path,
                method,
                auth: route_auth,
                _reserved: _,
            } = *r;
            text(o, path, "export.route.path")?;
            text(o, method, "export.route.method")?;
            o.u32(route_auth);
        }
    }
    Ok(())
}

/// # Safety
///
/// As [`render`]'s, for `t`'s lists and strings.
unsafe fn plane_tail(o: &mut Out, t: &plane::PlaneTail) -> Result<(), RenderError> {
    let plane::PlaneTail {
        head: _,
        flags,
        ingress,
        dispatch_shape,
        answer_layout,
        scope,
        label,
        subject_noun,
        admin_noun,
        audit_kind,
        signing_domain,
        signing_kid_prefix,
        cli_help,
        dialects,
        dialects_len,
        dialect_auth,
        dialect_auth_len,
        scope_kinds,
        scope_kinds_len,
        op_classes,
        op_classes_len,
        billable_classes,
        billable_classes_len,
        route_cost,
        route_cost_len,
        fee_units,
        fee_units_len,
        record_kinds,
        record_kinds_len,
        egress_targets,
        egress_targets_len,
        record_chains,
        record_chains_len,
        trust_keys,
        trust_keys_len,
        refusal_statuses,
        refusal_statuses_len,
        caller_credential_refusal,
        admin_routes,
        admin_routes_len,
        admin_openapi,
        stream_ceiling_secs,
        metric_lanes,
        metric_lanes_len,
    } = *t;
    o.u32(flags);
    o.u32(ingress);
    o.u32(dispatch_shape);
    o.u32(answer_layout);
    // SAFETY (every read below): the caller's contract; each list and string is bounded first.
    unsafe {
        text(o, scope, "plane.scope")?;
        text(o, label, "plane.label")?;
        text(o, subject_noun, "plane.subject_noun")?;
        text(o, admin_noun, "plane.admin_noun")?;
        text(o, audit_kind, "plane.audit_kind")?;
        text(o, signing_domain, "plane.signing_domain")?;
        text(o, signing_kid_prefix, "plane.signing_kid_prefix")?;
        text(o, cli_help, "plane.cli_help")?;
        texts(o, dialects, dialects_len, "plane.dialects")?;
        let l = list(dialect_auth, dialect_auth_len, "plane.dialect_auth")?;
        o.len(l.len(), "plane.dialect_auth")?;
        for d in l {
            let plane::DialectAuth {
                dialect,
                flags,
                style,
                params,
            } = *d;
            o.u32(dialect);
            o.u32(flags);
            text(o, style, "plane.dialect_auth.style")?;
            blob(o, params, "plane.dialect_auth.params")?;
        }
        texts(o, scope_kinds, scope_kinds_len, "plane.scope_kinds")?;
        let l = list(op_classes, op_classes_len, "plane.op_classes")?;
        o.len(l.len(), "plane.op_classes")?;
        for c in l {
            let plane::OpClass { op, name } = *c;
            text(o, op, "plane.op_class.op")?;
            text(o, name, "plane.op_class.name")?;
        }
        let l = list(
            billable_classes,
            billable_classes_len,
            "plane.billable_classes",
        )?;
        o.len(l.len(), "plane.billable_classes")?;
        for c in l {
            let plane::BillableClass { class, family } = *c;
            text(o, class, "plane.billable_class.class")?;
            text(o, family, "plane.billable_class.family")?;
        }
        let l = list(route_cost, route_cost_len, "plane.route_cost")?;
        o.len(l.len(), "plane.route_cost")?;
        for c in l {
            let plane::RouteCost {
                class,
                _reserved: _,
                weight,
            } = *c;
            o.u32(class);
            o.u64(weight.to_bits());
        }
        texts(o, fee_units, fee_units_len, "plane.fee_units")?;
        texts(o, record_kinds, record_kinds_len, "plane.record_kinds")?;
        texts(
            o,
            egress_targets,
            egress_targets_len,
            "plane.egress_targets",
        )?;
        let l = list(record_chains, record_chains_len, "plane.record_chains")?;
        o.len(l.len(), "plane.record_chains")?;
        for c in l {
            let plane::RecordChain {
                kind,
                framing,
                flags,
                _reserved: _,
            } = *c;
            o.u32(kind);
            o.u32(framing);
            o.u32(flags);
        }
        let l = list(trust_keys, trust_keys_len, "plane.trust_keys")?;
        o.len(l.len(), "plane.trust_keys")?;
        for k in l {
            let plane::TrustKey {
                key,
                role,
                flags,
                default,
                mechanisms,
                mechanisms_len,
            } = *k;
            text(o, key, "plane.trust_key.key")?;
            o.u32(role);
            o.u32(flags);
            text(o, default, "plane.trust_key.default")?;
            let m = list(mechanisms, mechanisms_len, "plane.trust_key.mechanisms")?;
            o.len(m.len(), "plane.trust_key.mechanisms")?;
            for p in m {
                let plane::PinMechanism {
                    token,
                    flags,
                    _reserved: _,
                } = *p;
                text(o, token, "plane.trust_key.mechanism.token")?;
                o.u32(flags);
            }
        }
        let l = list(
            refusal_statuses,
            refusal_statuses_len,
            "plane.refusal_statuses",
        )?;
        o.len(l.len(), "plane.refusal_statuses")?;
        for r in l {
            let plane::RefusalStatus {
                dialect,
                reason,
                status,
                _reserved: _,
            } = *r;
            o.u32(dialect);
            o.u32(reason);
            o.u32(status);
        }
        text(
            o,
            caller_credential_refusal,
            "plane.caller_credential_refusal",
        )?;
        let l = list(admin_routes, admin_routes_len, "plane.admin_routes")?;
        o.len(l.len(), "plane.admin_routes")?;
        for r in l {
            let plane::AdminRoute {
                verb,
                target,
                flags,
                _reserved: _,
                audit_verb,
            } = *r;
            text(o, verb, "plane.admin_route.verb")?;
            text(o, target, "plane.admin_route.target")?;
            o.u32(flags);
            text(o, audit_verb, "plane.admin_route.audit_verb")?;
        }
        blob(o, admin_openapi, "plane.admin_openapi")?;
        o.u64(stream_ceiling_secs);
        texts(o, metric_lanes, metric_lanes_len, "plane.metric_lanes")
    }
}

/// # Safety
///
/// As [`render`]'s, for `t`'s lists and strings.
unsafe fn transport_tail(o: &mut Out, t: &transport::TransportTail) -> Result<(), RenderError> {
    let transport::TransportTail {
        head: _,
        role,
        framing,
        facts,
        handshake_max_steps,
        composes_over,
        composes_over_len,
        claim_rows,
        claim_rows_len,
        upgrades_to,
        upgrades_to_len,
        handoff_from,
        handoff_to,
        handoff_binding_fact,
        handshake_frame_kind,
        status_rows,
        status_rows_len,
        settings,
        settings_len,
        fault_rows,
        fault_rows_len,
        frame_piece_size,
        _reserved: _,
    } = *t;
    o.u32(role);
    o.u32(framing);
    o.u32(facts);
    o.u32(handshake_max_steps);
    // SAFETY (every read below): the caller's contract; each list and string is bounded first.
    unsafe {
        texts(
            o,
            composes_over,
            composes_over_len,
            "transport.composes_over",
        )?;
        let l = list(claim_rows, claim_rows_len, "transport.claim_rows")?;
        o.len(l.len(), "transport.claim_rows")?;
        for c in l {
            let transport::Claim {
                selector_forms,
                egress_selector_forms,
                facts,
                facts_len,
                status_namespace,
                session,
                session_bound,
                unit0_trigger,
                status_at,
                _reserved: _,
            } = *c;
            text(o, selector_forms, "transport.claim.selector_forms")?;
            text(
                o,
                egress_selector_forms,
                "transport.claim.egress_selector_forms",
            )?;
            texts(o, facts, facts_len, "transport.claim.facts")?;
            text(o, status_namespace, "transport.claim.status_namespace")?;
            o.u8(session);
            o.u8(session_bound);
            o.u8(unit0_trigger);
            o.u8(status_at);
        }
        texts(o, upgrades_to, upgrades_to_len, "transport.upgrades_to")?;
        text(o, handoff_from, "transport.handoff_from")?;
        text(o, handoff_to, "transport.handoff_to")?;
        text(o, handoff_binding_fact, "transport.handoff_binding_fact")?;
        text(o, handshake_frame_kind, "transport.handshake_frame_kind")?;
        let l = list(status_rows, status_rows_len, "transport.status_rows")?;
        o.len(l.len(), "transport.status_rows")?;
        for r in l {
            let transport::StatusRow {
                claim,
                lo,
                hi,
                class,
            } = *r;
            o.u32(claim);
            o.u32(lo);
            o.u32(hi);
            o.u32(class);
        }
        let l = list(settings, settings_len, "transport.settings")?;
        o.len(l.len(), "transport.settings")?;
        for s in l {
            let transport::SettingDecl {
                path,
                kind,
                _reserved: _,
                default,
            } = *s;
            text(o, path, "transport.setting.path")?;
            o.u32(kind);
            text(o, default, "transport.setting.default")?;
        }
        let l = list(fault_rows, fault_rows_len, "transport.fault_rows")?;
        o.len(l.len(), "transport.fault_rows")?;
        for r in l {
            let transport::FaultRow {
                claim,
                lo,
                hi,
                fault: code,
            } = *r;
            o.u32(claim);
            o.u32(lo);
            o.u32(hi);
            o.u32(code);
        }
    }
    o.u32(frame_piece_size);
    Ok(())
}

// ── reading an auth tail back (a dropped-in auth row's facts, with no dlopen) ────────────────────

/// One outbound style an auth tail states, read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadStyle {
    /// The style name.
    pub name: String,
    /// `abi::auth::STYLE_*`.
    pub flags: u32,
    /// The auth points it needs.
    pub points: u32,
}

/// An auth Statement's tail, read back from its rendering's kind tail facts
/// ([`super::Read::kind_tail`]): every field [`auth::AuthTail`] states, owned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadAuthTail {
    /// `abi::auth::CAP_*`.
    pub caps: u32,
    /// `abi::auth::FACT_*`.
    pub facts: u32,
    /// `abi::auth::LOGIN_KIND_*`.
    pub login_kind: u32,
    /// The auth points `verify` needs inbound.
    pub inbound_points: u32,
    /// The outbound styles it serves.
    pub styles: Vec<ReadStyle>,
    /// The operator principal; empty = none.
    pub operator_principal: String,
    /// The credential kinds `verify` reads.
    pub credential_kinds: Vec<String>,
}

/// THE AUTH TAIL READ BACK from an auth rendering's kind tail facts, for a reader that must not open
/// the plugin. The whole input must be one auth tail: trailing bytes are refused.
///
/// # Errors
///
/// [`Unreadable`], at the first byte that is not what the format states (an empty input is the
/// facts of a Statement that states no tail).
pub fn read_auth_tail(facts: &[u8]) -> Result<ReadAuthTail, Unreadable> {
    let mut i = In { b: facts, at: 0 };
    let caps = i.u32("auth.caps")?;
    let fact_bits = i.u32("auth.facts")?;
    let login_kind = i.u32("auth.login_kind")?;
    let inbound_points = i.u32("auth.inbound_points")?;
    let n = i.count("auth.styles")?;
    let mut styles = Vec::with_capacity(n);
    for _ in 0..n {
        styles.push(ReadStyle {
            name: i.str("auth.style.name")?,
            flags: i.u32("auth.style.flags")?,
            points: i.u32("auth.style.points")?,
        });
    }
    let operator_principal = i.str("auth.operator_principal")?;
    let credential_kinds = i.strs("auth.credential_kinds")?;
    if i.at != facts.len() {
        return Err(Unreadable {
            at: i.at,
            what: "the end",
        });
    }
    Ok(ReadAuthTail {
        caps,
        facts: fact_bits,
        login_kind,
        inbound_points,
        styles,
        operator_principal,
        credential_kinds,
    })
}

// ── reading a plane's command-line help back (a dropped-in plane's `busbar --help` rows) ─────────

/// A PLANE STATEMENT'S COMMAND-LINE HELP ([`plane::PlaneTail::cli_help`], in the
/// [`plane::cli_help`] grammar), read back from its rendering's kind tail facts
/// ([`super::Read::kind_tail`]) for a reader that must not open the plugin: the host's command
/// line, read before any configuration is served, takes a dropped-in plane's rows, its line-serve
/// flag among them, from its signed manifest as it takes a linked door's from its tail
/// (BUSBAR-1.6.0.md l.2179, Part 2 #2). The tail's fields before the help are read past in their
/// rendered order; the fields after it are not read. An empty help is a plane that states none.
///
/// # Errors
///
/// [`Unreadable`], at the first byte up to the help's end that is not what the format states (an
/// empty input is the facts of a Statement that states no tail, and states no help).
pub fn read_plane_cli_help(facts: &[u8]) -> Result<String, Unreadable> {
    let mut i = In { b: facts, at: 0 };
    for field in [
        "plane.flags",
        "plane.ingress",
        "plane.dispatch_shape",
        "plane.answer_layout",
    ] {
        i.u32(field)?;
    }
    for field in [
        "plane.scope",
        "plane.label",
        "plane.subject_noun",
        "plane.admin_noun",
        "plane.audit_kind",
        "plane.signing_domain",
        "plane.signing_kid_prefix",
    ] {
        i.str(field)?;
    }
    i.str("plane.cli_help")
}
