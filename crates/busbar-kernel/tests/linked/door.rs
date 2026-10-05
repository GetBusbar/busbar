// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S DOOR-PLANE DOUBLE — the registry row a plane served through its memory-ABI door
//! enters the kernel by, built here by the kernel's OWN fold (`busbar_kernel::plane::door::fold`).
//!
//! WHY IT EXISTS. The cross-plane tests in this directory prove kernel behaviour over the roster a
//! build composes: two named-definition planes (the frozen 1.5.3 named-map order, a pool that may
//! not straddle them, a hook that may not reach across them), a plane that speaks several wire
//! formats at several doors (the superset-IR rule, a door labelled by the binding that was knocked
//! on), and stated admin trust verbs. The `agents:` plane that used to give those tests their second
//! plane was a linked engine crate with its own registry row; that crate is deleted, and the plane is
//! now a DOOR: its Statement states its section, dialects, admin routes and nouns, the loader reads
//! them as a `PlaneRegistration`, and the composition root folds that through
//! `busbar_kernel::plane::door::fold` beside the linked rows (DECL-FOLD). "A plugin tests itself; the
//! kernel never tests or names a plugin": the real door's own facts are pinned in its own crate. This
//! double states a registration of the SAME shape and rides the SAME fold, so every hook on its row
//! (section parse, named-map reads, claims, admission, admin routes, OpenAPI fragment) is the
//! kernel's production code for a door plane — only the words are the double's.
//!
//! What it states, and why each word is what it is:
//! * its declaring section is the fourth 1.5.3 named-definition map, READ OFF the kernel's frozen
//!   list (`NAMED_MAP_SECTIONS[3]`), so the named-map CRUD is generated from its row as it is for the
//!   door that owns that section in a shipped build;
//! * three dialects, JSON-RPC first (a mounted door shapes its refusals in JSON-RPC), then the
//!   request-line binding and the framed binding — the kernel's own wire-format words;
//! * with a public base URL it claims one door per binding (the request-line binding shares the
//!   JSON-RPC mount, so the fold's one-mount-per-prefix rule leaves two doors) and binds one audience;
//!   without one it claims nothing and binds nothing (a delegation-only deployment);
//! * two audited admin verbs (`connect`, `approve`) under its section, and one PUBLIC route the admin
//!   router must never mount (the fold's `ROUTE_PUBLIC` filter is exercised, not assumed);
//! * a pin trust key whose `unpinned` mechanism is not an authenticity root, and a reverify cadence;
//! * a `validate` that takes an entry only as a mapping naming its `url`.

use std::sync::{Arc, OnceLock};

use busbar_contract::plane::{PinMechanismDecl, TrustKeyDecl, TrustRole};
use busbar_contract::plane_calls::{DoorFacing, PlaneRegistration, StatedAdminRoute};
use busbar_kernel::plane::registry::PlaneDecl;
use busbar_kernel::plane::{WIRE_GRPC, WIRE_HTTP_JSON, WIRE_JSONRPC};

/// The double's registry key (a door's key is its Statement name).
pub const KEY: &str = "fleet";

/// The framed binding's service path, as a client derives it from its service description.
const FRAMED_SERVICE: &str = "/fleet.v1.FleetService/{method}";

/// The double's declaring section: the fourth frozen named-definition map.
fn section() -> &'static str {
    busbar_kernel::plane::config::NAMED_MAP_SECTIONS[3]
}

/// `/<section>/{name}/<verb>`, relative to the admin mount, kept for the process (a stated route's
/// target is `'static`, as a Statement's is).
fn verb_target(verb: &str) -> &'static str {
    Box::leak(format!("/{}/{{name}}/{verb}", section()).into_boxed_str())
}

/// The admin routes the double's Statement tail would state: the two audited trust verbs, then one
/// PUBLIC route that rides the data listener and must never reach the admin router.
fn admin_routes() -> Vec<StatedAdminRoute> {
    vec![
        StatedAdminRoute {
            verb: "POST",
            target: verb_target("connect"),
            flags: 0,
            audit_verb: "connect",
        },
        StatedAdminRoute {
            verb: "POST",
            target: verb_target("approve"),
            flags: 0,
            audit_verb: "approve",
        },
        StatedAdminRoute {
            verb: "POST",
            target: "/fleet/callback",
            flags: busbar_contract::abi::plane::ROUTE_PUBLIC,
            audit_verb: "",
        },
    ]
}

/// The two audited verbs' OpenAPI fragment, each path relative to the admin mount.
fn admin_openapi() -> &'static [u8] {
    let mut doc = serde_json::Map::new();
    for (verb, summary) in [
        ("connect", "Verify a registered member's published identity"),
        (
            "approve",
            "Lock a registered member to the identity an operator saw",
        ),
    ] {
        doc.insert(
            verb_target(verb).to_string(),
            serde_json::json!({ "post": { "summary": summary } }),
        );
    }
    Box::leak(
        serde_json::Value::Object(doc)
            .to_string()
            .into_bytes()
            .into_boxed_slice(),
    )
}

/// The door's own section judge: an empty section is the empty section; every entry beside the
/// reserved section words is a mapping that names its `url`.
fn validate(settings: &[u8]) -> Result<(), String> {
    if settings.is_empty() {
        return Ok(());
    }
    let doc: serde_json::Value = serde_json::from_slice(settings).map_err(|e| e.to_string())?;
    let Some(entries) = doc.as_object() else {
        return Err(format!("`{}`: expected a map of members", section()));
    };
    for (name, entry) in entries {
        if name == "hooks" || name == "upstream_credentials" {
            continue;
        }
        if !entry.is_object() {
            return Err(format!(
                "`{}.{name}`: expected a member definition",
                section()
            ));
        }
        if entry.get("url").is_none() {
            return Err(format!(
                "`{}.{name}`: `url:` must name the member",
                section()
            ));
        }
    }
    Ok(())
}

/// What the double faces the world with: with a public base URL, a door per binding and one
/// audience; without one, nothing.
fn facing(_settings: &[u8], _owned: &[u8], public_url: Option<&str>) -> Result<DoorFacing, String> {
    let Some(base) = public_url else {
        return Ok(DoorFacing::default());
    };
    Ok(DoorFacing {
        claims: vec![
            (format!("/{KEY}"), WIRE_JSONRPC),
            (format!("/{KEY}/{{id}}"), WIRE_HTTP_JSON),
            (FRAMED_SERVICE.to_string(), WIRE_GRPC),
        ],
        admission: Some((
            format!("{base}/{KEY}"),
            format!("{base}/.well-known/oauth-protected-resource/{KEY}"),
        )),
    })
}

/// The registration a door of this shape states.
fn registration() -> PlaneRegistration {
    PlaneRegistration {
        key: KEY,
        section: section(),
        owns: Vec::new(),
        secret_refs: Vec::new(),
        admin_routes: admin_routes(),
        admin_openapi: Some(admin_openapi()),
        label: "Fleet",
        subject_noun: "fleet member",
        admin_noun: "fleet-member",
        audit_kind: "fleet_member",
        signing: None,
        dialects: vec![WIRE_JSONRPC, WIRE_HTTP_JSON, WIRE_GRPC],
        scope_kinds: vec!["fleet_member"],
        billable_classes: Vec::new(),
        fee_units: Vec::new(),
        record_kinds: Vec::new(),
        trust_keys: vec![
            TrustKeyDecl {
                key: "pin",
                role: TrustRole::Pin,
                fingerprint: true,
                default: None,
                mechanisms: &[PinMechanismDecl {
                    token: "unpinned",
                    root: false,
                    peer_key: false,
                }],
            },
            TrustKeyDecl {
                key: "reverify_ttl",
                role: TrustRole::ReverifyTtl,
                fingerprint: false,
                default: Some("5s"),
                mechanisms: &[],
            },
        ],
        caller_credential_refusal: None,
        validate: Arc::new(validate),
        facing: Arc::new(facing),
    }
}

/// The double's registry row, folded once per process by the kernel's door fold.
pub fn row() -> &'static PlaneDecl {
    static ROW: OnceLock<&'static PlaneDecl> = OnceLock::new();
    ROW.get_or_init(|| {
        busbar_kernel::plane::door::fold(registration())
            .unwrap_or_else(|e| panic!("the door double folds: {e}"))
    })
}
