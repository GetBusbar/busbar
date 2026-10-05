// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR ROW of this test binary's roster — a door-plane double folded by the kernel's own door
//! fold (`busbar_kernel::plane::door::fold`), registered after the linked rows.
//!
//! WHY IT EXISTS. The admin surface these tests serve is the surface a shipped build serves, and in a
//! shipped build the fourth 1.5.3 named-definition section (`NAMED_MAP_SECTIONS[3]`) is owned by a
//! plane served through its memory-ABI door: the loader reads the door's Statement as a
//! `PlaneRegistration` and the composition root folds it beside the linked rows (DECL-FOLD). Its
//! named-map CRUD is generated from that row, its trust verbs reach the admin router through the
//! fold's stated-route adapter, and its section is judged by the kernel's trust-key reading plus the
//! door's own `validate`. The linked engine crate that used to give this binary a row for that
//! section is deleted, so the binary carries the door row the shipped roster carries: same shape,
//! same fold, the double's words. "A plugin tests itself; the kernel never tests or names a plugin":
//! the real door's own words are pinned in its own crate.
//!
//! What it states, and why:
//! * its declaring section is read off the kernel's frozen list (`NAMED_MAP_SECTIONS[3]`);
//! * two audited trust verbs under that section, `connect` and `approve`, at `POST` — the admin
//!   operations the committed admin corpus and OpenAPI document carry for it — and one PUBLIC route
//!   the admin router must never mount;
//! * the kernel-owned trust keys a registration of that section carries (a pin with three
//!   authenticity roots and the `unpinned` spelling, a reverify cadence, a recovery backoff and a
//!   private reach), so a definition the kernel's trust reading refuses is refused here as it is in a
//!   shipped build;
//! * a `validate` that takes an entry only as a mapping naming its `url`;
//! * with a public base URL, one JSON-RPC door and one audience.

use std::sync::{Arc, OnceLock};

use busbar_contract::plane::{PinMechanismDecl, TrustKeyDecl, TrustRole};
use busbar_contract::plane_calls::{DoorFacing, PlaneRegistration, StatedAdminRoute};
use busbar_kernel::plane::registry::PlaneDecl;

/// The double's registry key (a door's key is its Statement name).
const KEY: &str = "fleet";

/// The double's declaring section: the fourth frozen named-definition map.
fn section() -> &'static str {
    busbar_kernel::plane::config::NAMED_MAP_SECTIONS[3]
}

/// `/<section>/{name}/<verb>`, relative to the admin mount, kept for the process.
fn verb_target(verb: &str) -> &'static str {
    Box::leak(format!("/{}/{{name}}/{verb}", section()).into_boxed_str())
}

/// The pin's mechanisms: three authenticity roots (two of them the far end's key) and `unpinned`.
const PIN_MECHANISMS: &[PinMechanismDecl] = &[
    PinMechanismDecl {
        token: "jws_issuer_key",
        root: true,
        peer_key: false,
    },
    PinMechanismDecl {
        token: "cert_spki",
        root: true,
        peer_key: true,
    },
    PinMechanismDecl {
        token: "mtls",
        root: true,
        peer_key: true,
    },
    PinMechanismDecl {
        token: "unpinned",
        root: false,
        peer_key: false,
    },
];

fn trust_keys() -> Vec<TrustKeyDecl> {
    vec![
        TrustKeyDecl {
            key: "pin",
            role: TrustRole::Pin,
            fingerprint: true,
            default: None,
            mechanisms: PIN_MECHANISMS,
        },
        TrustKeyDecl {
            key: "reverify_ttl",
            role: TrustRole::ReverifyTtl,
            fingerprint: false,
            default: Some("5s"),
            mechanisms: &[],
        },
        TrustKeyDecl {
            key: "recovery_backoff",
            role: TrustRole::RecoveryBackoff,
            fingerprint: false,
            default: Some("30s"),
            mechanisms: &[],
        },
        TrustKeyDecl {
            key: "allow_private",
            role: TrustRole::PrivateReach,
            fingerprint: false,
            default: None,
            mechanisms: &[],
        },
    ]
}

/// The admin routes the double's Statement tail would state.
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

/// What the double faces the world with: with a public base URL, one JSON-RPC door and one
/// audience; without one, nothing.
fn facing(_settings: &[u8], _owned: &[u8], public_url: Option<&str>) -> Result<DoorFacing, String> {
    let Some(base) = public_url else {
        return Ok(DoorFacing::default());
    };
    Ok(DoorFacing {
        claims: vec![(format!("/{KEY}"), busbar_kernel::plane::WIRE_JSONRPC)],
        admission: Some((
            format!("{base}/{KEY}"),
            format!("{base}/.well-known/oauth-protected-resource/{KEY}"),
        )),
    })
}

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
        dialects: vec![busbar_kernel::plane::WIRE_JSONRPC],
        scope_kinds: vec!["fleet_member"],
        billable_classes: Vec::new(),
        fee_units: Vec::new(),
        record_kinds: Vec::new(),
        trust_keys: trust_keys(),
        caller_credential_refusal: None,
        validate: Arc::new(validate),
        facing: Arc::new(facing),
    }
}

/// The double's registry row, folded once per process by the kernel's door fold.
pub(crate) fn row() -> &'static PlaneDecl {
    static ROW: OnceLock<&'static PlaneDecl> = OnceLock::new();
    ROW.get_or_init(|| {
        busbar_kernel::plane::door::fold(registration())
            .unwrap_or_else(|e| panic!("the door double folds: {e}"))
    })
}
