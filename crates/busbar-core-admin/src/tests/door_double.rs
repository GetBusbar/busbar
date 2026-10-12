// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR ROW of this test binary's roster — a double of the plane door that owns the fourth
//! frozen named-definition section, folded by the kernel's own door fold
//! (`busbar_kernel::plane::door::fold`) and registered after the linked rows.
//!
//! WHY A DOUBLE. In a shipped build that section is owned by a plane served through its memory-ABI
//! door: the loader reads the door's Statement as a `PlaneRegistration` and the composition root
//! folds it (DECL-FOLD). This crate is a cleanliness crate with a one-way dependency on the kernel
//! (THE DESIGN, section 8; P2 D4): it links no loader, test-only or not, so it cannot read a door. Its
//! tests serve the admin surface a shipped build serves from a registration that states the same
//! facts as DATA (`door_double_statement.json`), every one of which the composition root's tests
//! pin to the linked door's own Statement (`root::serve` tests, `agent_door`), so the committed
//! admin `openapi.json` this crate's drift test holds is the door's entry and nothing else. The
//! door's own behaviour behind its routes (the card look, the trust book) is the composition root's
//! to drive, where the loader links.
//!
//! What the double does NOT state as data, and why:
//! * its `validate` takes an entry only as a mapping naming its `url` (the kernel reads and judges
//!   the trust keys first, as it does for the door);
//! * it faces the world with nothing (no claims, no audience): no cell here serves a data listener;
//! * it serves nothing: the trust verbs' answers are the linked door's, driven where the loader
//!   links (the composition root's admin cells).

use std::sync::{Arc, OnceLock};

use busbar_contract::plane::{PinMechanismDecl, TrustKeyDecl, TrustRole};
use busbar_contract::plane_calls::{DoorFacing, PlaneRegistration, StatedAdminRoute};
use busbar_kernel::plane::registry::PlaneDecl;

/// The double's Statement facts, as data.
fn statement() -> &'static serde_json::Value {
    static DOC: OnceLock<serde_json::Value> = OnceLock::new();
    DOC.get_or_init(|| {
        serde_json::from_str(include_str!("door_double_statement.json"))
            .expect("door_double_statement.json is JSON")
    })
}

fn kept(s: &str) -> &'static str {
    Box::leak(s.to_owned().into_boxed_str())
}

/// The string at `key` of `v`.
fn word(v: &serde_json::Value, key: &str) -> &'static str {
    kept(
        v[key]
            .as_str()
            .unwrap_or_else(|| panic!("door_double_statement.json: `{key}` is a string")),
    )
}

/// The string at `key` of `v`; `None` for `null`.
fn optional(v: &serde_json::Value, key: &str) -> Option<&'static str> {
    v[key].as_str().map(kept)
}

/// The strings at `key` of `v`.
fn words(v: &serde_json::Value, key: &str) -> Vec<&'static str> {
    v[key]
        .as_array()
        .unwrap_or_else(|| panic!("door_double_statement.json: `{key}` is a list"))
        .iter()
        .map(|w| kept(w.as_str().expect("a list of strings")))
        .collect()
}

fn role(name: &str) -> TrustRole {
    match name {
        "Pin" => TrustRole::Pin,
        "ReverifyTtl" => TrustRole::ReverifyTtl,
        "RecoveryBackoff" => TrustRole::RecoveryBackoff,
        "PrivateReach" => TrustRole::PrivateReach,
        "ItemApprovals" => TrustRole::ItemApprovals,
        other => panic!("door_double_statement.json: no trust role `{other}`"),
    }
}

fn trust_keys(doc: &serde_json::Value) -> Vec<TrustKeyDecl> {
    let list = doc["trust_keys"]
        .as_array()
        .expect("`trust_keys` is a list");
    list.iter()
        .map(|k| TrustKeyDecl {
            key: word(k, "key"),
            role: role(k["role"].as_str().expect("a role")),
            fingerprint: k["fingerprint"].as_bool().expect("a flag"),
            default: optional(k, "default"),
            mechanisms: k["mechanisms"]
                .as_array()
                .expect("`mechanisms` is a list")
                .iter()
                .map(|m| PinMechanismDecl {
                    token: word(m, "token"),
                    root: m["root"].as_bool().expect("a flag"),
                    peer_key: m["peer_key"].as_bool().expect("a flag"),
                })
                .collect::<Vec<_>>()
                .leak(),
        })
        .collect()
}

/// The admin routes the double's Statement tail states, in order.
fn admin_routes() -> Vec<StatedAdminRoute> {
    statement()["admin_routes"]
        .as_array()
        .expect("`admin_routes` is a list")
        .iter()
        .map(|r| StatedAdminRoute {
            verb: word(r, "verb"),
            target: word(r, "target"),
            flags: u32::try_from(r["flags"].as_u64().expect("flags")).expect("u32 flags"),
            audit_verb: word(r, "audit_verb"),
        })
        .collect()
}

/// The double's own section judge: an empty section is the empty section; every entry beside the
/// reserved section words is a mapping that names its `url`.
fn validate(section: &'static str, settings: &[u8]) -> Result<(), String> {
    if settings.is_empty() {
        return Ok(());
    }
    let doc: serde_json::Value = serde_json::from_slice(settings).map_err(|e| e.to_string())?;
    let Some(entries) = doc.as_object() else {
        return Err(format!("`{section}`: expected a map of registrations"));
    };
    for (name, entry) in entries {
        if name == "hooks" || name == "upstream_credentials" {
            continue;
        }
        if !entry.is_object() {
            return Err(format!("`{section}.{name}`: expected a registration"));
        }
        if entry.get("url").is_none() {
            return Err(format!("`{section}.{name}`: `url:` must name the endpoint"));
        }
    }
    Ok(())
}

/// What the double faces the world with: nothing (no claims, no audience).
fn facing(
    _settings: &[u8],
    _owned: &[u8],
    _public_url: Option<&str>,
    _dialects: &[busbar_contract::plane_calls::DialectFacts],
) -> Result<DoorFacing, String> {
    Ok(DoorFacing::default())
}

/// THE DOUBLE'S REGISTRATION: every data fact its Statement states, read off
/// `door_double_statement.json`.
pub(crate) fn registration() -> PlaneRegistration {
    let doc = statement();
    let section = word(doc, "section");
    PlaneRegistration {
        key: word(doc, "key"),
        section,
        owns: words(doc, "owns"),
        consumes: words(doc, "consumes"),
        secret_refs: words(doc, "secret_refs"),
        admin_routes: admin_routes(),
        admin_openapi: doc["admin_openapi"].is_object().then(|| {
            &*serde_json::to_vec(&doc["admin_openapi"])
                .expect("JSON")
                .leak()
        }),
        label: word(doc, "label"),
        subject_noun: word(doc, "subject_noun"),
        admin_noun: word(doc, "admin_noun"),
        audit_kind: word(doc, "audit_kind"),
        signing: doc["signing"].as_array().map(|s| {
            (
                kept(s[0].as_str().expect("a domain")),
                kept(s[1].as_str().expect("a prefix")),
            )
        }),
        dialects: words(doc, "dialects"),
        scope_kinds: words(doc, "scope_kinds"),
        billable_classes: doc["billable_classes"]
            .as_array()
            .expect("`billable_classes` is a list")
            .iter()
            .map(|c| {
                (
                    kept(c[0].as_str().expect("a class")),
                    kept(c[1].as_str().expect("a family")),
                )
            })
            .collect(),
        fee_units: words(doc, "fee_units"),
        record_kinds: words(doc, "record_kinds"),
        trust_keys: trust_keys(doc),
        caller_credential_refusal: optional(doc, "caller_credential_refusal"),
        validate: Arc::new(move |settings: &[u8]| validate(section, settings)),
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
