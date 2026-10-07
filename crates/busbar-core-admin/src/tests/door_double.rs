// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR ROW of this test binary's roster — a double of the plane door that owns the fourth
//! frozen named-definition section, folded by the kernel's own door fold
//! (`busbar_kernel::plane::door::fold`) and registered after the linked rows — and the instance
//! that serves its stated admin routes on the kernel's serve table.
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
//! * its `serve` ([`publish`]) answers the trust verbs' refusals in the taxonomy the door's answers
//!   carry (an unregistered name `404`; an `approve` body that is not the one-field
//!   `{"fingerprint": …}` document `400` under the MALFORMED-BODY condition, audited nowhere; an
//!   `approve` the double cannot agree with `400` under the INVALID-CONFIG condition, audited
//!   rejected: the double fetches no card, so it has nothing to approve).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};

use busbar_contract::abi::mechanism::call::{Outcome, Span};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, ProjectIn, ProjectOut, RefusalIn,
    RefusalOut, ServeIn, ServeOut, AUDIT_APPLIED, AUDIT_NONE, AUDIT_REJECTED, ROUTE_PUBLIC,
};
use busbar_contract::plane::{
    PinMechanismDecl, TrustKeyDecl, TrustRole, ADMIN_CONDITION_FIELD,
    ADMIN_CONDITION_INVALID_CONFIG, ADMIN_CONDITION_MALFORMED_BODY,
};
use busbar_contract::plane_calls::{
    Answered, DoorFacing, Grow, InstanceDecl, Lent, PieceInFlight, PlaneCalls, PlaneRegistration,
    ServeInFlight, StatedAdminRoute,
};
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

// ── THE INSTANCE THAT SERVES ITS ADMIN ROUTES ───────────────────────────────────────────────────

/// The double's instance, PUBLISHED on the kernel's serve table as the composition root publishes
/// a door's (K-SERVE): its stated admin routes served for as long as the guard lives.
pub(crate) struct Published(String);

impl Drop for Published {
    fn drop(&mut self) {
        busbar_kernel::plane_driver::serve::withdraw(&self.0);
    }
}

/// Publish the double's instance over `settings` (its section, JSON): the registrations it knows
/// are that section's names.
pub(crate) fn publish(settings: &serde_json::Value) -> Published {
    let reg = registration();
    let instance = format!("{}-double", reg.key);
    let registered = settings
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    let routes = reg
        .admin_routes
        .iter()
        .map(|r| busbar_kernel::plane_driver::serve::ServeRoute {
            verb: r.verb.to_string(),
            target: r.target.to_string(),
            flags: r.flags,
            audit_verb: r.audit_verb.to_string(),
        })
        .collect();
    busbar_kernel::plane_driver::serve::publish(
        busbar_kernel::plane_driver::serve::ServeTable {
            instance: instance.clone(),
            audit_kind: reg.audit_kind.to_string(),
            calls: Arc::new(Instance {
                routes: reg.admin_routes.clone(),
                registered,
                next: AtomicU32::new(1),
            }),
            caps: busbar_kernel::plane_driver::BufferCaps::default(),
            routes,
            records: None,
        },
        &[],
    )
    .expect("the double's admin routes publish");
    Published(instance)
}

/// The double's instance: its stated admin routes and the names its section registers.
struct Instance {
    routes: Vec<StatedAdminRoute>,
    registered: Vec<String>,
    next: AtomicU32,
}

/// The `len` bytes at `ptr`.
///
/// # Safety
///
/// `ptr` is NULL or names `len` readable bytes for the call.
unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len)
    }
}

/// One trust-verb answer: its status, the condition it names, its body and its audit row.
struct Answer {
    status: u32,
    condition: Option<&'static str>,
    body: Vec<u8>,
    audit: u32,
}

impl Instance {
    /// The answer to route `route` at `target` with `body`, in the door's taxonomy.
    fn answer(&self, route: u32, target: &[u8], body: &[u8]) -> Answer {
        let refused = |status, condition, words: &str, audit| Answer {
            status,
            condition,
            body: words.as_bytes().to_vec(),
            audit,
        };
        let Some(stated) = self
            .routes
            .get(route as usize)
            .filter(|r| r.flags & ROUTE_PUBLIC == 0)
        else {
            return refused(404, None, "", AUDIT_NONE);
        };
        // The name fills the stated target's one `{param}` segment.
        let path = String::from_utf8_lossy(target);
        let name = stated
            .target
            .split('/')
            .zip(path.split('/'))
            .find(|(t, _)| t.starts_with('{') && t.ends_with('}'))
            .map(|(_, p)| p.to_string());
        let Some(name) = name.filter(|n| self.registered.contains(n)) else {
            return refused(404, None, "", AUDIT_NONE);
        };
        let approving = stated.target.ends_with("/approve");
        if !approving {
            // A PREVIEW: the double fetches no card, so it reports the card unauthenticated.
            let view = serde_json::json!({
                "name": name,
                "state": "error",
                "pin_mechanism": "",
                "fingerprint": null,
                "pin_changed": false,
                "added": [],
                "changed": [],
                "removed": [],
                "observed_skills": 0,
                "failure": "the double fetches no card",
            });
            return Answer {
                status: 200,
                condition: None,
                body: view.to_string().into_bytes(),
                audit: AUDIT_APPLIED,
            };
        }
        // The `approve` body: the one-field `{"fingerprint": …}` document.
        let one_field = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|doc| doc.as_object().cloned())
            .is_some_and(|fields| {
                fields.len() == 1 && fields.get("fingerprint").is_some_and(|f| f.is_string())
            });
        if !one_field {
            return refused(
                400,
                Some(ADMIN_CONDITION_MALFORMED_BODY),
                "the approve body must be `{\"fingerprint\": \"…\"}` naming the fingerprint \
                 `connect` reported",
                AUDIT_NONE,
            );
        }
        refused(
            400,
            Some(ADMIN_CONDITION_INVALID_CONFIG),
            "the card could not be authenticated, so there is nothing to approve: the double \
             fetches no card",
            AUDIT_REJECTED,
        )
    }
}

/// A `serve` answered at once.
struct Served {
    answered: Answered,
    out: ServeOut,
}

// SAFETY: plain data the double wrote; its pointers are never dereferenced.
unsafe impl Send for Served {}

impl std::future::Future for Served {
    type Output = Answered;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Answered> {
        std::task::Poll::Ready(self.answered)
    }
}

impl ServeInFlight for Served {
    fn out(&self) -> Option<ServeOut> {
        Some(self.out)
    }
}

/// The double runs no unit: every `on_piece` answers FAULT at once.
struct NoPiece;

impl std::future::Future for NoPiece {
    type Output = Answered;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Answered> {
        std::task::Poll::Ready(FAULT)
    }
}

impl PieceInFlight for NoPiece {
    fn settled(&mut self) -> Option<Answered> {
        Some(FAULT)
    }
    fn out(&self) -> Option<OnPieceOut> {
        None
    }
}

const FAULT: Answered = Answered {
    outcome: Outcome::Fault,
    short: false,
    disposition: None,
};

impl PlaneCalls for Instance {
    fn now_ns(&self) -> u64 {
        static EPOCH: OnceLock<std::time::Instant> = OnceLock::new();
        u64::try_from(
            EPOCH
                .get_or_init(std::time::Instant::now)
                .elapsed()
                .as_nanos(),
        )
        .unwrap_or(u64::MAX)
    }

    fn arrive(
        &self,
        _: &mut ArriveIn,
        _: &mut ArriveOut,
        _: Grow<'_, ArriveIn, ArriveOut>,
    ) -> Outcome {
        Outcome::Fault
    }

    fn arrived_pool(&self, _: &ArriveOut) -> Option<Vec<u8>> {
        None
    }

    fn refusal(
        &self,
        _: &mut RefusalIn,
        _: &mut RefusalOut,
        _: Grow<'_, RefusalIn, RefusalOut>,
    ) -> Outcome {
        Outcome::Fault
    }

    fn project(
        &self,
        _: &mut ProjectIn,
        _: &mut ProjectOut,
        _: Grow<'_, ProjectIn, ProjectOut>,
    ) -> Outcome {
        Outcome::Ready
    }

    fn cancel(&self, _: Ticket) -> Option<busbar_contract::plane_calls::Cancelled> {
        None
    }

    fn mint(&self) -> Option<Ticket> {
        Some(Ticket {
            slot: self.next.fetch_add(1, Ordering::SeqCst),
            generation: 1,
        })
    }

    fn recycle(&self, _: Ticket) {}

    fn declared(&self) -> InstanceDecl {
        InstanceDecl::default()
    }

    fn driver(&self) -> Option<Ticket> {
        self.mint()
    }

    fn tick(
        &self,
        _: Ticket,
        _: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<u64>> + Send>> {
        Box::pin(std::future::ready(Some(0)))
    }

    fn ready(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<u64>> + Send>> {
        Box::pin(std::future::ready(Vec::new()))
    }

    fn drop_client(&self, _: Ticket) {}

    fn on_piece(&self, _: Ticket, _: OnPieceIn, _: OnPieceOut, _: Lent) -> Box<dyn PieceInFlight> {
        Box::new(NoPiece)
    }

    fn serve(
        &self,
        _: Ticket,
        input: ServeIn,
        mut out: ServeOut,
        _lent: Lent,
    ) -> Box<dyn ServeInFlight> {
        // SAFETY: the host's `in` names its lent buffers, held until this crossing returns.
        let (target, body) = unsafe {
            (
                bytes(input.target.ptr, input.target.len),
                bytes(input.body.ptr, input.body.len),
            )
        };
        let answer = self.answer(input.route, target, body);
        let media = if answer.status == 200 {
            "application/json"
        } else {
            "text/plain"
        };
        let mut fields: Vec<(&str, &str)> = vec![("content-type", media)];
        if let Some(c) = answer.condition {
            fields.push((ADMIN_CONDITION_FIELD, c));
        }
        let arena: usize = fields.iter().map(|(n, v)| n.len() + v.len()).sum();
        if answer.body.len() > input.reply_cap
            || fields.len() > input.fields_cap
            || arena > input.arena_cap
        {
            // SHORT: what each buffer needs; the host grows them and calls once more.
            out.reply_needed = answer.body.len() as u64;
            out.fields_needed = fields.len() as u32;
            out.arena_needed = arena as u64;
            return Box::new(Served {
                answered: Answered {
                    outcome: Outcome::Failed,
                    short: true,
                    disposition: None,
                },
                out,
            });
        }
        let mut at = 0usize;
        // SAFETY: the host's buffers of the capacities checked above.
        unsafe {
            std::ptr::copy_nonoverlapping(answer.body.as_ptr(), input.reply_buf, answer.body.len());
            for (k, (name, value)) in fields.iter().enumerate() {
                let mut span = |word: &str| {
                    let bytes = word.as_bytes();
                    std::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        input.arena_buf.add(at),
                        bytes.len(),
                    );
                    let s = Span {
                        offset: at as u32,
                        len: bytes.len() as u32,
                    };
                    at += bytes.len();
                    s
                };
                let field = OutField {
                    name: span(name),
                    value: span(value),
                };
                *input.fields_buf.add(k) = field;
            }
        }
        out.reply_written = answer.body.len() as u64;
        out.fields_written = fields.len() as u32;
        out.arena_written = at as u64;
        out.status = answer.status;
        out.audit = answer.audit;
        Box::new(Served {
            answered: Answered {
                outcome: Outcome::Ready,
                short: false,
                disposition: None,
            },
            out,
        })
    }
}
