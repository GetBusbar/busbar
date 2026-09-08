//! INVARIANT 6: NO PLANE-LOCAL REIMPLEMENTATION OF A SHARED CONCERN.
//!
//! THE RULE: a property that holds on one plane holds on all of them, or the difference is written
//! down and defended. Three of one release's security defects came from one concern implemented two
//! or three times — one copy gets fixed, the other does not, and the divergence surfaces as a hole.
//!
//! THE MECHANISM, deliberately mechanical rather than clever. Two signals, both facts about the
//! source and neither a judgement call:
//!
//! * SYMBOL — the same TOP-LEVEL name (a free `fn`, or a `struct`/`enum`/`trait`/`union`) declared
//!   in two planes. Top-level is what makes this usable: methods inside `impl` blocks are scoped by
//!   their type, so `new`, `fmt`, `len` and `default` never reach the comparison.
//! * MODULE — the same file name in two planes. A concern can be duplicated without one name
//!   colliding; `mcp/config.rs` beside `a2a/config.rs` is the author's own statement of which
//!   concern each file is. `mod.rs` is excluded — it names a directory, not an idea.
//!
//! COMMENTS ARE NOT DECLARATIONS, and that is load-bearing: the circuit breaker is NOT duplicated —
//! the `breaker` mentions under `mcp/` and `a2a/` are PROSE IN COMMENTS. A grep-for-the-word lint
//! would have reported a duplicate breaker and been wrong. This one reads declarations through
//! [`crate::scan::test_scope`], so prose and `#[cfg(test)]` code are both invisible to it.
//!
//! ## The ledger, and why the gate ships with one
//!
//! Every row in [`ledger`] is duplication that EXISTS TODAY. The lint was proven red against
//! exactly this list before the list was written; the ledger records the debt so the branch is green
//! while unification is done concern by concern, and so a SEVENTH duplicate cannot be added
//! quietly. Two rules make it a ledger and not an amnesty:
//!
//! * a ledger row that no longer matches is a HARD ERROR ([`ROW_STALE_LEDGER`]), so the row cannot
//!   rot, and the moment a unification lands the gate tells you to delete its row;
//! * ADDING a row for NEW code is not a fix, it is evading the check. Shrinking is the only
//!   permitted edit.
//!
//! Class `DEBT` is duplication owed a unification, and its concern id names what is owed. Class
//! `DISTINCT` is a name two unrelated concerns happen to share; it must STILL be written down,
//! because "these two are unrelated" is a claim, and an undocumented claim is indistinguishable
//! from duplication nobody noticed.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::Ctx;
use crate::ere::Ere;
use crate::gates::structure_lint::corpus::{scan_decls, Candidate};
use crate::gates::structure_lint::roots::Addresses;
use crate::gates::structure_lint::{row, Findings, Tables};
use crate::ledger::Row;
use crate::scan;

pub const ROW_UNLEDGERED: &str = "structure-lint:plane-dup:unledgered";
pub const ROW_LEDGER_INTEGRITY: &str = "structure-lint:plane-dup:ledger-integrity";
pub const ROW_STALE_LEDGER: &str = "structure-lint:plane-dup:stale-ledger";

const FN_DECL: &str = r"^(pub[[:space:]]*(\([^)]*\)[[:space:]]*)?)?((async|unsafe|const)[[:space:]]+)*fn[[:space:]]+[A-Za-z_][A-Za-z0-9_]*";
const TYPE_DECL: &str = r"^(pub[[:space:]]*(\([^)]*\)[[:space:]]*)?)?(struct|enum|trait|union)[[:space:]]+[A-Za-z_][A-Za-z0-9_]*";

/// One name found in two planes: what kind of name it is, the name itself, and every site it was
/// declared at. A named type rather than an inline tuple, because a finding wants all three.
type Duplicate = (&'static str, String, Vec<(String, String)>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Class {
    Debt,
    Distinct,
}

/// A concern, and where its single implementation should end up. `-` for an owner means THERE IS NO
/// SHARED HOME YET, which is itself the finding: the concern has only plane-local copies.
#[derive(Debug, Clone)]
pub struct Concern {
    pub id: String,
    pub owner: String,
    pub remedy: String,
}

#[derive(Debug, Clone)]
pub struct LedgerRow {
    /// The duplicated symbol or module name.
    pub name: String,
    pub class: Class,
    /// The concern id for `DEBT`; empty for `DISTINCT`.
    pub concern: String,
    /// The claim somebody signed. Never empty.
    pub note: String,
}

pub fn concerns(a: &Addresses) -> Vec<Concern> {
    let core = &a.core;
    vec![
        Concern {
            id: "outbound-credentials".into(),
            owner: format!("{core}/egress_auth"),
            remedy: "one lease/mint with the grant kinds as parameters, not a copy per plane"
                .into(),
        },
        Concern {
            id: "metering".into(),
            owner: format!("{core}/governance"),
            remedy:
                "one attribution + admission, taken from governance rather than restated per plane"
                    .into(),
        },
        Concern {
            id: "plane-admin-verbs".into(),
            owner: format!("{core}/admin"),
            remedy: "one admin verb surface parameterised by plane, not one handler set per plane"
                .into(),
        },
    ]
}

/// THE LEDGER. Every row here is a signed DISTINCT claim: a name two unrelated concerns share.
/// Four concerns have been RETIRED off this list rather than left with an empty row list — a concern
/// with nothing owed is a heading somebody adds a row under.
pub fn ledger() -> Vec<LedgerRow> {
    let d = |name: &str, note: &str| LedgerRow {
        name: name.to_string(),
        class: Class::Distinct,
        concern: String::new(),
        note: note.to_string(),
    };
    vec![
        d("config.rs", "The parse ORDER these two files shared is gone: plane::config::split_section owns the reserved-key refusals, the two typed lifts and the sequence they run in, and all THREE plane sections are read through it. What is left in each file is that plane's GRAMMAR and nothing else — they share no type, no field, no value rule, no sentence and no caller. What they share is a filename, which on every plane says the same true and un-actionable thing: this is where that section's grammar is written."),
        d("transport.rs", "mcp/client/transport.rs is JSON-RPC FRAMING on one carrier: it composes a POST from a WireLeg and reduces an SSE answer to its last data payload, building no client and pinning no address. a2a/transport.rs is CLIENT CONSTRUCTION: it pins the host to the address net_guard already judged, refuses every name at the resolver, offers busbar's client certificate and reads the peer SPKI off the accepted handshake. Two LAYERS, one noun."),
        d("judge", "mcp/client/argguard.rs judges whether an ARGUMENT is a URL-ish SSRF hazard; a2a/registry.rs judges whether an AGENT CARD matches a task shape. Same verb, unrelated subjects."),
        d("revalidate", "mcp/client/dispatch.rs re-checks a catalogue GENERATION before dispatch; a2a/pushnotify.rs re-resolves a pinned CALLBACK's DNS answer. Both re-check something pinned, but neither shares an input, an output or a failure mode with the other."),
        d("observed_pin", "mcp/connect.rs observed_pin derives the TransportPin actually presented on the wire, substituting the peer certificate SPKI read off the accepted handshake. a2a/pin.rs observed_pin extracts the CardPin carried by an agent-card Sighting. Different input, different output type, different subject — transport certificate identity versus a signed agent card."),
        d("Transport", "mcp/config.rs is a config ENUM naming stdio/http/sse; a2a/fetch.rs is a TRAIT abstracting the HTTP client for tests. Unrelated shapes that share a noun."),
        d("contains", "Each asks its OWN registry off the snapshot whether a name is registered — different container, disjoint key space, no shared value. One membership question asked of two unrelated name sets."),
        d("get", "mcp/admin_view.rs get projects one McpServerDefCfg onto NamedDefView; a2a/admin_view.rs get projects one AgentDefCfg onto the same view. Different config type, a different subset of the view's columns populated, no shared field and no shared caller."),
        d("list", "The vector twins of get and distinct for the same reason: the same iterate-and-project shape run over two unrelated registries and two unrelated config types, sharing only the verb."),
        d("openapi_schemas", "Each is its plane's half of PlaneDecl::openapi_schemas writing into the SHARED schemars generators — different response types, a request body on one plane and none on the other, different paths and different verbs."),
        d("reresolve_gates", "Each is its plane's half of the config-swap gate rebuild, moved out of core so core names no plane registry type — different gate field written, different registry read, different resolver entry point."),
        d("metadata_route", "Both serve the same well-known path and hand their Metadata to the ONE shared renderer, so the RFC 9728 rendering is NOT duplicated. What is left in each is the plane's own wrapper: two Words impls, two app-access seams, one shared renderer beneath both."),
        d("admin_view.rs", "Each plane's admin_view.rs is that plane's own read-side adapter over the SHARED admin CRUD, reached through PlaneDecl so core admin names no plane config type. Same filename because both say the same true and un-actionable thing over disjoint config types, disjoint view columns and disjoint verb sets."),
    ]
}

pub fn finding_duplicate(kind: &str, name: &str, where_: &str) -> String {
    format!("PLANE-DUPLICATE ({kind}): `{name}` — {where_}")
}

pub fn finding_malformed(name: &str, why: &str) -> String {
    format!("MALFORMED-LEDGER: `{name}` — {why}")
}

pub fn finding_stale(name: &str) -> String {
    format!(
        "STALE-LEDGER: `{name}` is on the plane ledger but is no longer duplicated across planes. \
         If you unified it — thank you — DELETE its row."
    )
}

pub fn scan(cx: &Ctx, a: &Addresses, t: &Tables, f: &mut Findings) {
    let fn_decl = Ere::new(FN_DECL).expect("the fn declaration pattern compiles");
    let type_decl = Ere::new(TYPE_DECL).expect("the type declaration pattern compiles");

    // The plane corpora are read separately from the candidate corpus, because a plane root is
    // resolved and may sit anywhere under `crates/`.
    let planes: Vec<(&str, &str)> = vec![("mcp", &a.mcp), ("a2a", &a.a2a)];
    // A symbol records EVERY site it was declared at (two copies in one plane and one in the other
    // is still a cross-plane duplicate, and the reader wants all three); a module name records the
    // first path per plane, because a directory tree repeating a filename inside ONE plane is not
    // the signal — the same distinction the shell's two collators drew.
    let mut symbol_homes: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut module_homes: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();

    for (key, dir) in &planes {
        // A PLANE THIS RULE COULD NOT READ TAKES THE WHOLE COMPARISON DOWN WITH IT, and saying so
        // is the fix. A name counts as duplicated only when it is seen in TWO planes, so losing one
        // plane's file set makes every cross-plane duplicate involving it disappear and the BAN row
        // passes over a comparison that never happened.
        //
        // The gate did go red — but on the wrong row and with the wrong instruction. Every ledger
        // row for a name in the lost plane fell out of `seen` and was reported STALE-LEDGER, whose
        // remedy reads "If you unified it — thank you — DELETE its row". So a developer whose mcp
        // root moved was told to delete thirteen signed claims about duplication that is still
        // there. And that incidental red is not a floor: on the day the ledger is empty — every
        // duplication unified, which is what the ledger exists to drive towards — a lost plane is a
        // clean green on all three rows.
        let files = match cx.walk(
            &crate::ctx::WalkSpec::new([(*dir).to_string()])
                .ext("rs")
                .exclude(["/tests/"]),
        ) {
            Ok(files) => files,
            Err(e) => {
                let why = format!(
                    "the `{key}` plane's source would not list ({e}), so no name could be compared \
                     ACROSS planes at all — and a comparison that did not happen names no \
                     duplicate, which is the passing answer to this ban"
                );
                for id in [ROW_UNLEDGERED, ROW_LEDGER_INTEGRITY, ROW_STALE_LEDGER] {
                    f.did_not_run.push((id, why.clone()));
                }
                return;
            }
        };
        for s in files {
            let rel = s.rel_str();
            let c = Candidate {
                rel: rel.clone(),
                lines: scan::test_scope(&s.text),
            };
            for (sym, line) in scan_decls(&c, &fn_decl, &type_decl) {
                symbol_homes
                    .entry(sym)
                    .or_default()
                    .push(((*key).to_string(), format!("{rel}:{line}")));
            }
            // `mod.rs` is Rust's spelling of "this directory", not a concern.
            if let Some(base) = rel.rsplit('/').next() {
                if base != "mod.rs" {
                    module_homes
                        .entry(base.to_string())
                        .or_default()
                        .entry((*key).to_string())
                        .or_insert(rel.clone());
                }
            }
        }
    }

    let mut duplicated: Vec<Duplicate> = Vec::new();
    for (name, sites) in &symbol_homes {
        let planes_named: BTreeSet<&str> = sites.iter().map(|(p, _)| p.as_str()).collect();
        if planes_named.len() >= 2 {
            duplicated.push(("symbol", name.clone(), sites.clone()));
        }
    }
    for (name, homes) in &module_homes {
        if homes.len() >= 2 {
            duplicated.push((
                "module",
                name.clone(),
                homes.iter().map(|(p, l)| (p.clone(), l.clone())).collect(),
            ));
        }
    }

    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (kind, name, sites) in &duplicated {
        seen.insert(name.clone());
        let Some(rowdef) = t.plane_ledger.iter().find(|r| &r.name == name) else {
            let where_ = sites
                .iter()
                .map(|(p, loc)| format!("{p}:{loc}"))
                .collect::<Vec<_>>()
                .join(" ");
            f.unledgered.push(finding_duplicate(kind, name, &where_));
            continue;
        };
        if rowdef.class == Class::Debt && !t.plane_concerns.iter().any(|c| c.id == rowdef.concern) {
            f.ledger_integrity.push(finding_malformed(
                name,
                &format!(
                    "it names concern `{}`, which is not a declared concern",
                    rowdef.concern
                ),
            ));
        }
    }

    // THE LEDGER MAY NOT ROT, and it may not be sloppy either. A row for duplication that is no
    // longer there is a row nobody will delete, and a ledger nobody prunes stops being a debt list
    // and becomes a permanent exemption.
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for r in &t.plane_ledger {
        *counts.entry(r.name.as_str()).or_default() += 1;
    }
    for r in &t.plane_ledger {
        if r.note.trim().is_empty() {
            f.ledger_integrity
                .push(finding_malformed(&r.name, "its WHY is empty"));
        }
        if r.note.contains('|') || r.name.contains('|') {
            f.ledger_integrity.push(finding_malformed(
                &r.name,
                "a cell carries a literal `|`, the separator the legacy row format uses",
            ));
        }
        if r.class == Class::Distinct && !r.concern.is_empty() {
            f.ledger_integrity.push(finding_malformed(
                &r.name,
                &format!(
                    "it is DISTINCT, so its concern field must be empty, not `{}`",
                    r.concern
                ),
            ));
        }
        if counts.get(r.name.as_str()).copied().unwrap_or(0) > 1 {
            f.ledger_integrity.push(finding_malformed(
                &r.name,
                "it has more than one row; one name, one verdict",
            ));
        }
        if !seen.contains(&r.name) {
            f.stale_ledger.push(finding_stale(&r.name));
        }
    }
}

pub fn rows(f: &Findings) -> Vec<Row> {
    vec![
        row(
            ROW_UNLEDGERED,
            "no name is declared in two planes without a signed claim about why",
            "a shared concern grew a second, plane-local implementation",
            &f.unledgered,
        ),
        row(
            ROW_LEDGER_INTEGRITY,
            "every ledger row is a complete, single, well-classed claim",
            "a ledger row is malformed, duplicated, or names a concern nobody declared",
            &f.ledger_integrity,
        ),
        row(
            ROW_STALE_LEDGER,
            "every ledger row still describes duplication that exists",
            "a ledger row outlived the duplication it recorded, which is an exemption nobody prunes",
            &f.stale_ledger,
        ),
    ]
}
