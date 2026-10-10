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
//! A ROW SIGNS FOR THE PLANES IT WAS ARGUED FOR, and a declared concern must have a DEBT row owing
//! against it. Both were missing (items 223, 236): a row matched by name alone silently excused the
//! same name in every plane added after it was written, and a concern with nothing owed read as an
//! owed unification while the gate tracked none. The first is an unledgered finding, the second a
//! stale-ledger one.
//!
//! EVERY DECLARED PLANE IS COMPARED WITH EVERY OTHER (items 184, 223): the corpora are the plane
//! homes [`super::roots`] derives from the tree's `PLANE_DECL` declarations, not a list of two.
//!
//! Class `DEBT` is duplication owed a unification, and its concern id names what is owed. Class
//! `DISTINCT` is a name two unrelated concerns happen to share; it must STILL be written down,
//! because "these two are unrelated" is a claim, and an undocumented claim is indistinguishable
//! from duplication nobody noticed.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::Ctx;
use crate::ere::Ere;
use crate::gates::structure_lint::corpus::{scan_decls, test_scoped, Candidate, Corpus};
use crate::gates::structure_lint::roots::Addresses;
use crate::gates::structure_lint::{row, Findings, Tables};
use crate::ledger::Row;

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
    /// The planes the claim was argued for. A name that is ALSO declared in a plane not listed
    /// here is a copy nobody signed for, and is reported as unledgered.
    pub planes: Vec<String>,
}

/// The declared concerns. NONE: `outbound-credentials`, `metering` and `plane-admin-verbs` have no
/// DEBT row left, so each was RETIRED — a concern with nothing owed is a heading somebody adds a
/// row under. A new concern is declared here together with the DEBT row that owes against it.
pub fn concerns(_a: &Addresses) -> Vec<Concern> {
    Vec::new()
}

/// THE LEDGER. Every row here is a signed DISTINCT claim: a name two unrelated concerns share.
/// Seven concerns have been RETIRED off this list rather than left with an empty row list — a concern
/// with nothing owed is a heading somebody adds a row under.
pub fn ledger() -> Vec<LedgerRow> {
    // Every row below was argued for the MCP and A2A planes — the only pair the scan could see
    // when each was written — and signs for exactly that pair.
    let d = |name: &str, note: &str| LedgerRow {
        name: name.to_string(),
        class: Class::Distinct,
        concern: String::new(),
        note: note.to_string(),
        planes: vec!["mcp".to_string(), "a2a".to_string()],
    };
    // FLIP-STREAMING: the streaming plane's home moved from `busbar-voice` to its door crate
    // `busbar-plane-streaming`, and every row below was argued for exactly the planes it names
    // against that crate. NOT signed, because they are copies and not distinct concerns: `settle`
    // (decisions' `plane_door` and streaming's `piece`), `absolute` (a2a's `serve` and streaming's
    // `door`) and `claim` (mcp's `tool_claims` and streaming's `claims`) — those stay findings.
    let s = |name: &str, planes: &[&str], note: &str| LedgerRow {
        name: name.to_string(),
        class: Class::Distinct,
        concern: String::new(),
        note: note.to_string(),
        planes: planes.iter().map(|p| (*p).to_string()).collect(),
    };
    vec![
        s("claims.rs", &["decisions", "streaming"], "Each plane's own claim table: decisions declares two exact-path claims under its decision-inbound scheme, streaming five dialect-tagged claims over ws and http under its streaming-key scheme. The table is per plane by construction; the claim grammar they both build is the contract's."),
        s("diagnostics.rs", &["mcp", "streaming"], "Each plane's own diagnostic catalogue handed to the root's install_diagnostics: the MCP_* entries and STREAMING_SESSION_LEASE_EXHAUSTED. They share no entry; the catalogue type is the contract's."),
        s("door.rs", &["mcp", "streaming"], "Each plane's door declaration: its Statement tail, its ROUTES table, its snapshot and settings. A door is per plane by definition; the ABI it fills is the contract's."),
        s("driven.rs", &["decisions", "streaming"], "Each plane's answers to the kernel plane driver's crossings (arrive, on_piece, refusal): jev's systemone operation for decisions, the mint and SDP-offer doors for streaming. The slots are the ABI's; the answers are the plane's."),
        s("meta.rs", &["decisions", "streaming"], "Each plane's PlaneMeta with its own meter classes: decisions' single decision class, streaming's audio token classes. The classes are what makes each plane's meter its own."),
        s("usage.rs", &["llm", "streaming"], "Unrelated: llm's engine file bills a non-streaming token response to a key's budget (record_resp_usage); streaming's codec file is the Realtime and Gemini duplex usage IR and its float-tolerant count reader."),
        s("Answer", &["mcp", "streaming"], "Unrelated: mcp's Answer is the reply to one MCP arrival (here with a status and body, or far); streaming's is a RequestUnit's per-piece answer (nothing, attempt, to the far end, to the caller, refused)."),
        s("Arrival", &["mcp", "streaming"], "Unrelated: mcp's Arrival is one carrier line read (a LineUnit and an optional dispatch body); streaming's is its arrive slot's answer (door, op class, dialect)."),
        s("CredentialPlacement", &["a2a", "streaming"], "Unrelated: a2a's places a leased credential in an HTTP header (Authorization Bearer or a named header); streaming's places a provider key on a WebSocket dial per dialect (a query parameter or a prefixed header)."),
        s("Dialect", &["a2a", "streaming"], "Unrelated: a2a's Dialect is the push-config verb spelling (V03 or V10); streaming's is its voice dialect roster (OpenAI Realtime, Gemini Live, Twilio Media Streams, one-shot transcribe and tts)."),
        s("Held", &["mcp", "streaming"], "Unrelated: mcp's Held is one generation's catalogue, tools section and pools; streaming's is a one-request door unit's state (its RequestUnit, what it owes, a short answer)."),
        s("Outbound", &["a2a", "streaming"], "Unrelated: a2a's Outbound is the caller's request in three forms for the outbound hop; streaming's is a session frame plan (upstream and downlink wire events, close, a refused reply)."),
        s("Reply", &["mcp", "streaming"], "Unrelated: mcp's Reply is a caller's answer to one of busbar's own asks (answered or failed); streaming's is the caller's HTTP answer (status, fields, body, the rtc call id)."),
        s("Route", &["mcp", "streaming"], "Each plane's own row type for its door's ROUTES table: mcp's carries verb, target, carrier and open; streaming's adds upgrade, auth, dialect and refusal dialect. The row is shaped by what the plane routes on."),
        s("Session", &["mcp", "streaming"], "Unrelated: mcp's Session is the carrier session's state (streams, buffered events, revision, owner); streaming's is the Realtime or Gemini enum over a codec's SessionUnit."),
        s("Unit", &["decisions", "streaming"], "Unrelated: decisions' Unit is one unit's attempt, reading and owed bytes in its plane door; streaming's is the Realtime or Gemini codec enum its session door dispatches over."),
        s("arrive", &["mcp", "decisions", "streaming"], "Each plane's body for the arrive slot: mcp reads a carrier line, decisions classifies verb and target through its ops table, streaming maps a claim index to a door. The slot is the ABI's; what an arrival means is the plane's."),
        s("open", &["mcp", "streaming"], "Unrelated: mcp's door_listen open starts a subscriptions/listen subscription and its tool_claims open builds a claim with no credential scheme; streaming's constructs a live Session for a door."),
        s("outbound", &["mcp", "streaming"], "Unrelated: mcp's builds the OutboundCall request (POST, path, body) for one tool-call round; streaming's is a const naming a connection need on the provider egress class."),
        s("parse", &["a2a", "streaming"], "Unrelated: a2a's reads an agent card value into an AgentCard; streaming's reads wire bytes into a JSON value in its codec."),
        s("read_settings", &["decisions", "streaming"], "Each plane judges its own settings blob by its own grammar and answers its own section for an empty one: DecisionsSection for decisions, StreamsCfg for streaming. The grammar is the plane's."),
        s("refusal_body", &["decisions", "streaming"], "Each plane renders the kernel's refusal in its own wire's error shape: jev's error code and message for decisions, the OpenAI REST error envelope for streaming. The status and text are the kernel's; the shape is the dialect's."),
        d("config.rs", "The parse ORDER these two files shared is gone: plane::config::split_section owns the reserved-key refusals, the two typed lifts and the sequence they run in, and all THREE plane sections are read through it. What is left in each file is that plane's GRAMMAR and nothing else — they share no type, no field, no value rule, no sentence and no caller. What they share is a filename, which on every plane says the same true and un-actionable thing: this is where that section's grammar is written."),
        // STRUCK at P3 DEL-MCP (ARCHITECT 2026-10-05: busbar-mcp deleted, the mcp plane is served
        // through its door crate alone): `transport.rs`, `judge`, `revalidate`, `observed_pin`,
        // `contains`, `get`, `list`, `openapi_schemas`, `reresolve_gates`, `metadata_route` and
        // `admin_view.rs`. Each signed a distinct claim whose mcp half was a file of the deleted
        // engine; with the engine gone none of the eleven is duplicated across planes any more, and
        // `plane-dup:stale-ledger` names every one. A row that outlived its duplication is an
        // exemption nobody prunes.
    ]
}

pub fn finding_duplicate(kind: &str, name: &str, where_: &str) -> String {
    format!("PLANE-DUPLICATE ({kind}): `{name}` — {where_}")
}

pub fn finding_malformed(name: &str, why: &str) -> String {
    format!("MALFORMED-LEDGER: `{name}` — {why}")
}

pub fn finding_stale_concern(id: &str) -> String {
    format!(
        "STALE-CONCERN: `{id}` is a declared concern and no DEBT row owes anything against it. \
         If it was unified — thank you — RETIRE the concern."
    )
}

pub fn finding_stale(name: &str) -> String {
    format!(
        "STALE-LEDGER: `{name}` is on the plane ledger but is no longer duplicated across planes. \
         If you unified it — thank you — DELETE its row."
    )
}

pub fn scan(cx: &Ctx, a: &Addresses, corpus: Option<&Corpus>, t: &Tables, f: &mut Findings) {
    let fn_decl = Ere::new(FN_DECL).expect("the fn declaration pattern compiles");
    let type_decl = Ere::new(TYPE_DECL).expect("the type declaration pattern compiles");

    // The plane corpora are read separately from the candidate corpus, because a plane root is
    // resolved and may sit anywhere under `crates/`.
    //
    // EVERY PLANE, and every pair of them. This was `[("mcp", ..), ("a2a", ..)]` — two corpora of
    // the five the tree declares — so a copy between voice and a2a (voice's `mount::absolute`,
    // whose own doc calls it "the A2A `serve::absolute` discipline, kept local"), or between any
    // pair without both mcp and a2a in it, could not be seen, and so could not be required to
    // carry a signed row either (items 184, 223).
    let planes: Vec<(&str, &str)> = a
        .planes
        .iter()
        .map(|p| (p.key.as_str(), p.home.as_str()))
        .collect();
    // A symbol records EVERY site it was declared at (two copies in one plane and one in the other
    // is still a cross-plane duplicate, and the reader wants all three); a module name records the
    // first path per plane, because a directory tree repeating a filename inside ONE plane is not
    // the signal — the same distinction the shell's two collators drew.
    let mut symbol_homes: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut module_homes: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();

    // THE PLANE FILES. With a candidate corpus they are read out of it — already walked, already
    // lexed, and with test scope already answered over the WHOLE tree (the `#[cfg(test)] mod x;`
    // that makes a file a test file sits in its parent, which one plane's home may not hold). The
    // corpus below its floor is the one case that walks again, because this rule reads the plane
    // homes directly and an empty candidate list says nothing about them.
    let mut plane_files: Vec<(&str, Vec<Candidate>)> = Vec::new();
    match corpus {
        Some(corpus) => {
            for (key, dir) in &planes {
                let prefix = vec![format!("{dir}/")];
                let files: Vec<Candidate> = corpus.production_in_scope(&prefix).cloned().collect();
                plane_files.push((key, files));
            }
        }
        None => {
            let test_only = cx
                .walk(&crate::ctx::WalkSpec::new([super::roots::CRATES]).ext("rs"))
                .map(|all| test_scoped(&all))
                .unwrap_or_default();
            for (key, dir) in &planes {
                let Ok(files) = cx.walk(
                    &crate::ctx::WalkSpec::new([(*dir).to_string()])
                        .ext("rs")
                        .exclude(["/tests/", "/benches/"]),
                ) else {
                    continue;
                };
                let files: Vec<Candidate> = files
                    .into_iter()
                    .filter(|s| !test_only.contains(&s.rel_str()))
                    .map(|s| Candidate {
                        rel: s.rel_str(),
                        lines: super::corpus::scope_lines(&s.rel_str(), &s.text),
                    })
                    .collect();
                plane_files.push((key, files));
            }
        }
    }

    for (key, files) in &plane_files {
        for c in files {
            let rel = &c.rel;
            for (sym, line) in scan_decls(c, &fn_decl, &type_decl) {
                symbol_homes
                    .entry(sym)
                    .or_default()
                    .push(((*key).to_string(), format!("{rel}:{line}")));
            }
            // `mod.rs` is Rust's spelling of "this directory", not a concern — and `lib.rs` and
            // `main.rs` are its spelling of "this crate", which is what a plane that IS a crate
            // (llm, voice, decision) is rooted at. Three planes' crate roots sharing a filename is
            // the language's naming, not a concern duplicated.
            if let Some(base) = rel.rsplit('/').next() {
                if !matches!(base, "mod.rs" | "lib.rs" | "main.rs") {
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
        let where_ = sites
            .iter()
            .map(|(p, loc)| format!("{p}:{loc}"))
            .collect::<Vec<_>>()
            .join(" ");
        let Some(rowdef) = t.plane_ledger.iter().find(|r| &r.name == name) else {
            f.unledgered.push(finding_duplicate(kind, name, &where_));
            continue;
        };
        // A SIGNED CLAIM IS ABOUT THE PLANES IT WAS SIGNED FOR. `config.rs` was argued for mcp and
        // a2a; the same filename in voice is a third file nobody has read, and a row matched by
        // name alone would have absorbed it — and every future plane's copy — without a word.
        let declared_in: BTreeSet<&str> = sites.iter().map(|(p, _)| p.as_str()).collect();
        let signed_for: BTreeSet<&str> = rowdef.planes.iter().map(String::as_str).collect();
        if declared_in != signed_for {
            f.unledgered.push(finding_duplicate(
                kind,
                name,
                &format!(
                    "{where_} (the ledger row signs for {} only)",
                    signed_for.iter().copied().collect::<Vec<_>>().join("+")
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
        // A DEBT row is a promise to unify, and the concern is what is promised. Checked on EVERY
        // row, not only on a name the scan happened to find duplicated: the check used to sit
        // behind the duplicate match, where a row naming no concern at all was never read.
        if r.class == Class::Debt && !t.plane_concerns.iter().any(|c| c.id == r.concern) {
            f.ledger_integrity.push(finding_malformed(
                &r.name,
                &format!(
                    "it is DEBT and names concern `{}`, which is not a declared concern",
                    r.concern
                ),
            ));
        }
        if r.planes.len() < 2 {
            f.ledger_integrity.push(finding_malformed(
                &r.name,
                "a row signs for the PLANES it was argued for, and a duplicate needs two",
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

    // A CONCERN NOTHING IS OWED AGAINST is a heading somebody adds a row under — the module doc's
    // own reason for retiring four of them. It is the other half of the ledger rotting, and it was
    // invisible: no DEBT row existed, so the three declared concerns read as three owed
    // unifications while the gate tracked none (item 236).
    for c in &t.plane_concerns {
        if !t
            .plane_ledger
            .iter()
            .any(|r| r.class == Class::Debt && r.concern == c.id)
        {
            f.stale_ledger.push(finding_stale_concern(&c.id));
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
