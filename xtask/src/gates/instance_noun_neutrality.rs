//! `cargo xtask gate instance-noun-neutrality` — THE WHOLE-APP KIND-NEUTRALITY WITNESS.
//!
//! THE OWNER'S RULE, RATIFIED. A concrete plugin-INSTANCE noun may appear ONLY inside its own
//! plugin crate family. Nothing else in the entire application — not the composition root, not a
//! sibling plugin, not a shared crate, not core, not the substrate — is allowed to KNOW a concrete
//! instance. This is the single enforceable witness for DECISION #1 (core names zero plane/plugin
//! types), DECISION #8 (the broker law: plugins never talk to each other), and DECISION #18
//! (streaming is the plane; voice is a dialect inside it). It generalises `plane-abi-neutrality`
//! (hot lane only) and `plane-transport-neutrality` (neutral crates only) to EVERY crate and EVERY
//! one of the seven plugin kinds: plane, transport, store, auth, secret, hook, export.
//!
//! THE MENTAL MODEL THAT MAKES TESTS FIRST-CLASS. Every plugin is written by a third-party team;
//! we build only the kernel. A plugin tests itself; the kernel never tests or names a plugin. So a
//! concrete instance noun in a NON-family crate is a leak whether it sits in production code or in
//! a test module — the ban is enforced identically over both. Comments are the one thing NOT
//! scanned: a doc comment discussing the architecture legitimately names `mcp`, and so does this
//! very file. The scan strips comments (line and block, string literals preserved) and judges the
//! code that remains, test code included.
//!
//! ## WHY A NOUN IS EITHER A PRECISE TOKEN OR NOT SCANNED AT ALL
//!
//! A census that over-flags is noise nobody reads. Every noun below is matched two ways and only
//! two: as a WORD (case-insensitive, with `_` as a boundary, so `mcp_codec` and `handle_mcp` both
//! hit but `rustls` does not hit `tls` and `assess` does not hit `sse`), and as a CamelCase segment
//! (`McpTransport`, `SdpOffer`). Nouns whose bare 2–3 char form is hopelessly ambiguous are matched
//! ONLY on an unambiguous identifier (`sigv4`, never bare `aws`; the example/test plugins on their
//! full crate identifier), never on a raw substring. The result is a census of REAL couplings.
//!
//! ## THE BASELINE IS A BURNDOWN LEDGER, NOT AN EXCUSE
//!
//! Real leaks exist today (the composition root names all four planes; auth schemes are DECISION #3
//! internal units and leak heavily into core; sibling planes reference one another). The gate is
//! therefore RED today, ON PURPOSE. `qa/instance-noun-neutrality.toml` records EACH current leak as
//! a `[[leak]]` row with its category and owning wave, so the red is a documented burndown rather
//! than a wall of noise. Two rows keep the ledger honest: `:undocumented` reds on any live leak the
//! baseline does not name (this is what bites a NEW coupling), and `:stale-baseline` reds on any
//! baseline row whose leak is gone (so the ledger cannot outlive the debt it tracked). The gate
//! goes GREEN only when the baseline is empty — i.e. when the app knows no concrete instance
//! outside its family.
//!
//! Regenerate the baseline from the live census with
//! `XTASK_INSN_EMIT_BASELINE=1 cargo xtask gate instance-noun-neutrality 2>qa/instance-noun-neutrality.toml`
//! then review every row by hand — the emitter derives category and wave mechanically; a human
//! confirms the reason.

use std::collections::BTreeMap;

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{execute, prove_rows_red_at, Case, Expect, Gate, Report};
use crate::ledger::{Row, Status, Verdict};
use crate::scan::strip_comment_line;

pub const BASELINE: &str = "qa/instance-noun-neutrality.toml";
const CROSS_ROW: &str = "instance-noun-neutrality";

pub fn row_id(key: &str) -> String {
    format!("{CROSS_ROW}:{key}")
}
pub const ROW_SCAN_FLOOR: &str = "instance-noun-neutrality:scan-floor";
pub const ROW_UNDOCUMENTED: &str = "instance-noun-neutrality:undocumented";
pub const ROW_STALE: &str = "instance-noun-neutrality:stale-baseline";

/// THE NEEDLE every per-noun census row carries. `--all` excuses this gate's standing red only when
/// every red row names it (see the REPORT_ONLY posture); the `:undocumented` and `:stale-baseline`
/// rows deliberately DO NOT carry it, so a new coupling or a stale ledger row scores under `--all`.
pub const TRACKED_NEEDLE: &str = "tracked known-debt";

/// One plugin-instance noun, its kind, the crate family that is allowed to name it, and the tokens
/// it is matched on. A crate is "in the family" when its directory name (`busbar-mcp`) is listed.
struct Noun {
    key: &'static str,
    kind: &'static str,
    /// Crate directory names under `crates/` that MAY name this instance. Empty = the backend has
    /// no crate in this tree yet, so ANY reference to it is premature coupling.
    family: &'static [&'static str],
    /// Word/CamelCase tokens. All are lowercase; the CamelCase rule capitalises the first letter.
    tokens: &'static [&'static str],
}

// ── PLANES (DECISION #1 / #18) ────────────────────────────────────────────────────────────────
const FAM_MCP: &[&str] = &["busbar-mcp", "busbar-plane-mcp", "busbar-mcp-codec"];
const FAM_A2A: &[&str] = &["busbar-a2a", "busbar-plane-a2a", "busbar-a2a-codec"];
const FAM_LLM: &[&str] = &["busbar-llm", "busbar-plane-llm", "busbar-llm-codec"];
// streaming + voice share one family. `busbar-streaming-codec` is named by the owner's map but does
// not exist in this tree; `busbar-plane-streaming` does. The family is what EXISTS.
const FAM_STREAM: &[&str] = &[
    "busbar-plane-streaming",
    "busbar-plane-streaming",
    "busbar-streaming",
    "busbar-streaming-codec",
];

// ── TRANSPORTS (each concrete transport is its own crate) ─────────────────────────────────────
const FAM_HTTP: &[&str] = &["busbar-transport-http"];
const FAM_WS: &[&str] = &["busbar-transport-ws"];
const FAM_STDIO: &[&str] = &["busbar-transport-stdio"];
const FAM_TCP: &[&str] = &["busbar-transport-tcp"];
const FAM_TLS: &[&str] = &["busbar-transport-tls"];
const FAM_SSE: &[&str] = &["busbar-transport-sse"];
const FAM_GRPC: &[&str] = &["busbar-transport-grpc"];

// ── STORES (no backend crate exists in this tree — any reference is premature coupling) ────────
const FAM_NONE: &[&str] = &[];

// ── AUTH SCHEMES (DECISION #3: currently internal units, so heavy known-debt into core/units) ──
const FAM_AUTH: &[&str] = &["auth-static-plugin", "auth-admin-tokens", "busbar-oauth2"];

// ── SECRET / HOOK / EXPORT (self-contained example/test plugins; matched on crate identity) ────
const FAM_SECRET: &[&str] = &["secret-example-plugin"];
const FAM_HOOK: &[&str] = &["hook-test-plugin"];
const FAM_EXPORT: &[&str] = &["export-example-plugin"];

const NOUNS: &[Noun] = &[
    // Planes.
    Noun { key: "mcp", kind: "plane", family: FAM_MCP, tokens: &["mcp"] },
    Noun { key: "a2a", kind: "plane", family: FAM_A2A, tokens: &["a2a"] },
    Noun { key: "llm", kind: "plane", family: FAM_LLM, tokens: &["llm"] },
    Noun { key: "streaming", kind: "plane", family: FAM_STREAM, tokens: &["streaming"] },
    Noun { key: "streaming", kind: "plane", family: FAM_STREAM, tokens: &["streaming"] },
    // Transports — KEYED ON THE PLUGIN-INSTANCE IDENTIFIER, NOT THE BARE PROTOCOL WORD. Bare
    // `http`/`tcp`/`tls`/… are the wire protocols and the `http` crate's own types, used as neutral
    // plumbing across nearly every crate (URL schemes, `http::HeaderMap`, OTLP endpoints); censusing
    // those is noise, not plugin-instance coupling. What #1/#8 forbid is a crate reaching for the
    // concrete transport PLUGIN, which reads `busbar_transport_http` / `transport_http` /
    // `transport-http` (the crate, module and feature spellings). Those are what the census tracks.
    Noun { key: "http", kind: "transport", family: FAM_HTTP,
           tokens: &["busbar_transport_http", "transport_http", "transport-http"] },
    Noun { key: "ws", kind: "transport", family: FAM_WS,
           tokens: &["busbar_transport_ws", "transport_ws", "transport-ws"] },
    Noun { key: "stdio", kind: "transport", family: FAM_STDIO,
           tokens: &["busbar_transport_stdio", "transport_stdio", "transport-stdio"] },
    Noun { key: "tcp", kind: "transport", family: FAM_TCP,
           tokens: &["busbar_transport_tcp", "transport_tcp", "transport-tcp"] },
    Noun { key: "tls", kind: "transport", family: FAM_TLS,
           tokens: &["busbar_transport_tls", "transport_tls", "transport-tls"] },
    Noun { key: "sse", kind: "transport", family: FAM_SSE,
           tokens: &["busbar_transport_sse", "transport_sse", "transport-sse"] },
    Noun { key: "grpc", kind: "transport", family: FAM_GRPC,
           tokens: &["busbar_transport_grpc", "transport_grpc", "transport-grpc"] },
    // Stores — no backend crate in this tree, so the family is empty and every hit is a leak.
    Noun { key: "postgres", kind: "store", family: FAM_NONE, tokens: &["postgres"] },
    Noun { key: "mysql", kind: "store", family: FAM_NONE, tokens: &["mysql"] },
    Noun { key: "valkey", kind: "store", family: FAM_NONE, tokens: &["valkey", "redis"] },
    Noun { key: "sqlite", kind: "store", family: FAM_NONE, tokens: &["sqlite"] },
    // Auth schemes — matched on the unambiguous scheme name only. `aws` (broad infra) is left to
    // its precise scheme spelling `sigv4`.
    Noun { key: "bearer", kind: "auth", family: FAM_AUTH, tokens: &["bearer"] },
    Noun { key: "mtls", kind: "auth", family: FAM_AUTH, tokens: &["mtls"] },
    Noun { key: "sigv4", kind: "auth", family: FAM_AUTH, tokens: &["sigv4"] },
    Noun { key: "gcp", kind: "auth", family: FAM_AUTH, tokens: &["gcp"] },
    Noun { key: "spki", kind: "auth", family: FAM_AUTH, tokens: &["spki"] },
    // Secret / hook / export — bare `secret`/`hook`/`export` are core subsystems (secret-ref,
    // busbar-core-hooks, export verbs), so the ENFORCEABLE instance token is the example/test
    // plugin's own crate identifier. Zero false positives; reds only if core names the plugin.
    Noun { key: "secret", kind: "secret", family: FAM_SECRET, tokens: &["secret_example_plugin"] },
    Noun { key: "hook", kind: "hook", family: FAM_HOOK, tokens: &["hook_test_plugin"] },
    Noun { key: "export", kind: "export", family: FAM_EXPORT, tokens: &["export_example_plugin"] },
];

const CLEAN: &str = "the scan cleared its floors and named nothing";
const DID_NOT_RUN: &str = "nothing was read, and nothing read is not a neutral app";

/// One live leak: an instance noun named in a crate outside its family.
#[derive(Clone)]
struct Leak {
    noun: &'static str,
    kind: &'static str,
    file: String,
    count: usize,
    category: &'static str,
    wave: &'static str,
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

/// A whole-word, case-insensitive hit of a lowercase needle where the identifier boundary is
/// `[^a-z0-9]` — SO `_` IS A BOUNDARY. `handle_mcp` and `mcp_codec` hit; `rustls`, `assess`,
/// `settles`, `rows`, `throws` do not.
fn word_ci(lower: &str, needle: &str) -> bool {
    let hay: Vec<char> = lower.chars().collect();
    let n: Vec<char> = needle.chars().collect();
    if n.is_empty() || n.len() > hay.len() {
        return false;
    }
    for i in 0..=(hay.len() - n.len()) {
        if hay[i..i + n.len()] != n[..] {
            continue;
        }
        let before_ok = i == 0 || !is_word_char(hay[i - 1]);
        let after_ok = i + n.len() == hay.len() || !is_word_char(hay[i + n.len()]);
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// A Capitalized needle followed by an uppercase letter, a non-identifier character, or end of
/// line: `McpTransport`, `WsFrame`, a bare `Sdp`.
fn camel_hit(code: &str, needle: &str) -> bool {
    let chars: Vec<char> = code.chars().collect();
    let mut cap: Vec<char> = needle.chars().collect();
    if cap.is_empty() {
        return false;
    }
    cap[0] = cap[0].to_ascii_uppercase();
    if cap.len() > chars.len() {
        return false;
    }
    for i in 0..=(chars.len() - cap.len()) {
        if chars[i..i + cap.len()] != cap[..] {
            continue;
        }
        // The char BEFORE must not be a lowercase letter or digit — otherwise this is the tail of
        // a longer word (`deepMcp` is not a leak of `mcp`; `DeepMcp` is caught by the word rule via
        // its lowercased form only if `mcp` is boundary-clean, which it is not here — the word rule
        // and this rule are deliberately complementary, not identical).
        let before_ok = i == 0 || !chars[i - 1].is_ascii_lowercase();
        if !before_ok {
            continue;
        }
        match chars.get(i + cap.len()) {
            None => return true,
            Some(c) if c.is_ascii_uppercase() => return true,
            Some(c) if !c.is_ascii_alphanumeric() => return true,
            _ => {}
        }
    }
    false
}

fn line_hits(orig: &str, lower: &str, noun: &Noun) -> bool {
    noun
        .tokens
        .iter()
        .any(|t| word_ci(lower, t) || camel_hit(orig, t))
}

/// The crate directory name for a `crates/<name>/...` path, or `None` for anything else.
fn crate_of(rel: &str) -> Option<&str> {
    rel.strip_prefix("crates/").and_then(|r| r.split('/').next())
}

/// Every crate that is SOME noun's family — used to tell a cross-plugin leak from a core one.
fn is_family_crate(krate: &str) -> bool {
    NOUNS.iter().any(|n| n.family.contains(&krate))
}

/// Category + owning wave for a leak, from the crate it landed in. Cross-plugin is checked first: a
/// plane naming another plane is the broker-law violation, wherever the crate otherwise sorts.
fn categorize(krate: &str, file: &str) -> (&'static str, &'static str) {
    if is_family_crate(krate) {
        return (
            "cross-plugin",
            "cross-plugin cleanup — broker law #8 (plugins never name each other)",
        );
    }
    if krate == "busbar" || file.contains("/bin/") {
        return (
            "composition-root",
            "keystone / composition-root — register_planes both-ways self-registration",
        );
    }
    match krate {
        "busbar-substrate" | "busbar-substrate-values" => (
            "substrate",
            "substrate neutralization — opaque PlaneRecord across the ABI, never an instance noun",
        ),
        "api" | "busbar-contract" | "busbar-contract-transport" | "busbar-caps"
        | "busbar-grammar" => (
            "shared-crate",
            "shared-crate neutralization — the ABI-side crates must compile with every plugin removed",
        ),
        _ => (
            "core",
            "core neutralization — DECISION #1 (core names no instance); auth schemes are DECISION #3 internal-unit debt",
        ),
    }
}

/// THE SCAN. Walks every `.rs` under `crates/`, strips comments (test code kept), and records one
/// entry per (noun, file) where a non-family crate names the noun.
fn census(cx: &Ctx) -> Result<Vec<Leak>, String> {
    let files = cx
        .walk(&WalkSpec::new(["crates"]).ext("rs").min_files(1))
        .map_err(|e| e.to_string())?;
    let mut leaks: Vec<Leak> = Vec::new();
    for f in &files {
        let rel = f.rel_str();
        let Some(krate) = crate_of(&rel) else {
            continue;
        };
        // Strip comments once; keep (original, lowercased) for the two match rules.
        let mut in_block = false;
        let lines: Vec<(String, String)> = f
            .text
            .lines()
            .map(|l| {
                let s = strip_comment_line(l, &mut in_block);
                let lower = s.to_lowercase();
                (s, lower)
            })
            .collect();
        for noun in NOUNS {
            if noun.family.contains(&krate) {
                continue;
            }
            let count = lines
                .iter()
                .filter(|(orig, lower)| line_hits(orig, lower, noun))
                .count();
            if count == 0 {
                continue;
            }
            let (category, wave) = categorize(krate, &rel);
            leaks.push(Leak {
                noun: noun.key,
                kind: noun.kind,
                file: rel.clone(),
                count,
                category,
                wave,
            });
        }
    }
    leaks.sort_by(|a, b| (a.noun, &a.file).cmp(&(b.noun, &b.file)));
    Ok(leaks)
}

/// The baseline as a set of `<noun>\t<file>` keys plus the raw entry list (for the stale check).
fn baseline_keys(cx: &Ctx) -> Vec<(String, String)> {
    let Ok(text) = cx.read(BASELINE) else {
        return Vec::new();
    };
    let Ok(doc) = crate::toml_doc::parse_str(&text) else {
        return Vec::new();
    };
    doc.array_of_tables("leak")
        .into_iter()
        .filter_map(|t| {
            let noun = t.str_of("noun")?;
            let file = t.str_of("file")?;
            Some((noun.to_string(), file.to_string()))
        })
        .collect()
}

fn leak_key(l: &Leak) -> (String, String) {
    (l.noun.to_string(), l.file.clone())
}

/// The baseline TOML for the current census — mechanical category/wave, one `[[leak]]` per pair.
fn emit_baseline(leaks: &[Leak]) -> String {
    let mut out = String::new();
    out.push_str(
        "# instance-noun-neutrality burndown ledger — AUTO-DERIVED, HUMAN-REVIEWED.\n\
         # One row per (instance noun, offending file) outside the noun's own crate family.\n\
         # The gate is RED while any row stands; it goes GREEN when this file is empty.\n\
         # Regenerate: XTASK_INSN_EMIT_BASELINE=1 cargo xtask gate instance-noun-neutrality \
         2>qa/instance-noun-neutrality.toml\n\n",
    );
    for l in leaks {
        out.push_str("[[leak]]\n");
        out.push_str(&format!("noun = \"{}\"\n", l.noun));
        out.push_str(&format!("kind = \"{}\"\n", l.kind));
        out.push_str(&format!("file = \"{}\"\n", l.file));
        out.push_str(&format!("count = {}\n", l.count));
        out.push_str(&format!("category = \"{}\"\n", l.category));
        out.push_str(&format!("wave = \"{}\"\n\n", l.wave.replace('"', "'")));
    }
    out
}

pub struct InstanceNounNeutralityGate;

impl Gate for InstanceNounNeutralityGate {
    fn name(&self) -> &'static str {
        "instance-noun-neutrality"
    }

    fn owed(&self) -> Vec<String> {
        let mut ids: Vec<String> = NOUNS.iter().map(|n| row_id(n.key)).collect();
        ids.push(ROW_SCAN_FLOOR.to_string());
        ids.push(ROW_UNDOCUMENTED.to_string());
        ids.push(ROW_STALE.to_string());
        ids
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let leaks = match census(cx) {
            Ok(l) => l,
            Err(e) => {
                let mut rows = vec![Row::fail(
                    ROW_SCAN_FLOOR,
                    "the crates tree could not be scanned",
                    format!("{e} — {DID_NOT_RUN}"),
                )];
                for n in NOUNS {
                    rows.push(Row::fail(row_id(n.key), "the scan did not run", DID_NOT_RUN));
                }
                rows.push(Row::fail(ROW_UNDOCUMENTED, "the scan did not run", DID_NOT_RUN));
                rows.push(Row::fail(ROW_STALE, "the scan did not run", DID_NOT_RUN));
                return Verdict::of(rows);
            }
        };

        // The baseline-regeneration affordance: print the census as TOML and keep going, so the
        // ordinary verdict still prints too.
        if std::env::var("XTASK_INSN_EMIT_BASELINE").as_deref() == Ok("1") {
            eprint!("{}", emit_baseline(&leaks));
        }

        let baseline: Vec<(String, String)> = baseline_keys(cx);
        let mut rows = Vec::new();

        rows.push(Row::pass(
            ROW_SCAN_FLOOR,
            "the crates tree was scanned",
            CLEAN,
        ));

        // Per-noun census rows.
        let mut by_noun: BTreeMap<&str, Vec<&Leak>> = BTreeMap::new();
        for l in &leaks {
            by_noun.entry(l.noun).or_default().push(l);
        }
        for n in NOUNS {
            let fam = n.family.join(", ");
            let fam = if fam.is_empty() {
                "(no crate in this tree)".to_string()
            } else {
                fam
            };
            match by_noun.get(n.key) {
                None => rows.push(Row::pass(
                    row_id(n.key),
                    format!("no crate outside the {} family names `{}`", n.kind, n.key),
                    CLEAN,
                )),
                Some(hits) => {
                    let listing: Vec<String> = hits
                        .iter()
                        .map(|l| format!("{}×{} [{}]", l.file, l.count, l.category))
                        .collect();
                    rows.push(Row::fail(
                        row_id(n.key),
                        format!(
                            "`{}` ({}) is named in {} file(s) outside its family [{fam}]",
                            n.key,
                            n.kind,
                            hits.len()
                        ),
                        format!(
                            "{TRACKED_NEEDLE} census — {}: {}",
                            hits.len(),
                            listing.join(" | ")
                        ),
                    ));
                }
            }
        }

        // Undocumented: a live leak the baseline does not name. This is what bites a NEW coupling.
        let mut undocumented: Vec<String> = leaks
            .iter()
            .filter(|l| !baseline.contains(&leak_key(l)))
            .map(|l| format!("{}@{}", l.noun, l.file))
            .collect();
        undocumented.sort();
        rows.push(if undocumented.is_empty() {
            Row::pass(
                ROW_UNDOCUMENTED,
                "every live leak is recorded in the baseline burndown",
                CLEAN,
            )
        } else {
            Row::fail(
                ROW_UNDOCUMENTED,
                "a live instance-noun leak is NOT in the baseline",
                format!(
                    "{} undocumented leak(s): {} — a NEW cross-family coupling landed. Neutralize \
                     it, or (if it is genuine debt) record it in {BASELINE} with its owning wave.",
                    undocumented.len(),
                    undocumented.join(", ")
                ),
            )
        });

        // Stale: a baseline row whose leak is gone. The ledger cannot outlive the debt it tracked.
        let live: std::collections::BTreeSet<(String, String)> =
            leaks.iter().map(leak_key).collect();
        let mut stale: Vec<String> = baseline
            .iter()
            .filter(|k| !live.contains(*k))
            .map(|(n, f)| format!("{n}@{f}"))
            .collect();
        stale.sort();
        rows.push(if stale.is_empty() {
            Row::pass(
                ROW_STALE,
                "every baseline row still names a live leak",
                CLEAN,
            )
        } else {
            Row::fail(
                ROW_STALE,
                "a baseline row no longer names a live leak",
                format!(
                    "{} stale row(s): {} — the coupling is gone; strike the row from {BASELINE} in \
                     the same commit that neutralized it.",
                    stale.len(),
                    stale.join(", ")
                ),
            )
        });

        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();

        // THE SELF-TEST RUNS OVER TINY FIXTURE TREES, NOT THE 660k-LINE REPO. A census gate that
        // planted into the real workspace and re-scanned it per case measured 168 751 work units —
        // the exact "grew a whole-tree scan per plant" regression the budget exists to catch. The
        // fixtures carry the same shapes in two crates, so every proof below is a millisecond scan.
        //
        // `xtask/fixtures/instance-noun/` is: busbar-core (a NON-family crate) naming EVERY noun in
        // code, busbar-mcp (mcp's OWN family) naming mcp legitimately, and a baseline that names one
        // GHOST leak and none of the live ones. So over it: every per-noun row is RED (busbar-core),
        // the family file is NOT named (skip), `:undocumented` is RED (live leaks unrecorded), and
        // `:stale-baseline` is RED (the ghost). `xtask/fixtures/instance-noun-empty/` has a `crates/`
        // that holds no `.rs`, so `:scan-floor` refuses it.
        const FIX: &str = "xtask/fixtures/instance-noun";
        const FIX_EMPTY: &str = "xtask/fixtures/instance-noun-empty";

        // ONE RED CASE PER NOUN: the fixture's busbar-core names it, so its census row goes RED and
        // names that file. If a noun's matcher regressed, its row would be PASS and the case fail.
        for n in NOUNS {
            report.push(prove_rows_red_at(
                cx,
                self,
                format!("`{}` named by a non-family crate reds its census row", n.key),
                &[&row_id(n.key)],
                FIX,
                &["crates/busbar-core/src/lib.rs"],
            ));
        }

        // THE UNDOCUMENTED ROW: the fixture's live leaks are absent from its baseline.
        report.push(prove_rows_red_at(
            cx,
            self,
            "a live leak absent from the baseline reds the undocumented row",
            &[ROW_UNDOCUMENTED],
            FIX,
            &["crates/busbar-core/src/lib.rs"],
        ));

        // THE STALE ROW: the fixture baseline names a ghost leak the tree does not have.
        report.push(prove_rows_red_at(
            cx,
            self,
            "a baseline row with no live leak reds the stale row",
            &[ROW_STALE],
            FIX,
            &["ghost-nonexistent"],
        ));

        // THE SCAN FLOOR: a `crates/` that holds no Rust is refused, never scanned as zero leaks.
        report.push(prove_rows_red_at(
            cx,
            self,
            "a crates tree holding no Rust reds the scan floor",
            &[ROW_SCAN_FLOOR],
            FIX_EMPTY,
            &["could not be scanned"],
        ));

        // GREEN CONTROL 1 — COMMENTS ARE NEVER A LEAK. Over the fixture, replace busbar-core with a
        // file whose only `mysql` is in comments: the mysql row goes GREEN, while the RED case above
        // proves the same word in code reds it — together, proof of the comment strip.
        let cx_c = cx.clone();
        report.push(Case {
            name: "a comment naming a store noun is not a leak".to_string(),
            covers: vec![row_id("mysql")],
            expected: Expect::Green,
            got: green_over_fixture(self, &cx_c, FIX, "mysql", |ov| {
                ov.set(
                    "crates/busbar-core/src/lib.rs",
                    "// a comment naming mysql is not a leak\n\
                     /* block comment: mysql again */\npub fn install() {}\n",
                );
            }),
        });

        // GREEN CONTROL 2 — THE FAMILY EXEMPTION IS NOT VACUOUS. The fixture already names mcp in
        // both busbar-core (leak) and busbar-mcp (family). Assert the mcp row names the core file and
        // NOT the family one; if `family.contains` regressed, the family file would appear.
        let cx_f = cx.clone();
        report.push(Case {
            name: "a token inside its own family crate is not a leak; outside it is".to_string(),
            covers: vec![row_id("mcp")],
            expected: Expect::Green,
            got: {
                match Ctx::at(cx_f.abs(FIX), cx_f.scratch().to_path_buf()) {
                    Err(_) => Expect::Skipped,
                    Ok(fcx) => {
                        let verdict = execute(self, &fcx);
                        let detail = verdict
                            .rows
                            .iter()
                            .find(|r| r.id == row_id("mcp"))
                            .map(|r| r.detail.clone())
                            .unwrap_or_default();
                        let names_core = detail.contains("busbar-core");
                        let names_family = detail.contains("busbar-mcp");
                        if names_core && !names_family {
                            Expect::Green
                        } else {
                            Expect::Red {
                                naming: vec![format!(
                                    "family-skip regressed: names_core={names_core} \
                                     names_family={names_family}"
                                )],
                            }
                        }
                    }
                }
            },
        });

        report
    }
}

/// Run the gate over `fixture` with `plant` applied, and report GREEN iff `row_id(noun)` is not red.
fn green_over_fixture(
    gate: &InstanceNounNeutralityGate,
    cx: &Ctx,
    fixture: &str,
    noun: &str,
    plant: impl FnOnce(&mut Overlay),
) -> Expect {
    let Ok(fcx) = Ctx::at(cx.abs(fixture), cx.scratch().to_path_buf()) else {
        return Expect::Skipped;
    };
    let mut ov = Overlay::new();
    plant(&mut ov);
    let verdict = execute(gate, &fcx.with_overlay(ov));
    let red = verdict
        .rows
        .iter()
        .any(|r| r.id == row_id(noun) && r.status != Status::Pass);
    if red {
        Expect::Red {
            naming: vec![format!("`{noun}` went red on a comment-only mention")],
        }
    } else {
        Expect::Green
    }
}
