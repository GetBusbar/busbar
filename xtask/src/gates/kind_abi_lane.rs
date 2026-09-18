//! `cargo xtask gate kind-abi-lane` — EACH PLUGIN KIND IS BOUND TO EXACTLY ONE ABI LANE, THE ONE
//! DECISIONS #30 ASSIGNS IT BY HEAT.
//!
//! > "Each plugin kind is bound to exactly ONE ABI lane, chosen by HEAT — a plugin uses the tier
//! > matched to its heat, NOT both. … **HOT/POD lane = plane, transport** … **COLD/JSON lane =
//! > store, secret, auth, hook, export** … a kind declaring the wrong lane ⇒ RED; per-token-loop grep
//! > = {plane,transport} only." — DECISIONS #30 (each kind bound to ONE lane by heat)
//!
//! This gate is the machine that makes #30's `kind-abi-lane gate` column real. #30 names it as the
//! enforcement and it did not exist; before this gate, nothing stopped a HOT kind (plane/transport)
//! from being wired onto the COLD six-symbol JSON `call` wire, or a COLD kind (store/secret/auth/
//! hook/export) from sprouting a `#[repr(C)]` POD surface on the per-token hot lane. This does not
//! re-litigate #30 — it CITES it, reads the lane assignment straight out of the decision, and holds
//! the tree to it.
//!
//! ## THE LANE ASSIGNMENT IS READ FROM THE DECISION, NOT COPIED BESIDE IT
//!
//! Which kind is HOT and which is COLD is READ from DECISIONS #30's own two lane lists (the
//! `HOT/POD lane = …` and `COLD/JSON lane = …` sentences), exactly as `plane-abi-neutrality` reads
//! its ban mandate from the taxonomy document rather than from a copy of the answer. A gate that
//! hard-codes the assignment it is checking is a gate that compares a list against itself and can
//! never fail; here the assignment moves the day #30 moves, and a #30 whose two lists stop
//! partitioning the seven kinds is RED rather than silently defaulted.
//!
//! ## WHERE A KIND "DECLARES" ITS LANE
//!
//! The authoritative per-kind lane binding in the tree is `supported_abi(kind)` in
//! `crates/plugin-loader/src/registry.rs`: the ONE `match kind { … }` where the engine decides which
//! ABI a kind of that name speaks. A COLD kind's arm binds the JSON lane
//! (`busbar_plugin::cold::…_ABI_VERSION` — the six-symbol `busbar_call` wire); the plane arm binds
//! the HOT airlock minor (`busbar_plugin::ABI_MINOR` — the `#[repr(C)]` `PlaneDecl` vtable of
//! `busbar_plugin::hot`), and its own comment says so: "driven over the HOT-tier `#[repr(C)]`
//! `PlaneDecl` vtable — NOT the six-symbol JSON `call` wire the five cold kinds share." A kind whose
//! arm binds the OTHER lane's ABI is a kind declaring the wrong lane, and this gate turns it RED.
//!
//! ## FOUR ROWS
//!
//! * `kind-abi-lane:decision-mapping` — #30's two lane lists parse, are disjoint, and together
//!   partition the seven plugin kinds. The anti-tautology row: if the decision cannot be read, the
//!   three rows below cannot be trusted and report DID NOT RUN.
//! * `kind-abi-lane:cold-kinds-declare-cold` — every COLD kind #30 names declares the COLD/JSON lane
//!   in `supported_abi` and NOT the hot airlock. A cold kind on the hot lane ⇒ RED.
//! * `kind-abi-lane:hot-kinds-declare-hot` — every HOT kind #30 names that is PRESENT in the tree
//!   (has a `busbar_plugin::cold::kind` const) declares the HOT/POD lane and NOT the cold JSON wire.
//!   A hot kind on the cold lane ⇒ RED. `transport` is HOT by #30 but not yet wired into the tree
//!   (no kind const, no arm); its absence is reported, not failed — absence is not a wrong lane.
//! * `kind-abi-lane:per-token-loop` — the per-token streaming inner loop (the HOT/POD lane itself,
//!   `crates/busbar-plugin/src/hot/`) names ONLY {plane, transport}: no COLD kind noun appears there
//!   as an identifier. This is #30's "per-token-loop grep = {plane,transport} only." A `store`/`auth`
//!   /… identifier on the hot lane ⇒ RED. The scan is case-sensitive over the lowercase kind strings
//!   #30 governs on code (non-doc-comment, non-test) lines, so the neutral taxonomy's PascalCase type
//!   names (`FaultClass::Auth`, a fault class, not the `auth` plugin kind) are not swept up.

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_rows_red, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_MAPPING: &str = "kind-abi-lane:decision-mapping";
pub const ROW_COLD: &str = "kind-abi-lane:cold-kinds-declare-cold";
pub const ROW_HOT: &str = "kind-abi-lane:hot-kinds-declare-hot";
pub const ROW_PER_TOKEN: &str = "kind-abi-lane:per-token-loop";

const DECISIONS_DOC: &str = "docs/design/DECISIONS.md";
const REGISTRY_REL: &str = "crates/plugin-loader/src/registry.rs";
const KIND_MOD_REL: &str = "crates/busbar-plugin/src/cold/mod.rs";
const HOT_LANE: &str = "crates/busbar-plugin/src/hot";

/// The seven plugin kinds #30 partitions. This is the ROSTER, not the assignment: which of these is
/// HOT and which is COLD is read from the decision. A #30 that named a kind outside this set, or
/// failed to name one in it, is the drift the mapping row catches.
const ALL_KINDS: &[&str] = &[
    "plane",
    "transport",
    "store",
    "secret",
    "auth",
    "hook",
    "export",
];

/// The COLD/JSON lane ABI witness in a `supported_abi` arm: the six-symbol wire's version consts all
/// live under `busbar_plugin::cold`.
const COLD_WITNESS: &str = "busbar_plugin::cold";
/// The HOT/POD lane ABI witness in a `supported_abi` arm: a plane's per-kind axis is the airlock
/// minor stamped into its `#[repr(C)]` `PlaneDecl` preamble.
const HOT_WITNESS: &str = "ABI_MINOR";

const DID_NOT_RUN: &str = "the decision mapping could not be read, so this lane check did not run";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lane {
    Hot,
    Cold,
}

impl Lane {
    fn label(self) -> &'static str {
        match self {
            Lane::Hot => "hot",
            Lane::Cold => "cold",
        }
    }
}

/// #30's two lane lists, read from the decision. `Err` when either sentence is missing/empty, the two
/// lists overlap, or they do not together partition [`ALL_KINDS`] — every one of which would leave
/// the lane checks resting on an assignment nobody can trust.
fn decision_lanes(cx: &Ctx) -> Result<(Vec<String>, Vec<String>), String> {
    let text = cx.read(DECISIONS_DOC).map_err(|e| {
        format!("DECISIONS #30 is unreadable at {DECISIONS_DOC} ({e}); the lane assignment cannot be read from the decision that issues it")
    })?;
    let hot = lane_list(&text, "HOT/POD lane = ").ok_or_else(|| {
        "no `HOT/POD lane = …` sentence in DECISIONS #30 — the HOT lane roster is read from that line".to_string()
    })?;
    let cold = lane_list(&text, "COLD/JSON lane = ").ok_or_else(|| {
        "no `COLD/JSON lane = …` sentence in DECISIONS #30 — the COLD lane roster is read from that line".to_string()
    })?;

    if let Some(k) = hot.iter().find(|k| cold.contains(k)) {
        return Err(format!(
            "`{k}` is named in BOTH lane lists in DECISIONS #30 — a kind is bound to exactly ONE lane by heat"
        ));
    }
    let mut union: Vec<String> = hot.iter().chain(cold.iter()).cloned().collect();
    union.sort();
    union.dedup();
    let mut roster: Vec<String> = ALL_KINDS.iter().map(|k| (*k).to_string()).collect();
    roster.sort();
    if union != roster {
        return Err(format!(
            "DECISIONS #30's two lane lists ({}) do not partition the seven plugin kinds ({}) — a kind is unassigned or unknown",
            union.join(", "),
            roster.join(", ")
        ));
    }
    Ok((hot, cold))
}

/// The comma list after `marker`, up to the closing `**` of the bolded lane sentence.
fn lane_list(text: &str, marker: &str) -> Option<Vec<String>> {
    let after = text.split(marker).nth(1)?;
    let list = after.split("**").next()?;
    let kinds: Vec<String> = list
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if kinds.is_empty() {
        None
    } else {
        Some(kinds)
    }
}

/// A kind is PRESENT in the tree when the `busbar_plugin::cold::kind` module declares its const (the
/// kind roster's home). `plane` is present; `transport` is not yet.
fn kind_present(cx: &Ctx, kind: &str) -> bool {
    let Ok(text) = cx.read(KIND_MOD_REL) else {
        return false;
    };
    text.contains(&format!("pub const {}:", kind.to_uppercase()))
}

/// The lane a kind DECLARES in `supported_abi`, or `None` when it has no arm there.
///
/// Comments are stripped first so a kind's slice cannot pick up the ABI witness of the NEXT arm's
/// preceding comment (the plane arm's comment names `busbar_plugin::ABI_MINOR`, and the export arm
/// sits right above it). After stripping, the double-quoted `"kind"` keys are the only place the kind
/// strings appear, so slicing between consecutive keys isolates each arm's VALUE.
fn declared_lane(registry: &str, kind: &str) -> Option<Lane> {
    let code = strip_line_comments(registry);
    let region_start = code.find("fn supported_abi")?;
    let region = &code[region_start..];
    let region_end = region.find("_ =>").unwrap_or(region.len());
    let region = &region[..region_end];

    // Byte offsets of every kind key present, plus the region end, sorted — each arm runs from its
    // key to the next boundary.
    let mut bounds: Vec<usize> = Vec::new();
    for k in ALL_KINDS {
        if let Some(pos) = region.find(&format!("\"{k}\"")) {
            bounds.push(pos);
        }
    }
    bounds.push(region.len());
    bounds.sort_unstable();

    let key = format!("\"{kind}\"");
    let start = region.find(&key)?;
    let end = bounds
        .iter()
        .copied()
        .find(|&b| b > start)
        .unwrap_or(region.len());
    let arm = &region[start..end];

    let cold = arm.contains(COLD_WITNESS);
    let hot = arm.contains(HOT_WITNESS);
    match (hot, cold) {
        (true, false) => Some(Lane::Hot),
        (false, true) => Some(Lane::Cold),
        // Neither or both: not a clean single-lane declaration. Reported by the row as an offender
        // rather than silently classified.
        _ => None,
    }
}

/// Drop `//`-started tails (line comments and doc comments) from every line. There are no `//`
/// sequences inside string literals in `supported_abi`, so a naive cut is exact here.
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The COLD-lane check: every COLD kind #30 names declares the cold lane in `supported_abi`.
fn cold_row(cx: &Ctx, cold: &[String]) -> Row {
    let registry = match cx.read(REGISTRY_REL) {
        Ok(t) => t,
        Err(e) => {
            return Row::fail(
                ROW_COLD,
                "the per-kind lane declaration could not be read",
                format!("{REGISTRY_REL}: {e} — {DID_NOT_RUN}"),
            )
        }
    };
    let mut offenders: Vec<String> = Vec::new();
    for kind in cold {
        match declared_lane(&registry, kind) {
            Some(Lane::Cold) => {}
            Some(other) => offenders.push(format!(
                "{kind}: supported_abi declares the {} lane, but #30 binds it to COLD/JSON",
                other.label()
            )),
            None => offenders.push(format!(
                "{kind}: no single-lane supported_abi arm (lane undeclared or ambiguous) — #30 binds it to COLD/JSON"
            )),
        }
    }
    if offenders.is_empty() {
        Row::pass(
            ROW_COLD,
            "every COLD kind declares the cold(JSON) lane #30 assigns it",
            format!(
                "{}: {} on the six-symbol JSON wire",
                REGISTRY_REL,
                cold.join(", ")
            ),
        )
    } else {
        Row::fail(
            ROW_COLD,
            "a COLD kind declares the wrong ABI lane",
            format!(
                "{} — a kind must use the tier matched to its heat, not both (DECISIONS #30)",
                offenders.join(" | ")
            ),
        )
    }
}

/// The HOT-lane check: every HOT kind #30 names that is present declares the hot lane.
fn hot_row(cx: &Ctx, hot: &[String]) -> Row {
    let registry = match cx.read(REGISTRY_REL) {
        Ok(t) => t,
        Err(e) => {
            return Row::fail(
                ROW_HOT,
                "the per-kind lane declaration could not be read",
                format!("{REGISTRY_REL}: {e} — {DID_NOT_RUN}"),
            )
        }
    };
    let mut offenders: Vec<String> = Vec::new();
    let mut deferred: Vec<String> = Vec::new();
    for kind in hot {
        match declared_lane(&registry, kind) {
            Some(Lane::Hot) => {}
            Some(other) => offenders.push(format!(
                "{kind}: supported_abi declares the {} lane, but #30 binds it to HOT/POD",
                other.label()
            )),
            None => {
                if kind_present(cx, kind) {
                    offenders.push(format!(
                        "{kind}: present in the tree but no single-lane supported_abi arm — #30 binds it to HOT/POD"
                    ));
                } else {
                    deferred.push(kind.clone());
                }
            }
        }
    }
    if offenders.is_empty() {
        let mut detail =
            format!("{REGISTRY_REL}: the hot kinds present declare the #[repr(C)] POD lane");
        if !deferred.is_empty() {
            detail.push_str(&format!(
                "; declared HOT by #30 but not yet wired into the tree: {}",
                deferred.join(", ")
            ));
        }
        Row::pass(
            ROW_HOT,
            "every HOT kind present declares the hot(POD) lane #30 assigns it",
            detail,
        )
    } else {
        Row::fail(
            ROW_HOT,
            "a HOT kind declares the wrong ABI lane",
            format!(
                "{} — a kind must use the tier matched to its heat, not both (DECISIONS #30)",
                offenders.join(" | ")
            ),
        )
    }
}

/// The per-token-loop check: the hot lane names only {plane, transport}, never a cold kind noun.
fn per_token_row(cx: &Ctx, cold: &[String]) -> Row {
    let files = match cx.walk(&WalkSpec::new([HOT_LANE]).ext("rs").min_files(1)) {
        Ok(f) => f,
        Err(e) => {
            return Row::fail(
                ROW_PER_TOKEN,
                "the hot lane is absent or holds no Rust",
                format!(
                    "{e} A per-token loop that cannot be read reports zero cold-kind nouns, which reads exactly like a clean hot lane. If the hot lane moved, point this gate at its new home."
                ),
            )
        }
    };
    let mut offenders: Vec<String> = Vec::new();
    for f in &files {
        let rel = f.rel_str();
        if rel.contains("/tests/") || rel.ends_with("_tests.rs") || rel.ends_with("_test.rs") {
            continue;
        }
        for (i, line) in f.text.lines().enumerate() {
            let code = match line.find("//") {
                Some(j) => &line[..j],
                None => line,
            };
            if code.trim().is_empty() {
                continue;
            }
            for kind in cold {
                if contains_word(code, kind) {
                    offenders.push(format!("{rel}:{}:{}", i + 1, line.trim()));
                    break;
                }
            }
        }
    }
    offenders.sort();
    if offenders.is_empty() {
        Row::pass(
            ROW_PER_TOKEN,
            "the per-token hot lane names only {plane, transport} — no cold kind runs in it",
            format!("{HOT_LANE}: 0 cold-kind nouns in code"),
        )
    } else {
        Row::fail(
            ROW_PER_TOKEN,
            "a COLD kind noun appears on the per-token hot lane",
            format!(
                "{} finding(s): {} — #30's per-token loop is {{plane, transport}} only",
                offenders.len(),
                offenders.join(" | ")
            ),
        )
    }
}

/// Whole-word, case-sensitive containment: `store` matches `store(` and `store:` but not `restore`
/// or `PascalStore`, and (case-sensitively) not the taxonomy's `FaultClass::Auth`.
fn contains_word(hay: &str, word: &str) -> bool {
    let bytes = hay.as_bytes();
    let mut from = 0;
    while let Some(rel) = hay[from..].find(word) {
        let start = from + rel;
        let end = start + word.len();
        let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        let after_ok = end == bytes.len() || !is_ident_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

pub struct KindAbiLaneGate;

impl Gate for KindAbiLaneGate {
    fn name(&self) -> &'static str {
        "kind-abi-lane"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_MAPPING.to_string(),
            ROW_COLD.to_string(),
            ROW_HOT.to_string(),
            ROW_PER_TOKEN.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let mut rows = Vec::new();
        match decision_lanes(cx) {
            Ok((hot, cold)) => {
                rows.push(Row::pass(
                    ROW_MAPPING,
                    "DECISIONS #30 partitions the seven kinds into the two lanes",
                    format!(
                        "HOT/POD = {}; COLD/JSON = {}",
                        hot.join(", "),
                        cold.join(", ")
                    ),
                ));
                rows.push(cold_row(cx, &cold));
                rows.push(hot_row(cx, &hot));
                rows.push(per_token_row(cx, &cold));
            }
            Err(why) => {
                rows.push(Row::fail(
                    ROW_MAPPING,
                    "the lane assignment could not be read from DECISIONS #30",
                    why,
                ));
                for row in [ROW_COLD, ROW_HOT, ROW_PER_TOKEN] {
                    rows.push(Row::fail(
                        row,
                        "the lane assignment is unknown",
                        DID_NOT_RUN.to_string(),
                    ));
                }
            }
        }
        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "every kind declares the lane #30 binds it to, and the hot lane names only plane/transport",
            &self.owed().iter().map(String::as_str).collect::<Vec<_>>(),
        ));

        // THE DECISION THAT CANNOT BE READ. A silent fallback to a copied assignment is the
        // tautology this row exists to refuse.
        let decisions = cx.read(DECISIONS_DOC).unwrap_or_default();
        let mut ov = Overlay::new();
        ov.set(
            DECISIONS_DOC,
            decisions.replace("HOT/POD lane = ", "HOT/POD lane (unspecified) "),
        );
        report.push(prove_rows_red(
            cx,
            self,
            "a #30 whose HOT lane sentence cannot be parsed is refused, not defaulted",
            &[ROW_MAPPING],
            ov,
            &["HOT/POD lane"],
        ));

        let registry = cx.read(REGISTRY_REL).unwrap_or_default();

        // A COLD KIND ON THE HOT LANE: rewrite auth's arm to bind the hot airlock minor.
        let mut ov = Overlay::new();
        ov.set(
            REGISTRY_REL,
            registry.replace(
                "busbar_plugin::cold::AUTH_ABI_VERSION",
                "busbar_plugin::ABI_MINOR",
            ),
        );
        report.push(prove_rows_red(
            cx,
            self,
            "a cold kind whose supported_abi arm binds the hot lane is RED",
            &[ROW_COLD],
            ov,
            &["auth"],
        ));

        // A HOT KIND ON THE COLD LANE: rewrite plane's arm to bind the cold JSON version const.
        let mut ov = Overlay::new();
        ov.set(
            REGISTRY_REL,
            registry.replace(
                "\"plane\" => &[1, busbar_plugin::ABI_MINOR]",
                "\"plane\" => &[1, busbar_plugin::cold::ABI_VERSION]",
            ),
        );
        report.push(prove_rows_red(
            cx,
            self,
            "a hot kind whose supported_abi arm binds the cold lane is RED",
            &[ROW_HOT],
            ov,
            &["plane"],
        ));

        // A COLD KIND NOUN ON THE PER-TOKEN HOT LANE.
        let mut ov = Overlay::new();
        ov.set(
            format!("{HOT_LANE}/planted_cold_kind.rs"),
            "pub fn planted() { let _cold_kind_on_the_hot_lane = store; }\n",
        );
        report.push(prove_rows_red(
            cx,
            self,
            "a cold kind noun on the per-token hot lane is a finding",
            &[ROW_PER_TOKEN],
            ov,
            &["store"],
        ));

        // ...AND A HOT-LANE FILE NAMING ONLY plane/transport IS NOT, so the case above is not a scan
        // that refuses everything.
        let mut ov = Overlay::new();
        ov.set(
            format!("{HOT_LANE}/planted_hot_ok.rs"),
            "pub fn plane_and_transport_ride_the_per_token_loop() {}\n",
        );
        report.push(prove_green(
            &cx.with_overlay(ov),
            self,
            "a hot-lane file naming only plane/transport is not a finding",
            &[ROW_PER_TOKEN],
        ));

        report
    }
}
