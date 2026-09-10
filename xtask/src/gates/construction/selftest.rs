//! THE CONSTRUCTION GATE'S RED PROOFS.
//!
//! `scripts/construction-gate/plant.py` was 428 lines of saboteur plus a `TOUCHED` list, a `tar` of
//! `crates/*/src` and every manifest into a scratch directory, a `--calibrate` step whose only job
//! was to relax every ceiling until the copy went green, and a `mktemp` race it had to learn about
//! the hard way. None of that is here, because none of it was about the rules: an
//! [`Overlay`] is per-plant by construction and never mutates the base context, so there is
//! nothing to restore and nothing two concurrent runs can take from each other.
//!
//! THREE THINGS ARE DIFFERENT FROM THE SHELL SELF-TEST, each deliberately:
//!
//! 1. **THE BASELINE IS NOT "GREEN".** This gate is RED BY DESIGN on HEAD — `ci.yml` runs it
//!    report-only and `scripts/full-gate.sh` says so in its skip list, because seven rows are over
//!    ceilings the construction work in flight is driving down. The shell obtained a green baseline
//!    by writing a calibrated ceilings file, which is to say by turning the gate off. The baseline
//!    here asserts the property that actually matters to every RED proof below: **the unplanted
//!    tree names no planted offender.** A plant that changed nothing would then name nothing, and
//!    its case would fail on the naming check rather than pass on "something went red".
//! 2. **PLANTS ARE GROUPED BY FAMILY.** One overlay carries every edit a family needs, so a
//!    per-crate family (`manifest-allowlist:*`, `source-denylist:*`) is exercised across every one
//!    of its crates at once instead of by a hundred full tree scans. Each family's offenders are
//!    named distinctly, so a failure still says which rule stopped seeing its violation.
//! 3. **THE DELEGATED INPUTS ARE MEASURED ONCE.** The purity lint and the denylist closure are a
//!    subprocess and a `cargo metadata` sweep; re-running them per plant would spend eleven seconds
//!    a case proving nothing about the plant. They are captured once into a base overlay, and the
//!    two cases that are ABOUT them plant a different answer over it.
//!
//! A ROW ALREADY RED ON HEAD CANNOT PROVE A TRANSITION, and the cases say so where it applies. For
//! the seven rows over their ceilings today, `covers` still claims the plant exercised the rule's
//! whole path — it did — but `naming` lists only strings the plant is the sole cause of, because a
//! string that would be there anyway is a check that passes whatever the plant did.
//!
//! TWO ROWS CANNOT GO RED, and are covered by the baseline case rather than pretended at:
//! `duplicate-dispatch`, which reports a shape and carries no threshold; and a
//! `forbid-unsafe:<crate>` row whose crate is on the `known_missing_*` ratchet, whose ceiling of 1
//! the single measurable value cannot exceed.
//!
//! Both are DECLARED, through [`crate::gates::Gate::informational`], rather than left to a baseline
//! case whose `covers` list the harness reads as proof. `verify_report` counts coverage from RED
//! cases only — so without the declaration they would be refused, and the two ways to answer that
//! without it are to hand-write the case's `got` or to make the rows judge something they do not.
//! Naming them is the honest third answer, and the declaration is itself stale-checked.
//!
//! THE THREE `legacy-reach:<crate>` ROWS WERE ON THAT LIST AND ARE NOT ANY MORE. They gate, and
//! [`ceiling_ratchet_cases`] plants their figures at zero to prove it — the plant that could not be
//! written while they were PASS by construction.

use crate::ctx::{Ctx, Overlay};
use crate::gates::construction::model::Cfg;
use crate::gates::construction::tree::{crate_name_of_dir, dirs_for_globs};
use crate::gates::construction::{
    ceilings, census, external, ConstructionGate, CEILINGS, UNSAFE_HALVES,
};
use crate::gates::{
    execute, prove_red, prove_rows_green, prove_rows_red, Case, Expect, Gate, Report,
};

/// The three delegated answers as the real tree gives them, captured once. Every plant starts from
/// a clone of this, so a case that is not about a delegated input never pays for one.
fn base_overlay(cx: &Ctx) -> Overlay {
    let mut ov = Overlay::new();
    if let Some(hits) = external::purity_hits(cx) {
        ov.set_command(external::PURITY_HITS_KEY, hits);
    }
    if let Some(map) = external::denylist_hits(cx) {
        let mut tsv = String::new();
        for (crate_name, entries) in &map {
            for e in entries {
                // Back through the wire form the reader parses, so the capture and the plant are
                // the same shape and this cannot quietly become a second format.
                let inner = e
                    .trim_start_matches('`')
                    .split("` via ")
                    .collect::<Vec<_>>();
                if inner.len() == 2 {
                    let via = inner[1].trim_end_matches(" (cargo xtask denylist)");
                    tsv.push_str(&format!("{crate_name}\t{}\t{via}\n", inner[0]));
                }
            }
        }
        ov.set_command(external::DENYLIST_KEY, tsv);
    }
    ov
}

fn on(base: &Overlay) -> Overlay {
    base.clone()
}

fn ids(prefix: &str, names: &[String]) -> Vec<String> {
    names.iter().map(|n| format!("{prefix}{n}")).collect()
}

fn refs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

fn kind_crates(cx: &Ctx, kinds: &[String]) -> Vec<String> {
    let Ok(cfg) = ConstructionGate::cfg(cx) else {
        return Vec::new();
    };
    let mut out: Vec<String> = kinds
        .iter()
        .flat_map(|k| dirs_for_globs(cx, &cfg.kind_globs(k)))
        .map(|d| crate_name_of_dir(&d))
        .collect();
    out.sort();
    out.dedup();
    out
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

/// Lines of filler that count as surface: non-blank, non-comment, outside any `#[cfg(test)]`.
fn bulk(n: usize) -> String {
    (0..n)
        .map(|i| format!("pub const PLANTED_{i}: u32 = {i};\n"))
        .collect()
}

pub fn run(gate: &dyn Gate, cx: &Ctx) -> Report {
    let mut r = Report::new();
    let base = base_overlay(cx);

    // ── the baseline ────────────────────────────────────────────────────────────────────────────
    // The same list `Gate::informational` declares, from the same derivation: these rows are
    // exercised here and are held to being measured rather than to going red, because they cannot.
    let informational: Vec<String> = ConstructionGate::informational_ids(cx);
    let verdict = execute(gate, &cx.with_overlay(on(&base)));
    let leaked: Vec<String> = verdict
        .rows
        .iter()
        .map(|row| format!("{} {}", row.id, row.detail))
        .filter(|t| t.contains("zz_planted") || t.contains("planted_"))
        .collect();
    r.push(Case {
        name: "the unplanted tree names no planted offender (this gate is RED BY DESIGN on HEAD, \
               so its baseline is this, not green)"
            .to_string(),
        covers: informational.clone(),
        expected: Expect::Green,
        got: if leaked.is_empty() {
            Expect::Green
        } else {
            Expect::Red { naming: leaked }
        },
    });
    if verdict.rows.is_empty() {
        r.note_infra_failure(
            "the construction gate produced no rows at all over the real tree, so every plant \
             below would be judged against nothing",
        );
    }

    r.append(shape_cases(gate, cx, &base));
    r.append(loop_cases(gate, cx, &base));
    r.append(delegated_cases(gate, cx, &base));
    r.append(ceiling_cases(gate, cx, &base));
    r.append(kind_cases(gate, cx, &base));
    r.append(vocabulary_cases(gate, cx, &base));
    r.append(money_cases(gate, cx, &base));
    r
}

/// The attempt seam, the request terminal, the plane's doors and the plane/kernel wall.
fn shape_cases(gate: &dyn Gate, cx: &Ctx, base: &Overlay) -> Report {
    let mut r = Report::new();

    let mut ov = on(base);
    ov.set(
        "crates/busbar-llm/src/zz_planted_shape.rs",
        "pub fn planted_second_attempt_site() {\n    let _ = \
         ctx.client().get().request(method, url);\n}\n\npub fn planted_extra_door() {\n    \
         unit.finish_inner(end);\n}\n\npub fn planted_door_caller() {\n    \
         finish_admitted(end);\n    finish_rejected(end);\n}\n\npub fn planted_pick_a() {\n    \
         pick_among(lanes);\n}\n\npub fn planted_pick_b() {\n    pick_among(lanes);\n}\n",
    );
    ov.set(
        "crates/busbar-llm/src/unit/zz_planted_escape.rs",
        "pub fn planted_response_escape() -> Response {\n    Response::new()\n}\n",
    );
    r.push(prove_red(
        cx,
        gate,
        "a second attempt site, a second terminal door, a door outside Audit, two more lane picks \
         and a Response escaping a step other than Audit",
        &[
            "one-attempt-seam",
            "single-terminal",
            "terminal-doors-in-audit-step",
            "one-pick-site",
            "no-response-escapes-audit",
        ],
        ov,
        &[
            "planted_second_attempt_site",
            "planted_extra_door",
            "zz_planted_shape.rs",
            "planted_response_escape",
        ],
    ));

    // request-path-fn-size names its files exactly, so the plant goes into one of them. PREPENDED,
    // not appended: the end of a request-path file is a `#[cfg(test)]` module, and a function
    // planted inside one is test code the rule is right to ignore.
    let mut ov = on(base);
    let target = "crates/busbar-llm/src/engine/pipeline.rs";
    if let Ok(basetext) = cx.read(target) {
        let body: String = (0..400)
            .map(|i| format!("    let _planted_{i} = {i};\n"))
            .collect();
        ov.set(
            target,
            format!("pub fn planted_unreadable_request_path() {{\n{body}}}\n{basetext}"),
        );
    }
    r.push(prove_red(
        cx,
        gate,
        "a request-path function grows past its line ceiling",
        &["request-path-fn-size"],
        ov,
        &["planted_unreadable_request_path"],
    ));

    let planes = ConstructionGate::cfg(cx)
        .and_then(|c| c.plane_crates())
        .unwrap_or_default();
    let mut ov = on(base);
    for p in &planes {
        ov.set(
            format!("crates/{p}/src/zz_planted_ports.rs"),
            (0..40)
                .map(|i| format!("pub fn planted_reach_{i}() {{ busbar_core::internals(); }}\n"))
                .collect::<String>(),
        );
        ov.set(
            format!("crates/{p}/src/zz_planted_ports_tests.rs"),
            format!(
                "#[cfg(test)]\nmod tests {{\n{}}}\n",
                (0..40)
                    .map(|i| format!("    fn planted_{i}() {{ busbar_core::internals(); }}\n"))
                    .collect::<String>()
            ),
        );
    }
    let mut cover = ids("ports-only:", &planes);
    cover.extend(ids("ports-only-tests:", &planes));
    r.push(prove_red(
        cx,
        gate,
        "every plane reaches past the ABI into the kernel, in production code and from tests",
        &refs(&cover),
        ov,
        &["zz_planted_ports.rs", "zz_planted_ports_tests.rs"],
    ));
    r
}

/// The Teller loop: its tokens, its order, its one entry per plane, and the substrate's seams.
fn loop_cases(gate: &dyn Gate, cx: &Ctx, base: &Overlay) -> Report {
    let mut r = Report::new();

    let mut ov = on(base);
    ov.set(
        "crates/busbar-llm/src/zz_planted_token.rs",
        "pub fn planted_forged_token() {\n    let _ = UnitToken::mint(seal);\n    let _ = \
         KernelSeal::acquire_for_kernel(x);\n    let _ = AdmitToken::mint(y);\n}\n",
    );
    r.push(prove_red(
        cx,
        gate,
        "a unit token, a kernel seal and an admit-hold mint are all forged outside the kernel",
        &[
            "token-sealed",
            "token-sealed:kernel-seal",
            "token-sealed:admit-token-mint",
        ],
        ov,
        &[
            "`UnitToken::mint(` at crates/busbar-llm/src/zz_planted_token.rs",
            "call site(s) of `KernelSeal::acquire_for_kernel(`",
            "call site(s) of `AdmitToken::mint(`",
        ],
    ));

    let mut ov = on(base);
    ov.set(
        "crates/busbar-llm/src/zz_planted_loop.rs",
        "pub fn planted_loop_entry_a() {\n    let _ = run_unit(ctx);\n}\n\npub fn \
         planted_loop_entry_b() {\n    let _ = run_unit(ctx);\n}\n\npub fn \
         planted_legacy_a() {\n    run_gauntlet(unit);\n}\n\npub fn planted_legacy_b() {\n    \
         run_gauntlet(unit);\n}\n",
    );
    r.push(prove_red(
        cx,
        gate,
        "a plane enters the loop from two places and grows two more legacy adapter sites",
        &["one-teller-loop", "one-teller-loop:run_gauntlet"],
        ov,
        &["zz_planted_loop.rs"],
    ));

    let mut ov = on(base);
    ov.set(
        "crates/busbar-substrate/src/teller/run.rs",
        "pub fn run_unit() {\n    unit.audit();\n    unit.arrival();\n}\n\npub fn open_unit() {\n \
         unit.audit();\n}\n",
    );
    r.push(prove_red(
        cx,
        gate,
        "the loop calls its steps out of the canonical order",
        &["teller-step-order"],
        ov,
        &["calls the steps as"],
    ));

    let mut ov = on(base);
    ov.set(
        "crates/busbar-substrate/src/zz_planted_seam.rs",
        "static PLANTED_SEAM_CELL: OnceLock<u32> = OnceLock::new();\n\npub fn \
         install_planted_seam(v: u32) {\n    let _ = PLANTED_SEAM_CELL.set(v);\n}\n",
    );
    r.push(prove_red(
        cx,
        gate,
        "an installable substrate seam that no production code installs",
        &["no-uninstalled-seam"],
        ov,
        &["install_planted_seam"],
    ));
    r
}

/// The two rules whose subject is another instrument's answer.
fn delegated_cases(gate: &dyn Gate, cx: &Ctx, base: &Overlay) -> Report {
    let mut r = Report::new();

    let mut ov = on(base);
    ov.set_command(
        external::PURITY_HITS_KEY,
        "#SCAN\tneutral_files=120\tneutral_roots=3\tplane_files=200\tplane_roots=4\n\
         DIALECT\tcrates/busbar-core/src/zz_planted_dialect.rs:7\tanthropic\n",
    );
    r.push(prove_red(
        cx,
        gate,
        "the purity lint reports a dialect noun in a neutral crate",
        &["neutral-no-dialect"],
        ov,
        &["zz_planted_dialect.rs"],
    ));

    let mut ov = on(base);
    ov.set_command(
        external::PURITY_HITS_KEY,
        "#SCAN\tneutral_files=0\tneutral_roots=0\tplane_files=0\tplane_roots=0\n",
    );
    r.push(prove_red(
        cx,
        gate,
        "the delegated scan opened no file at all, which is not a clean tree",
        &["neutral-no-dialect"],
        ov,
        &["scanned zero files"],
    ));

    // THE THIRD ANSWER, and the one this rule was rewritten for. The case above plants a scan that
    // RAN and reached nothing; this one plants a scan that could not be made at all. They are not
    // the same fact and only one of them used to be planted, so the arm that says "did not run" —
    // the arm that exists because a deleted script once made this rule report zero hits for weeks
    // — could be forced to PASS with the whole self-test still green.
    let mut ov = on(base);
    ov.set_command(external::PURITY_HITS_KEY, external::PURITY_HITS_ABSENT);
    r.push(prove_red(
        cx,
        gate,
        "the delegated purity scan producing no hits file at all is not a clean tree either",
        &["neutral-no-dialect"],
        ov,
        &["the delegated scan did not run"],
    ));
    r
}

/// The section 1.1 ceilings, each spent in the file or crate whose budget it is.
fn ceiling_cases(gate: &dyn Gate, cx: &Ctx, base: &Overlay) -> Report {
    let mut r = Report::new();
    let Ok(cfg) = ConstructionGate::cfg(cx) else {
        r.note_infra_failure("the ceilings file could not be read, so no ceiling can be planted");
        return r;
    };

    let mut ov = on(base);
    let mut cover = strings(&[
        "loc-ceilings:kernel",
        "loc-ceilings:caps-contract",
        "loc-ceilings:unit-total",
        "loc-ceilings:unit-verbs",
        "loc-ceilings:union",
    ]);
    // The row prints its label and its file patterns, never its offender list, so the naming is
    // the patterns the ceiling is written for: that text appears only when THAT row is not PASS.
    let mut naming: Vec<String> = Vec::new();
    for (key, spec) in cfg.doc.children("rules.loc-ceilings.kernel_files") {
        let patterns = spec.list_of("patterns");
        for p in &patterns {
            let rel = format!("crates/busbar-kernel/src/{p}");
            if let Ok(basetext) = cx.read(&rel) {
                ov.set(&rel, format!("{basetext}\n{}", bulk(2000)));
            }
        }
        naming.push(format!("({})", patterns.join(", ")));
        cover.push(format!("loc-ceilings:kernel:{key}"));
    }
    naming.push("reachable-by-name in".to_string());
    naming.push("together stay within their LOC ceiling".to_string());
    naming.push("all busbar-unit-* crates together".to_string());
    naming.push("the kernel + caps/contract + unit-* union".to_string());

    let caps = cfg
        .rule("loc-ceilings")
        .ok()
        .and_then(|t| t.str_of("caps_crate").map(String::from))
        .unwrap_or_else(|| "busbar-caps".to_string());
    ov.set(format!("crates/{caps}/src/zz_planted_loc.rs"), bulk(200));
    let verbs = cfg
        .rule("loc-ceilings")
        .ok()
        .and_then(|t| t.str_of("verbs_crate").map(String::from))
        .unwrap_or_default();
    for d in dirs_for_globs(cx, &strings(&["crates/busbar-unit-*"])) {
        let name = crate_name_of_dir(&d);
        let n = if name == verbs { 16_000 } else { 2_600 };
        ov.set(format!("crates/{name}/src/zz_planted_loc.rs"), bulk(n));
    }
    naming.push(format!("{verbs} stays within its LOC ceiling"));
    r.push(prove_red(
        cx,
        gate,
        "every section 1.1 ceiling is spent past its figure, in the file or crate it belongs to",
        &refs(&cover),
        ov,
        &refs(&naming),
    ));

    // The surface ceilings are `loc-surface.py`'s answer, planted for the same reason the purity
    // lint's is: the measuring subprocess cannot see this process's overlay.
    let mut ov = on(base);
    let mut cover = Vec::new();
    for (id, _key, crates, _what, _default) in super::SURFACE {
        ov.set_command(
            format!("{}{crates}", external::SURFACE_KEY_PREFIX),
            format!("1\n{crates}  999999\ntotal  999999\nFAIL  {crates}  999999 > 1\n"),
        );
        cover.push(format!("surface-ceiling:{id}"));
    }
    r.push(prove_red(
        cx,
        gate,
        "every section 1.1 surface ceiling is reported over by its meter",
        &refs(&cover),
        ov,
        &["999999"],
    ));

    r.append(ceiling_ratchet_cases(gate, cx, base, &cfg));
    r
}

/// THE RULES ABOUT THE CEILINGS THEMSELVES, planted through the ceilings file rather than through
/// the tree.
///
/// Both rules read a NUMBER, and the honest plant for a rule about a number is a different number:
/// planting a bigger tree would prove the measurement moved, which is what every other case in this
/// file already proves. So the ceilings file itself is the overlay, and the base commit's copy of
/// it is the overlay's answer to the `show` the rule asks git for.
fn ceiling_ratchet_cases(gate: &dyn Gate, cx: &Ctx, base: &Overlay, cfg: &Cfg) -> Report {
    let mut r = Report::new();
    let Ok(text) = cx.read(CEILINGS) else {
        r.note_infra_failure("the ceilings file could not be read, so it cannot be re-pinned");
        return r;
    };

    // -- ceiling-slack ---------------------------------------------------------------------------
    let Some(raised) = ceilings::set_int(&text, "rules.legacy-reach", "ceiling", 1_000_000) else {
        r.note_infra_failure(
            "[rules.legacy-reach] carries no `ceiling` to raise, so the slack rule cannot be \
             planted against the row it is written for",
        );
        return r;
    };
    let mut ov = on(base);
    ov.set(CEILINGS, raised);
    r.push(prove_rows_red(
        cx,
        gate,
        "a ceiling raised above what it measures is slack, and slack is a ceiling already spent",
        &[ceilings::ROW_SLACK],
        ov,
        &["rules.legacy-reach.ceiling = 1000000"],
    ));
    r.push(prove_rows_green(
        cx,
        gate,
        "on the committed ceilings file every ratcheted ceiling equals its measurement",
        &[ceilings::ROW_SLACK],
        on(base),
    ));

    // -- the per-crate reach figures, which used to be WARN rows nothing could fail on ------------
    let mut pinned = text.clone();
    let mut cover = Vec::new();
    for (key, _) in cfg.doc.children("rules.legacy-reach.prefixes") {
        let table = format!("rules.legacy-reach.prefixes.{key}");
        if let Some(next) = ceilings::set_int(&pinned, &table, "figure", 0) {
            pinned = next;
            cover.push(format!("legacy-reach:{key}"));
        }
    }
    if cover.is_empty() {
        r.note_infra_failure(
            "no `[rules.legacy-reach.prefixes.*]` figure could be planted, so the rows that used \
             to be informational are unproven",
        );
    } else {
        let mut ov = on(base);
        ov.set(CEILINGS, pinned);
        // The tree is UNCHANGED here and the figure is: a row that had stopped counting the root
        // would measure 0 against 0 and pass, so this plant proves both halves at once.
        r.push(prove_rows_red(
            cx,
            gate,
            "each retiring crate's own reach figure is a ratchet the root can exceed, not a \
             comment beside one",
            &refs(&cover),
            ov,
            &["ratchet 0, pinned to the measurement"],
        ));
    }

    // -- ceiling-rose ----------------------------------------------------------------------------
    let based = match ceilings::base_ref(cx) {
        Ok(b) => b,
        Err(e) => {
            r.note_infra_failure(format!(
                "no base commit could be resolved in this repository, so the rule that compares \
                 against one is unproven here rather than passing: {e}"
            ));
            return r;
        }
    };
    for (file, table, key) in rose_plants(cx) {
        let Ok(now) = cx.read(&file) else { continue };
        let Some(lowered) = ceilings::set_int(&now, &table, &key, 0) else {
            continue;
        };
        let mut ov = on(base);
        ov.set_command(format!("git-show:{based}:{file}"), lowered);
        r.push(prove_rows_red(
            cx,
            gate,
            format!("a ceiling in {file} that is higher than it was at the base is refused"),
            &[ceilings::ROW_ROSE],
            ov,
            &[&format!("{file} {table}.{key}: 0 ->")],
        ));
    }

    r.append(base_seam_cases(gate, cx, base, &based, &text));
    r.append(declared_raise_cases(gate, cx, base, &based, &text, cfg));
    r.append(kind_row_identity_cases(gate, cx, base, &based, &text));

    // A base whose ceilings file cannot be PARSED is a comparison that cannot be made, and a
    // comparison that cannot be made is not a comparison that passed.
    let mut ov = on(base);
    ov.set_command(
        format!("git-show:{based}:{CEILINGS}"),
        "[rules.x\nthis is not a ceilings file\n",
    );
    r.push(prove_rows_red(
        cx,
        gate,
        "a base whose ceilings file cannot be read is refused, never compared against nothing",
        &[ceilings::ROW_ROSE],
        ov,
        &["could not be compared against the base"],
    ));
    r.push(prove_rows_green(
        cx,
        gate,
        "against the real base no ceiling on this branch has risen",
        &[ceilings::ROW_ROSE],
        on(base),
    ));

    // -- ceiling-census --------------------------------------------------------------------------
    //
    // THE ROW THAT COUNTS THE RULE TABLES THE REST OF THE GATE IS DERIVED FROM. `owed()` reads the
    // same `Cfg` the rules read, so deleting `[rules.loc-ceilings.kernel_files.arena]` deleted the
    // check AND the obligation in one edit — 112 rows became 111, silently. These cases drive the
    // shortfall arm from the other side: raising a census floor above what the tree carries is the
    // same comparison as deleting the table under a floor that stayed put, and it is a one-integer
    // plant that cannot rot the way a hard-coded table name would.
    if let Some(planted) = ceilings::set_int(&text, "gate.census", "loc_ceilings_kernel_files", 99)
    {
        let mut ov = on(base);
        ov.set(CEILINGS, planted);
        r.push(prove_rows_red(
            cx,
            gate,
            "a rule table that went missing under its census floor is refused",
            &[census::ROW_CENSUS],
            ov,
            &["[rules.loc-ceilings.kernel_files] entries:", "99 pinned"],
        ));
    } else {
        r.note_infra_failure(
            "the [gate.census] loc_ceilings_kernel_files floor could not be rewritten, so the arm \
             that refuses a deleted rule table is unproven",
        );
    }

    // AND THE GLOB HALF. `kind-isolation:truths` checks that a `[gate.plugin_kinds]` KEY exists,
    // never that its globs still match anything, so narrowing `crates/busbar-plane-*` to one crate
    // leaves every cross-check green while four crates stop being scanned. The census pins the
    // MATCH COUNT, and this case is that pin doing its job.
    if let Some(planted) = ceilings::set_int(&text, "gate.census.plugin_kinds", "plane", 99) {
        let mut ov = on(base);
        ov.set(CEILINGS, planted);
        r.push(prove_rows_red(
            cx,
            gate,
            "a kind glob that stopped matching its crates is refused",
            &[census::ROW_CENSUS],
            ov,
            &["[gate.plugin_kinds] plane =", "99 pinned"],
        ));
    } else {
        r.note_infra_failure(
            "the [gate.census.plugin_kinds] plane floor could not be rewritten, so the arm that \
             refuses a narrowed kind glob is unproven",
        );
    }

    // -- ceiling-census: THE ONE THING THAT LOWERS A FLOOR ---------------------------------------
    //
    // Deleting a legacy crate is the work 1.6.0 exists to do, and every deletion drops a census
    // count. The floor refuses that, correctly — it cannot tell a retirement apart from "delete the
    // rule table and drop its number in the same edit" by looking at the numbers. A NAME can, so a
    // `[[gate.census_retired]]` row is the only thing that admits a lowered floor, and these are the
    // three ways the row itself is refused. The ADMISSION half is a claim about real git history —
    // the base's copy of the ceilings file — so it is proven by unit test in `census`, on the same
    // terms `lowered_floors` already was: no branch can stage a base commit.
    for (name, row, naming) in [
        (
            "a retirement row naming a crate that is still in the tree is refused",
            "crate = \"busbar-voice\"\ncommit = \"deadbeef\"\nfloor = \"plane_crates\"\nfrom = \
             4\nto = 3\n",
            &["busbar-voice", "is still in", "nothing was retired"][..],
        ),
        (
            "a retirement row that lowers its floor by more than one is refused",
            "crate = \"busbar-nosuch\"\ncommit = \"deadbeef\"\nfloor = \"plane_crates\"\nfrom = \
             4\nto = 2\n",
            &["lowers it by 2", "deletes ONE crate"][..],
        ),
        (
            "a retirement row missing a field is refused, not skipped",
            "crate = \"busbar-nosuch\"\nfloor = \"plane_crates\"\nfrom = 4\nto = 3\n",
            &["missing one of", "not a retirement"][..],
        ),
    ] {
        let mut ov = on(base);
        ov.set(
            CEILINGS,
            format!("{}\n\n[[gate.census_retired]]\n{row}", text.trim_end()),
        );
        r.push(prove_rows_red(
            cx,
            gate,
            name,
            &[census::ROW_CENSUS],
            ov,
            naming,
        ));
    }

    r.push(prove_rows_green(
        cx,
        gate,
        "on this tree every rule table, plane crate and kind glob is still counted",
        &[census::ROW_CENSUS],
        on(base),
    ));

    // -- one-attempt-seam: THE SCAN SET GOING EMPTY ----------------------------------------------
    //
    // `one-attempt-seam` counts send-verb sites OUTSIDE `allowed_function`, and its `inside == 0`
    // arm is the one that notices the seam MOVED — the send verb matched nothing inside the allowed
    // function, i.e. the scan set went empty. A blind-stub audit found that arm was driven by NO
    // selftest case: stub it and `construction --selftest` gained ZERO failures. It is the only
    // thing standing between an empty scan set and a vacuous green on this row, which is exactly
    // the shape the gate-wide scan-set floor exists to refuse.
    //
    // The plant makes the verb match nothing ANYWHERE, so `extra` is empty too and the row's single
    // offender is the arm under test — nothing else can be what turned it red.
    let verbless = text.replace(
        r#"send_verb = '\.client\(\)\.get\(\)\.request\('"#,
        r#"send_verb = '\.zz_planted_verb_that_matches_nothing\('"#,
    );
    if verbless != text {
        let mut ov = on(base);
        ov.set(CEILINGS, verbless);
        r.push(prove_rows_red(
            cx,
            gate,
            "a send verb that matches nothing inside the allowed function is the seam having \
             moved, not a clean tree",
            &["one-attempt-seam"],
            ov,
            &["performs no attempt at all"],
        ));
    } else {
        r.note_infra_failure(
            "[rules.one-attempt-seam] send_verb could not be rewritten, so the arm that refuses an \
             empty scan set is unproven rather than passing",
        );
    }

    r
}

/// THE DECLARED RAISE: an array of deltas per ceiling, summed against the rise, self-expiring.
///
/// THE PLANT IS THIS FAMILY'S OWN, NEVER THE COMMITTED FILE'S. The `[[gate.ceiling_raises]]`
/// table's entire design is that it EMPTIES ITSELF — an entry is struck the batch after its face
/// lands — so a case that read whichever entry the tree happened to carry would be a self-test
/// held hostage by the mechanism it is proving. Both halves are planted instead: the BASE's copy
/// of one real ceiling is lowered by a known amount, which makes the committed figure a genuine
/// rise of exactly that amount, and the declarations are appended to the tree's copy. Every case
/// below runs against a `[[gate.ceiling_raises]]` table that is empty on the committed tree, which
/// is the state it is meant to spend most of its life in.
///
/// The cases, over ONE real ceiling (`rules.legacy-reach.ceiling`) and one real base:
///
/// * two faces declared off the same base, each with its own delta, both green in one tree — the
///   shape the retired `[gate.ceiling_raises."<key>"]` header could not spell at all;
/// * a delta above what the tree rose by is over-declared and red;
/// * a delta below it leaves the remainder undeclared and red;
/// * an entry the BASE already carries is a warning, never red — its face landed, and the strike
///   cannot ride in the same batch as the face;
/// * an entry the base does NOT carry, naming a ceiling that did not rise, is stale and red;
/// * the retired `from`/`to` shape is refused by name, and the refusal prints the array shape;
/// * `--write` strikes exactly the carried entries and leaves the live one.
fn declared_raise_cases(
    gate: &dyn Gate,
    cx: &Ctx,
    base: &Overlay,
    based: &str,
    text: &str,
    cfg: &Cfg,
) -> Report {
    let mut r = Report::new();
    let (table, key) = ("rules.legacy-reach", "ceiling");
    let Some(now) = cfg.doc.table(table).and_then(|t| t.int_of(key)) else {
        r.note_infra_failure(format!(
            "[{table}] carries no `{key}`, so the declared-raise arms are unproven rather than \
             passing"
        ));
        return r;
    };
    const RISE: i64 = 15;
    let Some(lowered) = ceilings::set_int(text, table, key, now - RISE) else {
        r.note_infra_failure(format!(
            "[{table}] `{key}` could not be lowered at the base, so the declared-raise arms are \
             unproven rather than passing"
        ));
        return r;
    };
    let dotted = format!("{table}.{key}");
    let entry = |key: &str, by: i64, face: &str| -> String {
        format!(
            "\n[[gate.ceiling_raises]]\nkey = \"{key}\"\nby = {by}\nbecause = \"planted by the \
             self-test for the {face} face: its {by} measured lines are the whole of this \
             declared raise, and nothing else on this tree is\"\n"
        )
    };
    // The base's copy and the tree's copy, both planted.
    let plant = |at_base: String, tree: String| -> Overlay {
        let mut ov = on(base);
        ov.set_command(format!("git-show:{based}:{CEILINGS}"), at_base);
        ov.set(CEILINGS, tree);
        ov
    };

    r.push(prove_row_pass_naming(
        cx,
        gate,
        "two faces declared off one base, each by its own delta, are both green in one tree",
        ceilings::ROW_ROSE,
        plant(
            lowered.clone(),
            format!(
                "{text}{}{}",
                entry(&dotted, 10, "virtual-key"),
                entry(&dotted, 5, "key-facts")
            ),
        ),
        &["1 declared raise(s):", "#1 +10", "#2 +5"],
    ));
    r.push(prove_rows_red(
        cx,
        gate,
        "a declared `by` above what the tree rose by is over-declared and refused",
        &[ceilings::ROW_ROSE],
        plant(
            lowered.clone(),
            format!(
                "{text}{}{}",
                entry(&dotted, 10, "virtual-key"),
                entry(&dotted, 10, "key-facts")
            ),
        ),
        &["over-declared", "rose by 15", "sum to 20"],
    ));
    r.push(prove_rows_red(
        cx,
        gate,
        "a declared `by` below what the tree rose by leaves the remainder undeclared",
        &[ceilings::ROW_ROSE],
        plant(
            lowered.clone(),
            format!("{text}{}", entry(&dotted, 10, "virtual-key")),
        ),
        &["cover only 10", "remaining 5 is undeclared"],
    ));
    // SELF-EXPIRY. The base carries the entry — the face landed — so the entry is a warning and
    // the row is green; the strike is `--write`'s, not the next landing's.
    let carried = format!("{text}{}", entry(&dotted, RISE, "virtual-key"));
    r.push(prove_row_pass_naming(
        cx,
        gate,
        "a declared raise the base already carries is a warning, never red",
        ceilings::ROW_ROSE,
        plant(carried.clone(), carried.clone()),
        &["1 declared raise(s) already carried by the base", "--write"],
    ));
    r.push(prove_rows_red(
        cx,
        gate,
        "a declared raise the base does not carry, naming a ceiling that did not rise, is stale",
        &[ceilings::ROW_ROSE],
        plant(text.to_string(), carried),
        &[
            "not a rise at the base",
            "the face it was declared for is gone",
        ],
    ));
    r.push(prove_rows_red(
        cx,
        gate,
        "the retired `from`/`to` shape is refused by name, and the array shape is printed",
        &[ceilings::ROW_ROSE],
        plant(
            lowered.clone(),
            format!(
                "{text}\n[gate.ceiling_raises.\"{dotted}\"]\nfrom = {}\nto = {now}\n\
                 because = \"planted by the self-test in the shape this reader retired: a pair \
                 of numbers that cannot sum with a second face's or expire on its own\"\n",
                now - RISE
            ),
        ),
        &[
            "retired `from`/`to` shape",
            "[[gate.ceiling_raises]]",
            "by = 10",
        ],
    ));

    // THE STRIKE MUST NOT MANUFACTURE A RISE. The declarations carry an integer, `by`, and an
    // array row the reader cannot name is labelled by position — so with the table in the
    // comparison, striking the FIRST of two carried entries (by = 3 ahead of by = 7) read as slot
    // 0 rising 3 -> 7, which is the strike `--write` performs turning `ceiling-rose` red the batch
    // after. The base carries both entries and the same figure; the tree has struck the first.
    let two = format!(
        "{}{}",
        entry(&dotted, 3, "virtual-key"),
        entry("rules.loc-ceilings.union_ceiling", 7, "key-facts")
    );
    r.push(prove_row_pass_naming(
        cx,
        gate,
        "striking an earlier declared delta does not raise a later one's `by`",
        ceilings::ROW_ROSE,
        plant(
            format!("{text}{two}"),
            format!(
                "{text}{}",
                entry("rules.loc-ceilings.union_ceiling", 7, "key-facts")
            ),
        ),
        &["1 declared raise(s) already carried by the base"],
    ));

    // `--write` STRIKES EXACTLY THE CARRIED ENTRIES. The base carries two (one of them for a
    // different ceiling), the tree carries those two plus a live third, and the strike is read off
    // the same derivation `--write` commits — without writing a file.
    const SMALL: i64 = 5;
    let Some(lowered_small) = ceilings::set_int(text, table, key, now - SMALL) else {
        r.note_infra_failure(format!(
            "[{table}] `{key}` could not be lowered at the base, so the strike is unproven"
        ));
        return r;
    };
    let landed = format!(
        "{}{}",
        entry(&dotted, 3, "virtual-key"),
        entry("rules.loc-ceilings.union_ceiling", 7, "key-facts")
    );
    let tree = format!("{text}{landed}{}", entry(&dotted, SMALL, "key-directory"));
    let ov = plant(format!("{lowered_small}{landed}"), tree);
    r.push(prove_row_pass_naming(
        cx,
        gate,
        "a live delta beside two carried entries is judged alone; the carried two are warnings",
        ceilings::ROW_ROSE,
        ov.clone(),
        &[
            "1 declared raise(s):",
            "#3 +5",
            "2 declared raise(s) already carried by the base",
        ],
    ));
    let planted = cx.with_overlay(ov);
    let got = match ceilings::struck_text(&planted) {
        Ok((after, struck)) => {
            let struck: Vec<usize> = struck.iter().map(|s| s.ordinal).collect();
            let (left, refused) = ceilings::raises_in(&after);
            let left: Vec<(usize, i64)> = left.iter().map(|s| (s.ordinal, s.by)).collect();
            if struck == [1, 2] && left == [(1, SMALL)] && refused.is_empty() {
                Expect::Green
            } else {
                Expect::Red {
                    naming: vec![format!(
                        "--write would strike {struck:?} and leave {left:?} (refused: \
                         {refused:?}); it must strike exactly the two entries the base carries \
                         and leave the live one"
                    )],
                }
            }
        }
        Err(e) => Expect::Red {
            naming: vec![format!("--write could not derive its strike: {e}")],
        },
    };
    r.push(Case {
        name: "`--write` strikes exactly the declared raises the base carries and no other".into(),
        covers: vec![ceilings::ROW_ROSE.to_string()],
        expected: Expect::Green,
        got,
    });
    r
}

/// THE BASE SEAM — `BUSBAR_GATE_BASE_REF`, driven through the row that reads the base.
///
/// The seam has exactly three arms and each is a different claim, so each gets a case:
///
/// * SET, IT IS THE BASE. The variable names a ref; that ref's copy of the ceilings file is what
///   this tree is compared against, and no merge-base is computed at all.
/// * UNSET, NOTHING MOVED. The same overlay, the same tree, the variable absent — and the answer
///   is the merge-base's, which is what every run before this seam existed got. The two cases share
///   one overlay deliberately: the ONLY difference between them is the variable, so a green here
///   beside the red above is the seam doing exactly one thing.
/// * NAMED AND ABSENT, IT REFUSES BY NAME. A ref the repository has not got is the state a shallow
///   clone or a missing fetch is in. Falling back to the merge-base there would measure the branch
///   against a commit the operator did not name and report it as though they had, so the row is RED
///   and the detail says which variable and which ref.
///
/// The planted base is a SYNTHETIC ref — `git-ref:` says it resolves, `git-show:` says what it
/// carries — because a case that had to write a commit into the repository would be a case that
/// mutates the tree the developer is standing in.
fn base_seam_cases(gate: &dyn Gate, cx: &Ctx, base: &Overlay, based: &str, text: &str) -> Report {
    let mut r = Report::new();
    const NAMED: &str = "refs/busbar-selftest/base-seam";
    const ABSENT: &str = "refs/busbar-selftest/no-such-base";
    let (table, key) = ("rules.legacy-reach", "ceiling");
    let Some(lowered) = ceilings::set_int(text, table, key, 0) else {
        r.note_infra_failure(format!(
            "[{table}] carries no `{key}` to lower at a planted base, so the base seam is unproven \
             rather than passing"
        ));
        return r;
    };
    let mut ov = on(base);
    ov.set_command(format!("git-ref:{NAMED}"), "1");
    ov.set_command(format!("git-show:{NAMED}:{CEILINGS}"), lowered);
    // THE REAL BASE IS PLANTED WITH THIS TREE'S OWN FILE, so the unset arm is green because no
    // ceiling rose and not because of whatever the developer's actual merge-base happens to hold.
    // Without this the pair would be comparing the seam against the state of somebody's checkout.
    ov.set_command(format!("git-show:{based}:{CEILINGS}"), text.to_string());

    r.push(prove_rows_red(
        &cx.clone().with_base_ref(Some(NAMED.to_string())),
        gate,
        format!(
            "{}=<ref> IS the base: the ceilings file is compared against that ref's copy",
            ceilings::BASE_REF_ENV
        ),
        &[ceilings::ROW_ROSE],
        ov.clone(),
        &[&format!("{CEILINGS} {table}.{key}: 0 ->")],
    ));
    r.push(prove_rows_green(
        &cx.clone().with_base_ref(None),
        gate,
        format!(
            "with {} unset the base is the merge-base, on the same overlay that the named base \
             reddens",
            ceilings::BASE_REF_ENV
        ),
        &[ceilings::ROW_ROSE],
        ov,
    ));
    r.push(prove_rows_red(
        &cx.clone().with_base_ref(Some(ABSENT.to_string())),
        gate,
        format!(
            "{}=<a ref this repository has not got> is refused by name, never fallen back from",
            ceilings::BASE_REF_ENV
        ),
        &[ceilings::ROW_ROSE],
        on(base),
        &[
            ceilings::BASE_REF_ENV,
            ABSENT,
            "names no commit this repository can resolve",
        ],
    ));
    r
}

/// The green arm WITH ITS DETAIL READ: the named row is PASS and its detail names every string in
/// `naming`. A warning this gate reports rides in a PASS row's detail — there is no third status —
/// so "green" alone cannot prove the warning was printed.
fn prove_row_pass_naming(
    cx: &Ctx,
    gate: &dyn Gate,
    name: impl Into<String>,
    row: &str,
    overlay: Overlay,
    naming: &[&str],
) -> Case {
    let planted = cx.with_overlay(overlay);
    let verdict = execute(gate, &planted);
    let got = match verdict.rows.iter().find(|r| r.id == row) {
        None => Expect::Red {
            naming: vec![format!("{row}: no such row was emitted")],
        },
        Some(r) if r.status != crate::ledger::Status::Pass => Expect::Red {
            naming: vec![format!("{} {} {}", r.id, r.title, r.detail)],
        },
        Some(r) => {
            let missing: Vec<&&str> = naming.iter().filter(|n| !r.detail.contains(**n)).collect();
            if missing.is_empty() {
                Expect::Green
            } else {
                Expect::Red {
                    naming: vec![format!(
                        "{row} is PASS but its detail does not name {missing:?}: {}",
                        r.detail
                    )],
                }
            }
        }
    };
    Case {
        name: name.into(),
        covers: vec![row.to_string()],
        expected: Expect::Green,
        got,
    }
}

/// One ceiling per watched file, chosen FROM THE FILE rather than named here: a plant that
/// hard-codes a key is a plant that stops planting the day the key is renamed, and goes green.
/// THE STRIKE, AND THE DECLARATION THAT MUST SURVIVE IT.
///
/// `qa/kind-isolation.toml` is an array of tables, so [`crate::toml_doc`] spells every count in it
/// by POSITION. Strike one `[[cell]]` and every later row renumbers by one — and a strike is the
/// landing this entire ratchet exists to make cheap. Under an ordinal key that renumbering silently
/// hands a declared raise to whichever cell slid into the slot, which is a waiver granted to a
/// ceiling nobody wrote it for.
///
/// The plant is exactly that edit, three ways over one tree: the base carries a LOWERED ceiling for
/// a cell deep in the file, and this branch strikes a cell ABOVE it. The rise is therefore real and
/// the row it belongs to has moved.
///
/// * with no declaration, the refusal NAMES the cell — `cell.<crate>.<kind>.count`, not a slot;
/// * a declaration keyed by that identity excuses it, across the renumbering;
/// * a declaration keyed by the ordinal is refused outright, whatever it lines up with.
fn kind_row_identity_cases(
    gate: &dyn Gate,
    cx: &Ctx,
    base: &Overlay,
    based: &str,
    ceilings_text: &str,
) -> Report {
    let mut r = Report::new();
    let file = ceilings::KIND_CEILINGS;
    let Ok(kinds) = cx.read(file) else {
        r.note_infra_failure(format!(
            "{file} could not be read, so the rule that keys a declared raise by identity rather \
             than by ordinal is unproven here rather than passing"
        ));
        return r;
    };
    // THE CELL THE RAISE IS DECLARED ON is the first one at or after position 178 that carries a
    // count above zero, and the cell STRUCK is position 3 — far enough above it that the strike
    // renumbers it. Both are read off the file rather than written down, because a case pinned to
    // a literal ordinal is the very fragility this pair exists to refuse.
    let struck = strike_cell(&kinds, 3);
    let raised = (178..cell_count(&kinds)).find_map(|n| match cell_identity(&kinds, n) {
        Some((k, kd, c)) if c > 0 => Some((n, k, kd, c)),
        _ => None,
    });
    let (Some(struck), Some((ordinal, krate, kind, count))) = (struck, raised) else {
        r.note_infra_failure(format!(
            "{file} does not carry a strikable `[[cell]]` above a later one with a count above \
             zero, so the identity-keyed declaration is unproven here rather than passing"
        ));
        return r;
    };
    let Some(base_kinds) = set_cell_count(&kinds, ordinal, count - 1) else {
        r.note_infra_failure(format!(
            "the `[[cell]]` at {ordinal} in {file} carries no count to lower at the base, so the \
             identity-keyed declaration is unproven here rather than passing"
        ));
        return r;
    };
    let identity = format!("cell.{krate}.{kind}.count");
    let plant = |declaration: &str| -> Overlay {
        let mut ov = on(base);
        ov.set_command(format!("git-show:{based}:{file}"), base_kinds.clone());
        ov.set(file, struck.clone());
        ov.set(CEILINGS, format!("{ceilings_text}{declaration}"));
        ov
    };
    let because = "planted by the self-test: the cell above this one is struck on the same tree, \
                   so an ordinal key would name a different cell entirely and this declaration \
                   must follow the (crate, kind) it was written for";

    r.push(prove_rows_red(
        cx,
        gate,
        "a risen `[[cell]]` ceiling is named by its (crate, kind), never by its position",
        &[ceilings::ROW_ROSE],
        plant(""),
        &[&format!("{file} {identity}: {} -> {count}", count - 1)],
    ));
    r.push(prove_rows_green(
        cx,
        gate,
        "a declared raise keyed by (crate, kind) still names its own cell after a strike \
         renumbers the file",
        &[ceilings::ROW_ROSE],
        plant(&format!(
            "\n[[gate.ceiling_raises]]\nkey = \"{identity}\"\nfile = \"{file}\"\nby = 1\n\
             because = \"{because}\"\n"
        )),
    ));
    r.push(prove_rows_red(
        cx,
        gate,
        "a declared raise keyed by ORDINAL is refused, whatever it happens to line up with",
        &[ceilings::ROW_ROSE],
        plant(&format!(
            "\n[[gate.ceiling_raises]]\nkey = \"cell.{ordinal}.count\"\nfile = \"{file}\"\n\
             by = 1\nbecause = \"{because}\"\n"
        )),
        &["keyed by ORDINAL", "renumbers every later row"],
    ));
    r
}

/// How many `[[cell]]` rows a kind-isolation ledger carries.
fn cell_count(text: &str) -> usize {
    text.lines().filter(|l| l.trim() == "[[cell]]").count()
}

/// The `n`th `[[cell]]` row's bytes, as a half-open range over `text`.
fn nth_cell(text: &str, n: usize) -> Option<(usize, usize)> {
    let mut at = 0usize;
    let mut seen = 0usize;
    let mut start: Option<usize> = None;
    for line in text.split_inclusive('\n') {
        let t = line.trim();
        match start {
            Some(s) if t.starts_with('[') => return Some((s, at)),
            Some(_) => {}
            None => {
                if t == "[[cell]]" {
                    if seen == n {
                        start = Some(at);
                    }
                    seen += 1;
                }
            }
        }
        at += line.len();
    }
    start.map(|s| (s, text.len()))
}

/// `(crate, kind, count)` of the `n`th `[[cell]]` row.
fn cell_identity(text: &str, n: usize) -> Option<(String, String, i64)> {
    let (start, end) = nth_cell(text, n)?;
    let field = |key: &str| -> Option<String> {
        text[start..end].lines().find_map(|l| {
            let (k, v) = l.trim().split_once('=')?;
            (k.trim() == key).then(|| v.trim().trim_matches('"').to_string())
        })
    };
    Some((
        field("crate")?,
        field("kind")?,
        field("count")?.parse().ok()?,
    ))
}

/// The ledger with the `n`th `[[cell]]` row struck out entirely — the deletion that renumbers.
fn strike_cell(text: &str, n: usize) -> Option<String> {
    let (start, end) = nth_cell(text, n)?;
    Some(format!("{}{}", &text[..start], &text[end..]))
}

/// The ledger with the `n`th `[[cell]]` row's count set to `value`, and nothing else touched.
fn set_cell_count(text: &str, n: usize, value: i64) -> Option<String> {
    let (start, end) = nth_cell(text, n)?;
    let mut hit = false;
    let body: String = text[start..end]
        .split_inclusive('\n')
        .map(|line| match line.trim().split_once('=') {
            Some((k, _)) if k.trim() == "count" && !hit => {
                hit = true;
                let nl = if line.ends_with('\n') { "\n" } else { "" };
                format!("count = \"{value}\"{nl}")
            }
            _ => line.to_string(),
        })
        .collect();
    hit.then(|| format!("{}{body}{}", &text[..start], &text[end..]))
}

fn rose_plants(cx: &Ctx) -> Vec<(String, String, String)> {
    let mut out = vec![(
        CEILINGS.to_string(),
        "rules.legacy-reach".to_string(),
        "ceiling".to_string(),
    )];
    if let Ok(text) = cx.read(ceilings::KIND_CEILINGS) {
        if let Ok(doc) = crate::toml_doc::parse_str(&text) {
            let found = doc.tables().iter().find_map(|(p, t)| {
                t.keys()
                    .iter()
                    .find(|k| t.int_of(k).is_some())
                    .map(|k| (p.to_string(), k.clone()))
            });
            if let Some((path, key)) = found {
                out.push((ceilings::KIND_CEILINGS.to_string(), path, key));
            }
        }
    }
    out
}

/// The plugin kinds: the manifest allow-list, the source denylist and the unsafe attributes.
fn kind_cases(gate: &dyn Gate, cx: &Ctx, base: &Overlay) -> Report {
    let mut r = Report::new();
    let manifest_kinds = strings(&[
        "plane",
        "store",
        "pure_auth",
        "hook",
        "export",
        "secret",
        "egress_auth",
    ]);
    let crates = kind_crates(cx, &manifest_kinds);
    let mut ov = on(base);
    for c in &crates {
        let rel = format!("crates/{c}/Cargo.toml");
        if let Ok(basetext) = cx.read(&rel) {
            ov.set(
                &rel,
                basetext.replace(
                    "[dependencies]",
                    "[dependencies]\nbusbar-kernel = { path = \"../busbar-kernel\" }",
                ),
            );
        }
    }
    r.push(prove_red(
        cx,
        gate,
        "every plugin-kind crate names the kernel in its manifest",
        &refs(&ids("manifest-allowlist:", &crates)),
        ov,
        &["RED (kernel/caps/unit/plane/transport): busbar-kernel"],
    ));

    let denylist_kinds = ConstructionGate::cfg(cx)
        .map(|c| {
            c.rule("source-denylist")
                .map(|t| t.list_of("kinds"))
                .unwrap_or_default()
        })
        .unwrap_or_default();
    let pure = kind_crates(cx, &denylist_kinds);
    let mut ov = on(base);
    for c in &pure {
        ov.set(
            format!("crates/{c}/src/zz_planted_io.rs"),
            "pub fn planted_io() {\n    let _ = std::net::TcpStream::connect(addr);\n}\n",
        );
    }
    r.push(prove_red(
        cx,
        gate,
        "every pure-kind crate opens a socket of its own",
        &refs(&ids("source-denylist:", &pure)),
        ov,
        &["zz_planted_io.rs"],
    ));

    let Ok(cfg) = ConstructionGate::cfg(cx) else {
        r.note_infra_failure("the ceilings file would not parse, so no forbid-unsafe case is real");
        return r;
    };
    for (kinds_key, missing_key, rid) in UNSAFE_HALVES {
        let prefix = format!("{rid}:");
        // THE PLANT IS THE WHOLE KIND; THE PROOF IS THE HELD HALF. Every crate of the kind loses
        // the attribute, tracked or not — anything narrower would be a plant shaped to the answer.
        // What the RED case may claim is narrower than what it plants: a crate on the rule's
        // ratchet measures `1` against a ceiling of `1`, so it stays green under this exact plant
        // BY DESIGN, and asking `prove_red` for it would fail the case for the rule working. So
        // the ratcheted crates are proven the other way round, in the green case below: the same
        // plant, the tracked rows, and the claim that tolerating them is what the ratchet is for.
        let (held, tracked) = ConstructionGate::unsafe_split(cx, &cfg, kinds_key, missing_key);
        let here: Vec<String> = held.iter().chain(tracked.iter()).cloned().collect();
        let mut ov = on(base);
        for c in &here {
            for rel in ["src/lib.rs", "src/main.rs"] {
                let path = format!("crates/{c}/{rel}");
                if let Ok(basetext) = cx.read(&path) {
                    ov.set(
                        &path,
                        basetext
                            .replace("forbid(unsafe_code)", "planted_attribute_removed")
                            .replace("deny(unsafe_code)", "planted_attribute_removed"),
                    );
                }
            }
        }
        r.push(prove_red(
            cx,
            gate,
            format!("every crate of this kind loses its `{prefix}` attribute"),
            &refs(&ids(&prefix, &held)),
            ov.clone(),
            &["MISSING"],
        ));
        r.push(prove_rows_green(
            cx,
            gate,
            format!("a `{prefix}` crate the ceilings file already tracks is not a fresh violation"),
            &refs(&ids(&prefix, &tracked)),
            ov,
        ));
    }
    r
}

/// The vocabulary, the kind traits, the seals and the two raw-text scans.
fn vocabulary_cases(gate: &dyn Gate, cx: &Ctx, base: &Overlay) -> Report {
    let mut r = Report::new();

    let mut ov = on(base);
    ov.set(
        "crates/busbar-kernel/src/zz_planted_lean.rs",
        (0..40)
            .map(|i| format!("pub const PLANTED_{i}: &str = \"anthropic chat completion\";\n"))
            .collect::<String>(),
    );
    ov.set(
        "crates/busbar-kernel/src/zz_planted_seal.rs",
        "impl KernelSeal for PlantedForgery {}\n",
    );
    ov.set(
        "crates/busbar-contract/src/zz_planted_escape.rs",
        "pub fn planted_escape() {\n    mem::forget(planted_hold);\n    let _ = \
         KernelSeal::acquire_for_kernel(x);\n}\n",
    );
    ov.set(
        "crates/busbar-contract/src/zz_planted_secret.rs",
        "#[derive(Clone, Debug)]\npub struct Credential {\n    bytes: Vec<u8>,\n}\n",
    );
    ov.set(
        "crates/busbar-contract/src/zz_planted_docs.rs",
        "//! a doc comment that lost its line break\\n//! and carried on regardless\npub const \
         PLANTED_DOC: u32 = 1;\n",
    );
    if let Ok(basetext) = cx.read("crates/busbar-contract/src/kinds.rs") {
        ov.set(
            "crates/busbar-contract/src/kinds.rs",
            basetext.replace(
                "pub trait Hook: Plugin + Send + Sync + 'static {",
                "pub trait Hook: Plugin + Send + Sync + 'static {\n    fn \
                 planted_default_body(&self) -> u32 { 0 }",
            ),
        );
    }
    if let Ok(cfg) = ConstructionGate::cfg(cx) {
        for (_k, spec) in cfg.doc.children("rules.sealed-unit-traits.traits") {
            let (Some(rel), Some(name)) = (spec.str_of("file"), spec.str_of("trait")) else {
                continue;
            };
            if let Ok(basetext) = cx.read(rel) {
                ov.set(
                    rel,
                    basetext.replace(
                        &format!("pub trait {name}: sealed::Sealed"),
                        &format!("pub trait {name}"),
                    ),
                );
            }
        }
    }
    r.push(prove_red(
        cx,
        gate,
        "the kernel names a dialect, a crate forges the seal, a hold is forgotten, a carrier \
         derives Debug, a doc comment loses its line break, a kind trait grows a default body and \
         two unit traits lose their seal",
        &[
            "lean-core",
            "kernel-seal-impls",
            "hold-escapes",
            "seal-sites",
            "secret-carrier-debug",
            "no-escaped-newline-doc-comment",
            "no-default-bodies",
            "sealed-unit-traits",
        ],
        ov,
        &[
            "anthropic chat completion",
            "zz_planted_seal.rs",
            "zz_planted_escape.rs",
            "`Credential` derives Debug",
            "zz_planted_docs.rs",
            "planted_default_body",
            "private-supertrait seal",
        ],
    ));

    let mut ov = on(base);
    ov.set(
        "crates/busbar-kernel/src/zz_planted_hold.rs",
        "pub fn planted_take_and_settle() {\n    let hold = cell.take(token);\n    if x { return; \
         }\n    hold.settle(token);\n}\n\npub fn planted_catch() {\n    let h: Hold = make();\n    \
         let _ = catch_unwind(|| ());\n}\n\npub fn planted_abort() {\n    handle.abort();\n}\n\npub \
         fn planted_forget() {\n    mem::forget(planted_hold_value);\n}\n\npub async fn route() \
         {\n    let _ = planted_thing().await;\n}\n",
    );
    r.push(prove_red(
        cx,
        gate,
        "the hold discipline is broken all five ways in one planted file",
        &[
            "hold-discipline:no-early-exit",
            "hold-discipline:no-catch-unwind-capture",
            "hold-discipline:no-join-abort",
            "hold-discipline:no-forget-or-drop",
            "hold-discipline:cancellation-before-await",
        ],
        ov,
        &[
            "planted_take_and_settle at",
            "planted_catch at",
            "zz_planted_hold.rs",
            "route at",
        ],
    ));

    let units = dirs_for_globs(cx, &strings(&["crates/busbar-unit-*"]));
    let target = units
        .iter()
        .map(|d| crate_name_of_dir(d))
        .find(|n| n != "busbar-unit-ledger");
    match target {
        Some(unit) => {
            let mut ov = on(base);
            ov.set(
                format!("crates/{unit}/src/zz_planted_clock.rs"),
                "// PB-1, CG-2 and ARCHITECTURE.md § 3 all cited instead of stated\npub fn \
                 planted_clock() {\n    let _ = SystemTime::now();\n    let _ = \
                 Instant::now();\n}\n",
            );
            r.push(prove_red(
                cx,
                gate,
                "a unit crate reads the clock and cites a finding identifier",
                &["unit-no-wall-clock", "unit-no-finding-ids"],
                ov,
                &["zz_planted_clock.rs"],
            ));
        }
        None => r.push(Case {
            name: "a unit crate reads the clock and cites a finding identifier".to_string(),
            covers: strings(&["unit-no-wall-clock", "unit-no-finding-ids"]),
            expected: Expect::Red { naming: vec![] },
            got: Expect::Skipped,
        }),
    }
    r
}

/// The plane/price wall and the composition root's stand-ins.
/// A NEEDLE LIST IS PLANTED NEEDLE BY NEEDLE, AND EVERY ONE IS NAMED.
///
/// A rule whose subject is a LIST of spellings is one row over as many independent checks as the
/// list is long, and a plant that exercises three of five leaves the other two deletable with the
/// case still red and the self-test still reporting the gate proven. Both lists this helper is used
/// for had that gap when it was written: the doubles plant named three of five forbidden spellings,
/// and the fee plant named one of three fee fields — and the ceilings file's own comment beside
/// `fee_fields` records the rule having already gone blind once, on the other side of that list,
/// for exactly this reason.
///
/// The plant is derived from the list, one file per entry, so a spelling added to the ceilings file
/// arrives with its own proof and a spelling dropped from the SCAN is a case that stops being red.
fn plant_each(ov: &mut Overlay, dir: &str, tag: &str, needles: &[String]) -> Vec<String> {
    let mut named = Vec::new();
    for (i, needle) in needles.iter().enumerate() {
        let rel = format!("{dir}/zz_planted_{tag}_{i}.rs");
        ov.set(
            &rel,
            format!("pub fn planted_{tag}_{i}() {{\n    let _ = {needle};\n}}\n"),
        );
        named.push(rel);
    }
    named
}

fn money_cases(gate: &dyn Gate, cx: &Ctx, base: &Overlay) -> Report {
    let mut r = Report::new();
    let cfg = ConstructionGate::cfg(cx).ok();
    let listed = |rule: &str, key: &str| -> Vec<String> {
        cfg.as_ref()
            .and_then(|c| c.rule(rule).ok().map(|t| t.list_of(key)))
            .unwrap_or_default()
    };

    let mut ov = on(base);
    ov.set(
        "crates/busbar-llm-codec/src/zz_planted_money.rs",
        "pub fn planted_price() {\n    let _ = RateCard::new();\n    let _ = \
         busbar_unit_cost::price_of(x);\n}\n",
    );
    ov.set(
        "crates/busbar-contract/src/zz_planted_pricing.rs",
        "pub fn planted_pricing() {\n    let _ = cost_price_usage(usage);\n}\n",
    );
    let fee_fields = listed("one-pricing-site", "fee_fields");
    if fee_fields.is_empty() {
        r.note_infra_failure(
            "[rules.one-pricing-site] lists no `fee_fields`, so the fee-reader rule is planted \
             against nothing",
        );
    }
    let mut naming = plant_each(&mut ov, "crates/busbar-contract/src", "fee", &fee_fields);
    naming.extend(strings(&[
        "zz_planted_money.rs",
        "`cost_price_usage(` at crates/busbar-contract/src/zz_planted_pricing.rs",
    ]));
    r.push(prove_red(
        cx,
        gate,
        "a plane codec names a rate card and the cost unit, a second site prices a unit, and EVERY \
         configured fee field is read where the card does not live",
        &[
            "plane-no-money",
            "one-pricing-site",
            "one-pricing-site:fee-fields",
        ],
        ov,
        &refs(&naming),
    ));

    let mut ov = on(base);
    let doubles = listed("no-test-doubles-in-production", "forbidden");
    if doubles.is_empty() {
        r.note_infra_failure(
            "[rules.no-test-doubles-in-production] lists no `forbidden` spellings, so the rule is \
             planted against nothing",
        );
    }
    let mut double_naming = plant_each(&mut ov, "crates/busbar/src", "double", &doubles);
    ov.set(
        "crates/busbar/src/zz_planted_double.rs",
        "pub fn planted_double() {\n    let _ = NullShipper;\n    let _ = RecordingRows;\n    let \
         _ = Pricer::flat(0);\n}\n",
    );
    if let Ok(basetext) = cx.read("crates/busbar/src/main.rs") {
        ov.set(
            "crates/busbar/src/main.rs",
            format!("{basetext}\npub fn planted_extra_double() {{ let _ = NullShipper; }}\n"),
        );
    }
    ov.set(
        "crates/busbar/src/root/zz_planted_reach.rs",
        (0..200)
            .map(|i| {
                format!(
                    "pub fn planted_{i}() {{ busbar_core::planted_{i}(); \
                     busbar_llm::planted_{i}(); busbar_substrate::planted_{i}(); }}\n"
                )
            })
            .collect::<String>(),
    );
    r.push(prove_red(
        cx,
        gate,
        "the shipped binary constructs a stand-in nobody reviewed, gains a reviewed double, and \
         the root's reach into the retiring crates grows",
        &[
            "no-test-doubles-in-production",
            "no-test-doubles-in-production:doubles",
            "legacy-reach",
        ],
        ov,
        // The doubles row prints its reviewed site's REASON, not the code that constructed it, so
        // what names the plant there is the row itself: it is PASS on HEAD (five doubles against a
        // ratchet of five), so its title appearing among the failures is the transition.
        //
        // `legacy-reach` is in `covers` but not here, and the split is the honest one. That row is
        // already RED on HEAD (95 distinct symbols against a ratchet of 92), so no string can
        // distinguish "red because of the plant" from "red because of the tree" — naming one would
        // be a check that passes whatever the plant did. The plant still exercises the rule's whole
        // path, which is what `covers` claims; the RED transition for that row is not provable
        // while the tree is over its own ratchet, and that is a fact about the tree.
        &refs(&{
            double_naming.extend(strings(&[
                "zz_planted_double.rs",
                "the reviewed stand-ins that are doubles rather than real values only shrink",
            ]));
            double_naming
        }),
    ));
    r
}
