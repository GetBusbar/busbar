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
//! TWO ROW FAMILIES CANNOT GO RED, and are covered by the baseline case rather than pretended at:
//! the informational rows (`duplicate-dispatch`, `legacy-reach:<crate>`), which are PASS whatever
//! they measure and say `WARN` in their title; and a `forbid-unsafe:<crate>` row whose crate is on
//! the `known_missing_*` ratchet, whose ceiling of 1 the single measurable value cannot exceed.
//!
//! The first family is DECLARED, through [`crate::gates::Gate::informational`], rather than left
//! to a baseline case whose `covers` list the harness reads as proof. `verify_report` counts
//! coverage from RED cases only — so without the declaration these four rows would be refused, and
//! the two ways to answer that without the declaration are to hand-write the case's `got` or to
//! make the rows judge something the shell they were proven identical to does not judge. Naming
//! them is the honest third answer, and the declaration is itself stale-checked.

use crate::ctx::{Ctx, Overlay};
use crate::gates::construction::tree::{crate_name_of_dir, dirs_for_globs};
use crate::gates::construction::{external, ConstructionGate, UNSAFE_HALVES};
use crate::gates::{execute, prove_red, prove_rows_green, Case, Expect, Gate, Report};

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
    r
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
fn money_cases(gate: &dyn Gate, cx: &Ctx, base: &Overlay) -> Report {
    let mut r = Report::new();

    let mut ov = on(base);
    ov.set(
        "crates/busbar-llm-codec/src/zz_planted_money.rs",
        "pub fn planted_price() {\n    let _ = RateCard::new();\n    let _ = \
         busbar_unit_cost::price_of(x);\n}\n",
    );
    ov.set(
        "crates/busbar-contract/src/zz_planted_pricing.rs",
        "pub fn planted_pricing() {\n    let _ = cost_price_usage(usage);\n    let _ = \
         per_request_fee_cents;\n}\n",
    );
    r.push(prove_red(
        cx,
        gate,
        "a plane codec names a rate card and the cost unit, and a second site prices a unit and \
         reads the per-request fee",
        &[
            "plane-no-money",
            "one-pricing-site",
            "one-pricing-site:fee-fields",
        ],
        ov,
        &[
            "zz_planted_money.rs",
            "`cost_price_usage(` at crates/busbar-contract/src/zz_planted_pricing.rs",
            "zz_planted_pricing.rs",
        ],
    ));

    let mut ov = on(base);
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
        &[
            "zz_planted_double.rs",
            "the reviewed stand-ins that are doubles rather than real values only shrink",
        ],
    ));
    r
}
