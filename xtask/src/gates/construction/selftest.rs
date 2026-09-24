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

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::{Ctx, Overlay};
use crate::gates::construction::model::{CRow, Cfg};
use crate::gates::construction::tree::{crate_name_of_dir, dirs_for_globs};
use crate::gates::construction::{
    ceilings, census, external, rules, ConstructionGate, CEILINGS, UNSAFE_HALVES,
};
use crate::gates::{prove_red, prove_rows_green, prove_rows_red, Case, Expect, Gate, Report};

/// The three delegated answers as the real tree gives them, captured once. Every plant starts from
/// a clone of this, so a case that is not about a delegated input never pays for one.
fn base_overlay(cx: &Ctx) -> Overlay {
    let mut ov = Overlay::new();
    if let Some(hits) = external::purity_hits(cx) {
        ov.set_command(external::PURITY_HITS_KEY, hits);
    }
    if let Ok(map) = external::denylist_hits(cx) {
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
    } else {
        // Captured as what it is — "did not answer" — so every case sees the same answer the
        // real run gave instead of each re-running a scan that fails.
        ov.set_command(external::DENYLIST_KEY, external::DENYLIST_ABSENT);
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

/// The crates of these kinds, or a refusal naming the kind key that does not resolve.
///
/// THE ERROR IS THE POINT. This used to swallow both failures — an unparseable ceilings file and
/// an unknown kind key — into an empty list, and an empty list here plants NOTHING, covers NO row
/// ids, and leaves the case claiming a proof it never ran. That is how the `pure_auth`/`egress_auth`
/// spellings survived: the self-test asked for two kinds that do not exist, planted a kernel
/// dependency into no crate at all, and reported the plugin-kind case green.
fn kind_crates(cx: &Ctx, kinds: &[String]) -> Result<Vec<String>, String> {
    let cfg = ConstructionGate::cfg(cx)?;
    let mut out: Vec<String> = Vec::new();
    for k in kinds {
        out.extend(
            dirs_for_globs(cx, &cfg.kind_globs(k)?)
                .iter()
                .map(|d| crate_name_of_dir(d)),
        );
    }
    out.sort();
    out.dedup();
    Ok(out)
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

pub fn run<'a>(gate: &'a dyn Gate, cx: &'a Ctx) -> Report<'a> {
    let mut r = Report::new();
    let base = base_overlay(cx);

    // ── the baseline ────────────────────────────────────────────────────────────────────────────
    // The same list `Gate::informational` declares, from the same derivation: these rows are
    // exercised here and are held to being measured rather than to going red, because they cannot.
    //
    // MEASURED, NOT EXECUTED, because this one run now has two readers: the leak check below, which
    // needs only ids and details, and the GREEN FIXTURE, which needs each row's measurement and its
    // full offender list — neither of which survives into a `Verdict`. It is the same call
    // `Gate::run` makes; running the gate twice to get both would be the whole-tree-per-plant cost
    // the budget entry exists to catch.
    let informational: Vec<String> = ConstructionGate::informational_ids(cx);
    let measured = ConstructionGate::measure(&cx.with_overlay(on(&base)));
    let rows: Vec<CRow> = measured
        .as_ref()
        .map(|(rows, _)| rows.clone())
        .unwrap_or_default();
    let leaked: Vec<String> = rows
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
    if rows.is_empty() {
        r.note_infra_failure(format!(
            "the construction gate produced no rows at all over the real tree, so every plant \
             below would be judged against nothing{}",
            measured.err().map(|e| format!(": {e}")).unwrap_or_default()
        ));
        return r;
    }

    // ── THE GREEN FIXTURE (item 89) ─────────────────────────────────────────────────────────────
    // Every case below plants into THIS, not into the bare tree. See [`green_fixture`] for what it
    // clears and why that is a baseline and not a waiver.
    let (fixture, cleared) = match green_fixture(cx, &base, &rows) {
        Ok(f) => f,
        Err(e) => {
            r.note_infra_failure(format!(
                "the green fixture could not be built, so every RED case below would be asked on \
                 rows that are already red: {e}"
            ));
            return r;
        }
    };
    let gcx = cx.with_overlay(fixture.clone());

    r.append(shape_cases(gate, &gcx, &fixture));
    r.append(loop_cases(gate, &gcx, &fixture));
    r.append(delegated_cases(gate, &gcx, &fixture));
    r.append(ceiling_cases(gate, &gcx, cx, &fixture, &cleared));
    r.append(kind_cases(gate, &gcx, &fixture));
    r.append(vocabulary_cases(gate, &gcx, &fixture));
    r.append(money_cases(gate, &gcx, &fixture));
    r
}

/// THE GREEN FIXTURE — the cure for standing-red poisoning (item 89), and the baseline every RED
/// case below plants into.
///
/// A RED case proves a rule by a TRANSITION: its rows green unplanted, red planted. On this tree a
/// dozen rows are red before anything is planted — real debt, which the gate reports on HEAD and
/// goes on reporting — and a plant on an already-red row proves nothing (`prove_red` scores it
/// IMPOSSIBLE, and a row red for other reasons among green ones is the same non-proof, only
/// quieter). The cure is never to weaken the rule, drop the case or accept the IMPOSSIBLE. It is
/// to ask the question on a baseline where the row is green, which is this overlay: the tree plus
/// TODAY'S DEBT RECORDED THROUGH EACH RULE'S OWN REVIEW MECHANISM, so the case asks about a site
/// the debt does not touch.
///
/// * `neutral-no-dialect` — the delegated purity answer with its hit lines removed (the `#SCAN`
///   counts kept, so the scan still reports what it opened).
/// * `token-sealed` and its three sub-rows — today's sites NEUTRALISED in the overlay copy of their
///   files (`::mint(` becomes `::zz_fixture_mint(`), so the scan set is every other line of the
///   tree. The rule's `max_sites = 0` is untouched.
/// * `lean-core` — today's sites added to the rule's own `known_sites`.
/// * `manifest-allowlist:<crate>` — today's deps added to that crate's `reviewed_extra` and
///   `known_red_deps`, the rule's two review lists.
/// * every RATCHETED ceiling (`ceilings::pins`) pinned to what it measures — which is exactly the
///   state `ceiling-slack` asks for and `--write` would produce, in both directions.
/// * `ceiling-rose` — the base's copy of both ceilings files planted as THIS file, and the
///   `[gate.ceiling_raises]` declarations dropped, since over a base with no raise every one of
///   them is stale by design.
///
/// NOTHING HERE REACHES THE GATE ITSELF. `cargo xtask gate construction` never sees this overlay;
/// every row it clears stays exactly as red on the gate as it was. What moves is the SELF-TEST's
/// question: "does the rule fire on a NEW violation", which a baseline carrying the old ones in
/// review cannot answer with a false yes. The ids it cleared are returned so the fixture's own
/// green is asserted (see the green control in [`ceiling_ratchet_cases`]) rather than assumed.
fn green_fixture(
    cx: &Ctx,
    base: &Overlay,
    rows: &[CRow],
) -> Result<(Overlay, Vec<String>), String> {
    let cfg = ConstructionGate::cfg(cx)?;
    let mut g = base.clone();
    let mut cleared: Vec<String> = Vec::new();
    let red = |id: &str| -> Option<&CRow> {
        rows.iter()
            .find(|r| r.id == id && r.status != crate::ledger::Status::Pass)
    };
    // `path:line` off an offender, whichever of the two spellings the row uses.
    let site = |o: &str| -> Option<(String, usize)> {
        let loc = o.rsplit_once(" at ").map(|(_, l)| l).unwrap_or(o);
        let (rel, n) = loc.rsplit_once(':')?;
        Some((rel.to_string(), n.parse().ok()?))
    };

    // ── neutral-no-dialect ─────────────────────────────────────────────────────────────────────
    if red("neutral-no-dialect").is_some() {
        if let Some(hits) = base.command(external::PURITY_HITS_KEY) {
            let cats = cfg.rule("neutral-no-dialect")?.list_of("categories");
            let kept = hits
                .split('\n')
                .filter(|ln| {
                    let first = ln.split('\t').next().unwrap_or("");
                    !cats.iter().any(|c| c == first)
                })
                .collect::<Vec<_>>()
                .join("\n");
            g.set_command(external::PURITY_HITS_KEY, kept);
            cleared.push("neutral-no-dialect".to_string());
        }
    }

    // ── token-sealed ────────────────────────────────────────────────────────────────────────────
    let scans = rules::token_sealed_scans(&cfg)?;
    let mut sites: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
    for row in rows.iter().filter(|r| {
        (r.id == "token-sealed" || r.id.starts_with("token-sealed:"))
            && r.status != crate::ledger::Status::Pass
    }) {
        cleared.push(row.id.clone());
        for o in &row.offenders {
            if let Some((rel, n)) = site(o) {
                sites.entry(rel).or_default().insert(n);
            }
        }
    }
    for (rel, lines) in &sites {
        let text = cx.read(rel)?;
        let out = text
            .split('\n')
            .enumerate()
            .map(|(i, l)| {
                if lines.contains(&(i + 1)) {
                    neutralise(l, &scans)
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        g.set(rel, out);
    }

    // ── the ceilings file ───────────────────────────────────────────────────────────────────────
    let mut text = cx.read(CEILINGS)?;
    for pin in ceilings::pins(&cfg) {
        let Some(row) = rows.iter().find(|r| r.id == pin.row) else {
            continue;
        };
        if row.current >= 0 && row.current != row.threshold {
            if let Some(t) = ceilings::set_int(&text, &pin.table, &pin.key, row.current) {
                text = t;
                cleared.push(pin.row.clone());
            }
        }
    }
    if let Some(row) = red("lean-core") {
        let known: Vec<String> = row
            .offenders
            .iter()
            .filter_map(|o| site(o).map(|(rel, n)| format!("{rel}:{n}")))
            .collect();
        text = ceilings::add_to_list(&text, "rules.lean-core", "known_sites", &known)
            .ok_or("[rules.lean-core] has no header to record its known sites under")?;
        cleared.push(row.id.clone());
    }
    for row in rows.iter().filter(|r| {
        r.id.starts_with("manifest-allowlist:") && r.status != crate::ledger::Status::Pass
    }) {
        let crate_name = row.id.trim_start_matches("manifest-allowlist:");
        for table in [
            "rules.manifest-allowlist.reviewed_extra",
            "rules.manifest-allowlist.known_red_deps",
        ] {
            text = ceilings::add_to_list(&text, table, crate_name, &row.offenders)
                .ok_or_else(|| format!("[{table}] has no header to record {crate_name} under"))?;
        }
        cleared.push(row.id.clone());
    }
    let text = ceilings::strip_tables(&text, "gate.ceiling_raises.");
    if let Ok(based) = ceilings::base_ref(cx) {
        g.set_command(ceilings::BASE_PIN_KEY, based.sha.clone());
        g.set_command(format!("git-show:{based}:{CEILINGS}"), text.clone());
        if let Ok(kind) = cx.read(ceilings::KIND_CEILINGS) {
            g.set_command(
                format!("git-show:{based}:{}", ceilings::KIND_CEILINGS),
                kind,
            );
        }
    }
    g.set(CEILINGS, text);
    cleared.sort();
    cleared.dedup();
    Ok((g, cleared))
}

/// One line with every `token-sealed` site on it defused: `zz_fixture_` is inserted after the LAST
/// `::` of each match (after its first byte, for a match with no path separator), which leaves the
/// line's shape and length class intact and matches none of the scans.
fn neutralise(line: &str, scans: &[crate::rx::Regex]) -> String {
    let bytes = line.as_bytes();
    let mut at: BTreeSet<usize> = BTreeSet::new();
    for rx in scans {
        for m in rx.find_iter(bytes) {
            let span = &line[m.start..m.end];
            at.insert(match span.rfind("::") {
                Some(i) => m.start + i + 2,
                None => m.start + 1,
            });
        }
    }
    let mut out = line.to_string();
    for i in at.into_iter().rev() {
        if out.is_char_boundary(i) {
            out.insert_str(i, "zz_fixture_");
        }
    }
    out
}

/// The attempt seam, the request terminal, the plane's doors and the plane/kernel wall.
fn shape_cases<'a>(gate: &'a dyn Gate, cx: &Ctx, base: &Overlay) -> Report<'a> {
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
fn loop_cases<'a>(gate: &'a dyn Gate, cx: &Ctx, base: &Overlay) -> Report<'a> {
    let mut r = Report::new();

    let mut ov = on(base);
    ov.set(
        "crates/busbar-llm/src/zz_planted_token.rs",
        "pub fn planted_forged_token() {\n    let _ = UnitToken::mint(seal);\n    let _ = \
         KernelSeal::acquire_for_kernel(x);\n    let _ = AdmitToken::mint(y);\n}\n",
    );
    // X-178: THE KERNEL'S OTHER SEALED CONSTRUCTORS, WHICH NO ROW OF THIS GATE SCANNED AT ALL.
    //
    // A SECOND FILE IN THIS CASE'S OVERLAY, NOT A SECOND CASE. The budget entry for `construction`
    // says the plants are "grouped by family so one case carries every edit a family needs", and a
    // new case is a whole new drive of every rule over a 660k-line tree — the exact growth that
    // entry exists to catch. These forgeries belong to the family this case already covers, so
    // they ride in its overlay and cost one more file scan rather than one more battery.
    //
    // X-177 widened the TOKEN family and stopped there. A grep of qa/ and xtask/src/ returned ZERO
    // for every symbol below, so each was a badge press reachable from any crate by writing one
    // line. Planted together in an orphan module, all three token-sealed rows stood PASS on all six.
    //
    // The last line is the odd one and is here ON PURPOSE. `SecretOnce::mint(`'s home is the VERBS
    // unit, not the kernel, so it is owned by the `secret-once-mint` sub-row rather than by the
    // family list — and it is written in the FULLY-QUALIFIED spelling the tree actually uses
    // (crates/busbar/src/root/units_admin/tests/units_admin.rs:851), so this also proves the
    // path-prefixed form is reached. Covering that row here proves the DELEGATION too: six planted
    // forgeries, five counted by `token-sealed` and the sixth by its own row, never one twice.
    ov.set(
        "crates/busbar-llm/src/zz_planted_sealed.rs",
        "pub fn planted_forged_kernel_values() {\n    let _ = CallId::seal(seal, 7);\n    let _ = \
         Origin::seal(seal, kind);\n    let _ = SessionId::mint(seal, 9);\n    let _ = \
         IdempotencyKey::mint(seal, digest);\n    let _ = UnitEnd::seal(exit, outcome, \
         posted);\n    let _ = busbar_contract::caps::SecretOnce::mint(admin, n, unit, \
         target);\n}\n",
    );
    r.push(prove_red(
        cx,
        gate,
        "a unit token, a kernel seal, an admit-hold mint, the kernel's own value constructors and \
         the verbs unit's one-time secret placeholder are all forged outside their homes",
        &[
            "token-sealed",
            "token-sealed:kernel-seal",
            "token-sealed:admit-token-mint",
            "token-sealed:secret-once-mint",
        ],
        ov,
        // X-177: THIS CASE WAS ALREADY FAILING, AND WHAT IT WAS FAILING ABOUT WAS TRUE. The plant
        // below is the exact forgery the finding reproduces, and two of the three rows it covers
        // went PASS under it — `narrowed_got` therefore reported Green where Red was expected, so
        // `cargo xtask gate construction --selftest` was red on the one case that holds the badge
        // press. The case was right and the ROWS were wrong; the rows are widened now.
        //
        // The third string used to read "call site(s) of `AdmitToken::mint(`", which the sub-row's
        // detail satisfied out of a HARD-CODED subject label rather than out of anything it
        // scanned. It is now two strings against the same row: that its claim still NAMES the
        // pre-#73 constructor, and that it reported the planted `AdmitToken::mint(` line (4) as an
        // offender SITE — so the label can no longer be green on a symbol the scan cannot see.
        &[
            "`UnitToken::mint(` at crates/busbar-llm/src/zz_planted_token.rs",
            "call site(s) of `KernelSeal::acquire_for_kernel(`",
            "pre-#73 name `AdmitToken::mint(`",
            "(ceiling 0): crates/busbar-llm/src/zz_planted_token.rs:4",
            // X-178. One string per symbol, each naming the SPELLING and the SITE, so a row that
            // goes red for some other reason cannot satisfy this case.
            "`CallId::seal(` at crates/busbar-llm/src/zz_planted_sealed.rs:2",
            "`Origin::seal(` at crates/busbar-llm/src/zz_planted_sealed.rs:3",
            "`SessionId::mint(` at crates/busbar-llm/src/zz_planted_sealed.rs:4",
            "`IdempotencyKey::mint(` at crates/busbar-llm/src/zz_planted_sealed.rs:5",
            "`UnitEnd::seal(` at crates/busbar-llm/src/zz_planted_sealed.rs:6",
            // The verbs-unit symbol lands on its own sub-row, which prints sites as `path:line`.
            "(ceiling 0): crates/busbar-llm/src/zz_planted_sealed.rs:7",
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

    // Three RED proofs, all against `crates/busbar-kernel/src/teller.rs` — the rule's own `file`,
    // since the REPOINT (ff61939db) moved it off the deleted busbar-substrate path. A minimal,
    // same-line `units.step()` pair is enough to exercise `in_order` and `duplicate_findings`
    // without needing the real file's multi-line `units\n    .step(...)` chain style; the real
    // file's own GREEN (see `loop_cases` baseline coverage below and the construction gate run
    // itself) is what proves the chain-style receiver scan and the `route_leg`/`reached`
    // indirections still resolve correctly, so these three plants only need to prove `in_order` and
    // `duplicate_findings` still catch what they are FOR.
    let mut ov = on(base);
    ov.set(
        "crates/busbar-kernel/src/teller.rs",
        "pub fn run_unit() {\n    units.arrival();\n    units.authenticate();\n    \
         units.decode();\n    units.verify();\n    units.approve();\n    units.admit();\n    \
         units.route();\n    units.meter();\n    units.audit();\n}\n\npub fn open_unit() {\n    \
         units.arrival();\n    units.decode();\n    units.authenticate();\n    units.verify();\n  \
         units.approve();\n    units.admit();\n    units.audit();\n}\n",
    );
    r.push(prove_red(
        cx,
        gate,
        "a swapped pair: the loop calls decode and authenticate out of the canonical order",
        &["teller-step-order"],
        ov,
        &["calls the steps as"],
    ));

    let mut ov = on(base);
    ov.set(
        "crates/busbar-kernel/src/teller.rs",
        "pub fn run_unit() {\n    units.arrival();\n    units.decode();\n    \
         units.authenticate();\n    units.approve();\n    units.admit();\n    units.route();\n    \
         units.meter();\n    units.audit();\n}\n\npub fn open_unit() {\n    units.arrival();\n    \
         units.decode();\n    units.authenticate();\n    units.verify();\n    units.approve();\n   \
         units.admit();\n    units.audit();\n}\n",
    );
    r.push(prove_red(
        cx,
        gate,
        "a missing step: the loop never calls verify at all",
        &["teller-step-order"],
        ov,
        &["calls the steps as"],
    ));

    let mut ov = on(base);
    ov.set(
        "crates/busbar-kernel/src/teller.rs",
        "pub fn run_unit() {\n    units.arrival();\n    units.decode();\n    \
         units.authenticate();\n    units.verify();\n    units.approve();\n    units.admit();\n    \
         units.admit();\n    units.route();\n    units.meter();\n    units.audit();\n}\n\npub fn \
         open_unit() {\n    units.arrival();\n    units.decode();\n    units.authenticate();\n    \
         units.verify();\n    units.approve();\n    units.admit();\n    units.audit();\n}\n",
    );
    r.push(prove_red(
        cx,
        gate,
        "a duplicated step: the loop calls admit twice",
        &["teller-step-order"],
        ov,
        &["calls step `admit` 2 times; it must run exactly once"],
    ));

    let mut ov = on(base);
    ov.set(
        // Under `[rules.no-uninstalled-seam].seam_root` AS REPOINTED: the engine half of the
        // substrate is `crates/busbar-kernel/src` (5fa320208 absorbed it at R100), so a plant at
        // the deleted `crates/busbar-substrate/src` would sit under no declared root and this
        // positive control would stop proving anything at all.
        "crates/busbar-kernel/src/zz_planted_seam.rs",
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
fn delegated_cases<'a>(gate: &'a dyn Gate, cx: &Ctx, base: &Overlay) -> Report<'a> {
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
fn ceiling_cases<'a>(
    gate: &'a dyn Gate,
    cx: &Ctx,
    real: &Ctx,
    base: &Overlay,
    cleared: &[String],
) -> Report<'a> {
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
        "loc-ceilings:union",
    ]);
    // The row prints its label and its file patterns, never its offender list, so the naming is
    // the patterns the ceiling is written for: that text appears only when THAT row is not PASS.
    let mut naming: Vec<String> = Vec::new();
    for (key, spec) in cfg.doc.children("rules.loc-ceilings.kernel_files") {
        let patterns = spec.list_of("patterns");
        for p in &patterns {
            let rel = format!("crates/busbar-kernel/src/{p}");
            // A PATTERN WHOSE FILE IS NOT THERE STILL HAS TO BE PLANTABLE. This used to plant only
            // when the file already existed, so the rows whose subject had LEFT the kernel --
            // `slice.rs`, which moved to busbar-contract, and `arena.rs`/`masking.rs`, which no
            // longer exist anywhere -- measured the empty set, passed under every plant, and made
            // this case unable to tell "the ceiling held" from "the ceiling was never spent". That
            // is the one thing the case is for. Planting the file INTO EXISTENCE reds the row the
            // way the file coming back would.
            let planted = match cx.read(&rel) {
                Ok(basetext) => format!("{basetext}\n{}", bulk(2000)),
                Err(_) => bulk(2000),
            };
            ov.set(&rel, planted);
        }
        naming.push(format!("({})", patterns.join(", ")));
        cover.push(format!("loc-ceilings:kernel:{key}"));
    }
    naming.push("reachable-by-name in".to_string());
    naming.push("together stay within their LOC ceiling".to_string());
    naming.push("all busbar-unit-* crates together".to_string());
    // The union row's title, as `loc_ceilings` spells it since busbar-caps folded into the contract
    // (#37/#38). It read "caps/contract" here after the row stopped saying so, and the case failed
    // on the stale string rather than on anything the rule did.
    naming.push("the kernel + contract + unit-* union".to_string());

    // THE CONTRACT CRATE, READ FROM THE KEY THE ROW READS. This planted into `caps_crate`, falling
    // back to `busbar-caps` — a key struck from the ceilings file and a crate folded into
    // busbar-contract (2c9eddecf) — so the plant landed in a crate no row measures, and
    // `loc-ceilings:caps-contract` looked proven only because it was already over its ceiling.
    // On the green fixture it is at its ceiling, and this plant is what has to move it.
    let contract = cfg
        .rule("loc-ceilings")
        .ok()
        .and_then(|t| t.str_of("contract_crate").map(String::from))
        .unwrap_or_else(|| "busbar-contract".to_string());
    ov.set(
        format!("crates/{contract}/src/zz_planted_loc.rs"),
        bulk(200),
    );
    for d in dirs_for_globs(cx, &strings(&["crates/busbar-unit-*"])) {
        let name = crate_name_of_dir(&d);
        ov.set(format!("crates/{name}/src/zz_planted_loc.rs"), bulk(2_600));
    }
    r.push(prove_red(
        cx,
        gate,
        "every section 1.1 ceiling is spent past its figure, in the file or crate it belongs to",
        &refs(&cover),
        ov,
        &refs(&naming),
    ));

    // The surface ceilings are `cargo xtask loc`'s answer. It is asked IN PROCESS now and is
    // overlay-aware, so a plant could drive it directly; the planted-command seam is kept because
    // it is the only way to plant a figure the tree cannot actually hold (999999), which is what
    // proves the ROW rather than the counter.
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

    r.append(ceiling_ratchet_cases(gate, cx, real, base, &cfg, cleared));
    r
}

/// THE RULES ABOUT THE CEILINGS THEMSELVES, planted through the ceilings file rather than through
/// the tree.
///
/// Both rules read a NUMBER, and the honest plant for a rule about a number is a different number:
/// planting a bigger tree would prove the measurement moved, which is what every other case in this
/// file already proves. So the ceilings file itself is the overlay, and the base commit's copy of
/// it is the overlay's answer to the `show` the rule asks git for.
fn ceiling_ratchet_cases<'a>(
    gate: &'a dyn Gate,
    cx: &Ctx,
    real: &Ctx,
    base: &Overlay,
    cfg: &Cfg,
    cleared: &[String],
) -> Report<'a> {
    let mut r = Report::new();
    let Ok(text) = cx.read(CEILINGS) else {
        r.note_infra_failure("the ceilings file could not be read, so it cannot be re-pinned");
        return r;
    };

    // ONE PLANTED CEILINGS FILE FOR FOUR RULES. `ceiling-slack`, the per-crate reach figures,
    // `ceiling-census` and the `one-attempt-seam` scan-set arm are each proven by a different
    // number or string in this one file, touching disjoint keys and read by disjoint rows. They
    // were six cases — six whole-gate drives over a 660k-line tree — and the budget entry for this
    // gate is exactly about that growth. They are one plant now, and each row is still held to its
    // own naming string, so a rule that stopped seeing its edit fails this case by name.
    let mut combined = text.clone();
    let mut combined_cover: Vec<String> = Vec::new();
    let mut combined_naming: Vec<String> = Vec::new();

    // -- ceiling-slack ---------------------------------------------------------------------------
    match ceilings::set_int(&combined, "rules.legacy-reach", "ceiling", 1_000_000) {
        Some(raised) => {
            combined = raised;
            combined_cover.push(ceilings::ROW_SLACK.to_string());
            combined_naming.push("rules.legacy-reach.ceiling = 1000000".to_string());
        }
        None => r.note_infra_failure(
            "[rules.legacy-reach] carries no `ceiling` to raise, so the slack rule cannot be \
             planted against the row it is written for",
        ),
    }

    // -- the per-crate reach figures, which used to be WARN rows nothing could fail on ------------
    let mut pinned = combined.clone();
    let mut cover = Vec::new();
    // ONLY A FIGURE ABOVE ZERO CAN BE PLANTED DOWN TO ZERO. `busbar_core` and `busbar_substrate`
    // measure 0 against 0, so rewriting their figure to 0 changes nothing and their rows cannot go
    // red under this plant — which is how this case reported "expected Red, got Green" while every
    // rule under it worked. Those rows are proven where their MEASUREMENT can move: the root-reach
    // plant in `money_cases`, which names all three prefixes and covers every per-crate row.
    for (key, spec) in cfg.doc.children("rules.legacy-reach.prefixes") {
        let table = format!("rules.legacy-reach.prefixes.{key}");
        if spec.int_of("figure").unwrap_or(0) <= 0 {
            continue;
        }
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
        // The tree is UNCHANGED here and the figure is: a row that had stopped counting the root
        // would measure 0 against 0 and pass, so this plant proves both halves at once.
        combined = pinned;
        combined_cover.extend(cover);
        combined_naming.push("ratchet 0, pinned to the measurement".to_string());
    }

    // -- ceiling-rose ----------------------------------------------------------------------------
    //
    // A BASE THAT CANNOT BE ESTABLISHED IS RED, NEVER GREEN, and until this case existed that claim
    // lived only in a doc comment. It was false twice: `base_ref` once treated "the ref does not
    // resolve" as "compare against HEAD~1", and later resolved a ref that had gone stale and
    // diverged. Both read exactly like a working gate, for weeks, because nothing ever drove the
    // arm. The ref is asked of `base_line` rather than written down here, so this case keeps
    // exercising the arm on a checkout whose branch is not the one it was written on.
    if let Ok((line, _)) = ceilings::base_line(cx) {
        let mut ov = on(base);
        // The fixture PINS the base; this case is about the live derivation, so it unpins it.
        ov.set_command(ceilings::BASE_PIN_KEY, "");
        ov.set_command(format!("git-ref:{line}"), "0");
        r.push(prove_rows_red(
            cx,
            gate,
            "a base ref that does not resolve is refused, never quietly replaced by HEAD~1",
            &[ceilings::ROW_ROSE],
            ov,
            &["no base commit could be established"],
        ));
    } else {
        r.note_infra_failure(
            "this checkout has no base line to plant as unresolvable (detached HEAD), so the arm \
             that refuses an unestablishable base is unproven here",
        );
    }

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
    // …AND A DECLARATION THAT DESCRIBES NO RAISE AT ALL IS A WAIVER THAT OUTLIVED WHAT IT EXCUSED.
    // This is the half that makes the mechanism unable to silt up: the entry is struck by the
    // commit after the one that needed it, or this row says so. It rides in the SAME plant as the
    // qa/kind-isolation.toml raise below: the two edits are in different files, each produces its
    // own finding on this row, and the case names both — one drive of the gate instead of two.
    let stale_declaration = format!(
        "{text}\n[gate.ceiling_raises.\"rules.legacy-reach.ceiling\"]\nfrom = 1\nto = 2\n\
         because = \"planted by the self-test; it describes no raise on this branch and must \
         therefore be refused as a stale declaration rather than carried\"\n"
    );
    let mut stale_carried = false;
    for (file, table, key) in rose_plants(cx) {
        let Ok(now) = cx.read(&file) else { continue };
        let Some(lowered) = ceilings::set_int(&now, &table, &key, 0) else {
            continue;
        };
        let mut ov = on(base);
        ov.set_command(format!("git-show:{based}:{file}"), lowered);
        let raised = format!("{file} {table}.{key}: 0 ->");
        let mut naming: Vec<&str> = vec![&raised];
        let mut name =
            format!("a ceiling in {file} that is higher than it was at the base is refused");
        if file != CEILINGS && !stale_carried {
            ov.set(CEILINGS, stale_declaration.clone());
            naming.push("is not a raise at the base");
            name.push_str(
                ", and a declared raise that is not a raise at the base is a waiver that outlived \
                 its commit",
            );
            stale_carried = true;
        }
        r.push(prove_rows_red(
            cx,
            gate,
            name,
            &[ceilings::ROW_ROSE],
            ov,
            &naming,
        ));
    }

    // ── the declared raise, and both ways it is refused ─────────────────────────────────────────
    //
    // A DECLARATION THAT DOES NOT DESCRIBE THIS RAISE EXCUSES NOTHING. The committed entry says
    // 26 -> 47; rewriting its `to` leaves the raise in the file undeclared, and a declaration that
    // named a direction rather than an edit would be a permanent hole with a reason field.
    //
    // THE PLANT IS THIS CASE'S OWN, NEVER THE COMMITTED FILE'S. It used to rewrite whichever
    // `[gate.ceiling_raises]` entry the tree happened to carry — and that made the case depend on a
    // table whose entire design is that it EMPTIES ITSELF. A declaration expires the commit after
    // the one that needed it; the commit that struck the last standing entry turned this case into
    // an infra failure, which is a self-test held hostage by the mechanism it is proving. So both
    // halves are planted: the BASE's copy of one real ceiling is lowered, which makes the committed
    // file a genuine raise, and a declaration is appended whose numbers describe a different edit.
    // The refusal is then proven against a `[gate.ceiling_raises]` table that is empty in the tree,
    // which is the state it is supposed to spend most of its life in.
    if let Some(base_lowered) = ceilings::set_int(&text, "rules.legacy-reach", "ceiling", 0) {
        let mut ov = on(base);
        ov.set_command(format!("git-show:{based}:{CEILINGS}"), base_lowered);
        ov.set(
            CEILINGS,
            format!(
                "{text}\n[gate.ceiling_raises.\"rules.legacy-reach.ceiling\"]\nfrom = 999\n\
                 to = 998\nbecause = \"planted by the self-test: a declaration whose numbers are \
                 not the raise it sits beside, so the raise is still undeclared and still \
                 refused\"\n"
            ),
        );
        r.push(prove_rows_red(
            cx,
            gate,
            "a declared raise whose numbers are not this raise excuses nothing",
            &[ceilings::ROW_ROSE],
            ov,
            &["declared as 999->998"],
        ));
    } else {
        r.note_infra_failure(
            "[rules.legacy-reach] carries no `ceiling` to lower at the base, so the arm that \
             refuses a declaration describing a different edit is unproven",
        );
    }

    if !stale_carried {
        let mut ov = on(base);
        ov.set(CEILINGS, stale_declaration);
        r.push(prove_rows_red(
            cx,
            gate,
            "a declared raise that is not a raise at the base is a waiver that outlived its commit",
            &[ceilings::ROW_ROSE],
            ov,
            &["is not a raise at the base"],
        ));
    }

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

    // -- ceiling-census --------------------------------------------------------------------------
    //
    // THE ROW THAT COUNTS THE RULE TABLES THE REST OF THE GATE IS DERIVED FROM. `owed()` reads the
    // same `Cfg` the rules read, so deleting `[rules.loc-ceilings.kernel_files.arena]` deleted the
    // check AND the obligation in one edit — 112 rows became 111, silently. These cases drive the
    // shortfall arm from the other side: raising a census floor above what the tree carries is the
    // same comparison as deleting the table under a floor that stayed put, and it is a one-integer
    // plant that cannot rot the way a hard-coded table name would.
    if let Some(planted) =
        ceilings::set_int(&combined, "gate.census", "loc_ceilings_kernel_files", 99)
    {
        combined = planted;
        combined_cover.push(census::ROW_CENSUS.to_string());
        combined_naming.push("[rules.loc-ceilings.kernel_files] entries:".to_string());
        combined_naming.push("99 pinned".to_string());
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
    if let Some(planted) = ceilings::set_int(&combined, "gate.census.plugin_kinds", "plane", 99) {
        combined = planted;
        combined_cover.push(census::ROW_CENSUS.to_string());
        combined_naming.push("[gate.plugin_kinds] plane =".to_string());
    } else {
        r.note_infra_failure(
            "the [gate.census.plugin_kinds] plane floor could not be rewritten, so the arm that \
             refuses a narrowed kind glob is unproven",
        );
    }

    // THE THREE GREEN CONTROLS, AND THE FIXTURE'S OWN, IN ONE RUN. They used to be three cases
    // with one identical overlay — three whole-gate drives to read three rows of one verdict — and
    // two of them asserted the REAL tree green on `ceiling-slack` and `ceiling-rose`, which it is
    // not: that is real debt the gate reports, not a fact about either rule. The claim now is the
    // one each RED case above depends on: over the green fixture, planted onto the REAL tree (so
    // the plant bites), every ratcheted ceiling equals its measurement, no ceiling has risen
    // against a base that carries this file, every census floor holds, and every row the fixture
    // was built to clear is green. If the fixture ever stops clearing a row, this says which.
    let mut control: Vec<String> =
        strings(&[ceilings::ROW_SLACK, ceilings::ROW_ROSE, census::ROW_CENSUS]);
    control.extend(cleared.iter().cloned());
    control.sort();
    control.dedup();
    r.push(prove_rows_green(
        real,
        gate,
        "over the green fixture every ceiling equals its measurement, none has risen against its \
         base, every census floor holds, and every row the fixture clears is green",
        &refs(&control),
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
    let verbless = combined.replace(
        r#"send_verb = '\.client\(\)\.get\(\)\.request\('"#,
        r#"send_verb = '\.zz_planted_verb_that_matches_nothing\('"#,
    );
    if verbless != combined {
        combined = verbless;
        combined_cover.push("one-attempt-seam".to_string());
        combined_naming.push("performs no attempt at all".to_string());
    } else {
        r.note_infra_failure(
            "[rules.one-attempt-seam] send_verb could not be rewritten, so the arm that refuses an \
             empty scan set is unproven rather than passing",
        );
    }

    combined_cover.dedup();
    if !combined_cover.is_empty() {
        let mut ov = on(base);
        ov.set(CEILINGS, combined);
        r.push(prove_rows_red(
            cx,
            gate,
            "one planted ceilings file: a ceiling raised above what it measures is slack, each \
             retiring crate's reach figure is a ratchet the root can exceed, a rule table and a \
             kind glob that went missing under their census floors are refused, and a send verb \
             that matches nothing is the seam having moved, not a clean tree",
            &refs(&combined_cover),
            ov,
            &refs(&combined_naming),
        ));
    }
    r
}

/// One ceiling per watched file, chosen FROM THE FILE rather than named here: a plant that
/// hard-codes a key is a plant that stops planting the day the key is renamed, and goes green.
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
fn kind_cases<'a>(gate: &'a dyn Gate, cx: &Ctx, base: &Overlay) -> Report<'a> {
    let mut r = Report::new();
    // THE SIX KEYS `manifest_allowlist` READS, AND `auth` IS ONE OF THEM. `pure_auth` and
    // `egress_auth` stood here, and neither is a key of `[gate.plugin_kinds]`, so this case planted
    // a `busbar-kernel` dependency into ZERO crates for the auth kind and proved nothing about the
    // one kind it thereby exempted. `crates/auth-admin-tokens` and `crates/auth-static-plugin` are
    // planted into now, and their `manifest-allowlist:` rows must go RED under the plant or this
    // case fails.
    //
    // AND THE SEVENTH, `transport` (item 120). The rule read six kinds, so the seven
    // `busbar-transport-*` crates had no `manifest-allowlist:` row at all and this plant never
    // touched them; the completeness oracle owed their rows and nothing covered them. They are
    // planted now like every other kind. Each is RED on the real tree (third-party deps nobody has
    // reviewed; `busbar-transport-tls` path-depends on `busbar-unit-transport-key`, `-grpc`/`-sse`
    // on `busbar-transport-http`) and stays red on the gate; the green fixture records those deps
    // in the rule's review lists so this plant asks about a NEW kernel edge, which is a transition.
    let manifest_kinds = strings(&[
        "plane",
        "store",
        "auth",
        "hook",
        "export",
        "secret",
        "transport",
    ]);
    let crates = match kind_crates(cx, &manifest_kinds) {
        Ok(c) => c,
        Err(e) => {
            r.note_infra_failure(format!(
                "the plugin-kind scopes would not resolve, so no manifest-allowlist plant is \
                 real: {e}"
            ));
            return r;
        }
    };
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
    let pure = match kind_crates(cx, &denylist_kinds) {
        Ok(c) => c,
        Err(e) => {
            r.note_infra_failure(format!(
                "the source-denylist scopes would not resolve, so no purity plant is real: {e}"
            ));
            return r;
        }
    };
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

    // ITEM 167: THE CLOSURE HALF THAT NEVER ANSWERED. The rule's UNPROVEN arm was unreachable —
    // every path of `denylist_hits` answered "asked, clean" — so it could not be planted and was
    // never proven. The rows above are green at baseline; this plant makes the closure scan not
    // answer and every one of them must go RED saying so.
    let mut ov = on(base);
    ov.set_command(external::DENYLIST_KEY, external::DENYLIST_ABSENT);
    r.push(prove_red(
        cx,
        gate,
        "the transitive-closure scan not answering is not a clean closure",
        &refs(&ids("source-denylist:", &pure)),
        ov,
        &["UNPROVEN: `cargo xtask denylist` did not answer"],
    ));

    let Ok(cfg) = ConstructionGate::cfg(cx) else {
        r.note_infra_failure("the ceilings file would not parse, so no forbid-unsafe case is real");
        return r;
    };
    // BOTH HALVES IN ONE PLANT. `forbid-unsafe:` and `forbid-unsafe-deny:` read disjoint kinds,
    // so stripping every attribute from both sets of crate roots at once moves each row for its own
    // reason; they were four whole-gate drives (a red and a green per half) and are two now.
    let mut ov = on(base);
    let (mut held_ids, mut tracked_ids) = (Vec::new(), Vec::new());
    for (kinds_key, missing_key, rid) in UNSAFE_HALVES {
        let prefix = format!("{rid}:");
        // THE PLANT IS THE WHOLE KIND; THE PROOF IS THE HELD HALF. Every crate of the kind loses
        // the attribute, tracked or not — anything narrower would be a plant shaped to the answer.
        // What the RED case may claim is narrower than what it plants: a crate on the rule's
        // ratchet measures `1` against a ceiling of `1`, so it stays green under this exact plant
        // BY DESIGN, and asking `prove_red` for it would fail the case for the rule working. So
        // the ratcheted crates are proven the other way round, in the green case below: the same
        // plant, the tracked rows, and the claim that tolerating them is what the ratchet is for.
        let (held, tracked) = match ConstructionGate::unsafe_split(cx, &cfg, kinds_key, missing_key)
        {
            Ok(split) => split,
            Err(e) => {
                r.note_infra_failure(format!(
                    "the `{rid}` scopes would not resolve, so no unsafe-attribute plant is \
                     real: {e}"
                ));
                return r;
            }
        };
        for c in held.iter().chain(tracked.iter()) {
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
        held_ids.extend(ids(&prefix, &held));
        tracked_ids.extend(ids(&prefix, &tracked));
    }
    r.push(prove_red(
        cx,
        gate,
        "every crate of both unsafe-attribute kinds loses its attribute",
        &refs(&held_ids),
        ov.clone(),
        &["MISSING"],
    ));
    r.push(prove_rows_green(
        cx,
        gate,
        "an unsafe-attribute crate the ceilings file already tracks is not a fresh violation",
        &refs(&tracked_ids),
        ov,
    ));
    r
}

/// The vocabulary, the kind traits, the seals and the two raw-text scans.
fn vocabulary_cases<'a>(gate: &'a dyn Gate, cx: &Ctx, base: &Overlay) -> Report<'a> {
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

fn money_cases<'a>(gate: &'a dyn Gate, cx: &Ctx, base: &Overlay) -> Report<'a> {
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
        &refs(&{
            let mut cover = strings(&[
                "no-test-doubles-in-production",
                "no-test-doubles-in-production:doubles",
                "legacy-reach",
            ]);
            // EVERY PER-CRATE REACH ROW TOO. The plant names all three retiring prefixes, 200
            // symbols each, so every `legacy-reach:<key>` measurement moves past its figure —
            // including the two at 0, which the figure plant in `ceiling_ratchet_cases` cannot
            // move.
            if let Some(c) = cfg.as_ref() {
                cover.extend(
                    c.doc
                        .children("rules.legacy-reach.prefixes")
                        .into_iter()
                        .map(|(k, _)| format!("legacy-reach:{k}")),
                );
            }
            cover
        }),
        ov,
        // The doubles row prints its reviewed site's REASON, not the code that constructed it, so
        // what names the plant there is the row itself: it is PASS on HEAD (five doubles against a
        // ratchet of five), so its title appearing among the failures is the transition.
        //
        // The `legacy-reach` rows are in `covers` and not named here: every one of them is GREEN
        // on the fixture (each ratchet pinned to its measurement), so `prove_red` already requires
        // each to go red under this plant, which only the planted root file can make it do.
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
