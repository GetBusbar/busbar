// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn cx() -> Ctx {
    Ctx::workspace().expect("workspace context")
}

fn tops() -> BTreeSet<String> {
    ["crates", "docs", "qa", "scripts", "testing", "xtask"]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

#[test]
fn prose_is_never_a_path_and_a_scan_root_always_is() {
    let t = tops();
    assert!(is_path_shaped("crates/busbar-substrate/src", &t));
    assert!(is_path_shaped("qa/construction.toml", &t));
    assert!(!is_path_shaped(
        "An installable seam under crates/busbar-substrate/src is a promise",
        &t
    ));
    // A module path and a regex are not paths, whatever the key is called.
    assert!(!is_path_shaped("busbar_kernel_ledger::cost::", &t));
    assert!(!is_path_shaped("^(install_[a-z0-9_]+)$", &t));
    // A first segment that is not a directory of this repo is not a path either.
    assert!(!is_path_shaped("vendor/anthropic/v1", &t));
}

#[test]
fn a_fragment_key_is_never_a_name_and_a_path_key_is_not_a_crate() {
    let t = tops();
    assert_eq!(
        classify(CONFIG_REL, "non_production_path_fragments", "testkit", &t),
        None
    );
    assert_eq!(
        classify(CONFIG_REL, "exempt_seam_path_fragments", "/testkit/", &t),
        None
    );
    assert_eq!(
        classify(CONFIG_REL, "entry_path_patterns", "crates/x/y.rs", &t),
        None
    );
    // `crate_roots = ["crates"]` is a directory list, not a package called `crates`.
    assert_eq!(classify("qa/loc.toml", "crate_roots", "crates", &t), None);
    assert_eq!(
        classify(CONFIG_REL, "fee_reader_crates", "busbar-kernel", &t),
        Some(Class::Crate)
    );
    assert_eq!(
        classify(CONFIG_REL, "kinds", "pure_auth", &t),
        Some(Class::Kind)
    );
    // ...and the SAME key in another file is another vocabulary, deliberately not read here.
    assert_eq!(classify("qa/kind-isolation.toml", "kind", "api", &t), None);
}

#[test]
fn a_known_site_tail_is_stripped_before_the_path_is_resolved() {
    let mk = |text: &str| Name {
        text: text.to_string(),
        file: CONFIG_REL.to_string(),
        line: 1,
        site: String::new(),
        class: Class::Path,
        in_array: true,
    };
    assert_eq!(
        mk("crates/busbar-contract/src/ids.rs::key").core(),
        "crates/busbar-contract/src/ids.rs"
    );
    assert_eq!(
        mk("crates/busbar-kernel/src/appbuild.rs:240").core(),
        "crates/busbar-kernel/src/appbuild.rs"
    );
    assert_eq!(
        mk("crates/plugin-loader/src/").core(),
        "crates/plugin-loader/src"
    );
    // A crate name with a `::` that is not a function tail keeps its spelling.
    assert_eq!(mk("crates/a/b.rs").core(), "crates/a/b.rs");
}

#[test]
fn a_crate_glob_matches_the_way_fnmatch_does() {
    assert!(glob_one("busbar-unit-*", "busbar-unit-transport-key"));
    assert!(!glob_one("busbar-unit-*", "busbar-kernel-wal"));
    assert!(glob_one("busbar*", "busbar"));
    assert!(!glob_one("busbar-*", "busbar"));
}

#[test]
fn a_declaration_parses_into_its_three_fields() {
    let d = parse_decl(&format!("{DECL} n{SEP}qa/construction.toml{SEP}a reason")).expect("parses");
    assert_eq!(
        (d.name.as_str(), d.file.as_str()),
        ("n", "qa/construction.toml")
    );
    assert_eq!(d.reason, "a reason");
    // A line that carries the prefix and not the shape comes back with empty fields, so the
    // file and reason rules report it rather than the parser swallowing it.
    let d = parse_decl(&format!("{DECL} n")).expect("parses");
    assert!(d.file.is_empty() && d.reason.is_empty());
    assert!(parse_decl("# something else").is_none());
}

/// ITEM 88: a quoted spelling in a `#` comment above the value is prose. The citation (and so the
/// glob plant, which goes beside the cited line) must land on the value line, or the plant is
/// written into a comment and `glob-matches-something` scores a planted dead glob GREEN.
#[test]
fn a_citation_skips_a_quoted_spelling_in_a_comment() {
    let text = "[gate]\n# It read `[\"crates/*/src\"]` and that is not the tree.\n\
                scan_roots = [\"crates/*/src\", \"crates/*/tests\"]\n";
    assert_eq!(line_of(text, "gate", "crates/*/src"), 3);
    // Only prose carries it: the comment is still the best citation there is.
    let prose = "[gate]\n# It read `[\"crates/*/src\"]`.\nscan_roots = []\n";
    assert_eq!(line_of(prose, "gate", "crates/*/src"), 2);
}

#[test]
fn a_phantom_is_planted_as_a_sibling_and_takes_nothing_away() {
    let text = "[t]\nkinds = [\"plane\", \"hook\"]\n";
    let at = Name {
        text: "hook".to_string(),
        file: CONFIG_REL.to_string(),
        line: 2,
        site: String::new(),
        class: Class::Kind,
        in_array: true,
    };
    assert_eq!(
        plant_beside(text, &at, "ghost").as_deref(),
        Some("[t]\nkinds = [\"plane\", \"hook\", \"ghost\"]\n")
    );
}

/// The ids that went non-PASS under one planted overlay.
fn failed_ids(cx: &Ctx, ov: Overlay) -> BTreeSet<String> {
    crate::gates::execute(&QaNamesGate, &cx.with_overlay(ov))
        .rows
        .iter()
        .filter(|r| r.status != crate::ledger::Status::Pass)
        .map(|r| r.id.clone())
        .collect()
}

/// EVERY PLANT MUST REDDEN ITS OWN ROW AND TURN NOTHING ELSE RED THAT WAS GREEN — except the
/// kind-table plant, whose whole point is that everything below it is unproven. Stated against
/// the tree's OWN baseline rather than against "nothing else is red", because three rows carry
/// standing dead names that are not this change's to drain and a case that demanded they be
/// clean would be a case nobody could keep.
#[test]
fn each_plant_reddens_its_own_row_and_nothing_that_was_green() {
    let cx = cx();
    let base = failed_ids(&cx, Overlay::new());
    for p in plants(&cx) {
        if p.rule == ROW_UNIVERSE {
            continue;
        }
        let ov = p
            .overlay
            .unwrap_or_else(|| panic!("nothing to plant: {}", p.label));
        let got = failed_ids(&cx, ov);
        assert!(
            got.contains(p.rule),
            "plant `{}` did not redden `{}` (red: {got:?})",
            p.label,
            p.rule
        );
        let fresh: Vec<&String> = got
            .iter()
            .filter(|id| id.as_str() != p.rule && !base.contains(*id))
            .collect();
        assert!(
            fresh.is_empty(),
            "plant `{}` also reddened rows that were green: {fresh:?}",
            p.label
        );
    }
}

/// AN EXEMPTION IS SCOPED TO ITS OWN FILE: the declared file stays green on the path row, and a
/// second file writing the same dead path is RED, cited by its own path and line.
#[test]
fn a_declaration_excuses_the_dead_name_only_in_the_file_it_names() {
    let cx = cx();
    let ((a, a_text, a_at), (b, b_text, b_at)) =
        anchor_pair(&cx, |n| n.class == Class::Path && !n.is_glob())
            .expect("two covered TOML files carrying a path array");
    let dead = planted_path();
    let a_declared = format!(
        "{}\n{DECL} {dead}{SEP}{a}{SEP}{PLANTED_REASON}\n",
        plant_beside(&a_text, &a_at, &dead).expect("planted beside A")
    );
    let path_detail = |ov: Overlay| {
        crate::gates::execute(&QaNamesGate, &cx.with_overlay(ov))
            .rows
            .into_iter()
            .find(|r| r.id == ROW_PATH)
            .expect("the path row")
            .detail
    };

    let mut only_a = Overlay::new();
    only_a.set(&a, a_declared.clone());
    assert!(
        !path_detail(only_a).contains(&dead),
        "the declared name in its own file must stay excused"
    );

    let mut both = Overlay::new();
    both.set(&a, a_declared);
    both.set(
        &b,
        plant_beside(&b_text, &b_at, &dead).expect("planted beside B"),
    );
    let detail = path_detail(both);
    assert!(
        detail.contains(&format!("{b}:{} `{dead}`", b_at.line)),
        "{detail}"
    );
    assert!(
        !detail.contains(&format!("{a}:{} `{dead}`", a_at.line)),
        "{detail}"
    );
}

/// The rows with no standing debt are green, and the scan is over a real population.
#[test]
fn the_clean_rows_are_green_and_the_scan_is_not_empty() {
    let verdict = crate::gates::execute(&QaNamesGate, &cx());
    for id in [
        ROW_UNIVERSE,
        ROW_FLOOR,
        ROW_KIND,
        ROW_DECL_LIVE,
        ROW_DECL_FILE,
        ROW_DECL_REASON,
    ] {
        let r = verdict
            .rows
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("{id} did not run"));
        assert_eq!(
            r.status,
            crate::ledger::Status::Pass,
            "{id} is RED on the real tree: {}",
            r.detail
        );
    }
}

/// THE DAY'S FOUR FIXES, OLDEST FIRST, each as `(<sha>, <what it fixed>, <what the gate must
/// name in the config its PARENT carried>)`. `<sha>^:qa/construction.toml` is the pre-fix
/// config, and the needles differ per commit because each fix struck a different name: by
/// `ab5bcb45c^` the `[rules.source-denylist].kinds` half had already been corrected by
/// `383f23875`, so demanding it there would be demanding a defect that was gone.
#[allow(clippy::type_complexity)]
const FIXES: &[(&str, &str, &[&str])] = &[
    (
        "2b5727416",
        "the export family glob at the wrong path",
        &[
            // Defect 1's own table, naming a plane folded into busbar-plane-streaming.
            "`crates/busbar-plane-voice` ([gate.plugin_kinds] plane)",
            // Defects 3 and 4: four phantom kind names across two rules.
            "`pure_auth` ([rules.source-denylist] kinds)",
            "`egress_auth` ([rules.source-denylist] kinds)",
            "`pure_auth` ([rules.forbid-unsafe] forbid_kinds)",
            "`egress_auth` ([rules.forbid-unsafe] forbid_kinds)",
            // The same kind again as a census KEY, declaring a population of two.
            "`pure_auth` ([gate.census.plugin_kinds] pure_auth)",
            // Defect 5's open names, and two codec crates that had already been deleted.
            "`busbar-a2a-codec` ([gate.plane_codec_crates] busbar-a2a)",
            "`busbar-mcp-codec` ([gate.plane_codec_crates] busbar-mcp)",
            "`busbar-admin` ([rules.one-pricing-site] fee_reader_crates)",
            "`crates/busbar-substrate/src` ([rules.no-uninstalled-seam] seam_root)",
        ],
    ),
    (
        "2b2de9712",
        "the fifth plane in no kind list",
        &[
            "`pure_auth` ([rules.source-denylist] kinds)",
            "`egress_auth` ([rules.forbid-unsafe] forbid_kinds)",
            "`pure_auth` ([gate.census.plugin_kinds] pure_auth)",
            "`busbar-a2a-codec` ([gate.plane_codec_crates] busbar-a2a)",
        ],
    ),
    (
        "383f23875",
        "source-denylist naming kinds that do not exist",
        &[
            "`pure_auth` ([rules.source-denylist] kinds)",
            "`egress_auth` ([rules.source-denylist] kinds)",
            "`pure_auth` ([rules.forbid-unsafe] forbid_kinds)",
            "`pure_auth` ([gate.census.plugin_kinds] pure_auth)",
        ],
    ),
    (
        "ab5bcb45c",
        "forbid-unsafe naming the same two, and the census re-pin",
        &[
            "`pure_auth` ([rules.forbid-unsafe] forbid_kinds)",
            "`egress_auth` ([rules.forbid-unsafe] forbid_kinds)",
            "`pure_auth` ([gate.census.plugin_kinds] pure_auth)",
        ],
    ),
];

/// THE HISTORICAL CATCH, AND IT IS THE WHOLE PROOF.
///
/// A gate written against an already-cleaned tree proves nothing: it was shaped until it
/// passed, and "it passes" is exactly what the config it replaced did. So this reconstructs the
/// config as it stood BEFORE each of the day's four fixes — read from history with `git show`,
/// never from the working tree, which the same change is free to edit — lays it over TODAY'S
/// tree, and requires the gate to name each defect BY ITS TABLE AND ITS KEY.
///
/// THE OTHER HALF OF THE PROOF is the three names it must NOT report. `dialect = 0`,
/// `control = 0` and `egress_auth = 0` stood in the same pre-fix `[gate.census.plugin_kinds]`
/// as `pure_auth = 2`, and all four name no key in `[gate.plugin_kinds]`. The three declaring
/// ZERO are kinds with no crate yet, which the header over that table says in terms is
/// legitimate; the one declaring TWO claims a population nothing can find. A rule that reported
/// all four would be a rule with no way to satisfy it, which is a rule somebody deletes.
#[test]
fn the_pre_fix_config_of_the_day_is_named_in_full() {
    let cx = cx();
    for (sha, what, needles) in FIXES {
        assert!(
            cx.git_ref_resolves(&format!("{sha}^")),
            "{sha}^ ({what}) does not resolve — this proof needs history, not a shallow clone"
        );
        let before = cx
            .git_show(&format!("{sha}^"), CONFIG_REL)
            .unwrap_or_else(|e| panic!("{sha}^:{CONFIG_REL}: {e}"));
        let mut ov = Overlay::new();
        ov.set(CONFIG_REL, before);
        let verdict = crate::gates::execute(&QaNamesGate, &cx.with_overlay(ov));
        let said: String = verdict
            .rows
            .iter()
            .filter(|r| r.status != crate::ledger::Status::Pass)
            .map(|r| format!("{} {}\n", r.id, r.detail))
            .collect();
        println!("\n===== {sha}^ ({what}) =====\n{said}");

        for needle in *needles {
            assert!(
                said.contains(needle),
                "{sha}^: the gate did not name {needle:?}"
            );
        }
        for zero in [
            "`dialect`",
            "`control`",
            "`egress_auth` ([gate.census.plugin_kinds]",
        ] {
            assert!(
                !said.contains(zero),
                "{sha}^: a DECLARED zero was reported: {zero}"
            );
        }
    }
}

#[test]
fn the_selftest_proves_every_owed_row() {
    let cx = cx();
    let report = QaNamesGate.selftest(&cx);
    crate::gates::verify_report(&QaNamesGate, &report)
        .unwrap_or_else(|errs| panic!("qa-names selftest: {errs:#?}"));
    assert_eq!(report.skipped(), 0, "a case had nothing to plant");
}

#[test]
fn a_path_into_a_vanished_top_directory_is_still_path_shaped() {
    // The tree no longer has `legacy/`, so `is_path_shaped` cannot see these; the shape can.
    let t = tops();
    for v in [
        "legacy/src/lib.rs",
        "legacy/gates/",
        "legacy/crates/busbar-*/src",
        "legacy/src/a.rs:240",
        "legacy/src/a.rs::run",
        ".gone/x.toml",
    ] {
        assert!(!is_path_shaped(v, &t), "{v}");
        assert!(is_repo_path_shaped(v), "{v}");
    }
    // Prose, URLs, versions, rooted paths, bare words and extension-less ratios are not.
    for v in [
        "see legacy/src/lib.rs",
        "https://example.com/a.rs",
        "github.com/x/y@v1.2.3",
        "/stats",
        "legacy",
        "1/2",
        "and/or",
        "ghcr.io/getbusbar/img",
        "",
    ] {
        assert!(!is_repo_path_shaped(v), "{v}");
    }
}

#[test]
fn an_unparseable_qa_toml_is_reported_not_dropped() {
    let t = tops();
    let (names, _, bad) = scan_checked("qa/x.toml", "[unterminated\nscan_roots = []\n", &t);
    assert!(names.is_empty());
    assert!(bad.is_some_and(|w| w.contains("unterminated")));
    let (_, _, ok) = scan_checked("qa/x.toml", "[a]\nscan_roots = [\"crates/x\"]\n", &t);
    assert!(ok.is_none());
}
