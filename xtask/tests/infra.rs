//! Cases proving each rule of the `cargo xtask gate` infrastructure can go red, one per rule the design
//! document names. Every case here was written and observed FAILING before the module it drives
//! existed; each one names the rule it pins so a deletion of that rule is a named test failure
//! rather than a quieter test suite.

use std::collections::BTreeSet;
use std::path::PathBuf;

use xtask::ctx::{Ctx, Edit, Overlay, WalkError, WalkSpec};
use xtask::gates::{self, Case, Expect, Gate, Report, Tier};
use xtask::ledger::{self, Reconcile, Resolution, Row, Status, Verdict};
use xtask::parity;
use xtask::planes::{self, PlaneRootError, PlaneRoots};
use xtask::scan;
use xtask::yaml_lite;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask/ has a parent")
        .to_path_buf()
}

fn cx() -> Ctx {
    Ctx::new(repo_root()).expect("the real tree opens with a writable scratch dir")
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = repo_root().join(".fix").join(format!(
        "xtask-test-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).expect("scratch dir");
    d
}

// ── ledger ──────────────────────────────────────────────────────────────────────────────────────

#[test]
fn row_tsv_is_the_shape_record_writes_with_tabs_and_newlines_flattened() {
    let r = Row::new(Status::Pass, "install:script", "a\ttitle", "a\ndetail");
    assert_eq!(r.tsv(), "install:script\tPASS\ta title\ta detail");
}

#[test]
fn write_leg_appends_and_never_truncates() {
    let dir = tmpdir("leg");
    let path = dir.join("leg.tsv");
    ledger::write_leg(&path, &[Row::new(Status::Pass, "a", "t", "d")]).unwrap();
    ledger::write_leg(&path, &[Row::new(Status::Fail, "b", "t", "d")]).unwrap();
    let rows = ledger::read_leg(&path).unwrap();
    assert_eq!(
        rows.len(),
        2,
        "the second write must not have truncated the first"
    );
    assert_eq!(rows[0].id, "a");
    assert_eq!(rows[1].id, "b");
}

#[test]
fn read_leg_refuses_a_missing_file_rather_than_reporting_zero_rows() {
    let dir = tmpdir("leg-missing");
    assert!(ledger::read_leg(&dir.join("never-written.tsv")).is_err());
}

#[test]
fn truncate_leg_makes_the_file_exists_guard_honest() {
    let dir = tmpdir("leg-trunc");
    let path = dir.join("leg.tsv");
    ledger::write_leg(&path, &[Row::new(Status::Pass, "stale", "t", "d")]).unwrap();
    ledger::truncate_leg(&path).unwrap();
    assert!(
        ledger::read_leg(&path).unwrap().is_empty(),
        "a run that dies before writing must not inherit the previous run's rows"
    );
}

#[test]
fn zero_rows_against_a_non_empty_owed_set_is_red() {
    let v = Reconcile::new(["a", "b"]).verdict(Vec::new());
    assert!(v.red, "a ledger with no rows is not a clean ledger");
    assert!(v.problems.iter().any(|p| p.contains("zero rows")));
}

#[test]
fn an_owed_id_with_no_row_is_red_as_did_not_run() {
    let v = Reconcile::new(["a", "b"]).verdict(vec![Row::new(Status::Pass, "a", "t", "d")]);
    assert!(v.red);
    assert!(v.problems.iter().any(|p| p.contains('b')));
    assert_eq!(v.resolve("b"), None);
}

#[test]
fn a_row_nobody_owes_is_red_so_a_rule_cannot_write_a_row_nobody_reads() {
    let v = Reconcile::new(["a"]).verdict(vec![
        Row::new(Status::Pass, "a", "t", "d"),
        Row::new(Status::Fail, "surprise", "t", "d"),
    ]);
    assert!(v.red);
    assert!(v.problems.iter().any(|p| p.contains("surprise")));
}

#[test]
fn duplicate_rows_resolve_by_agreement_and_disagreement_is_conflict_not_first_wins() {
    let agree = Reconcile::new(["a"]).verdict(vec![
        Row::new(Status::Pass, "a", "t", "d"),
        Row::new(Status::Pass, "a", "t", "d"),
    ]);
    assert_eq!(agree.resolve("a"), Some(Resolution::Pass));
    assert!(!agree.red);

    let disagree = Reconcile::new(["a"]).verdict(vec![
        Row::new(Status::Pass, "a", "t", "d"),
        Row::new(Status::Fail, "a", "t", "d"),
    ]);
    assert_eq!(
        disagree.resolve("a"),
        Some(Resolution::Conflict),
        "a PASS followed by a FAIL for one id is a conflict, never a PASS that got there first"
    );
    assert!(disagree.red);
}

#[test]
fn every_skip_is_red_unless_the_id_is_explicitly_allowlisted() {
    let v = Reconcile::new(["a"]).verdict(vec![Row::new(Status::Skip, "a", "t", "d")]);
    assert!(v.red, "a SKIP is a check that did not verify");

    let allowed = Reconcile::new(["a"])
        .allow_skip(["a"])
        .verdict(vec![Row::new(Status::Skip, "a", "t", "d")]);
    assert!(!allowed.red);
    assert_eq!(allowed.resolve("a"), Some(Resolution::Skip));
}

#[test]
fn a_fail_row_is_red() {
    let v = Reconcile::new(["a"]).verdict(vec![Row::new(Status::Fail, "a", "t", "d")]);
    assert!(v.red);
    assert_eq!(v.resolve("a"), Some(Resolution::Fail));
}

// ── ctx ─────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn scratch_is_proven_writable_by_writing_a_byte() {
    let c = cx();
    assert!(c.scratch().is_dir());
    let probe = c.scratch().join("probe");
    std::fs::write(&probe, b"x").unwrap();
    std::fs::remove_file(&probe).unwrap();
}

#[test]
fn walk_is_sorted_and_honours_exclude_fragments() {
    let c = cx();
    let spec = WalkSpec::new(["xtask/src"]).ext("rs").min_files(3);
    let files = c.walk(&spec).expect("xtask/src has rust files");
    let rels: Vec<String> = files.iter().map(|f| f.rel.display().to_string()).collect();
    let mut sorted = rels.clone();
    sorted.sort();
    assert_eq!(rels, sorted, "several gates' outputs are order-sensitive");

    let excluded = c
        .walk(
            &WalkSpec::new(["xtask"])
                .ext("rs")
                .exclude(["/src/"])
                .min_files(0),
        )
        .unwrap();
    assert!(excluded
        .iter()
        .all(|f| !f.rel.display().to_string().contains("/src/")));
}

#[test]
fn a_walk_below_its_floor_is_an_error_not_a_clean_tree() {
    let c = cx();
    let err = c
        .walk(
            &WalkSpec::new(["xtask/fixtures"])
                .ext("no-such-ext")
                .min_files(1),
        )
        .expect_err("zero files under a floor of one must not read as a clean scan");
    assert!(matches!(err, WalkError::BelowFloor { .. }));
}

#[test]
fn a_missing_walk_root_is_an_error_rather_than_being_silently_dropped() {
    let c = cx();
    let err = c
        .walk(
            &WalkSpec::new(["xtask/src", "no/such/root"])
                .ext("rs")
                .min_files(1),
        )
        .expect_err("`find A B` silently drops a missing root; this must not");
    assert!(matches!(err, WalkError::MissingRoot { .. }));
}

#[test]
fn the_overlay_is_fresh_per_plant_and_read_consults_it_first() {
    let c = cx();
    let real = c.read("xtask/Cargo.toml").unwrap();
    assert!(real.contains("name = \"xtask\""));

    let mut ov = Overlay::new();
    Edit::Append("\n# planted\n".to_string())
        .apply(&c, "xtask/Cargo.toml", &mut ov)
        .unwrap();
    let planted = c.with_overlay(ov);
    assert!(planted
        .read("xtask/Cargo.toml")
        .unwrap()
        .contains("# planted"));

    assert!(
        !c.read("xtask/Cargo.toml").unwrap().contains("# planted"),
        "an overlay must never mutate the base context, which is what retires plant.py's TOUCHED list"
    );
}

#[test]
fn an_overlay_delete_makes_a_file_absent_to_read_and_exists_and_walk() {
    let c = cx();
    let mut ov = Overlay::new();
    Edit::Delete
        .apply(&c, "xtask/src/scan.rs", &mut ov)
        .unwrap();
    let planted = c.with_overlay(ov);
    assert!(!planted.exists("xtask/src/scan.rs"));
    assert!(planted.read("xtask/src/scan.rs").is_err());
    let files = planted
        .walk(&WalkSpec::new(["xtask/src"]).ext("rs").min_files(0))
        .unwrap();
    // THE EXACT PATH, not the file NAME. `Path::ends_with` matches whole trailing components, so
    // `ends_with("scan.rs")` also matches `xtask/src/gates/config_schema/scan.rs` — a second,
    // unrelated `scan.rs` that this case never deleted. The claim is "the file the plant deleted is
    // gone from the walk", and a basename is not that claim.
    assert!(files.iter().all(|f| f.rel_str() != "xtask/src/scan.rs"));
}

#[test]
fn an_overlay_create_makes_a_new_file_visible_to_walk() {
    let c = cx();
    let mut ov = Overlay::new();
    Edit::Create("fn planted() {}\n".to_string())
        .apply(&c, "xtask/src/planted_only_in_the_overlay.rs", &mut ov)
        .unwrap();
    let planted = c.with_overlay(ov);
    let files = planted
        .walk(&WalkSpec::new(["xtask/src"]).ext("rs").min_files(1))
        .unwrap();
    assert!(files
        .iter()
        .any(|f| f.rel.ends_with("planted_only_in_the_overlay.rs")));
    assert!(!repo_root()
        .join("xtask/src/planted_only_in_the_overlay.rs")
        .exists());
}

#[test]
fn materialize_writes_the_overlaid_tree_for_a_gate_that_must_shell_out() {
    let c = cx();
    let mut ov = Overlay::new();
    Edit::Replace("planted\n".to_string())
        .apply(&c, "xtask/Cargo.toml", &mut ov)
        .unwrap();
    let planted = c.with_overlay(ov);
    let dest = tmpdir("materialize");
    planted
        .materialize(&dest, &["xtask/Cargo.toml", "xtask/src/main.rs"])
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(dest.join("xtask/Cargo.toml")).unwrap(),
        "planted\n"
    );
    assert!(dest.join("xtask/src/main.rs").exists());
}

// ── scan ────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn production_lines_drops_comments_and_cfg_test_modules() {
    let src = "\
use std::fs; // trailing
/* block
   comment */
#[cfg(test)]
mod tests {
    use std::env;
}
fn after() {}
";
    let lines = scan::production_lines(src);
    let joined: String = lines
        .iter()
        .map(|(_, l)| l.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(joined.contains("use std::fs;"));
    assert!(!joined.contains("trailing"));
    assert!(!joined.contains("block"));
    assert!(!joined.contains("std::env"));
    assert!(joined.contains("fn after"));
}

// ── LITERALS ARE NOT STRUCTURE ───────────────────────────────────────────────────────────────────
//
// Every delimiter count in this crate reads `scan::blank_code` output. These are the shapes that
// were really in the tree, or really reachable, when it did not: each one drove a counter off a
// brace that the compiler reads as text, and each failure direction is a SILENT PASS — a region
// latched open hides the production code after it from every ban built on the scanner.

#[test]
fn a_char_literal_holding_a_brace_is_text_and_does_not_open_a_region() {
    // The live instance: crates/busbar-core/src/admin/v1/contract/taxonomy.rs:610, inside a
    // `#[cfg(any(test, …))]` item. The line has no `"`, so the whole of it was counted, both `{`
    // included — depth went up by two where the compiler goes up by one, and the region opened at
    // the attribute never closed, reporting the rest of the file gated to EOF.
    let src = "#[cfg(any(test, feature = \"openapi-schema\"))]\n\
               fn declared_errors(rel: &str) -> u8 {\n\
               \x20   if rel.contains('{') {\n\
               \x20       1\n\
               \x20   } else {\n\
               \x20       0\n\
               \x20   }\n\
               }\n\
               pub fn production() {\n\
               \x20   std::fs::rename(a, b);\n\
               }\n";
    assert_eq!(gated_lines(src), vec![1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn a_brace_in_a_test_assertion_message_does_not_hold_the_test_module_open() {
    let src = "#[cfg(test)]\n\
               mod tests {\n\
               \x20   #[test]\n\
               \x20   fn t() {\n\
               \x20       assert_eq!(x, \"a{b\");\n\
               \x20   }\n\
               }\n\
               pub fn production() {\n\
               \x20   std::fs::rename(a, b);\n\
               }\n";
    assert_eq!(gated_lines(src), vec![1, 2, 3, 4, 5, 6, 7]);
    // The same file read the other way: the production tail must survive the filter.
    let joined: String = scan::production_lines(src)
        .iter()
        .map(|(_, l)| l.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("fn production"),
        "the test module's brace-bearing message swallowed the file: {joined:?}"
    );
    assert!(!joined.contains("assert_eq"));
}

#[test]
fn a_raw_string_full_of_braces_is_text_in_both_scanners() {
    // An UNBALANCED run of braces: a raw string is the one place a `{` can appear without a `}`
    // anywhere near it, so this is the cheapest way to latch the module open for the rest of a file.
    let src = "#[cfg(test)]\n\
               mod tests {\n\
               \x20   const OPENERS: &str = r#\"{{{\"#;\n\
               }\n\
               pub fn production() {\n\
               \x20   std::fs::rename(a, b);\n\
               }\n";
    assert_eq!(gated_lines(src), vec![1, 2, 3, 4]);

    // There is NO escape processing inside `r#"…"#`, so the `\` before the closing quote is a
    // backslash and the literal ends where the compiler says it does. Reading `\"` as an escape
    // ran the string state past the end of the literal and blanked the real code after it.
    let blanked = scan::blank_literals("let j = r#\"a\\\"#; if x {");
    assert_eq!(
        scan::delta(&blanked, '{', '}'),
        1,
        "the literal ate the code after it: {blanked:?}"
    );
}

#[test]
fn the_blanker_reads_byte_strings_escaped_char_quotes_and_nested_block_comments() {
    // A char literal whose ESCAPE carries a brace, a byte char, a byte string, and the escaped
    // quote that used to make `blank_literals` treat the rest of the line as string body.
    for line in [
        r"let c = '\u{7f}'; if x {",
        r"let b = b'{'; if x {",
        r#"let s = b"{{{"; if x {"#,
        r#"let q = '"'; if x {"#,
    ] {
        let blanked = scan::blank_literals(line);
        assert_eq!(
            scan::delta(&blanked, '{', '}'),
            1,
            "literal contents leaked into the count: {line:?} -> {blanked:?}"
        );
        assert_eq!(blanked.chars().count(), line.chars().count());
    }
    // A `'"'` no longer blanks what follows it, which is what a needle search reads.
    assert!(scan::blank_literals(r#"let q = '"'; use banned::thing;"#).contains("use banned"));

    // Rust block comments NEST; a flag reopens code as comment at the first `*/`.
    let mut st = scan::LexState::default();
    let first = scan::blank_code("/* outer /* inner */ still comment {", &mut st);
    assert_eq!(scan::delta(&first, '{', '}'), 0, "{first:?}");
    let second = scan::blank_code("*/ fn f() {", &mut st);
    assert_eq!(scan::delta(&second, '{', '}'), 1, "{second:?}");

    // A `"…"` left open at end of line carries; its body is not code.
    let mut st = scan::LexState::default();
    let a = scan::blank_code("let s = \"opened", &mut st);
    let b = scan::blank_code("still string {{{\" ; fn g() {", &mut st);
    assert_eq!(scan::delta(&a, '{', '}') + scan::delta(&b, '{', '}'), 1);
}

#[test]
fn a_lifetime_is_not_a_char_literal() {
    // `'a` has no closing quote on the line; a blanker that guessed it did would eat the braces
    // after it and under-count every generic function in the tree.
    let line = "fn f<'a>(x: &'a str) -> &'a str { x }";
    let blanked = scan::blank_literals(line);
    assert_eq!(blanked, line, "a lifetime must survive blanking untouched");
    assert_eq!(scan::delta(&blanked, '{', '}'), 0);
}

#[test]
fn strip_comment_line_keeps_string_literals_intact() {
    let mut in_block = false;
    assert_eq!(
        scan::strip_comment_line("let s = \"a // b\"; // gone", &mut in_block),
        "let s = \"a // b\"; "
    );
}

// ── planes ──────────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_plane_key_contract_matches_plane_keys_sh() {
    assert_eq!(planes::PLANE_KEYS, ["llm", "mcp", "a2a", "voice"]);
    assert_eq!(planes::plane_keys_protocol(), vec!["mcp", "a2a", "voice"]);
    assert_eq!(planes::plane_keys_other("a2a"), vec!["mcp", "voice"]);
    let src = planes::plane_src_roots();
    assert_eq!(src[0], "crates/busbar-llm/src");
    assert!(src.contains(&"crates/busbar-llm-codec/src".to_string()));
    assert!(src.contains(&"crates/busbar-voice-codec/src".to_string()));
    // THE NEUTRAL SET, IN THE ORDER THE SHELL TWIN SPELLS IT. The four retiring crates, then the
    // kernel, then the units — the crates the retiring four are being drained INTO, which is the
    // end of the move this gate was not watching.
    let neutral = planes::neutral_src_roots();
    assert_eq!(
        neutral,
        vec![
            "crates/busbar-core/src",
            "crates/busbar-substrate/src",
            "crates/busbar-substrate-values/src",
            "crates/api/src",
            "crates/busbar-kernel/src",
            "crates/busbar-unit-admission/src",
            "crates/busbar-unit-audit/src",
            "crates/busbar-unit-auth/src",
            "crates/busbar-unit-breaker/src",
            "crates/busbar-unit-cost/src",
            "crates/busbar-unit-egress/src",
            "crates/busbar-unit-egress-auth/src",
            "crates/busbar-unit-ledger/src",
            "crates/busbar-unit-scope/src",
            "crates/busbar-unit-transport-key/src",
            "crates/busbar-unit-trust/src",
            "crates/busbar-unit-usage/src",
            "crates/busbar-unit-verbs/src",
            "crates/busbar-unit-wal/src",
        ]
    );
    // ALL FOURTEEN, NOW PRESENT. `busbar-unit-trust` and `busbar-unit-ledger` were the two owed:
    // their test code carried vendor-named fixtures, which forced the test-scope DIALECT and KEY
    // ceilings up until the fixtures were reworded to neutral spellings. This assertion used to
    // name them absent on purpose; it now asserts them present, which is the day this cell said it
    // would change.
    for landed in [
        "crates/busbar-unit-trust/src",
        "crates/busbar-unit-ledger/src",
    ] {
        assert!(
            neutral.contains(&landed.to_string()),
            "{landed} is missing from the neutral scan set"
        );
    }
}

#[test]
fn plane_root_resolution_ports_the_four_shell_selftest_cases() {
    let tmp = tmpdir("plane-roots");

    // 1. the wire-codec split: a same-named sibling that declares nothing is not a second home.
    std::fs::create_dir_all(tmp.join("split/plane-x/src/x")).unwrap();
    std::fs::create_dir_all(tmp.join("split/plane-x-codec/src/x")).unwrap();
    std::fs::write(
        tmp.join("split/plane-x/src/x/mod.rs"),
        "pub const PLANE_DECL: Foo = Foo;\n",
    )
    .unwrap();
    std::fs::write(
        tmp.join("split/plane-x-codec/src/x/canonical.rs"),
        "pub fn canonical() {}\n",
    )
    .unwrap();
    let r = PlaneRoots::at(tmp.join("split")).resolve("x").unwrap();
    assert_eq!(r, tmp.join("split/plane-x/src/x"));

    // 2. two declaring homes are refused, and the refusal names both.
    std::fs::create_dir_all(tmp.join("two/plane-y/src/y")).unwrap();
    std::fs::create_dir_all(tmp.join("two/plane-y-fork/src/y")).unwrap();
    std::fs::write(
        tmp.join("two/plane-y/src/y/mod.rs"),
        "pub const PLANE_DECL: Foo = Foo;\n",
    )
    .unwrap();
    std::fs::write(
        tmp.join("two/plane-y-fork/src/y/mod.rs"),
        "pub const PLANE_DECL: Foo = Foo;\n",
    )
    .unwrap();
    match PlaneRoots::at(tmp.join("two")).resolve("y") {
        Err(PlaneRootError::Ambiguous { candidates, .. }) => {
            let joined = candidates
                .iter()
                .map(|c| c.display().to_string())
                .collect::<Vec<_>>()
                .join(" ");
            assert!(joined.contains("plane-y/src/y") && joined.contains("plane-y-fork/src/y"));
        }
        other => panic!("expected Ambiguous, got {other:?}"),
    }

    // 3. no declaring home is a hard error, never a skip.
    std::fs::create_dir_all(tmp.join("none/plane-z/src/z")).unwrap();
    std::fs::write(
        tmp.join("none/plane-z/src/z/canonical.rs"),
        "pub fn unrelated() {}\n",
    )
    .unwrap();
    assert!(matches!(
        PlaneRoots::at(tmp.join("none")).resolve("z"),
        Err(PlaneRootError::Missing { .. })
    ));

    // 4. the real tree's a2a resolves to the owner, not the codec crate.
    let real = PlaneRoots::at(repo_root().join("crates"))
        .resolve("a2a")
        .unwrap();
    assert!(
        real.ends_with("busbar-a2a/src/a2a"),
        "resolved to {}",
        real.display()
    );
}

// ── yaml_lite ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn logical_lines_port_the_five_continuation_fixture_assertions() {
    let yml = "\
jobs:
  j:
    steps:
      - name: cargo test --test named-in-a-step-name
        run: |
          cargo test -p busbar-core \\
            --features a \\
            --lib
          echo \"cargo build --quoted-inside-an-echo\"
          # cargo build --in-a-comment
          testing/planted/gate.sh --check
";
    let lines = yaml_lite::logical_lines(yml);
    let joined = lines.join("\n");
    assert!(
        joined.contains("cargo test -p busbar-core --features a --lib"),
        "{joined}"
    );
    assert!(!joined.contains("quoted-inside-an-echo"));
    assert!(!joined.contains("in-a-comment"));
    assert!(!joined.contains("named-in-a-step-name"));
    assert!(joined.contains("testing/planted/gate.sh --check"));
}

#[test]
fn folded_scalars_join_every_line_while_literal_scalars_keep_them_apart() {
    let folded = yaml_lite::logical_lines("    run: >\n      cargo build\n      --workspace\n");
    assert_eq!(folded, vec!["cargo build --workspace".to_string()]);
    let literal = yaml_lite::logical_lines("    run: |\n      cargo build\n      cargo test\n");
    assert_eq!(
        literal,
        vec!["cargo build".to_string(), "cargo test".to_string()]
    );
}

#[test]
fn an_empty_workflow_is_refused_rather_than_parsed_as_zero_jobs() {
    assert!(yaml_lite::parse_workflow("").is_err());
    assert!(yaml_lite::parse_workflow("jobs:\n").is_err());
}

#[test]
fn parse_workflow_reads_jobs_needs_env_and_step_runs() {
    let wf = yaml_lite::parse_workflow(
        "\
env:
  RUSTFLAGS: \"-D warnings\"
jobs:
  lint:
    steps:
      - name: one
        run: cargo xtask gate denylist
  umbrella:
    needs: [lint]
    steps:
      - run: echo ok
",
    )
    .unwrap();
    assert_eq!(
        wf.env.get("RUSTFLAGS").map(String::as_str),
        Some("-D warnings")
    );
    assert_eq!(wf.job_names(), vec!["lint", "umbrella"]);
    assert_eq!(wf.job("umbrella").unwrap().needs, vec!["lint"]);
    assert_eq!(
        wf.job("lint").unwrap().steps[0].name.as_deref(),
        Some("one")
    );
    assert_eq!(
        wf.job("lint").unwrap().steps[0].run.as_deref(),
        Some("cargo xtask gate denylist")
    );
}

#[test]
fn the_real_ci_workflow_parses_and_its_gate_call_sites_are_discoverable() {
    let text = std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml")).unwrap();
    let wf = yaml_lite::parse_workflow(&text).expect("the real ci.yml parses");
    assert!(
        wf.job_names().len() > 15,
        "ci.yml carries ~24 jobs: {:?}",
        wf.job_names()
    );
    assert!(
        wf.job_names()
            .iter()
            .any(|j| wf.job(j).unwrap().steps.iter().any(|s| s.run.is_some())),
        "every job's `run:` steps must be visible to the discovery"
    );

    // EVERY GATE ci.yml CALLS IS ONE THE RUNNER ANSWERS TO. This replaces the placeholder that
    // pinned "no call site has been switched yet": that assertion had exactly one job, to prove the
    // discovery reads the file rather than a cached list, and the first switched call site did the
    // proving. What survives it is the direction that keeps mattering — a `cargo xtask gate <typo>`
    // in `ci.yml` is a step that exits 2 on every push, and the registry is what can say so here
    // rather than in a red run.
    //
    // The OTHER direction — a registered gate absent from `ci.yml` — is deliberately not asserted
    // here. It is `cargo xtask gate full`'s set-equality rule, which owns the SKIP_REASON table
    // that makes a deliberate absence say why; duplicating half of it here would be a second place
    // for that reasoning to rot.
    let called = yaml_lite::xtask_gate_invocations(&text);
    assert!(
        !called.is_empty(),
        "ci.yml calls no `cargo xtask gate` at all — either every call site was reverted or the \
         discovery stopped reading the file"
    );
    let registered = gates::names();
    let unknown: Vec<&String> = called
        .iter()
        .filter(|n| !registered.contains(&n.as_str()))
        .collect();
    assert!(
        unknown.is_empty(),
        "ci.yml calls gate(s) the registry does not answer to: {unknown:?} — every one of those \
         steps exits 2 on every push. Registered: {registered:?}"
    );
    // And ONE NAME IS PINNED BY HAND, because `!called.is_empty()` above would still hold if every
    // call site but one were reverted. `plane-purity` is the one the batch that switched it named
    // here; a `called` set that has lost it is a call site that went back to a script.
    assert!(
        called.contains(&"plane-purity".to_string()),
        "the plane-purity call site is switched; discovery must see it: {called:?}"
    );
    for name in &called {
        assert!(
            gates::find(name).is_some(),
            "ci.yml calls `cargo xtask gate {name}`, which no registration answers to"
        );
    }
    assert_eq!(
        yaml_lite::xtask_gate_invocations("    run: |\n      cargo xtask gate plane-purity --selftest\n      cargo xtask gate plane-purity\n"),
        vec!["plane-purity".to_string()]
    );
    assert_eq!(
        yaml_lite::xtask_gate_invocations("        run: cargo xtask denylist --selftest\n"),
        vec!["denylist".to_string()],
        "the pre-registry `cargo xtask <name>` form is a call site too"
    );
}

// ── gitp ────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn git_runs_as_a_process_rooted_with_dash_c_and_never_cds() {
    let c = cx();
    let head = c.git(&["rev-parse", "HEAD"]).unwrap();
    assert_eq!(head.trim().len(), 40);
    assert!(c
        .git(&["cat-file", "-e", "0000000000000000000000000000000000000000"])
        .is_err());
}

// ── the registry, the trait, the derived owed set ───────────────────────────────────────────────

#[test]
fn the_registry_is_non_empty_and_its_names_are_unique_and_sorted_lookups_work() {
    assert!(!gates::REGISTRY.is_empty());
    let names: Vec<&str> = gates::names();
    let uniq: BTreeSet<&str> = names.iter().copied().collect();
    assert_eq!(names.len(), uniq.len(), "two registrations under one name");
    assert!(names.contains(&"denylist"));
    assert!(names.contains(&"segregation"));
    assert!(gates::find("denylist").is_some());
    assert!(gates::find("no-such-gate").is_none());
}

#[test]
fn every_registration_declares_at_least_one_owed_row_id() {
    for reg in gates::REGISTRY {
        let gate = (reg.build)();
        assert!(
            !gate.owed().is_empty(),
            "{} declares no owed row ids, so nothing reconciles what it writes",
            reg.name
        );
        assert_eq!(
            gate.name(),
            reg.name,
            "registration name and gate name disagree"
        );
    }
}

#[test]
fn nearest_names_are_offered_for_an_unknown_gate() {
    let near = gates::nearest("denylst");
    assert!(near.contains(&"denylist"), "{near:?}");
}

struct RowNobodyOwes;
impl Gate for RowNobodyOwes {
    fn name(&self) -> &'static str {
        "row-nobody-owes"
    }
    fn owed(&self) -> Vec<String> {
        vec!["owed:one".to_string()]
    }
    fn run(&self, _cx: &Ctx) -> Verdict {
        Verdict::of(vec![
            Row::new(Status::Pass, "owed:one", "t", "d"),
            Row::new(Status::Fail, "not-owed", "t", "d"),
        ])
    }
    fn selftest<'a>(&'a self, _cx: &'a Ctx) -> Report<'a> {
        Report::new()
    }
}

#[test]
fn the_runner_reconciles_a_gates_rows_against_the_owed_set_it_declared() {
    let c = cx();
    let v = gates::execute(&RowNobodyOwes, &c);
    assert!(
        v.red,
        "a gate that writes a row nobody owes must be RED, not exit 0"
    );
    assert!(v.problems.iter().any(|p| p.contains("not-owed")));
}

#[test]
fn a_gate_with_no_red_proof_is_refused_by_the_selftest_runner() {
    let c = cx();
    let err = gates::verify_report(&RowNobodyOwes, &RowNobodyOwes.selftest(&c))
        .expect_err("a gate whose selftest proves no RED case is not a proven gate");
    assert!(err.iter().any(|e| e.contains("no case")));
}

#[test]
fn a_report_that_leaves_an_owed_row_id_uncovered_is_refused() {
    let mut report = Report::new();
    report.push(Case {
        name: "covers nothing owed".to_string(),
        covers: vec!["some:other".to_string()],
        expected: Expect::Red {
            naming: vec!["x".to_string()],
        },
        got: Expect::Red {
            naming: vec!["x".to_string()],
        },
    });
    let errs = gates::verify_report(&RowNobodyOwes, &report).expect_err("owed:one is uncovered");
    assert!(errs.iter().any(|e| e.contains("owed:one")));
}

/// `RowNobodyOwes` with its one owed row declared PASS-by-construction, plus a second declaration
/// that names nothing — the two halves of the informational contract in one gate.
struct DeclaresInformational {
    declare: &'static [&'static str],
}
impl Gate for DeclaresInformational {
    fn name(&self) -> &'static str {
        "declares-informational"
    }
    fn owed(&self) -> Vec<String> {
        vec!["owed:one".to_string()]
    }
    fn informational(&self) -> Vec<String> {
        self.declare.iter().map(|s| (*s).to_string()).collect()
    }
    fn run(&self, _cx: &Ctx) -> Verdict {
        Verdict::of(vec![Row::new(Status::Pass, "owed:one", "t", "d")])
    }
    fn selftest<'a>(&'a self, _cx: &'a Ctx) -> Report<'a> {
        Report::new()
    }
}

/// A report with one RED case (so the gate has a red proof at all) and one GREEN case naming
/// `owed:one`, which is exactly what a PASS-by-construction row can offer.
fn report_covering_owed_one_green_only<'a>() -> Report<'a> {
    let mut report = Report::new();
    report.push(Case {
        name: "some other rule goes red".to_string(),
        covers: vec!["some:other".to_string()],
        expected: Expect::Red {
            naming: vec!["x".to_string()],
        },
        got: Expect::Red {
            naming: vec!["x".to_string()],
        },
    });
    report.push(Case {
        name: "the informational row is measured".to_string(),
        covers: vec!["owed:one".to_string()],
        expected: Expect::Green,
        got: Expect::Green,
    });
    report
}

#[test]
fn an_owed_row_declared_informational_is_discharged_by_a_green_case_and_nothing_else_is() {
    let undeclared = DeclaresInformational { declare: &[] };
    let errs = gates::verify_report(&undeclared, &report_covering_owed_one_green_only())
        .expect_err("a green case does not discharge a row that is not declared informational");
    assert!(
        errs.iter().any(|e| e.contains("owed:one")),
        "the undeclared row must still be refused: {errs:?}"
    );

    let declared = DeclaresInformational {
        declare: &["owed:one"],
    };
    gates::verify_report(&declared, &report_covering_owed_one_green_only())
        .expect("a declared informational row is held to being exercised, and it was");
}

#[test]
fn a_declared_informational_row_that_no_case_exercises_at_all_is_still_refused() {
    let declared = DeclaresInformational {
        declare: &["owed:one"],
    };
    let mut report = Report::new();
    report.push(Case {
        name: "some other rule goes red".to_string(),
        covers: vec!["some:other".to_string()],
        expected: Expect::Red {
            naming: vec!["x".to_string()],
        },
        got: Expect::Red {
            naming: vec!["x".to_string()],
        },
    });
    let errs = gates::verify_report(&declared, &report)
        .expect_err("a row that cannot go RED must at least be measured by one case");
    assert!(
        errs.iter()
            .any(|e| e.contains("owed:one") && e.contains("exercised by no case")),
        "{errs:?}"
    );
}

#[test]
fn an_informational_declaration_that_names_no_owed_row_is_refused_as_a_stale_exemption() {
    let stale = DeclaresInformational {
        declare: &["owed:one", "owed:gone"],
    };
    let errs = gates::verify_report(&stale, &report_covering_owed_one_green_only())
        .expect_err("an exemption that names nothing is a line nobody re-reads");
    assert!(
        errs.iter().any(|e| e.contains("owed:gone")),
        "the stale declaration must be named: {errs:?}"
    );
}

#[test]
fn a_case_that_went_green_where_red_was_expected_fails_the_report() {
    let mut report = Report::new();
    report.push(Case {
        name: "planted violation".to_string(),
        covers: vec!["owed:one".to_string()],
        expected: Expect::Red {
            naming: vec!["offender".to_string()],
        },
        got: Expect::Green,
    });
    assert!(!report.ok());
    assert!(report
        .failures()
        .iter()
        .any(|f| f.contains("planted violation")));
}

#[test]
fn a_red_that_does_not_name_the_planted_offender_fails_the_report() {
    let mut report = Report::new();
    report.push(Case {
        name: "unnamed".to_string(),
        covers: vec!["owed:one".to_string()],
        expected: Expect::Red {
            naming: vec!["the-offender".to_string()],
        },
        got: Expect::Red {
            naming: vec!["something else entirely".to_string()],
        },
    });
    assert!(
        !report.ok(),
        "'something went red' is not an accepted answer"
    );
}

#[test]
fn a_plant_with_nothing_to_plant_is_visible_in_the_report_never_silently_green() {
    let mut report = Report::new();
    report.push(Case {
        name: "subject absent".to_string(),
        covers: vec!["owed:one".to_string()],
        expected: Expect::Red { naming: vec![] },
        got: Expect::Skipped,
    });
    assert!(!report.ok());
    assert!(report
        .failures()
        .iter()
        .any(|f| f.contains("subject absent")));
    assert_eq!(report.skipped(), 1);
}

#[test]
fn tier_and_batch_are_carried_on_every_registration() {
    for reg in gates::REGISTRY {
        assert!(
            (1..=3).contains(&reg.batch),
            "{} has batch {}",
            reg.name,
            reg.batch
        );
        assert!(matches!(reg.tier, Tier::Fast | Tier::Full | Tier::Release));
    }
}

// ── the segregation gate ────────────────────────────────────────────────────────────────────────

fn segregation() -> Box<dyn Gate> {
    (gates::find("segregation")
        .expect("segregation is registered")
        .build)()
}

#[test]
fn segregation_is_green_over_the_real_tree() {
    let c = cx();
    let v = gates::execute(segregation().as_ref(), &c);
    assert!(!v.red, "segregation over the real tree: {:?}", v.problems);
    assert!(
        v.rows.iter().all(|r| r.status == Status::Pass),
        "{:?}",
        v.rows
    );
}

#[test]
fn segregation_reds_on_each_of_the_five_planted_violations() {
    let c = cx();
    let gate = segregation();
    let report = gate.selftest(&c);
    assert!(report.ok(), "{:#?}", report.failures());
    assert!(
        report
            .cases()
            .iter()
            .filter(|c| matches!(c.expected, Expect::Red { .. }))
            .count()
            >= 5,
        "the five section-4 violations each need their own discriminating fixture"
    );
    gates::verify_report(segregation().as_ref(), &report).expect("owed ids all covered");
}

#[test]
fn segregation_reds_when_xtask_src_names_a_product_crate() {
    let c = cx();
    let mut ov = Overlay::new();
    Edit::Append("\nuse busbar_core::plane::PlaneDecl;\n".to_string())
        .apply(&c, "xtask/src/scan.rs", &mut ov)
        .unwrap();
    let v = gates::execute(segregation().as_ref(), &c.with_overlay(ov));
    assert!(v.red);
    assert!(
        v.rows
            .iter()
            .any(|r| r.status == Status::Fail && r.detail.contains("busbar_core")),
        "the RED must name the import it found: {:?}",
        v.rows
    );
}

#[test]
fn segregation_reds_when_the_oracle_names_xtask() {
    let c = cx();
    let mut ov = Overlay::new();
    Edit::Create("# see cargo xtask gate segregation\n".to_string())
        .apply(&c, "testing/shadow-oracle/tempted.py", &mut ov)
        .unwrap();
    let v = gates::execute(segregation().as_ref(), &c.with_overlay(ov));
    assert!(
        v.red,
        "the oracle must import nothing from the workspace it judges"
    );
}

// ── the parity helper ───────────────────────────────────────────────────────────────────────────

#[test]
fn parity_passes_only_on_identical_ledger_rows() {
    let legacy = vec![Row::new(Status::Pass, "a", "t", "d")];
    let rust = vec![Row::new(Status::Pass, "a", "t", "d")];
    assert!(parity::compare(&legacy, &rust).is_empty());

    let drifted = vec![Row::new(Status::Pass, "a", "t", "different detail")];
    let diffs = parity::compare(&legacy, &drifted);
    assert_eq!(diffs.len(), 1);
    assert!(diffs[0].contains('a'));

    let missing = parity::compare(&legacy, &[]);
    assert!(
        !missing.is_empty(),
        "a Rust gate that emits nothing is not at parity"
    );
}

#[test]
fn parity_runs_a_legacy_script_over_the_same_tree_and_reads_its_ledger_back() {
    let dir = tmpdir("parity");
    let script = dir.join("legacy.sh");
    std::fs::write(
        &script,
        "#!/usr/bin/env bash\nprintf 'a\\tPASS\\tt\\td\\n' >> \"$LEDGER\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let c = cx();
    let rows = parity::run_legacy(&c, &[script.display().to_string()], "LEDGER").unwrap();
    assert_eq!(rows, vec![Row::new(Status::Pass, "a", "t", "d")]);
}

#[test]
fn parity_refuses_a_legacy_run_that_wrote_no_rows() {
    let dir = tmpdir("parity-empty");
    let script = dir.join("silent.sh");
    std::fs::write(&script, "#!/usr/bin/env bash\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let c = cx();
    assert!(
        parity::run_legacy(&c, &[script.display().to_string()], "LEDGER").is_err(),
        "zero legacy rows would make every parity comparison vacuous"
    );
}

#[test]
fn the_walk_skips_what_the_tree_ignores_and_still_refuses_a_missing_root() {
    // `find` reads whatever a build left behind. A scan set holding `__pycache__/*.pyc` is a gate
    // red on a byte nobody wrote, and a gate that reds for a reason unrelated to its rule is how a
    // runner earns a `|| true`.
    let c = cx();
    let ignored = PathBuf::from(format!("testing/{}/__pycache__/probe.pyc", "shadow-oracle"));
    let mut ov = Overlay::new();
    ov.set(&ignored, "compiled bytecode\n");
    let planted = c.with_overlay(ov);
    let files = planted
        .walk(&WalkSpec::new([format!("testing/{}", "shadow-oracle")]).min_files(1))
        .expect("the oracle tree walks");
    assert!(
        !files.iter().any(|f| f.rel == ignored),
        "an ignored path is not part of the tree the gates judge"
    );

    // The two refusals are evaluated AROUND the filter, never through it.
    assert!(matches!(
        c.walk(&WalkSpec::new(["no/such/root"]).ext("rs").min_files(1)),
        Err(WalkError::MissingRoot { .. })
    ));
}

#[test]
fn check_ignore_reads_a_clean_scan_set_as_none_ignored_rather_than_as_an_error() {
    // `git check-ignore` exits 1 when NOTHING matched, which is the ordinary answer over a clean
    // set. A caller that tested `success()` would call every clean tree unreadable.
    let root = repo_root();
    let none = xtask::gitp::check_ignore(&root, &["xtask/src/ctx.rs".to_string()])
        .expect("exit 1 is `nothing matched`, not a failure");
    assert!(none.is_empty());
    let some = xtask::gitp::check_ignore(&root, &[".fix/whatever".to_string()])
        .expect("exit 0 is `something matched`");
    assert_eq!(some, vec![".fix/whatever".to_string()]);
}

// ── THE ERE SUBSET MATCHER ────────────────────────────────────────────────────────────────────────
//
// The rule tables the structure-lint port drives are EREs, so a matcher that quietly disagrees with
// one is a rule scanning for something other than what its row says — and a rule that matches
// nothing is a rule that passed. Every case below drives a pattern taken VERBATIM from a shipped
// row against a line that must hit and a line that must not.

fn ere(p: &str) -> xtask::ere::Ere {
    xtask::ere::Ere::new(p).unwrap_or_else(|e| panic!("`{p}` must compile: {e}"))
}

#[test]
fn ere_matches_the_choke_point_rows_verbatim() {
    assert!(ere(r"fs::rename\(").is_match("        std::fs::rename(&tmp, &dst)?;"));
    assert!(!ere(r"fs::rename\(").is_match("        std::fs::renamed;"));

    assert!(ere("sync_[ad]").is_match("    f.sync_all()?;"));
    assert!(ere("sync_[ad]").is_match("    f.sync_data()?;"));
    assert!(!ere("sync_[ad]").is_match("    f.sync_everything()?;"));

    assert!(ere(r"#\[(unsafe\()?no_mangle").is_match("#[no_mangle]"));
    assert!(ere(r"#\[(unsafe\()?no_mangle").is_match("#[unsafe(no_mangle)]"));
    assert!(!ere(r"#\[(unsafe\()?no_mangle").is_match("let x = no_mangle;"));

    assert!(ere(r"AskEntryCfg[[:space:]]*\{").is_match("    let a = AskEntryCfg {"));
    assert!(!ere(r"AskEntryCfg[[:space:]]*\{").is_match("    fn f(a: &AskEntryCfg) -> u8 {"));

    assert!(ere(r"schema_hash[[:space:]]*\.is_some").is_match("if e.schema_hash.is_some() {"));
    assert!(ere(r"\.pin[[:space:]]*\.is_none").is_match("if approval.pin .is_none() {"));
}

#[test]
fn ere_matches_the_axis_rows_verbatim() {
    let op = ere(r"[Oo]peration(\(\))?[[:space:]]*==");
    assert!(op.is_match("    if operation == Operation::Chat {"));
    assert!(op.is_match("    if req.operation() == want {"));
    assert!(!op.is_match("    let operation = pick();"));

    let m = ere(r"match[[:space:]]+[A-Za-z0-9_.:]*[Tt]ransport(\(\))?[[:space:]]*\{");
    assert!(m.is_match("        match self.transport {"));
    assert!(m.is_match("        match Transport {"));
    assert!(!m.is_match("        match self.other {"));

    let mm = ere(r"matches!\([^)]*OpShape::");
    assert!(mm.is_match("    if matches!(v, OpShape::Stream) {"));
    assert!(!mm.is_match("    if matches!(v, Other::Stream) {"));

    let il = ere(r"if[[:space:]]+let[[:space:]]+[A-Za-z0-9_:]*Transport::");
    assert!(il.is_match("    if let Transport::Stdio = t {"));
    assert!(il.is_match("    if let busbar::Transport::Stdio = t {"));
    assert!(!il.is_match("    if let Some(t) = t {"));
}

#[test]
fn ere_matches_the_request_path_word_boundaries_the_shell_spelled_by_hand() {
    let mid = ere("[^A-Za-z0-9_][Ss]tore[^A-Za-z0-9_]");
    assert!(mid.is_match("        self.store.get(k)"));
    assert!(mid.is_match("        let s: &dyn Store = x;"));
    // The whole reason the boundaries are spelled out rather than written `\b`: these must NOT trip.
    assert!(!mid.is_match("        restore_from_store_id(x)"));
    assert!(!mid.is_match("        let store_id = 3;"));

    let end = ere("[^A-Za-z0-9_][Ss]tore$");
    assert!(end.is_match("        let s = self.store"));
    assert!(!end.is_match("        let s = self.restore"));
}

#[test]
fn ere_reads_the_inline_test_attribute_class_with_a_leading_bracket() {
    // `[]([:space:]]` — a `]` FIRST in a bracket expression is a literal `]`, and reading that
    // wrong makes the whole inline-test rule match nothing, which is its pass.
    let attr = ere(
        r"^[[:space:]]*#\[((tokio|async_std|actix_rt|serial_test)::)?(test|rstest|test_case|bench|proptest)[]([:space:]]",
    );
    assert!(attr.is_match("    #[test]"));
    assert!(attr.is_match("    #[tokio::test]"));
    assert!(attr.is_match("    #[tokio::test(flavor = \"multi_thread\")]"));
    assert!(attr.is_match("    #[test_case(1)]"));
    assert!(attr.is_match("    #[rstest]"));
    assert!(!attr.is_match("    #[testing]"));
    assert!(!attr.is_match("    #[derive(Debug)]"));
}

#[test]
fn ere_finds_the_declaration_span_the_plane_scanner_reads() {
    let decl = ere(
        r"^(pub[[:space:]]*(\([^)]*\)[[:space:]]*)?)?((async|unsafe|const)[[:space:]]+)*fn[[:space:]]+[A-Za-z_][A-Za-z0-9_]*",
    );
    assert_eq!(
        decl.find_str("pub(crate) async fn observed_pin(x: u8) -> u8 {"),
        Some("pub(crate) async fn observed_pin".to_string())
    );
    assert_eq!(decl.find_str("fn judge() {"), Some("fn judge".to_string()));
    // A METHOD is indented, so the anchor keeps it out of the comparison — the property that makes
    // the cross-plane duplicate rule usable at all.
    assert_eq!(decl.find_str("    fn new() -> Self {"), None);
}

#[test]
fn ere_refuses_a_pattern_that_does_not_compile_rather_than_matching_nothing() {
    assert!(xtask::ere::Ere::new("(unclosed").is_err());
    assert!(xtask::ere::Ere::new("[unclosed").is_err());
    assert!(xtask::ere::Ere::new("closed)").is_err());
}

#[test]
fn ere_terminates_on_a_nullable_group_under_a_star() {
    // An iteration that consumed nothing ends the repeat; without that guard this hangs forever.
    assert!(ere("(a?)*b").is_match("xxb"));
    assert!(!ere("(a?)*b").is_match("xxc"));
}

#[test]
fn ere_prefilters_on_a_literal_no_match_can_avoid() {
    assert_eq!(
        ere(r"fn[[:space:]]+validate_request[^a-zA-Z0-9_]").required_literal(),
        Some("validate_request")
    );
    assert_eq!(
        ere(r"[Oo]peration(\(\))?[[:space:]]*==").required_literal(),
        Some("peration")
    );
    // Nothing is mandatory at the top level here: the prefilter must be ABSENT rather than wrong.
    assert_eq!(ere("(abc|def)").required_literal(), None);
}

// ── TEST_SCOPE_AWK, PORTED ────────────────────────────────────────────────────────────────────────
//
// The two bugs the shell's own self-test proved exploitable, plus the brace-less-item case that
// made the second one reachable. A line wrongly called "test" is a line exempt from every ban.

fn gated_lines(src: &str) -> Vec<usize> {
    scan::test_scope(src)
        .into_iter()
        .filter(|l| l.gated)
        .map(|l| l.no)
        .collect()
}

#[test]
fn a_doc_comment_naming_the_test_attribute_does_not_shadow_the_production_item_below_it() {
    let src = "/// This item is NOT #[cfg(test)] — the comment merely says the words.\n\
               pub fn production() {\n    std::fs::rename(a, b);\n}\n";
    assert_eq!(gated_lines(src), Vec::<usize>::new());
}

#[test]
fn a_brace_less_cfg_test_item_gates_its_own_line_and_no_more() {
    let src = "#[cfg(test)]\nmod tests;\n\npub fn production() {\n    std::fs::rename(a, b);\n}\n";
    // The attribute and the brace-less item it applies to, and nothing after them.
    assert_eq!(gated_lines(src), vec![1, 2]);
}

#[test]
fn a_braced_cfg_test_body_is_gated_to_its_closing_brace_and_not_past_it() {
    let src = "#[cfg(test)]\nmod tests {\n    fn t() {\n        std::fs::rename(a, b);\n    }\n}\n\
               pub fn production() {\n    std::fs::rename(a, b);\n}\n";
    assert_eq!(gated_lines(src), vec![1, 2, 3, 4, 5, 6]);
}

#[test]
fn cfg_not_test_is_production_and_a_feature_gate_is_not_a_test_gate() {
    let src = "#[cfg(not(test))]\npub fn only_in_prod() {\n    std::fs::rename(a, b);\n}\n";
    assert_eq!(gated_lines(src), Vec::<usize>::new());
    let src =
        "#[cfg(feature = \"test-utils\")]\npub fn helper() {\n    std::fs::rename(a, b);\n}\n";
    assert_eq!(gated_lines(src), Vec::<usize>::new());
}

#[test]
fn cfg_all_test_arms_and_an_unresolvable_attribute_fails_closed() {
    assert_eq!(
        gated_lines("#[cfg(all(test, unix))]\nmod t {\n}\n"),
        vec![1, 2, 3]
    );
    // An attribute that resolves to no item within a handful of lines is DROPPED rather than
    // latching onto the next braced item, which is production code.
    let mut src = String::from("#[cfg(test)]\n");
    for _ in 0..14 {
        src.push_str("this line resolves nothing\n");
    }
    src.push_str("pub fn production() {}\n");
    let gated = gated_lines(&src);
    assert!(
        !gated.contains(&16),
        "the arm must be dropped, not latched: {gated:?}"
    );
}

/// A literal-bearing line keeps its literal AND loses its trailer — the two halves of one rule.
///
/// This case used to assert the second half backwards. `code_of` gave up and handed back the WHOLE
/// line whenever the line held a `"` anywhere, and the test pinned that as the contract ("a line
/// holding a literal keeps its raw text"). It is the behaviour `scan: the trailing comment is
/// stripped at the position the blanker found it` removed: a `// }` in a trailer closed a scope
/// that was never opened, and a `#[cfg(test)]` written in one armed the test-scope machine. The
/// literal was never the problem — not knowing where it ENDED was — so both halves hold at once,
/// and a test that can only see one of them cannot tell the fix from the defect.
#[test]
fn the_code_of_a_line_keeps_a_literals_slash_slash_and_still_drops_the_real_trailer() {
    let lines = scan::test_scope("let u = \"https://x\"; // trailer\nlet v = 1; // trailer\n");
    assert!(
        lines[0].code.contains("https://x"),
        "the `//` inside the literal is not a comment marker, so the literal survives"
    );
    assert!(
        !lines[0].code.contains("trailer"),
        "the line's REAL trailer goes, literal or not"
    );
    assert!(
        !lines[1].code.contains("trailer"),
        "a line holding no literal loses its trailer"
    );
}

// ── structure-lint ────────────────────────────────────────────────────────────────────────────────

#[test]
fn structure_lint_emits_exactly_the_rows_it_owes_and_owes_each_of_them_once() {
    use xtask::gates::structure_lint::{StructureLintGate, OWED};
    let gate = StructureLintGate::new();
    let owed: BTreeSet<String> = gate.owed().into_iter().collect();
    assert_eq!(
        owed.len(),
        OWED.len(),
        "an id owed twice is an id whose second rule nobody notices"
    );

    let rows = gates::execute(&gate, &cx()).rows;
    let emitted: BTreeSet<String> = rows.iter().map(|r| r.id.clone()).collect();
    assert_eq!(
        emitted, owed,
        "every rule this gate carries is a row somebody reconciles, in both directions"
    );
}

#[test]
fn every_pattern_in_every_structure_lint_table_compiles() {
    // A pattern that will not compile is a rule that scans nothing, and nothing found is a ban's
    // pass — so the tables are proven READABLE here rather than at the moment somebody violates one.
    use xtask::gates::structure_lint::{roots, Tables};
    let mut f = xtask::gates::structure_lint::Findings::default();
    let t = Tables::real(&roots::resolve(&cx(), &mut f));

    let mut n = 0usize;
    for r in &t.choke_points {
        for rule in &r.rules {
            xtask::ere::Ere::new(&rule.pattern).unwrap_or_else(|e| panic!("{}: {e}", r.id));
            n += 1;
        }
    }
    for r in t.request_path.iter().chain(t.decision_input.iter()) {
        for rule in &r.rules {
            xtask::ere::Ere::new(&rule.pattern).unwrap_or_else(|e| panic!("{}: {e}", r.id));
            n += 1;
        }
    }
    for r in &t.axis_branch {
        for rule in &r.rules {
            xtask::ere::Ere::new(&rule.pattern).unwrap_or_else(|e| panic!("{}: {e}", r.axis));
            n += 1;
        }
    }
    for r in &t.census {
        xtask::ere::Ere::new(&r.pattern).unwrap_or_else(|e| panic!("{}: {e}", r.id));
        n += 1;
    }
    assert!(
        n >= 30,
        "the tables shrank to {n} patterns, which is a rule set that quietly stopped asking things"
    );
}

#[test]
fn the_structure_lint_translator_refuses_a_finding_it_cannot_classify() {
    // An unclassified finding dropped on the floor is how a rewrite gets proven faithful to a
    // script nobody read.
    use xtask::gates::structure_lint::StructureLintGate;
    let gate = StructureLintGate::new();
    let run = parity::LegacyRun {
        argv: vec!["scripts/structure-lint.sh".to_string()],
        code: Some(1),
        stdout: "== a header ==\n  BRAND-NEW-FINDING: something nobody taught this to read\n"
            .to_string(),
        stderr: String::new(),
        scratch: std::env::temp_dir(),
    };
    let err = gate
        .legacy_rows(&cx(), std::slice::from_ref(&run))
        .expect("this gate translates its legacy's own output")
        .expect_err("an unrecognised finding is an error, never a line dropped");
    assert!(err.contains("BRAND-NEW-FINDING"), "{err}");
}

#[test]
fn the_structure_lint_translator_refuses_output_it_recognised_nothing_in() {
    use xtask::gates::structure_lint::StructureLintGate;
    let gate = StructureLintGate::new();
    let run = parity::LegacyRun {
        argv: vec!["scripts/structure-lint.sh".to_string()],
        code: Some(0),
        stdout: String::new(),
        stderr: String::new(),
        scratch: std::env::temp_dir(),
    };
    assert!(
        gate.legacy_rows(&cx(), std::slice::from_ref(&run))
            .expect("this gate translates")
            .is_err(),
        "silence read as a clean tree is the exact defect this gate exists for"
    );
}

// ── no-deferral ─────────────────────────────────────────────────────────────────────────────────

/// THE OVER- AND UNDER-COUNT ARMS, ON ONE TREE. This is the case the retired shell's `--parity`
/// run was compared through before it was deleted: an allowlist that waives NONE of the tree's
/// markers and carries one row matching nothing. Both directions must report, by name and at once
/// — a gate that only notices new markers lets a resolved one leave a lying waiver behind, and a
/// gate that only notices stale rows lets a new deferral land inside a file that already had one.
#[test]
fn no_deferral_reports_the_unwaived_markers_and_the_stale_waiver_together() {
    let mut ov = Overlay::new();
    ov.set(
        "scripts/no-deferral.waivers",
        "crates/busbar-core/src/no-such-file.rs:1\tplanted, matches nothing [retires: H5]\n",
    );
    let reg = gates::find("no-deferral").expect("the gate is registered");
    let gate = (reg.build)();
    let rows = gates::execute(gate.as_ref(), &cx().with_overlay(ov)).rows;

    let row = |id: &str| {
        rows.iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("{id} is owed and must be emitted"))
            .clone()
    };
    let unwaived = row("no-deferral:unwaived");
    assert_eq!(unwaived.status, Status::Fail);
    assert!(
        unwaived
            .detail
            .contains("crates/busbar-plugin/src/hot/host.rs:"),
        "the over-count arm names the markers nobody waived: {}",
        unwaived.detail
    );
    let stale = row("no-deferral:stale-waiver");
    assert_eq!(stale.status, Status::Fail);
    assert!(
        stale.detail.contains("no-such-file.rs:1"),
        "the under-count arm names the waiver that matched nothing: {}",
        stale.detail
    );
    // The allowlist itself LOADED — the two findings above are about the tree, not about a file
    // the gate could not read.
    assert_eq!(row("no-deferral:waiver-shape").status, Status::Pass);
    assert_eq!(row("no-deferral:discovery-floor").status, Status::Pass);
}
