// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn cx() -> Ctx {
    Ctx::workspace().expect("workspace context")
}

#[test]
fn a_p_is_only_a_package_selector_when_cargo_is_in_the_same_command() {
    let mut out = Vec::new();
    scan_commands(
        "f.sh",
        "mkdir -p reports\n\
         docker run -d --name x -p 8080:8080 img\n\
         sudo gdb -p \"$stuck\" -batch\n\
         rm -rf t; mkdir -p t\n\
         N=$(printf '%s' \"$M\" | xxd -r -p | b64url)\n\
         cargo build --locked -p busbar-kernel\n",
        &mut out,
    );
    assert_eq!(
        out.iter().map(|s| s.pkg.as_str()).collect::<Vec<_>>(),
        vec!["busbar-kernel"],
        "{out:?}"
    );
}

#[test]
fn a_continued_command_keeps_its_cargo_and_a_comment_is_not_a_command() {
    let mut out = Vec::new();
    scan_commands(
        "f.yml",
        "          cargo build --locked \\\n\
         \x20           -p busbar-store-example-plugin \\\n\
         \x20           -p busbar-hook-test-plugin\n\
         # it read `-p busbar-core` until the fold deleted that crate\n",
        &mut out,
    );
    assert_eq!(
        out.iter().map(|s| s.pkg.as_str()).collect::<Vec<_>>(),
        vec!["busbar-store-example-plugin", "busbar-hook-test-plugin"]
    );
    assert!(out.iter().all(|s| s.line == 1), "{out:?}");
}

#[test]
fn a_dollar_substitution_and_a_pipeline_are_each_read_on_their_own_terms() {
    let mut out = Vec::new();
    scan_commands(
        "f.yml",
        "          out=\"$(cargo test -p busbar -p busbar-kernel --locked | tee /dev/stderr)\"\n\
         (cd ../sibling && cargo build --release -p busbar-store-sqlite-plugin)\n\
         cargo build --release --manifest-path x/Cargo.toml -p \"$PLUGIN_CRATE\"\n",
        &mut out,
    );
    assert_eq!(
        out.iter().map(|s| s.pkg.as_str()).collect::<Vec<_>>(),
        vec!["busbar", "busbar-kernel", "busbar-store-sqlite-plugin"],
        "a shell variable is not a package name and must not be reported: {out:?}"
    );
}

#[test]
fn the_matrix_reader_takes_the_package_half_of_a_feature_cell_and_the_whole_tests_cell() {
    let mut out = Vec::new();
    scan_matrix(
        "ci.yml",
        "  tests:\n\
         \x20           features: busbar-kernel/timing,busbar-llm/timing\n\
         \x20           tests: -p busbar-kernel -p busbar-llm\n\
         \x20           features: plane-a2a\n\
         \x20           features: \"\"\n",
        &mut out,
    );
    assert_eq!(
        out.iter().map(|s| s.pkg.as_str()).collect::<Vec<_>>(),
        vec!["busbar-kernel", "busbar-llm", "busbar-kernel", "busbar-llm"],
        "a bare feature name names no package, and an empty job key is not a cell: {out:?}"
    );
}

#[test]
fn only_a_rust_literal_that_begins_with_cargo_is_a_command() {
    let mut out = Vec::new();
    let prose = "the alloc gate. (It read '-p busbar-core' here for as long as ci.yml did.)";
    let line = format!("    (\"cargo test -p busbar-plane-llm --lib alloc_gate\", \"{prose}\"),");
    scan_rust_commands("full_gate.rs", &line, &mut out);
    assert_eq!(
        out.iter().map(|s| s.pkg.as_str()).collect::<Vec<_>>(),
        vec!["busbar-plane-llm"],
        "prose that quotes a dead selector is not a command: {out:?}"
    );
    // ...and a doc comment is not scanned at all. THE PACKAGE HERE IS A LIVE ONE ON PURPOSE:
    // this file is itself a covered file, the literal below really does begin with `cargo `
    // once the escapes are read, and a dead name planted in it would red this gate against its
    // own source. The assertion is `is_empty`, so it proves the doc-line skip either way.
    let mut none = Vec::new();
    scan_rust_commands("m.rs", "//! \"cargo test -p busbar-kernel\"", &mut none);
    assert!(none.is_empty(), "{none:?}");
}

#[test]
fn a_declaration_parses_into_its_three_fields_in_either_comment_spelling() {
    let d = parse_decl(&format!("{DECL_HASH} pkg{SEP}scripts/x.sh{SEP}a reason"))
        .expect("hash form parses");
    assert_eq!((d.pkg.as_str(), d.file.as_str()), ("pkg", "scripts/x.sh"));
    assert_eq!(d.reason, "a reason");
    assert!(parse_decl(&format!("{DECL_SLASH} pkg{SEP}f{SEP}r")).is_some());
    // The module header prints the template; it must not declare anything.
    assert!(parse_decl(&format!("//! {DECL_HASH} pkg{SEP}f{SEP}r")).is_none());
    assert!(parse_decl(&format!("/// {DECL_SLASH} pkg{SEP}f{SEP}r")).is_none());
}

#[test]
fn a_port_number_is_not_a_package_and_a_variable_is_not_a_package() {
    assert_eq!(
        package_token("busbar-kernel").as_deref(),
        Some("busbar-kernel")
    );
    assert_eq!(package_token("busbar)\"").as_deref(), Some("busbar"));
    assert_eq!(package_token("\"$BIN_NAME\""), None);
    assert_eq!(package_token("${{"), None);
    assert_eq!(package_token("busbar-store-<backend>"), None);
    assert_eq!(package_token("22"), None);
    assert_eq!(package_token("8080:8080"), None);
}

#[test]
fn the_reader_is_picked_by_the_files_own_shape_and_only_markdown_is_unread() {
    assert_eq!(reader_for("xtask/src/gates/x.rs"), Reader::Rust);
    assert_eq!(reader_for(".github/workflows/plugin-ci.yml"), Reader::Yaml);
    assert_eq!(reader_for(".github/actions/a/action.yaml"), Reader::Yaml);
    assert_eq!(reader_for("qa/pipeline-checks.json"), Reader::Json);
    assert_eq!(reader_for("qa/DESIGN-BINDINGS.md"), Reader::Prose);
    for commands in [
        "scripts/x.sh",
        "scripts/x.py",
        "scripts/x.mjs",
        "qa/construction.toml",
        "scripts/sub/Makefile",
        "scripts/release-gate/run",
        ".github/release-notify-targets.txt",
    ] {
        assert_eq!(reader_for(commands), Reader::Commands, "{commands}");
    }
}

#[test]
fn a_python_argv_list_is_a_cargo_command_and_a_js_comment_is_not() {
    let mut out = Vec::new();
    scan_commands(
        "x.py",
        "    base = [\"cargo\", \"test\", \"-p\", \"busbar\", \"--features\", F]\n\
         // cargo build -p busbar-kernel\n",
        &mut out,
    );
    assert_eq!(
        out.iter().map(|s| s.pkg.as_str()).collect::<Vec<_>>(),
        vec!["busbar"],
        "{out:?}"
    );
}

#[test]
fn a_json_run_value_is_a_command_and_a_json_prose_field_is_not() {
    let mut out = Vec::new();
    scan_json_commands(
        "qa/x.json",
        "{\n  \"run\": \"m=$(cargo metadata --locked); cargo build -p busbar-kernel\",\n\
         \x20 \"summary\": \"it ran `cargo test -p busbar-plane-llm --lib x` and found nothing\",\n\
         \x20 \"positive_control\": \"cargo test -p busbar-plane-llm usage (run in the pin)\"\n}\n",
        &mut out,
    );
    assert_eq!(
        out.iter()
            .map(|s| (s.pkg.as_str(), s.line))
            .collect::<Vec<_>>(),
        vec![("busbar-kernel", 2)],
        "a prose field that opens with a command is the record of a run, not a run: {out:?}"
    );
}

/// AN EXEMPTION IS SCOPED TO ITS OWN FILE: the declared file stays green and the other file
/// carrying the same dead selector is RED, cited by its own path and line.
#[test]
fn a_declaration_excuses_the_dead_selector_only_in_the_file_it_names() {
    let ((a, a_text), (b, b_text)) = plant_pair(&cx()).expect("two covered scripts");
    let declared_in_a = format!(
        "{a_text}\ncargo build --locked -p {PLANTED_SCOPED}\n\
         {DECL_HASH} {PLANTED_SCOPED}{SEP}{a}{SEP}{PLANTED_REASON}\n"
    );

    let mut only_a = Overlay::new();
    only_a.set(&a, declared_in_a.clone());
    assert!(
        failed_ids(only_a).is_empty(),
        "the declared site in its own file must stay green"
    );

    let mut both = Overlay::new();
    both.set(&a, declared_in_a);
    both.set(
        &b,
        format!("{b_text}\ncargo build --locked -p {PLANTED_SCOPED}\n"),
    );
    let planted = cx().with_overlay(both);
    let verdict = crate::gates::execute(&PackageSelectorsGate, &planted);
    let red: Vec<_> = verdict
        .rows
        .iter()
        .filter(|r| r.status != crate::ledger::Status::Pass)
        .collect();
    assert_eq!(
        red.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        vec![ROW_RESOLVES]
    );
    assert!(
        red[0].detail.contains(&format!("{b}:")),
        "{}",
        red[0].detail
    );
    assert!(
        !red[0].detail.contains(&format!("{a}:")),
        "{}",
        red[0].detail
    );
}

/// The ids that went non-PASS under one planted overlay.
fn failed_ids(ov: Overlay) -> Vec<String> {
    let planted = cx().with_overlay(ov);
    crate::gates::execute(&PackageSelectorsGate, &planted)
        .rows
        .iter()
        .filter(|r| r.status != crate::ledger::Status::Pass)
        .map(|r| r.id.clone())
        .collect()
}

/// EVERY PLANT MUST REDDEN ITS OWN ROW AND NOTHING ELSE — except the root-manifest plant, whose
/// whole point is that everything below it is unproven. A rule proven only alongside its
/// neighbours is a rule that could be deleted with the self-test still green.
#[test]
fn each_plant_reddens_exactly_its_own_row() {
    for p in plants(&cx()) {
        if p.rule == ROW_UNIVERSE {
            continue;
        }
        let ov = p
            .overlay
            .unwrap_or_else(|| panic!("nothing to plant: {}", p.label));
        assert_eq!(
            failed_ids(ov),
            vec![p.rule.to_string()],
            "plant `{}` did not redden exactly `{}`",
            p.label,
            p.rule
        );
    }
}

#[test]
fn the_gate_is_green_on_the_workspace() {
    let verdict = crate::gates::execute(&PackageSelectorsGate, &cx());
    assert!(
        !verdict.red,
        "package-selectors is RED on the real tree: {:?}",
        verdict
            .rows
            .iter()
            .filter(|r| r.status != crate::ledger::Status::Pass)
            .map(|r| format!("{} {}", r.id, r.detail))
            .collect::<Vec<_>>()
    );
}

#[test]
fn the_selftest_proves_every_owed_row() {
    let cx = cx();
    let report = PackageSelectorsGate.selftest(&cx);
    crate::gates::verify_report(&PackageSelectorsGate, &report)
        .unwrap_or_else(|errs| panic!("package-selectors selftest: {errs:#?}"));
    assert_eq!(report.skipped(), 0, "a case had nothing to plant");
}

#[test]
fn a_rust_argv_array_is_read_only_when_it_is_a_cargo_command() {
    let src = "fn f() {\n\
        let a = [\n\
            \"cargo\",\n\
            \"build\",\n\
            \"-p\",\n\
            \"busbar-gone\",\n\
        ];\n\
        let b = vec![\"docker\", \"compose\", \"-p\", \"busbar-oidf\"];\n\
        let c = [\"-o\", \"stat=\", \"-p\", pid];\n\
        // [\"cargo\", \"-p\", \"in-a-comment\"]\n\
        let d = \"[\\\"cargo\\\", \\\"-p\\\", \\\"in-a-string\\\"]\";\n\
    }\n\
    fn g() {\n\
        let mut cmd = Command::new(&cargo);\n\
        cmd.args([\n\
            \"bench\",\n\
            \"--package\",\n\
            \"busbar-kernel\",\n\
        ]);\n\
    }\n";
    let mut out = Vec::new();
    scan_rust_argv("x.rs", src, &mut out);
    let got: Vec<(&str, usize)> = out.iter().map(|s| (s.pkg.as_str(), s.line)).collect();
    assert_eq!(
        got,
        vec![("busbar-gone", 5), ("busbar-kernel", 17)],
        "{out:?}"
    );
}

#[test]
fn the_ci_bin_and_hook_roots_are_covered() {
    for root in [".ci", "bin", ".githooks"] {
        assert!(ROOTS.contains(&root), "{root} is not a covered root");
    }
    assert_eq!(reader_for(".ci/dev.yaml"), Reader::Yaml);
    assert_eq!(reader_for("bin/oracle"), Reader::Commands);
    assert_eq!(reader_for(".githooks/pre-push"), Reader::Commands);
}
