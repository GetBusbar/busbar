// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::{Path, PathBuf};

use super::{
    answer, busbar_version, fence_filter_from, line_builds_from, premise_closure, py_num_list,
    py_oserror, py_repr, py_str_list, shard_filter, shard_slice, Answer,
};
use crate::repo_root;

/// A scratch directory under the system temp dir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "busbar-ci-checks-oracle-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch dir is created");
        Self(dir)
    }

    fn write(&self, rel: &str, text: &str) -> PathBuf {
        let path = self.0.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("the parent dir is created");
        }
        std::fs::write(&path, text).expect("the fixture is written");
        path
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn arg(&self, rel: &str) -> String {
        self.0.join(rel).to_string_lossy().into_owned()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> Answer {
    let args: Vec<String> = args.iter().map(|arg| String::from(*arg)).collect();
    answer(&args)
}

/// The five-cell corpus shard-selftest uses, with no accepted difference.
fn five_cells(name: &str) -> Scratch {
    let scratch = Scratch::new(name);
    scratch.write(
        "cells.json",
        r#"{"cells":[{"id":"a|1"},{"id":"a|2"},{"id":"b|1"},{"id":"b|2"},{"id":"c|1"}]}"#,
    );
    scratch.write("accepted-differences.json", r#"{"accepted":[]}"#);
    scratch
}

/// The corpus premise-selftest uses: one forgiven cell whose premise probes another cell.
fn premise_corpus(name: &str, premise_cell: &str) -> Scratch {
    let scratch = Scratch::new(name);
    scratch.write(
        "cells.json",
        r#"{"cells": [{"id": "fam|forgiven"}, {"id": "fam|other"}, {"id": "probe|premise"}]}"#,
    );
    scratch.write(
        "accepted-differences.json",
        &format!(
            r#"{{"accepted": [{{"id": "PLANT", "cells": "^fam\\|forgiven$", "premise": {{"all": [{{"cell": "{premise_cell}", "status": 200}}]}}}}]}}"#
        ),
    );
    scratch
}

#[test]
fn names_print_as_the_shim_always_printed_them() {
    assert_eq!(py_repr("a|1"), "'a|1'");
    assert_eq!(py_repr(r"^fam\|x$"), r"'^fam\\|x$'");
    assert_eq!(py_repr("it's"), r#""it's""#);
    assert_eq!(py_repr("it's \"q\""), r#"'it\'s "q"'"#);
    assert_eq!(py_repr("a\nb\x01"), r"'a\nb\x01'");
    assert_eq!(py_str_list(&["a", "b"]), "['a', 'b']");
    assert_eq!(py_str_list::<&str>(&[]), "[]");
    assert_eq!(py_num_list(&[1, 2]), "[1, 2]");
    let missing = std::io::Error::from_raw_os_error(2);
    assert_eq!(
        py_oserror("r/selected-ids.txt", &missing),
        format!(
            "[Errno 2] {}: 'r/selected-ids.txt'",
            missing
                .to_string()
                .split(" (os error ")
                .next()
                .unwrap_or_default()
        )
    );
}

#[test]
fn shards_split_the_sorted_ids_round_robin() {
    let ids: Vec<String> = ["a|1", "a|2", "b|1", "b|2", "c|1"]
        .iter()
        .map(|id| String::from(*id))
        .collect();
    assert_eq!(shard_slice(&ids, 1, 2), ["a|1", "b|1", "c|1"]);
    assert_eq!(shard_slice(&ids, 2, 2), ["a|2", "b|2"]);
    assert_eq!(shard_filter(&shard_slice(&ids, 2, 2)), r"^(?:a\|2|b\|2)$");
    assert_eq!(shard_filter(&[]), "^(?:)$");
}

#[test]
fn shard_ids_and_filters_answer_one_shard_and_refuse_a_shard_outside_1_to_n() {
    let corpus = five_cells("ids");
    let data = corpus.arg("");
    let ids = run(&["shard-ids", &data, "1", "2"]);
    assert_eq!((ids.code, ids.stdout.as_str()), (0, "a|1\nb|1\nc|1\n"));
    let filter = run(&["shard-filter", &data, "2", "2"]);
    assert_eq!(
        (filter.code, filter.stdout.as_str()),
        (0, "^(?:a\\|2|b\\|2)$\n")
    );
    for (k, n) in [("3", "2"), ("0", "2"), ("1", "0"), ("x", "2")] {
        let refused = run(&["shard-filter", &data, k, n]);
        assert_eq!(refused.code, 1, "shard {k} of {n} answered");
        assert!(refused.stdout.is_empty());
        assert!(refused.stderr.contains("is not a shard (1 <= k <= n)"));
    }
}

#[test]
fn shard_cover_proves_every_split_and_refuses_a_corpus_that_repeats_an_id() {
    let corpus = five_cells("cover");
    let data = corpus.arg("");
    let two = run(&["shard-cover", &data, "2"]);
    assert_eq!(two.code, 0, "{}", two.stderr);
    assert_eq!(
        two.stdout,
        "oracle shard-cover: 2 shards select all 5 cells of cells.json, each exactly once\n"
    );
    for n in ["1", "3", "5", "7"] {
        assert_eq!(run(&["shard-cover", &data, n]).code, 0, "{n} shards");
    }
    assert_eq!(run(&["shard-cover", &data, "0"]).code, 3);
    corpus.write(
        "cells.json",
        r#"{"cells":[{"id":"a|1"},{"id":"a|2"},{"id":"a|1"}]}"#,
    );
    let dup = run(&["shard-cover", &data, "2"]);
    assert_eq!(dup.code, 3);
    assert!(
        dup.stderr.contains("'a|1' is selected by shard(s) [1, 2]"),
        "{}",
        dup.stderr
    );
    assert!(
        dup.stderr.contains("cells.json repeats an id"),
        "{}",
        dup.stderr
    );
}

/// The real tree: four shards cover the corpus exactly once.
#[test]
fn four_shards_cover_the_real_corpus_exactly_once() {
    let data = repo_root().join("testing/shadow-oracle");
    let cover = run(&["shard-cover", &data.to_string_lossy(), "4"]);
    assert_eq!(cover.code, 0, "{}", cover.stderr);
}

#[test]
fn shard_verify_refuses_a_shard_that_judged_less_than_it_owns() {
    let corpus = five_cells("verify");
    let data = corpus.arg("");
    let report = corpus.arg("rep");
    std::fs::create_dir_all(&report).expect("the report dir is created");
    let none = run(&["shard-verify", &data, "1", "2", &report]);
    assert_eq!(none.code, 3);
    assert!(
        none.stderr.contains("wrote no selected-ids.txt ([Errno 2]"),
        "{}",
        none.stderr
    );
    corpus.write("rep/selected-ids.txt", "a|1\nb|1\n");
    let short = run(&["shard-verify", &data, "1", "2", &report]);
    assert_eq!(short.code, 3);
    assert_eq!(
        short.stderr,
        "oracle shard-verify: shard 1/2 did not select 1 of its 3 cells: ['c|1']. Refusing.\n"
    );
    corpus.write("rep/selected-ids.txt", "a|1\nb|1\nc|1\nb|2\n");
    let full = run(&["shard-verify", &data, "1", "2", &report]);
    assert_eq!(full.code, 0, "{}", full.stderr);
    assert_eq!(
        full.stdout,
        "oracle shard-verify: shard 1/2 selected all 3 cells it owns\n"
    );
}

#[test]
fn shard_merge_is_green_only_for_every_shard_once_each_green() {
    let corpus = five_cells("merge");
    let data = corpus.arg("");
    corpus.write("m1/selected-ids.txt", "a|1\nb|1\nc|1\n");
    corpus.write("m1/shard.tsv", "1\t2\t0\n");
    corpus.write("m2/selected-ids.txt", "a|2\nb|2\n");
    corpus.write("m2/shard.tsv", "2\t2\t0\n");
    let (m1, m2) = (corpus.arg("m1"), corpus.arg("m2"));
    let green = run(&["shard-merge", &data, &m1, &m2]);
    assert_eq!(green.code, 0, "{}", green.stderr);
    assert_eq!(
        green.stdout,
        "oracle shard-merge: GREEN: 2 shards, each green, together judged all 5 cells\n"
    );
    let one = run(&["shard-merge", &data, &m1]);
    assert_eq!(one.code, 1);
    assert!(
        one.stderr.contains("no report for shard(s) 2 of 2"),
        "{}",
        one.stderr
    );
    assert!(
        one.stderr
            .contains("2 cell(s) no shard judged: ['a|2', 'b|2']"),
        "{}",
        one.stderr
    );
    let twice = run(&["shard-merge", &data, &m1, &m1]);
    assert_eq!(twice.code, 1);
    assert!(
        twice.stderr.contains("shard 1 reported twice"),
        "{}",
        twice.stderr
    );
    corpus.write("m2/shard.tsv", "2\t2\t1\n");
    let red = run(&["shard-merge", &data, &m1, &m2]);
    assert_eq!(red.code, 1);
    assert!(
        red.stderr.contains("shard 2/2 was red (exit 1)"),
        "{}",
        red.stderr
    );
    corpus.write("m2/shard.tsv", "2\n");
    let short = run(&["shard-merge", &data, &m1, &m2]);
    assert!(
        short
            .stderr
            .contains("no shard verdict (not enough values to unpack (expected 3, got 1))"),
        "{}",
        short.stderr
    );
    assert_eq!(run(&["shard-merge", &data]).code, 2);
}

#[test]
fn a_filter_is_widened_to_the_premise_cells_its_forgivenesses_probe() {
    let corpus = premise_corpus("widen", "probe|premise");
    let data = corpus.arg("");
    let widened = run(&["widen-filter", &data, r"^fam\|forgiven$"]);
    assert_eq!(widened.code, 0, "{}", widened.stderr);
    assert_eq!(
        widened.stdout,
        "(?:^fam\\|forgiven$)|^(?:probe\\|premise)$\n"
    );
    assert!(
        widened.stderr.contains("probe: probe|premise"),
        "{}",
        widened.stderr
    );
    let got = widened.stdout.trim_end();
    assert_eq!(
        run(&["regex-search", got, "probe|premise", "fam|forgiven"]).code,
        0
    );
    assert_eq!(run(&["regex-search", got, "fam|other"]).code, 1);
    let left = run(&["widen-filter", &data, r"^fam\|other$"]);
    assert_eq!((left.code, left.stdout.as_str()), (0, "^fam\\|other$\n"));
    assert!(left.stderr.is_empty());
    assert_eq!(run(&["widen-filter", &data, "("]).code, 3);
}

#[test]
fn a_premise_naming_a_cell_the_corpus_lacks_is_refused_by_name() {
    let corpus = premise_corpus("gone", "probe|gone");
    let refused = run(&["widen-filter", &corpus.arg(""), r"^fam\|forgiven$"]);
    assert_eq!(refused.code, 3);
    assert_eq!(
        refused.stderr,
        "oracle: a filtered run cannot evaluate a forgiveness it selects:\n  'PLANT' probes premise \
         cell 'probe|gone', which cells.json does not have\n"
    );
    assert!(premise_closure(corpus.path(), r"^fam\|other$").is_ok());
}

#[test]
fn a_withheld_forgiveness_the_filter_selected_refuses_the_replay() {
    let corpus = premise_corpus("withheld", "probe|premise");
    let data = corpus.arg("");
    let log = corpus.write(
        "out",
        "accepted-differences: entry 'PLANT' is WITHHELD \u{2014} premise UNEVALUABLE: premise probes \
         cell \"probe|premise\", which the build under test did not record\n",
    );
    let log = log.to_string_lossy();
    let refused = run(&["withheld", &data, &log, r"^fam\|forgiven$"]);
    assert_eq!(refused.code, 3);
    assert!(
        refused
            .stderr
            .contains("'PLANT' (premise cell 'probe|premise')"),
        "{}",
        refused.stderr
    );
    assert!(refused.stderr.ends_with("and replay again.\n"));
    assert_eq!(
        run(&["withheld", &data, &log, r"^fam\|other$"]),
        Answer::default()
    );
}

#[test]
fn a_line_builds_from_source_only_when_no_row_of_it_is_released() {
    let src = format!("src:{}", "a".repeat(40));
    let built = format!("p\t{src}\tbuild:busbar-store-x\tsha\t1.6\n");
    let released = "p\tv1.0.6\tbusbar-store-x-1.0.6.tar.gz\tsha\t1.6\n";
    assert!(line_builds_from(&built, "1.6"));
    assert!(!line_builds_from(&built, "1.5"));
    assert!(!line_builds_from(&format!("{built}{released}"), "1.6"));
    assert!(!line_builds_from(&format!("# {built}"), "1.6"));
    // No fifth column: the row is the 1.5 line's.
    assert!(line_builds_from(
        &format!("p\t{src}\tbuild:x\tsha\n"),
        "1.5"
    ));
    assert!(!line_builds_from("p\tsrc:abc\tbuild:x\tsha\t1.6\n", "1.6"));
    assert!(!line_builds_from("", "1.6"));
}

#[test]
fn the_busbar_version_is_the_one_package_with_a_busbar_bin() {
    let one = r#"{"packages":[
        {"version":"1.6.0","targets":[{"name":"busbar","kind":["bin"]}]},
        {"version":"9.9.9","targets":[{"name":"busbar","kind":["lib"]}]}]}"#;
    let answered = busbar_version(one);
    assert_eq!((answered.code, answered.stdout.as_str()), (0, "1.6.0\n"));
    let none = busbar_version(r#"{"packages":[]}"#);
    assert_eq!(none.code, 1);
    assert_eq!(none.stderr, "no package builds the busbar binary\n");
}

#[test]
fn a_fence_filter_names_exactly_its_ledger_ids() {
    assert_eq!(
        fence_filter_from("a2a|fence|x\tdigest\n\nmcp|y.z\tother\n  \n"),
        r"^(a2a\|fence\|x|mcp\|y\.z)$"
    );
}

#[test]
fn a_replay_that_compared_no_owed_cell_is_refused() {
    let scratch = Scratch::new("owed");
    let zero = scratch.write("z/report.json", r#"{"totals": {"owed": 0}}"#);
    let some = scratch.write("s/report.json", r#"{"totals": {"owed": 3}}"#);
    let refused = run(&["report-owed", &zero.to_string_lossy()]);
    assert_eq!(refused.code, 1);
    assert!(
        refused.stderr.contains("ZERO owed cells"),
        "{}",
        refused.stderr
    );
    assert_eq!(
        run(&["report-owed", &some.to_string_lossy()]),
        Answer::default()
    );
    let missing = run(&["report-owed", &scratch.arg("none/report.json")]);
    assert_eq!(missing.code, 1);
    assert!(
        missing.stderr.contains("nothing was judged"),
        "{}",
        missing.stderr
    );
    let keyless = scratch.write("k/report.json", "{}");
    let keyless = run(&["report-owed", &keyless.to_string_lossy()]);
    assert!(
        keyless.stderr.contains(": 'totals'); nothing was judged"),
        "{}",
        keyless.stderr
    );
}

#[test]
fn rebaselined_families_and_store_cells_are_read_from_the_corpus() {
    let scratch = Scratch::new("families");
    scratch.write(
        "cells.json",
        r#"{"cells":[
            {"id":"streams|a","family":"streams"},
            {"id":"core|b","plane":"core"},
            {"id":"store|pg","family":"store","needs_fixture":"BUSBAR_TEST_POSTGRES_URL"},
            {"id":"store|mem","family":"store","needs_fixture":true}]}"#,
    );
    let data = scratch.arg("");
    assert_eq!(
        run(&["only-rebaselined", &data, "^streams", "streams "]).code,
        0
    );
    assert_eq!(
        run(&["only-rebaselined", &data, "a$|b$", "streams"]).code,
        1
    );
    assert_eq!(run(&["only-rebaselined", &data, "^core", "core"]).code, 0);
    assert_eq!(
        run(&["only-rebaselined", &data, "^none", "streams"]).code,
        1
    );
    assert_eq!(
        run(&["family-selected", &data, "^streams", "streams"]).code,
        0
    );
    assert_eq!(run(&["family-selected", &data, "^core", "core"]).code, 1);
    assert_eq!(run(&["needs-store", &data, ""]).stdout, "yes\n");
    assert_eq!(run(&["needs-store", &data, "^streams"]).stdout, "no\n");
    assert_eq!(run(&["needs-store", &data, "pg$"]).stdout, "yes\n");
    assert_eq!(run(&["needs-store", &data, "mem$"]).stdout, "no\n");
}

#[test]
fn an_unknown_subcommand_or_a_bad_regex_is_refused() {
    assert_eq!(run(&["no-such"]).code, 2);
    assert_eq!(run(&["regex-search", "(", "x"]).code, 2);
}

#[test]
fn the_json_tree_reads_through_the_facade_and_keeps_the_last_duplicate() {
    use super::Node;
    let tree = Node::parse(r#"{"a": 1.50, "b": [true, null, "x"], "a": 0}"#).expect("parses");
    assert_eq!(tree.get("a"), Some(&Node::Number(String::from("0"))));
    assert_eq!(
        tree.get("b").and_then(Node::as_array).map(Vec::len),
        Some(3)
    );
    // One member per name, the last duplicate kept; the member order is the tree's own.
    let text = tree.to_string();
    assert_eq!(text.matches("\"a\":").count(), 1, "{text}");
    assert!(
        text.contains(r#""a":0"#) && text.contains(r#""b":[true,null,"x"]"#),
        "{text}"
    );
    assert!(Node::parse("{").is_err());
}

#[test]
fn the_launcher_helpers_read_what_the_shell_read() {
    use crate::oracle_judge::{base64_decode, base64_encode, pin_in};
    for sample in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
        assert_eq!(
            base64_decode(&base64_encode(sample)).as_deref(),
            Some(sample)
        );
    }
    assert_eq!(base64_encode(b"fo"), "Zm8=");
    assert_eq!(base64_decode("Zm9v\nYmFy").as_deref(), Some(&b"foobar"[..]));
    assert_eq!(pin_in("release_ref=abc\nsha=1=2\n", "sha"), "1=2");
    assert_eq!(pin_in("release_ref=abc\n", "sha"), "");
}
