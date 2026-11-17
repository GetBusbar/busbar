// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The command line: the three exit codes, the advisory mode, and the usage and read errors.

use crate::run;

const OLD: &str =
    r#"{"paths":{"/a":{"get":{"operationId":"GetA","responses":{"200":{"description":"ok"}}}}}}"#;
const ADDITIVE: &str = r#"{"paths":{"/a":{"get":{"operationId":"GetA","responses":{"200":{"description":"ok"},"429":{"description":"slow"}}}},"/b":{"get":{"operationId":"GetB","responses":{"200":{"description":"ok"}}}}}}"#;
const BREAKING: &str = r#"{"paths":{}}"#;

struct Files(std::path::PathBuf);

impl Files {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("openapi-diff-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn write(&self, name: &str, text: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, text).unwrap();
        path.display().to_string()
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn words(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

#[test]
fn an_additive_head_exits_zero() {
    let files = Files::new("additive");
    let (base, head) = (
        files.write("base.json", OLD),
        files.write("head.json", ADDITIVE),
    );
    let (code, lines) = run(&words(&["--base", &base, "--head", &head]));
    assert_eq!((code, lines), (0, Vec::new()));
}

#[test]
fn a_breaking_head_exits_one_with_its_findings() {
    let files = Files::new("breaking");
    let (base, head) = (
        files.write("base.json", OLD),
        files.write("head.json", BREAKING),
    );
    let (code, lines) = run(&words(&["--base", &base, "--head", &head]));
    assert_eq!(code, 1);
    assert!(
        lines
            .iter()
            .any(|line| line.contains("/a") && line.contains("removed")),
        "{lines:?}"
    );
}

#[test]
fn advisory_turns_breaking_into_exit_three_and_leaves_additive_at_zero() {
    let files = Files::new("advisory");
    let (base, head, good) = (
        files.write("base.json", OLD),
        files.write("head.json", BREAKING),
        files.write("good.json", ADDITIVE),
    );
    let (code, lines) = run(&words(&["--base", &base, "--head", &head, "--advisory"]));
    assert_eq!(code, 3);
    assert!(!lines.is_empty());
    assert_eq!(
        run(&words(&["--advisory", "--base", &base, "--head", &good])).0,
        0
    );
}

#[test]
fn usage_and_read_errors_exit_two() {
    let files = Files::new("errors");
    let base = files.write("base.json", OLD);
    assert_eq!(run(&words(&[])).0, 2, "no arguments");
    assert_eq!(run(&words(&["--base", &base])).0, 2, "no head");
    assert_eq!(
        run(&words(&["--base", &base, "--head", &base, "--nope"])).0,
        2,
        "unknown word"
    );
    assert_eq!(
        run(&words(&[
            "--base",
            &base,
            "--head",
            "/nonexistent/openapi.json"
        ]))
        .0,
        2
    );
    let junk = files.write("junk.json", "not json");
    assert_eq!(
        run(&words(&["--base", &base, "--head", &junk])).0,
        2,
        "unparseable"
    );
}
