//! Q128 arch u93: a closed finding's `closed_by` is CHECKED against the repository, never taken on
//! the record's word. These plants run the real `cargo xtask q128 audit` entry over a scratch git
//! repository: the auditor reads candidate C, and the record is committed on top of C, so the
//! judged tree differs from C's in the record alone.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const CODE: &str = "crates/x/src/lib.rs";

struct Scratch {
    root: PathBuf,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Scratch {
    fn new(name: &str) -> Scratch {
        let root =
            std::env::temp_dir().join(format!("xtask-q128-closure-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("the scratch repository directory is creatable");
        let s = Scratch { root };
        let hooks = s.root.join(".nohooks");
        std::fs::create_dir_all(&hooks).expect("the empty hooks directory is creatable");
        for args in [
            vec!["init", "-q"],
            vec!["config", "user.email", "q128@selftest"],
            vec!["config", "user.name", "q128"],
            vec!["config", "commit.gpgsign", "false"],
            vec![
                "config",
                "core.hooksPath",
                hooks.to_str().expect("utf-8 path"),
            ],
        ] {
            s.git(&args);
        }
        s
    }

    fn git(&self, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(args)
            .output()
            .expect("git runs");
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn write(&self, rel: &str, text: &str) {
        let p = self.root.join(rel);
        std::fs::create_dir_all(p.parent().expect("a parent")).expect("dirs");
        std::fs::write(p, text).expect("write");
    }

    /// Write `rel`, commit it, and return the new commit's id.
    fn commit(&self, rel: &str, text: &str, msg: &str) -> String {
        self.write(rel, text);
        self.git(&["add", "--", rel]);
        self.git(&["commit", "-q", "-m", msg]);
        self.git(&["rev-parse", "HEAD"])
    }

    /// Run `q128 audit` on the scratch tree; every finding of the result file.
    fn audit(&self) -> Vec<Value> {
        let out = self.root.join(".q128-result.json");
        let _ = crate::q128::main(
            &self.root,
            &[
                "audit".to_string(),
                "--out".to_string(),
                out.to_string_lossy().into_owned(),
            ],
        );
        let text = std::fs::read_to_string(&out).expect("the result is written");
        let v: Value = serde_json::from_str(&text).expect("the result is JSON");
        v["findings"].as_array().cloned().unwrap_or_default()
    }
}

fn record(candidate: &str, findings: &str) -> String {
    format!(r#"{{"candidate": "{candidate}", "auditor": "fresh-auditor", "findings": {findings}}}"#)
}

fn block(id: &str, status: &str, closed_by: Option<&str>) -> String {
    let by = closed_by.map_or(String::new(), |b| format!(r#","closed_by":"{b}""#));
    format!(
        r#"[{{"id":"{id}","severity":"BLOCK","status":"{status}"{by},"scope":"crates/x/src","evidence":"{CODE}:1","cite":"Law 0"}}]"#
    )
}

/// Every BLOCK whose title or evidence mentions `needle`.
fn blocks_naming(fs: &[Value], needle: &str) -> Vec<String> {
    fs.iter()
        .filter(|f| f["severity"] == "BLOCK" && f["status"] == "open")
        .map(|f| format!("{} :: {}", f["title"], f["evidence"]))
        .filter(|s| s.contains(needle))
        .collect()
}

fn root_of(s: &Scratch) -> &Path {
    &s.root
}

/// THE PLANT: a closed BLOCK whose `closed_by` names no change at all. Before u93 any non-empty
/// string closed it.
#[test]
fn a_bogus_closed_by_is_a_block() {
    let s = Scratch::new("bogus");
    let c = s.commit(CODE, "pub fn f() {}\n", "the candidate");
    s.commit(
        crate::q128::RECORD_REL,
        &record(&c, &block("A1", "closed", Some("anything"))),
        "the audit record",
    );
    let fs = s.audit();
    let hits = blocks_naming(&fs, "closed_by");
    assert!(!hits.is_empty(), "{fs:#?} ({})", root_of(&s).display());
}

/// A `closed_by` naming a real commit that the candidate does not contain (a side line) names no
/// change in the code that was read.
#[test]
fn a_closed_by_outside_the_audited_history_is_a_block() {
    let s = Scratch::new("side");
    let base = s.commit(CODE, "pub fn f() {}\n", "base");
    s.git(&["checkout", "-q", "-b", "side"]);
    let side = s.commit("crates/x/src/side.rs", "pub fn g() {}\n", "a side change");
    s.git(&["checkout", "-q", "-"]);
    let c = s.git(&["rev-parse", "HEAD"]);
    assert_eq!(c, base);
    s.commit(
        crate::q128::RECORD_REL,
        &record(&c, &block("A1", "closed", Some(&side))),
        "the audit record",
    );
    let fs = s.audit();
    let hits = blocks_naming(&fs, &side);
    assert!(!hits.is_empty(), "{fs:#?}");
}

/// A record-only edit cannot close a BLOCK the record already carried open on the same candidate,
/// even naming a real commit the candidate contains: the code is byte-identical to the tree the
/// BLOCK was found in.
#[test]
fn a_record_only_edit_cannot_close_an_open_block_of_this_candidate() {
    let s = Scratch::new("flip");
    let c = s.commit(CODE, "pub fn f() {}\n", "the candidate");
    s.commit(
        crate::q128::RECORD_REL,
        &record(&c, &block("A1", "open", None)),
        "the audit record: one open BLOCK",
    );
    s.commit(
        crate::q128::RECORD_REL,
        &record(&c, &block("A1", "closed", Some(&c))),
        "the record alone says it is closed",
    );
    let fs = s.audit();
    let hits = blocks_naming(&fs, "`A1`");
    assert!(!hits.is_empty(), "{fs:#?}");
}
