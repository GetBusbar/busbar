//! THE PLANE DOES NOT NAME A DIALECT IT CARVED OUT — asserted on the source, not promised in a
//! comment.
//!
//! ## Why this needs a test at all
//!
//! The split moves a vendor's vocabulary out of this crate, and the thing that would quietly undo it
//! is not a bad decision — it is a convenience. A helper that needs to know whether a request is
//! "the openai one", a special case for a spelling only one vendor uses, a default that happens to
//! be one vendor's: each is one line, each compiles, and each puts the branch back that the kind
//! exists to remove. Nothing else in the tree fails when that line lands, because the behaviour is
//! unchanged; what changes is that the plane is no longer neutral, and the eighth dialect is a patch
//! to this crate again.
//!
//! So the assertion is textual and it is over the SHIPPED source: no carved-out dialect's key
//! appears as a string in `src/`, in any position.
//!
//! ## What it deliberately allows
//!
//! A COMMENT MAY NAME THE CRATE THAT TOOK THE ROW. The gaps at rung 7 and rung 14 are the two spots
//! a reader is most likely to think they have found a bug, and the comment that says where the rung
//! went is the difference between a documented split and a hole. Naming the crate is not naming the
//! dialect: `busbar-plane-llm-openai` is a Cargo package this crate does not depend on and cannot
//! name in code, while `"openai"` is a key this crate would be resolving against.
//!
//! ## What it does not cover, said out loud
//!
//! The five dialects that have not been carved out yet are still declared here, so their keys are
//! still in this source and this test says nothing about them. Each leaves on its own line, and the
//! list below is what grows as each one does — a dialect that moved crates and left its key behind
//! is exactly the case this file is for.

use std::fs;
use std::path::Path;

/// The dialects that have left this crate, by key.
///
/// ONE ROW PER CARVED-OUT DIALECT. The row is added in the same commit that removes the dialect's
/// declarations, so there is no window in which a key is gone from the tables and unguarded here.
const CARVED_OUT: &[&str] = &["openai"];

/// Every shipped `.rs` file of this crate, as (path, text).
fn shipped_source() -> Vec<(String, String)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).expect("the crate has a src directory");
        for entry in entries {
            let path = entry.expect("a readable directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = fs::read_to_string(&path).expect("a readable source file");
                out.push((path.display().to_string(), text));
            }
        }
    }
    assert!(!out.is_empty(), "no shipped source was read");
    out
}

/// A line with its comment removed, so a comment may say what the code may not.
///
/// Crude on purpose: it cuts at the first `//`, which over-trims a line whose string literal
/// contains those two characters. Over-trimming can only make this test MISS something, never
/// invent one — and the alternative, a real lexer in a test, is a second parser to keep correct.
/// The one shape it could miss is a dialect key inside a URL literal, and this crate declares no
/// URLs: it names hosts as configured upstreams and paths as claim selectors.
fn code_of(line: &str) -> &str {
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}

/// NO CARVED-OUT DIALECT'S KEY APPEARS IN THIS CRATE'S CODE.
#[test]
fn the_plane_names_no_dialect_it_carved_out() {
    let mut offenders: Vec<String> = Vec::new();
    for (path, text) in shipped_source() {
        for (n, line) in text.lines().enumerate() {
            let code = code_of(line);
            for key in CARVED_OUT {
                if code.contains(key) {
                    offenders.push(format!("{path}:{}: {}", n + 1, line.trim()));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "this plane names a dialect that was carved out into its own crate; the dialect declares \
         itself and registers by claim, so a key here is a branch the kind exists to remove:\n{}",
        offenders.join("\n")
    );
}

/// THE GUARD ITSELF DISCRIMINATES.
///
/// A textual test whose matcher stopped matching would pass for the wrong reason and go on passing
/// for as long as anyone left it alone. So the matcher is run against a line that DOES name a
/// carved-out dialect, and is required to find it.
#[test]
fn the_guard_finds_a_key_that_is_really_there() {
    let planted = r#"    let d = plane.locations("openai").unwrap();"#;
    assert!(
        CARVED_OUT.iter().any(|k| code_of(planted).contains(k)),
        "the matcher does not find a carved-out key in a line that carries one"
    );
    // And it is the COMMENT allowance that lets the two rung gaps be explained, so that is proved
    // to be an allowance rather than a hole the first case falls through.
    let commented = "    // rung 7 went to busbar-plane-llm-openai, which declares it";
    assert!(
        !CARVED_OUT.iter().any(|k| code_of(commented).contains(k)),
        "a comment naming the crate that took a rung is read as code"
    );
}

/// EVERY CARVED-OUT DIALECT IS REALLY GONE FROM THE DECLARATIONS.
///
/// The other direction of the same rule: a key listed above that is still in the plane's own tables
/// would mean the row was never removed, and the first case would then be failing for a reason the
/// list claims is settled.
#[test]
fn no_carved_out_dialect_is_still_declared() {
    for key in CARVED_OUT {
        assert!(
            busbar_plane_llm::dialect::dialect(key).is_none(),
            "{key} was carved out and its row is still in the plane's own table"
        );
        assert!(
            !busbar_plane_llm::claims::LADDER
                .iter()
                .any(|c| c.dialect == *key),
            "{key} was carved out and its rungs are still in the plane's own ladder"
        );
    }
}
