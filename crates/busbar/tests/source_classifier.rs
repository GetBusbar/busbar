// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CLASSIFIER'S OWN GATE. `tests/common/mod.rs` decides what "production source" means for
//! every scanning gate in this crate, so a bug in it is a silent weakening of all of them at once —
//! a classifier that fails to recognise a `#[cfg(test)] mod` hands the scans the test bodies back,
//! and every one of those gates becomes satisfiable by a mock.
//!
//! So the classifier is driven directly, over the shapes that actually appear in this tree, and the
//! decisive cases are the negative ones: a token that appears ONLY inside a test module must be
//! invisible, and a token in a comment or a string must not be mistaken for either.

mod common;

use common::{classify, item_body, production_lines};
use std::path::Path;

/// Join the production lines of a classified text back into one scannable string.
fn production_of(src: &str) -> String {
    classify(src, false)
        .into_iter()
        .filter(|l| !l.intest)
        .map(|l| format!("{}\n", l.code))
        .collect()
}

#[test]
fn a_cfg_test_module_is_not_production() {
    let src = r#"
pub fn serve() {
    dispatch();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_meters() {
        // the mock the gate must not see
        Usage::report(usage, lines);
    }
}
"#;
    let prod = production_of(src);
    assert!(
        prod.contains("dispatch()"),
        "production code survives: {prod}"
    );
    assert!(
        !prod.contains("Usage::report("),
        "a seam token that exists ONLY inside `#[cfg(test)] mod tests` was handed to the scan. \
         Every reachability gate in this crate is satisfiable by a mock while that is true:\n{prod}"
    );
}

#[test]
fn a_cfg_test_on_its_own_line_still_opens_a_test_module() {
    let src = r#"
pub fn serve() {}

#[cfg(test)]
mod tests {
    fn helper() { Usage::report(x); }
}
"#;
    assert!(
        !production_of(src).contains("Usage::report("),
        "`#[cfg(test)]` and the `mod tests` opener on separate lines is the ordinary rustfmt \
         output; the \
         classifier must follow it across the line break"
    );
}

#[test]
fn a_cfg_test_gating_a_non_module_item_does_not_swallow_the_rest_of_the_file() {
    let src = r#"
#[cfg(test)]
use std::sync::Arc;

pub fn serve() { Usage::report(x); }
"#;
    assert!(
        production_of(src).contains("Usage::report("),
        "a `#[cfg(test)]` on a `use` gates one item; treating it as a module opening would hide \
         every remaining line of the file from the scan, which turns a gate green by accident"
    );
}

#[test]
fn a_nested_brace_inside_a_test_module_does_not_end_it_early() {
    let src = r#"
#[cfg(test)]
mod tests {
    fn a() { if x { y(); } }
    fn b() { Usage::report(x); }
}

pub fn serve() { dispatch(); }
"#;
    let prod = production_of(src);
    assert!(!prod.contains("Usage::report("), "test body leaked: {prod}");
    assert!(
        prod.contains("dispatch()"),
        "the test module must END at its closing brace, not swallow the file: {prod}"
    );
}

#[test]
fn a_brace_inside_a_string_does_not_disturb_the_structure() {
    let src = r#"
#[cfg(test)]
mod tests {
    fn a() { println!("}"); }
    fn b() { Usage::report(x); }
}
pub fn serve() { dispatch(); }
"#;
    let prod = production_of(src);
    assert!(
        !prod.contains("Usage::report("),
        "a closing brace inside a string literal ended the test module early and leaked its \
         body: {prod}"
    );
}

#[test]
fn comments_are_stripped_and_strings_are_not() {
    let src = "let url = \"http://example.test/x\"; // Usage::report(x)\n";
    let prod = production_of(src);
    assert!(
        prod.contains("http://example.test/x"),
        "a `//` inside a string literal is not a comment: {prod}"
    );
    assert!(
        !prod.contains("Usage::report("),
        "a trailing line comment was handed to the scan: {prod}"
    );
}

#[test]
fn a_block_comment_spanning_lines_is_stripped() {
    let src =
        "pub fn a() {}\n/* Usage::report(x)\n   still a comment */\npub fn b() { dispatch(); }\n";
    let prod = production_of(src);
    assert!(
        !prod.contains("Usage::report("),
        "block comment leaked: {prod}"
    );
    assert!(
        prod.contains("dispatch()"),
        "code after the block comment was lost: {prod}"
    );
}

#[test]
fn an_item_body_is_the_item_and_not_the_file() {
    let src = r#"
pub fn meter(&mut self) -> Decision<Meter> {
    let d = self.walk.step();
    Decision::proceed(d)
}

pub fn audit(&mut self) {
    Usage::report(usage, lines);
}
"#;
    let lines = classify(src, false);
    let body = item_body(&lines, "fn meter(").expect("the signature is present");
    let text: String = body.iter().map(|l| format!("{}\n", l.code)).collect();
    assert!(
        text.contains("self.walk.step()"),
        "the body is the item's own: {text}"
    );
    assert!(
        !text.contains("Usage::report("),
        "`item_body` ran past the item's closing brace and picked up the NEXT function. A gate \
         built on that asks its question of the file, not of the step:\n{text}"
    );
}

#[test]
fn an_absent_item_is_absent_rather_than_the_whole_file() {
    let lines = classify("pub fn other() {}\n", false);
    assert!(item_body(&lines, "fn meter(").is_none());
}

/// The classifier is pointed at a real file in the tree so a refactor that moves the source layout
/// out from under it is caught here rather than as nine silently-vacuous gates.
#[test]
fn the_classifier_reads_this_crate_s_own_root() {
    let main = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let lines = production_lines(&main);
    assert!(
        lines.len() > 50,
        "crates/busbar/src/main.rs classified to {} production lines. The scanning gates are \
         reading nothing, and a scan that reads nothing passes everything.",
        lines.len()
    );
}
