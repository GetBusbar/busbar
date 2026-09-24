//! Tests that hold the crate root's own prose to the tree it describes.

const LIB_RS: &str = include_str!("../lib.rs");
const FACTS_RS: &str = include_str!("../facts.rs");

/// The crate's integration test files, by the path a doc cites them under. Read at compile time, so
/// a cited file that does not exist is a file this table cannot name, and a test it cites is one
/// whose definition can be searched for without the test reaching outside the crate at run time.
const TEST_FILES: &[(&str, &str)] = &[
    (
        "tests/alloc_gate.rs",
        include_str!("../../tests/alloc_gate.rs"),
    ),
    (
        "tests/conformance.rs",
        include_str!("../../tests/conformance.rs"),
    ),
    (
        "tests/invariance.rs",
        include_str!("../../tests/invariance.rs"),
    ),
    ("tests/jev.rs", include_str!("../../tests/jev.rs")),
    ("tests/purity.rs", include_str!("../../tests/purity.rs")),
];

/// Item 403. Every `tests/<file>.rs` the crate root or the fact vocabulary cites as the home of a
/// guarantee is one of the crate's test files, and a cited `::test_name` is a test that file
/// defines.
#[test]
fn every_cited_test_file_exists_and_defines_the_cited_test() {
    let mut cited = 0;
    for source in [LIB_RS, FACTS_RS] {
        for token in source.split('`').skip(1).step_by(2) {
            if !token.starts_with("tests/") {
                continue;
            }
            let (file, test) = match token.split_once("::") {
                Some((file, test)) => (file, Some(test)),
                None => (token, None),
            };
            let Some((_, body)) = TEST_FILES.iter().find(|(path, _)| *path == file) else {
                panic!("a doc cites `{token}`, and the crate has no test file {file}");
            };
            if let Some(test) = test {
                assert!(
                    body.contains(&format!("fn {test}(")),
                    "a doc cites `{token}`, and {file} defines no such test"
                );
            }
            cited += 1;
        }
    }
    assert!(
        cited >= 2,
        "the PII witness is cited from both lib.rs and facts.rs"
    );
}

/// Item 398. The provider doc states what the composition root does today — installs the plane's
/// identity and config seam and builds no plane — rather than a boot-time build nothing performs.
#[test]
fn the_provider_doc_does_not_claim_a_boot_build_that_does_not_exist() {
    assert!(!LIB_RS.contains("The composition root builds one at boot"));
    assert!(LIB_RS.contains("builds no `DecisionPlane` today"));
}
