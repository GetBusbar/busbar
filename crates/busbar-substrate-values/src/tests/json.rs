//! Tests for `json.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

/// This module is THE SINGLE SEAM where the JSON library is named. A body serialize/parse spelled
/// `serde_json::to_vec` / `serde_json::from_slice` anywhere else in the crate silently opts that
/// call site out of the seam: it skips the depth guard, and it would survive an engine swap that
/// is supposed to be a change to this file alone. Scan the crate's own sources and fail on any
/// such call outside this module and the test sources.
#[test]
fn no_direct_serde_json_body_calls_outside_this_seam() {
    fn scan(dir: &std::path::Path, offenders: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("read source dir") {
            let path = entry.expect("dir entry").path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            if path.is_dir() {
                if matches!(name.as_str(), "tests" | "test_support" | "testkit") {
                    continue;
                }
                scan(&path, offenders);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            // The seam itself names the library by definition; co-located test sources may too.
            if name == "json.rs" || name.ends_with("_tests.rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("read source file");
            for (i, line) in src.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue; // prose about the seam is not a call
                }
                if line.contains("serde_json::to_vec")
                    || line.contains("serde_json::from_slice")
                {
                    offenders.push(format!("{}:{}: {}", path.display(), i + 1, line.trim()));
                }
            }
        }
    }

    let mut offenders = Vec::new();
    scan(
        std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src")),
        &mut offenders,
    );
    assert!(
        offenders.is_empty(),
        "body JSON must go through the crate::json seam (crate::json::to_vec / \
         crate::json::parse), not serde_json directly:\n{}",
        offenders.join("\n")
    );
}
