//! Tests for `json.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else.

/// This module is THE SINGLE SEAM where the JSON library is named. A body serialize/parse spelled
/// `serde_json::to_vec` / `serde_json::from_slice` in the code that came with it from the retired
/// shared value crate ([`crate::tests::moved_sources`]) silently opts that call site out of the
/// seam: it skips the depth guard, and it would survive an engine swap that is supposed to be a
/// change to this file alone. The rule that crate held over its own tree, kept over the same code.
#[test]
fn no_direct_serde_json_body_calls_outside_this_seam() {
    let mut offenders = Vec::new();
    for rel in crate::tests::moved_sources() {
        // The seam itself names the library by definition.
        if rel.ends_with("/json.rs") {
            continue;
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
        let src = std::fs::read_to_string(&path).expect("read source file");
        for (i, line) in src.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue; // prose about the seam is not a call
            }
            if line.contains("serde_json::to_vec") || line.contains("serde_json::from_slice") {
                offenders.push(format!("{}:{}: {}", path.display(), i + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "body JSON must go through the crate::json seam (crate::json::to_vec / \
         crate::json::parse), not serde_json directly:\n{}",
        offenders.join("\n")
    );
}
