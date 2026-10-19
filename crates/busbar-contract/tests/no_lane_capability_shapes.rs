//! The contract carries no lane-capability or model shape (audit C14 step 3; BUSBAR-1.6.0.md Part 2
//! #49, "core names zero plane types"; Part 4: every ABI shape in busbar-contract is neutral).
//!
//! `LaneCaps`, `MaxOutputKey`, `EgressPrep` (with `IrHandle::prepare_for_egress`, the one method
//! that names it) and `ModelCfg` describe one plane's far ends: a provider's output-token key, its
//! thinking switches, a model's lifetime cap. No neutral routing fact carries them (the routing a
//! plane publishes states caps, windows and bounds as `FACT_*` values), so once the kernel stops
//! reading them their one user is that plane, and they live there. The check is a source scan, as
//! `protocol_names_no_plane_type.rs` is, because "this shape is defined nowhere here" is not a
//! property a type can state about itself.

use std::path::{Path, PathBuf};

/// Every `.rs` file under `src/`.
fn sources() -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
        for entry in std::fs::read_dir(dir).expect("src is readable") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("a source file is readable");
                out.push((path, text));
            }
        }
    }
    let mut out = Vec::new();
    walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
    out
}

/// The definitions that must not be in the contract: each a needle a defining line carries.
const DEFINED_ELSEWHERE: &[&str] = &[
    "struct LaneCaps",
    "enum MaxOutputKey",
    "struct EgressPrep",
    "struct ModelCfg",
    "fn prepare_for_egress",
];

/// RED while the contract still defines one of them.
#[test]
fn the_contract_defines_no_lane_capability_or_model_shape() {
    let offenders: Vec<String> = sources()
        .iter()
        .flat_map(|(path, text)| {
            text.lines().enumerate().filter_map(move |(i, line)| {
                let code = line.split("//").next().unwrap_or_default();
                DEFINED_ELSEWHERE
                    .iter()
                    .any(|needle| code.contains(needle))
                    .then(|| format!("{}:{}: {}", path.display(), i + 1, line.trim()))
            })
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "the contract still defines a plane's lane-capability or model shape: {offenders:#?}"
    );
}
