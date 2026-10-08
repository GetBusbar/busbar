//! `cargo xtask selftest --declare --format=json` — every selftest case's STATIC declaration,
//! with no gate run.
//!
//! A selftest case plants a fixture into the tree and asserts the gate names an expected finding.
//! When the crate it plants into leaves the workspace, the case silently stops proving anything,
//! and the only way to learn it used to be driving the whole battery — one masked batch per
//! ~45-minute run. All of it is visible from the case's own declaration: what it plants and what it
//! expects. A declaring [`Ctx`] (see [`Ctx::declaring`]) makes every `prove_*` case record that
//! declaration here and hand back a case that ran nothing, so the whole registry declares in
//! seconds.
//!
//! The release engine's preflight walk-around (busbar-release `walk_around`) reads this emit and
//! resolves every plant path under `crates/` against one `cargo metadata`, before any shard
//! builds. The schema:
//!
//! ```text
//! {"gates": [{"gate": "<name>", "cases": [{"name", "covers", "expected_naming",
//!   "plant_paths", "planted_crates", "unresolved_naming"}]}]}
//! ```

use crate::ctx::{Change, Ctx, Overlay};

/// One selftest case as declared: what it plants and what it expects, never what it got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declared {
    pub name: String,
    /// The owed row ids the case exercises.
    pub covers: Vec<String>,
    /// The strings a red must name (`Expect::Red { naming }`); empty for a green case.
    pub expected_naming: Vec<String>,
    /// Every repo-relative path the plant touches: written, removed or made unreadable.
    pub plant_paths: Vec<String>,
    /// The directories whose `Cargo.toml` the plant WRITES: crates the case plants itself, which
    /// own the paths under them although no workspace member does.
    pub planted_crates: Vec<String>,
}

impl Declared {
    pub fn new(
        cx: &Ctx,
        name: &str,
        covers: &[String],
        naming: &[String],
        overlay: Option<&Overlay>,
    ) -> Declared {
        let mut plant_paths = Vec::new();
        let mut planted_crates = Vec::new();
        for (path, change) in overlay.into_iter().flat_map(|o| o.changes()) {
            let rel = path.strip_prefix(cx.root()).unwrap_or(path);
            if matches!(change, Change::Content(_))
                && rel.file_name().is_some_and(|f| f == "Cargo.toml")
            {
                if let Some(dir) = rel.parent().filter(|d| !d.as_os_str().is_empty()) {
                    planted_crates.push(dir.to_string_lossy().replace('\\', "/"));
                }
            }
            plant_paths.push(rel.to_string_lossy().replace('\\', "/"));
        }
        Declared {
            name: name.to_string(),
            covers: covers.to_vec(),
            expected_naming: naming.to_vec(),
            plant_paths,
            planted_crates,
        }
    }

    /// The case's entry in the emit. `unresolved` is the gate's own answer to which expected
    /// needles its live vocabulary no longer produces ([`crate::gates::Gate::unresolved_naming`]).
    pub fn to_json(&self, unresolved: &[String]) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "covers": self.covers,
            "expected_naming": self.expected_naming,
            "plant_paths": self.plant_paths,
            "planted_crates": self.planted_crates,
            "unresolved_naming": unresolved,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plant's paths come back repo-relative, and a crate the plant writes a manifest for is a
    /// planted crate; a manifest it REMOVES is not (that crate must still exist to be removed).
    #[test]
    fn a_declaration_lists_every_plant_path_and_the_crates_it_writes() {
        let cx = Ctx::workspace().expect("the workspace opens");
        let mut ov = Overlay::new();
        ov.set(
            "crates/zz-planted/Cargo.toml",
            "[package]\nname = \"zz-planted\"\n",
        );
        ov.set("crates/zz-planted/src/lib.rs", "");
        ov.remove("crates/busbar-kernel/Cargo.toml");
        let d = Declared::new(
            &cx,
            "c",
            &["g:row".to_string()],
            &["needle".to_string()],
            Some(&ov),
        );
        assert_eq!(
            d.plant_paths,
            vec![
                "crates/busbar-kernel/Cargo.toml",
                "crates/zz-planted/Cargo.toml",
                "crates/zz-planted/src/lib.rs",
            ]
        );
        assert_eq!(d.planted_crates, vec!["crates/zz-planted"]);
        let json = d.to_json(&[]);
        assert_eq!(json["expected_naming"][0], "needle");
        assert_eq!(json["unresolved_naming"], serde_json::json!([]));
    }
}
