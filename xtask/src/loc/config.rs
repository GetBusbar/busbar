//! `qa/loc.toml` — WHAT IS COUNTED AND HOW IT IS GROUPED, AS DATA.
//!
//! "Excluding the four new planes" is a claim the release's headline ratio rests on, and until this
//! file existed it meant whatever the person typing the command remembered. A set that lives in a
//! chat message is a set that drifts between two readings of the same tree. It lives here, named,
//! checked in, and diffable — so the number is REPRODUCIBLE rather than re-derived.

use std::path::Path;

use crate::toml_doc;

/// Where the counter looks and how it groups what it finds.
#[derive(Clone, Debug)]
pub struct Config {
    /// Directories whose immediate subdirectories are each one crate (`crates`).
    pub crate_roots: Vec<String>,
    /// Single-crate directories outside those roots (`xtask`), if any.
    pub extra_crates: Vec<String>,
    /// Named crate sets, in declaration order.
    pub groups: Vec<Group>,
}

#[derive(Clone, Debug)]
pub struct Group {
    pub name: String,
    pub label: String,
    pub crates: Vec<String>,
}

pub const CONFIG_PATH: &str = "qa/loc.toml";

impl Config {
    pub fn load(root: &Path) -> Result<Config, String> {
        let path = root.join(CONFIG_PATH);
        let doc = toml_doc::parse(&path).map_err(|e| format!("{CONFIG_PATH}: {e}"))?;
        let scan = doc
            .table("scan")
            .ok_or_else(|| format!("{CONFIG_PATH}: no [scan] table"))?;
        let crate_roots = scan.list_of("crate_roots");
        if crate_roots.is_empty() {
            // A counter pointed at nothing measures 0 and is under every ceiling. That is the
            // vacuous-green shape this whole exercise exists to remove, so it is refused here
            // rather than reported as a small tree.
            return Err(format!(
                "{CONFIG_PATH}: [scan].crate_roots is empty — a counter with no roots measures \
                 zero and passes every ceiling"
            ));
        }
        let extra_crates = scan.list_of("extra_crates");
        let mut groups = Vec::new();
        for (name, table) in doc.children("groups") {
            let crates = table.list_of("crates");
            if crates.is_empty() {
                return Err(format!(
                    "{CONFIG_PATH}: [groups.{name}] names no crate — an empty group's totals are \
                     zero and say nothing"
                ));
            }
            groups.push(Group {
                label: table.str_of("label").unwrap_or(name.as_str()).to_string(),
                name,
                crates,
            });
        }
        Ok(Config {
            crate_roots,
            extra_crates,
            groups,
        })
    }

    /// The config a fixture tree gets when it has no `qa/loc.toml` of its own.
    pub fn bare(crate_roots: &[&str]) -> Config {
        Config {
            crate_roots: crate_roots.iter().map(|s| s.to_string()).collect(),
            extra_crates: Vec::new(),
            groups: Vec::new(),
        }
    }
}
