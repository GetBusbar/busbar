//! THE BUILD CI'S TEST RUN COMPILES, AND WHETHER A CITED TEST IS IN IT (Law 10, status row 178).
//!
//! A proof ledger (`qa/teller-steps.json`, `qa/capability-equality.json`) names a loop cell as
//! `<file>::<fn>`. Its gates used to accept the citation when `fn <name>(` appeared in the file, so
//! a cell whose module is declared under a cfg no build enables stayed `proven`: after the llm
//! plane's node-axis row went, `#[cfg(all(test, linked_axis_node))] mod tests;` compiled in no
//! CI step and fourteen root-llm cells pointed at tests that never ran.
//!
//! So a citation is judged against the build that RUNS it: the composition root's own test binary
//! as the `test` check of `.ci/default.yaml` builds it (`cargo nextest run --workspace`: the
//! crate's DEFAULT features, `cfg(test)` on). This module derives that build's cfgs from the one
//! place `crates/busbar/build.rs` reads them, the crate's manifest, and evaluates a cited fn's
//! module chain and attributes ([`crate::libtest_path::resolve_cell`]) against it. A cell passes
//! only when every cfg on its way is one this build enables, it carries a test attribute, and it is
//! not `#[ignore]`d.
//!
//! WHAT IS DERIVED, AND WHAT IS NOT. Derived exactly, mirroring `build.rs`: `test`; `feature = ".."`
//! over the closure of the `default` row; `linked_axis_<axis>` for every axis an enabled
//! `linked-axes` row carries (build.rs emits only declared axes, but a cfg it does not declare is an
//! `unexpected_cfgs` error under CI's `-D warnings`, so no compiled code can name one);
//! `linked_section_<section>`; `linked_driver_proofs`; `linked_every_plane`;
//! `linked_every_plane_door`; `linked_every_auth`; `linked_operator_auth`. Anything else (`unix`, `miri`,
//! `target_os = ..`, a `linked_*` family not listed here) is UNKNOWN, and an unknown cfg on a cited
//! cell's way is a refusal naming it: a cell CI is not shown to run is not evidence. The fix for a
//! refusal that should pass is to teach this module the cfg, never to drop the check.

use std::collections::BTreeSet;

use crate::libtest_path::{cfg_predicate, FnItem, ResolvedCell};

/// The build this module models, named in every refusal.
pub const CI_TEST_BUILD: &str = "CI's test build (the `test` check of .ci/default.yaml: \
                                 `cargo nextest run --workspace`, default features, cfg(test))";

/// The `linked_*` families [`CiBuild`] derives completely: absent from the set means OFF, not
/// unknown.
const DERIVED_PREFIXES: &[&str] = &["linked_axis_", "linked_section_"];
const DERIVED_FLAGS: &[&str] = &[
    "linked_driver_proofs",
    "linked_every_plane",
    "linked_every_plane_door",
    "linked_every_auth",
    "linked_operator_auth",
];

/// A cfg predicate's value in the modelled build. `Unknown` is a cfg this module cannot answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tri {
    Yes,
    No,
    Unknown,
}

/// The cfgs and features of the composition root's test build in CI.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CiBuild {
    pub features: BTreeSet<String>,
    pub cfgs: BTreeSet<String>,
    /// `features` is a FLOOR, not the whole set: a feature outside it may still be on. Another
    /// workspace member's tests are built in the same `--workspace` run, where cargo unifies a
    /// crate's features across every member that depends on it, so only its own `default` closure
    /// (and its self dev-dependency's) is known ON; any other feature is unknown, never OFF.
    pub open_features: bool,
}

impl CiBuild {
    /// The build the `test` check compiles, read off the crate's manifest text.
    ///
    /// # Errors
    /// The manifest states no `default` feature row: with nothing to close over, every feature
    /// would read OFF and the verdict would be a guess.
    pub fn of_manifest(text: &str) -> Result<CiBuild, String> {
        let doc = crate::toml_lite::parse_text(text);
        let features = doc.table("features");
        if !features.values.contains_key("default") {
            return Err(
                "the manifest states no `default` feature row to derive CI's test build \
                        from"
                    .to_string(),
            );
        }
        let mut on: BTreeSet<String> = BTreeSet::new();
        let mut todo = features.get_list("default");
        while let Some(f) = todo.pop() {
            // `dep:x` enables a dependency, `x/y` another crate's feature: neither is a feature of
            // this crate.
            if f.starts_with("dep:") || f.contains('/') {
                continue;
            }
            if on.insert(f.clone()) {
                todo.extend(features.get_list(&f));
            }
        }
        // A fold's switch swaps its row OUT while it is on (build.rs `swapped_in`).
        let swaps = rows(&doc, "package.metadata.busbar.linked-swaps");
        let enabled = |f: &str| {
            on.contains(f)
                && !swaps
                    .iter()
                    .any(|(row, switch)| row == f && on.contains(switch.as_str()))
        };

        let mut cfgs: BTreeSet<String> = BTreeSet::new();
        cfgs.insert("test".to_string());
        let axes = rows(&doc, "package.metadata.busbar.linked-axes");
        for (feature, list) in &axes {
            if enabled(feature) {
                for axis in list.split_whitespace() {
                    cfgs.insert(format!("linked_axis_{}", axis.replace('-', "_")));
                }
            }
        }
        for (feature, section) in rows(&doc, "package.metadata.busbar.linked-section") {
            if enabled(&feature) {
                cfgs.insert(format!("linked_section_{}", section.replace('-', "_")));
            }
        }
        if rows(&doc, "package.metadata.busbar.driver-proofs")
            .iter()
            .any(|(feature, _)| enabled(feature))
        {
            cfgs.insert("linked_driver_proofs".to_string());
        }
        let every = |axis: &str| {
            axes.iter()
                .filter(|(_, list)| list.split_whitespace().any(|a| a == axis))
                .all(|(feature, _)| enabled(feature))
        };
        if every("plane") {
            cfgs.insert("linked_every_plane".to_string());
        }
        if every("plane-door") {
            cfgs.insert("linked_every_plane_door".to_string());
        }
        // build.rs `AUTH_AXIS`: every linked row on the `auths` axis is enabled.
        if every("auths") {
            cfgs.insert("linked_every_auth".to_string());
        }
        if doc
            .table("package.metadata.busbar.operator-auth")
            .get_one("row")
            .is_some_and(&enabled)
        {
            cfgs.insert("linked_operator_auth".to_string());
        }
        Ok(CiBuild {
            features: on,
            cfgs,
            open_features: false,
        })
    }

    /// The build the `test` check compiles ANOTHER workspace member's own tests in (its lib's unit
    /// tests, its integration-test targets), read off that member's manifest text: `cfg(test)`,
    /// and, as a floor ([`Self::open_features`]), the closure of its `default` row and of the
    /// features its self dev-dependency (`<name> = { path = ".", features = [..] }`) asks for. No
    /// `linked_*` cfg: only the composition root's build script emits those.
    #[must_use]
    pub fn of_member_manifest(text: &str) -> CiBuild {
        let doc = crate::toml_lite::parse_text(text);
        let features = doc.table("features");
        let name = doc
            .table("package")
            .get_one("name")
            .unwrap_or_default()
            .to_string();
        let mut todo = features.get_list("default");
        for (key, raw) in &doc.table("dev-dependencies").entries {
            let Some(fields) = crate::toml_lite::inline_table(raw) else {
                continue;
            };
            let field = |k: &str| fields.iter().find(|(f, _)| f == k).map(|(_, v)| v.clone());
            let own = key.trim_matches('"') == name
                && field("path").is_some_and(|p| {
                    matches!(crate::toml_lite::string_value(&p).as_str(), "." | "./")
                });
            if own {
                todo.extend(
                    field("features")
                        .and_then(|f| crate::toml_lite::array_items(&f))
                        .unwrap_or_default(),
                );
            }
        }
        let mut on: BTreeSet<String> = BTreeSet::new();
        while let Some(f) = todo.pop() {
            if f.starts_with("dep:") || f.contains('/') {
                continue;
            }
            if on.insert(f.clone()) {
                todo.extend(features.get_list(&f));
            }
        }
        CiBuild {
            features: on,
            cfgs: std::iter::once("test".to_string()).collect(),
            open_features: true,
        }
    }

    /// The value of one cfg predicate (as [`crate::libtest_path`] spells it: `all(test,x)`,
    /// `feature="y"`) in this build.
    #[must_use]
    pub fn eval(&self, pred: &str) -> Tri {
        let chars: Vec<char> = pred.chars().filter(|c| !c.is_whitespace()).collect();
        let mut at = 0;
        let v = self.eval_at(&chars, &mut at);
        if at == chars.len() {
            v
        } else {
            Tri::Unknown
        }
    }

    fn eval_at(&self, c: &[char], at: &mut usize) -> Tri {
        let start = *at;
        while *at < c.len() && (c[*at].is_ascii_alphanumeric() || c[*at] == '_') {
            *at += 1;
        }
        let name: String = c[start..*at].iter().collect();
        if name.is_empty() {
            return Tri::Unknown;
        }
        match c.get(*at) {
            Some('(') => {
                *at += 1;
                let mut args = Vec::new();
                while *at < c.len() && c[*at] != ')' {
                    args.push(self.eval_at(c, at));
                    if c.get(*at) == Some(&',') {
                        *at += 1;
                    } else if c.get(*at) != Some(&')') {
                        *at = c.len() + 1;
                        return Tri::Unknown;
                    }
                }
                if c.get(*at) != Some(&')') {
                    *at = c.len() + 1;
                    return Tri::Unknown;
                }
                *at += 1;
                match name.as_str() {
                    "all" if args.contains(&Tri::No) => Tri::No,
                    "all" if args.contains(&Tri::Unknown) => Tri::Unknown,
                    "all" => Tri::Yes,
                    "any" if args.contains(&Tri::Yes) => Tri::Yes,
                    "any" if args.contains(&Tri::Unknown) => Tri::Unknown,
                    "any" => Tri::No,
                    "not" if args.len() == 1 => match args[0] {
                        Tri::Yes => Tri::No,
                        Tri::No => Tri::Yes,
                        Tri::Unknown => Tri::Unknown,
                    },
                    _ => Tri::Unknown,
                }
            }
            Some('=') => {
                *at += 1;
                if c.get(*at) != Some(&'"') {
                    *at = c.len() + 1;
                    return Tri::Unknown;
                }
                *at += 1;
                let vstart = *at;
                while *at < c.len() && c[*at] != '"' {
                    *at += 1;
                }
                let value: String = c[vstart..(*at).min(c.len())].iter().collect();
                *at += 1;
                if name == "feature" {
                    if self.features.contains(&value) {
                        Tri::Yes
                    } else if self.open_features {
                        Tri::Unknown
                    } else {
                        Tri::No
                    }
                } else {
                    Tri::Unknown
                }
            }
            _ => {
                if self.cfgs.contains(&name) {
                    Tri::Yes
                } else if DERIVED_FLAGS.contains(&name.as_str())
                    || DERIVED_PREFIXES.iter().any(|p| name.starts_with(p))
                {
                    Tri::No
                } else {
                    Tri::Unknown
                }
            }
        }
    }

    /// Whether `pred` holds here, as a refusal naming it when it does not or cannot be shown to.
    fn holds(&self, pred: &str, what: &str) -> Result<(), String> {
        match self.eval(pred) {
            Tri::Yes => Ok(()),
            Tri::No => Err(format!(
                "{what} is compiled only under `cfg({pred})`, which {CI_TEST_BUILD} does not \
                 enable, so no CI step compiles or runs it"
            )),
            Tri::Unknown => Err(format!(
                "{what} is compiled only under `cfg({pred})`, which this gate cannot show \
                 {CI_TEST_BUILD} enables (crate::ci_cfg derives test, the default features and \
                 build.rs's linked_* cfgs); a cell CI is not shown to run is not evidence"
            )),
        }
    }

    /// One definition: its own cfgs hold, it carries a test attribute, and it is not ignored.
    fn def_runs(&self, def: &FnItem) -> Result<(), String> {
        for pred in &def.cfgs {
            self.holds(pred, "the fn")?;
        }
        if !def.attrs.iter().any(|a| is_test_attr(a)) {
            return Err(
                "the fn carries no test attribute (`#[test]`, `#[tokio::test]`, ...): \
                        the harness never runs a helper"
                    .to_string(),
            );
        }
        for a in &def.attrs {
            if attr_name(a) == "ignore" {
                return Err(format!(
                    "the fn is `#[{a}]`: CI's test run skips an ignored test"
                ));
            }
            if let Some(inner) = a
                .strip_prefix("cfg_attr(")
                .and_then(|r| r.strip_suffix(')'))
            {
                let parts = split_top(inner);
                if parts.iter().skip(1).any(|p| attr_name(p) == "ignore")
                    && self.eval(parts.first().map_or("", String::as_str)) != Tri::No
                {
                    return Err(format!(
                        "the fn is `#[{a}]`, and this gate cannot show the condition is off in \
                         {CI_TEST_BUILD}: CI's test run may skip it"
                    ));
                }
            }
        }
        Ok(())
    }

    /// THE VERDICT: the cited fn is a test that `CI_TEST_BUILD` compiles and its run executes.
    ///
    /// # Errors
    /// A sentence naming the cfg, missing attribute or `ignore` that keeps the cell out of CI.
    pub fn runs(&self, cell: &ResolvedCell) -> Result<(), String> {
        for pred in &cell.chain {
            self.holds(pred, &format!("its module ({})", module_of(&cell.path)))?;
        }
        let mut why = Vec::new();
        for def in &cell.defs {
            match self.def_runs(def) {
                Ok(()) => return Ok(()),
                Err(e) => why.push(e),
            }
        }
        if why.is_empty() {
            why.push("no definition of the fn was read".to_string());
        }
        Err(why.join("; "))
    }
}

/// The `key = value` rows of `[table]`, the value's words joined.
fn rows(doc: &crate::toml_lite::Document, table: &str) -> Vec<(String, String)> {
    doc.table(table)
        .values
        .iter()
        .map(|(k, v)| (k.trim_matches('"').to_string(), v.join(" ")))
        .collect()
}

/// The module part of a libtest path (`root::serve::door_tests::f` -> `root::serve::door_tests`).
fn module_of(path: &str) -> &str {
    path.rsplit_once("::").map_or("the crate root", |(m, _)| m)
}

/// An attribute's path: its text up to its first `(` or `=`.
fn attr_name(attr: &str) -> &str {
    attr.split(['(', '=']).next().unwrap_or("").trim()
}

/// `#[test]`, `#[tokio::test]`, `#[tokio::test(flavor = ..)]`: an attribute whose path ends in
/// the segment `test`.
fn is_test_attr(attr: &str) -> bool {
    cfg_predicate(attr).is_none() && attr_name(attr).rsplit("::").next() == Some("test")
}

/// `a,b(c,d),e` -> `["a", "b(c,d)", "e"]`: the top-level comma-separated parts.
fn split_top(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut level = 0usize;
    let mut cur = String::new();
    for ch in s.chars() {
        match ch {
            '(' => {
                level += 1;
                cur.push(ch);
            }
            ')' => {
                level = level.saturating_sub(1);
                cur.push(ch);
            }
            ',' if level == 0 => out.push(std::mem::take(&mut cur)),
            _ => cur.push(ch),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
#[path = "tests/ci_cfg_tests.rs"]
mod tests;
