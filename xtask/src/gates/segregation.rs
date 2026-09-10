//! `cargo xtask gate segregation` — THE SEPARATION OF JUDGE, GATE AND SUBJECT, AS A GATE.
//!
//! The oracle judges the workspace. The gates read the workspace. Neither may become the other and
//! neither may import the thing it grades. Six rules, each its own ledger row:
//!
//! 1. `segregation:xtask-manifest-deps` — `xtask/Cargo.toml` declares no product crate.
//! 2. `segregation:xtask-dep-closure` — the resolved dependency closure holds no product package.
//!    New dependencies are allowed; product crates are not.
//! 3. `segregation:xtask-src-imports` — nothing under `xtask/src/` imports a product crate.
//!    **xtask reads sources as TEXT.** A gate that `use`s the type it audits is a gate whose
//!    verdict moves when the type does, which is the one failure the shell gates never had.
//! 4. `segregation:no-reverse-dep` — no manifest in the tree depends on `xtask`.
//! 5. `segregation:oracle-clean` — no file under `testing/shadow-oracle/` carries the token
//!    `xtask`: not an invocation, not an import, not a comment that would tempt the next person.
//! 6. `segregation:oracle-data-allow` — an oracle path read from `xtask/src/` must be on
//!    [`ORACLE_DATA_ALLOW`]. Reading a TSV is data; running the oracle's code is not.

use crate::ctx::{Ctx, Edit, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Case, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::scan;

pub const ROW_MANIFEST: &str = "segregation:xtask-manifest-deps";
pub const ROW_CLOSURE: &str = "segregation:xtask-dep-closure";
pub const ROW_SRC: &str = "segregation:xtask-src-imports";
pub const ROW_REVERSE: &str = "segregation:no-reverse-dep";
pub const ROW_ORACLE: &str = "segregation:oracle-clean";
pub const ROW_ORACLE_DATA: &str = "segregation:oracle-data-allow";

/// The oracle outputs a gate may legitimately read AS DATA: `design-bindings` and
/// `inventory-coverage` resolve against the golden ledger, `full` reads the golden digests, and
/// `changelog-register` reads the accepted-differences register — the owner's own sign-off list,
/// parsed as JSON — and `teller-steps` asks the two id registers whether anything in the tree still
/// owns a named rig cell, a lookup in a list rather than an execution.
///
/// Reading a data file the oracle wrote is data; running the oracle's code is not, and this list is
/// where that distinction is written down rather than assumed. The line it draws is the whole rule:
/// `teller-steps` may ask `rigs-baseline.json` what ids exist, and may NOT run `rigs-ledger.sh` to
/// find out. The Python it replaces did run it; that arm stayed in `scripts/verify-1.6.0-done.sh`,
/// where a caller driving the oracle is a caller, rather than moving into the gate runner, where it
/// would be the runner importing its subject.
pub const ORACLE_DATA_ALLOW: &[&str] = &[
    "testing/shadow-oracle/golden/1.5.5/ledger.tsv",
    "testing/shadow-oracle/golden/1.5.5/golden-digests.tsv",
    "testing/shadow-oracle/accepted-differences.json",
    "testing/shadow-oracle/cells.json",
    "testing/shadow-oracle/rigs-baseline.json",
];

/// Oracle CODE paths a gate may NAME but never open, because it writes them into a document it
/// GENERATES. Scoped to the naming file as well as the path, so the licence is one renderer's and
/// not xtask's.
///
/// The rule already draws this line once — "a bare directory mention is prose; a FILE path is a
/// read" — and this is the same distinction one step finer. `design-bindings`'s markdown carries a
/// "Running the checks (a slower tier)" section telling a reader which command executes an
/// `oracle-cell` ref; that sentence names `record.sh`, and it named it just the same when
/// `scripts/design-bindings.py` rendered it. The path is a citation in prose the gate EMITS, never
/// a path the gate opens, and the difference is the whole point of rule 6.
///
/// Keeping it a `(file, path)` pair rather than adding the script to [`ORACLE_DATA_ALLOW`] is what
/// keeps the ban intact: that list is read as "xtask may open this", and `record.sh` is exactly the
/// thing rule 6 exists to stop xtask opening. Nothing here grants a read to anyone.
/// The second entry is this file itself, and it is not a loophole: a `(file, path)` allowlist has
/// to WRITE the path down to exempt it, so the declaration is an occurrence of the very string it
/// governs. The alternative — exempting the rule's own source wholesale — would let any future
/// mention hide here. This exempts one path in one file, which is the same bargain as the first row.
pub const ORACLE_PROSE_CITATION_ALLOW: &[(&str, &str)] = &[
    (
        "xtask/src/gates/design_bindings/build.rs",
        "testing/shadow-oracle/record.sh",
    ),
    (
        "xtask/src/gates/segregation.rs",
        "testing/shadow-oracle/record.sh",
    ),
];

/// The `xtask/src/**` walk's denominator floor. An emptied or moved `src/` scans nothing, and zero
/// is the passing answer to every ban here.
const SRC_FLOOR: usize = 6;

/// Manifests are found by walking; this is the floor under that walk.
const MANIFEST_FLOOR: usize = 5;

pub struct SegregationGate;

fn is_product_package(name: &str) -> bool {
    let n = name.trim().trim_matches(['"', '\'']);
    n.starts_with("busbar") || n == "api"
}

/// The import spellings, built at run time rather than written as literals, so this scanner cannot
/// be reported by rule 3 for containing its own needle. Belt AND braces: rule 3 also blanks string
/// literals before matching.
fn import_needles() -> Vec<String> {
    let product = "busbar";
    vec![
        format!("use {product}_"),
        format!("use {product}::"),
        format!("extern crate {product}"),
        format!("{product}_core::"),
    ]
}

impl Gate for SegregationGate {
    fn name(&self) -> &'static str {
        "segregation"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_MANIFEST.to_string(),
            ROW_CLOSURE.to_string(),
            ROW_SRC.to_string(),
            ROW_REVERSE.to_string(),
            ROW_ORACLE.to_string(),
            ROW_ORACLE_DATA.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let mut rows = Vec::new();
        rows.push(rule_manifest(cx));
        rows.push(rule_closure(cx));
        let src = match cx.walk(&WalkSpec::new(["xtask/src"]).ext("rs").min_files(SRC_FLOOR)) {
            Ok(files) => files,
            Err(e) => {
                rows.push(Row::fail(
                    ROW_SRC,
                    "xtask/src is unscannable",
                    e.to_string(),
                ));
                rows.push(Row::fail(
                    ROW_ORACLE_DATA,
                    "xtask/src is unscannable",
                    e.to_string(),
                ));
                rows.push(rule_reverse(cx));
                rows.push(rule_oracle(cx));
                return Verdict::of(rows);
            }
        };
        rows.push(rule_src(&src));
        rows.push(rule_oracle_data(&src));
        rows.push(rule_reverse(cx));
        rows.push(rule_oracle(cx));
        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the real tree is segregated",
            &self.owed().iter().map(String::as_str).collect::<Vec<_>>(),
        ));

        report.push(plant(
            cx,
            self,
            "xtask/Cargo.toml declares a product crate",
            &[ROW_MANIFEST],
            "xtask/Cargo.toml",
            Edit::Append("\nbusbar-core = { path = \"../crates/busbar-core\" }\n".to_string()),
            &["busbar-core"],
        ));

        // The closure arm plants `cargo metadata`'s OUTPUT rather than a manifest, because the
        // rule's subject is the RESOLVED graph and a self-test that planted a manifest would be
        // proving the manifest rule twice.
        let mut ov = Overlay::new();
        ov.set_command(
            "cargo-metadata:xtask/Cargo.toml",
            r#"{"packages":[{"id":"x","name":"xtask"},{"id":"s","name":"serde_json"},
                {"id":"b","name":"busbar-substrate"}],
                "resolve":{"nodes":[{"id":"x","deps":[{"pkg":"s"},{"pkg":"b"}]},
                {"id":"s","deps":[]},{"id":"b","deps":[]}]}}"#,
        );
        report.push(prove_red(
            cx,
            self,
            "the resolved closure reaches a product crate",
            &[ROW_CLOSURE],
            ov,
            &["busbar-substrate"],
        ));

        report.push(plant(
            cx,
            self,
            "xtask/src imports a product crate",
            &[ROW_SRC],
            "xtask/src/scan.rs",
            Edit::Append("\nuse busbar_core::plane::PlaneDecl;\n".to_string()),
            &["busbar_core"],
        ));

        report.push(plant(
            cx,
            self,
            "a workspace crate depends on xtask",
            &[ROW_REVERSE],
            "xtask/fixtures/clean-pure/Cargo.toml",
            Edit::Append("\n[dev-dependencies]\nxtask = { path = \"../..\" }\n".to_string()),
            &["xtask/fixtures/clean-pure/Cargo.toml"],
        ));

        // Both oracle paths below are BUILT AT RUN TIME rather than written as literals: a
        // self-test that spells an offending oracle path in the gate's own source would be
        // planting that violation into the real tree permanently, and rule 6 would be red on
        // itself. The gate must not be a violation of the rule it enforces.
        let oracle_dir = format!("testing/{}/", "shadow-oracle");
        report.push(plant(
            cx,
            self,
            "the oracle names the gate runner",
            &[ROW_ORACLE],
            &format!("{oracle_dir}tempted-by-the-runner.py"),
            Edit::Create(format!(
                "# one day we could just call cargo {} gate ...\n",
                "xtask"
            )),
            &["tempted-by-the-runner.py"],
        ));

        report.push(plant(
            cx,
            self,
            "xtask reads an oracle path that is not data",
            &[ROW_ORACLE_DATA],
            "xtask/src/scan.rs",
            Edit::Append(format!(
                "\npub const PLANTED: &str = \"{oracle_dir}capture.py\";\n"
            )),
            &["capture.py"],
        ));

        // THE IGNORED FILE IS NOT PART OF THE TREE. `find` reads whatever a build left behind, and
        // this rule's walk has no extension filter, so an untracked `__pycache__/*.pyc` under the
        // oracle made the whole gate red on "the oracle tree could not be scanned" — a verdict
        // about a byte nobody wrote, on a rule about what the oracle NAMES. The plant carries the
        // banned token so the case can only stay green by the path being filtered, never by the
        // content being harmless.
        let mut ov = Overlay::new();
        ov.set(
            format!("testing/{}/__pycache__/planted.pyc", "shadow-oracle"),
            format!("compiled bytecode naming {}\n", "xtask"),
        );
        report.push(prove_green(
            &cx.with_overlay(ov),
            self,
            "a gitignored artefact under a walked root is not a finding",
            &[ROW_ORACLE],
        ));

        report
    }
}

fn plant<'a>(
    cx: &'a Ctx,
    gate: &'a dyn Gate,
    name: &str,
    covers: &[&str],
    path: &str,
    edit: Edit,
    naming: &[&str],
) -> crate::gates::CasePlan<'a> {
    let mut ov = Overlay::new();
    if edit.apply(cx, path, &mut ov).is_err() {
        // NOTHING TO PLANT (the rule's subject is absent from this tree) is a VISIBLE case in the
        // report, counted as unproven — never a silent green.
        return Case {
            name: name.to_string(),
            covers: covers.iter().map(|s| (*s).to_string()).collect(),
            expected: crate::gates::Expect::Red {
                naming: naming.iter().map(|s| (*s).to_string()).collect(),
            },
            got: crate::gates::Expect::Skipped,
        }
        .into();
    }
    prove_red(cx, gate, name, covers, ov, naming)
}

fn rule_manifest(cx: &Ctx) -> Row {
    let text = match cx.read("xtask/Cargo.toml") {
        Ok(t) => t,
        Err(e) => {
            return Row::fail(
                ROW_MANIFEST,
                "xtask/Cargo.toml is unreadable",
                format!("{e} — a gate whose own manifest vanished proves nothing"),
            )
        }
    };
    let offenders = manifest_dep_names(&text)
        .into_iter()
        .filter(|d| is_product_package(d))
        .collect::<Vec<_>>();
    if offenders.is_empty() {
        Row::pass(
            ROW_MANIFEST,
            "xtask/Cargo.toml declares no product crate",
            "new dependencies are allowed here; product crates are not",
        )
    } else {
        Row::fail(
            ROW_MANIFEST,
            "xtask/Cargo.toml declares a product crate",
            format!(
                "{}: the gate runner would then be built from the thing it audits",
                offenders.join(", ")
            ),
        )
    }
}

/// Dependency NAMES declared in any `[*dependencies]` table of a manifest.
fn manifest_dep_names(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_deps = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_deps = t.contains("dependencies");
            if let Some(rest) = t.strip_prefix("[dependencies.") {
                out.push(rest.trim_end_matches(']').to_string());
            }
            continue;
        }
        if !in_deps || t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some((name, _)) = t.split_once('=') {
            let name = name.trim().trim_matches(['"', '\'']);
            if !name.is_empty() {
                out.push(name.to_string());
            }
        }
    }
    out
}

fn rule_closure(cx: &Ctx) -> Row {
    let json = match cx.cargo_metadata("xtask/Cargo.toml") {
        Ok(j) => j,
        Err(e) => {
            return Row::fail(
                ROW_CLOSURE,
                "cargo metadata could not resolve xtask's closure",
                format!("{e} — an unresolvable closure is unproven, not clean"),
            )
        }
    };
    let value: serde_json::Value = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(e) => {
            return Row::fail(
                ROW_CLOSURE,
                "cargo metadata output did not parse",
                e.to_string(),
            )
        }
    };
    // `packages` is every package in the WORKSPACE, which for a workspace member is the whole
    // tree; the subject here is the RESOLVE CLOSURE of the `xtask` package alone. Reading the
    // wrong array would red this gate permanently and for the wrong reason.
    let closure = match resolve_closure(&value, "xtask") {
        Ok(c) => c,
        Err(e) => return Row::fail(ROW_CLOSURE, "xtask's closure could not be walked", e),
    };
    let offenders: Vec<String> = closure
        .iter()
        .filter(|n| is_product_package(n))
        .cloned()
        .collect();
    if offenders.is_empty() {
        Row::pass(
            ROW_CLOSURE,
            "xtask's resolved closure holds no product package",
            format!("{} package(s): {}", closure.len(), closure.join(", ")),
        )
    } else {
        Row::fail(
            ROW_CLOSURE,
            "xtask's resolved closure reaches a product crate",
            offenders.join(", "),
        )
    }
}

/// The transitive resolve closure of one package, by NAME, out of `cargo metadata`'s
/// `format-version=1` shape. An empty closure is an error: it satisfies every ban vacuously.
fn resolve_closure(value: &serde_json::Value, root_name: &str) -> Result<Vec<String>, String> {
    let packages = value
        .get("packages")
        .and_then(|p| p.as_array())
        .ok_or("cargo metadata carried no `packages` array")?;
    let mut name_of = std::collections::BTreeMap::new();
    for p in packages {
        let (Some(id), Some(name)) = (
            p.get("id").and_then(|v| v.as_str()),
            p.get("name").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        name_of.insert(id.to_string(), name.to_string());
    }
    let root_id = name_of
        .iter()
        .find(|(_, n)| n.as_str() == root_name)
        .map(|(id, _)| id.clone())
        .ok_or_else(|| format!("no package named `{root_name}` in the metadata"))?;

    let nodes = value
        .get("resolve")
        .and_then(|r| r.get("nodes"))
        .and_then(|n| n.as_array())
        .ok_or("cargo metadata carried no `resolve.nodes` — the closure is unknown, not empty")?;
    let mut deps_of: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for node in nodes {
        let Some(id) = node.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let deps = node
            .get("deps")
            .and_then(|d| d.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|d| d.get("pkg").and_then(|p| p.as_str()))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        deps_of.insert(id.to_string(), deps);
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut queue = vec![root_id];
    while let Some(id) = queue.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        for dep in deps_of.get(&id).cloned().unwrap_or_default() {
            queue.push(dep);
        }
    }
    let names: Vec<String> = seen
        .iter()
        .filter_map(|id| name_of.get(id).cloned())
        .collect();
    if names.is_empty() {
        return Err(
            "the resolved closure is empty, which satisfies every ban vacuously".to_string(),
        );
    }
    Ok(names)
}

fn rule_src(files: &[crate::ctx::SourceFile]) -> Row {
    let needles = import_needles();
    let mut hits = Vec::new();
    for f in files {
        for (lineno, code) in f.production_lines() {
            let code = scan::blank_literals(&code);
            for needle in &needles {
                if code.contains(needle.as_str()) {
                    hits.push(format!("{}:{lineno}: {}", f.rel_str(), code.trim()));
                }
            }
        }
    }
    if hits.is_empty() {
        Row::pass(
            ROW_SRC,
            "xtask/src imports no product crate",
            format!(
                "{} file(s) scanned; xtask reads sources as text",
                files.len()
            ),
        )
    } else {
        Row::fail(
            ROW_SRC,
            "xtask/src imports a product crate",
            hits.join(" | "),
        )
    }
}

fn rule_oracle_data(files: &[crate::ctx::SourceFile]) -> Row {
    let prefix = "testing/shadow-oracle/";
    let mut offenders = Vec::new();
    for f in files {
        for (lineno, code) in f.production_lines() {
            let mut rest = code.as_str();
            while let Some(i) = rest.find(prefix) {
                let tail = &rest[i..];
                // A BACKTICK ENDS A PATH like a quote does. Without it a path written the way
                // markdown writes one — `testing/shadow-oracle/record.sh` — is extracted with the
                // closing backtick glued on, so it matches no allowlist entry and cannot be
                // reasoned about at all. The offender's own name has to be the path.
                let end = tail
                    .find(|c: char| {
                        c.is_whitespace() || c == '"' || c == '\'' || c == ')' || c == '`'
                    })
                    .unwrap_or(tail.len());
                let path = &tail[..end];
                // A bare directory mention is prose; a FILE path is a read.
                let cited_in_prose = ORACLE_PROSE_CITATION_ALLOW
                    .iter()
                    .any(|(file, cited)| *file == f.rel_str() && *cited == path);
                if path.len() > prefix.len()
                    && path.contains('.')
                    && !ORACLE_DATA_ALLOW.contains(&path)
                    && !cited_in_prose
                {
                    offenders.push(format!("{}:{lineno}: {path}", f.rel_str()));
                }
                rest = &tail[end.max(1)..];
            }
        }
    }
    if offenders.is_empty() {
        Row::pass(
            ROW_ORACLE_DATA,
            "xtask reads oracle files only from the data allowlist",
            format!("allowlist: {}", ORACLE_DATA_ALLOW.join(", ")),
        )
    } else {
        Row::fail(
            ROW_ORACLE_DATA,
            "xtask reads an oracle path that is not on the data allowlist",
            format!(
                "{} — reading a TSV is data; running the oracle's code is not",
                offenders.join(" | ")
            ),
        )
    }
}

fn rule_reverse(cx: &Ctx) -> Row {
    let spec = WalkSpec::new(["Cargo.toml", "crates", "xtask"])
        .ext("toml")
        .min_files(MANIFEST_FLOOR);
    let manifests = match cx.walk(&spec) {
        Ok(m) => m,
        Err(e) => {
            return Row::fail(
                ROW_REVERSE,
                "the manifest walk could not run",
                e.to_string(),
            )
        }
    };
    let mut offenders = Vec::new();
    for m in &manifests {
        if !m.rel_str().ends_with("Cargo.toml") || m.rel_str().starts_with("xtask/Cargo.toml") {
            continue;
        }
        if manifest_dep_names(&m.text).iter().any(|d| d == "xtask") {
            offenders.push(m.rel_str());
        }
    }
    if offenders.is_empty() {
        Row::pass(
            ROW_REVERSE,
            "nothing in the tree depends on xtask",
            format!("{} manifest(s) scanned", manifests.len()),
        )
    } else {
        Row::fail(
            ROW_REVERSE,
            "a manifest depends on xtask",
            format!(
                "{} — the gate runner is a judge of the tree, never a part of it",
                offenders.join(", ")
            ),
        )
    }
}

fn rule_oracle(cx: &Ctx) -> Row {
    let spec = WalkSpec::new(["testing/shadow-oracle"]).min_files(1);
    let files = match cx.walk(&spec) {
        Ok(f) => f,
        Err(e) => {
            return Row::fail(
                ROW_ORACLE,
                "the oracle tree could not be scanned",
                e.to_string(),
            )
        }
    };
    let needle = "xtask";
    let offenders: Vec<String> = files
        .iter()
        .filter(|f| f.text.contains(needle))
        .map(|f| f.rel_str())
        .collect();
    if offenders.is_empty() {
        Row::pass(
            ROW_ORACLE,
            "the oracle names nothing from the workspace it judges",
            format!("{} oracle file(s) scanned", files.len()),
        )
    } else {
        Row::fail(
            ROW_ORACLE,
            "the oracle names xtask",
            format!(
                "{} — the oracle's inputs are a published binary and its own goldens; its outputs \
                 are cells and a ledger. Nothing else.",
                offenders.join(", ")
            ),
        )
    }
}
