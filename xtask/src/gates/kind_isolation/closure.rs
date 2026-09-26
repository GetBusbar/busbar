//! THE DEP-WALL, AS #40(a) STATES IT: A CLOSURE, NOT A DECLARATION.
//!
//! > "a plugin crate's entire workspace dependency closure = `busbar-contract` and nothing else; a
//! > RED-provable `kind-isolation` CI gate **runs `cargo metadata` on every `busbar-<kind>-*`
//! > crate and asserts closure ∩ {kernel, core-\*, any secret impl, any other plugin} = ∅**"
//! > — `docs/design/BUSBAR-1.6.0.md` #40(a), OWNER-LOCKED 2026-09-18
//!
//! ## WHAT THIS ROW EXISTS TO FIX
//!
//! Every other rule in this gate is PER-DECLARATION. `:deps` reads one manifest, scores the edges
//! that manifest writes down, and says so in its own words — *"1 declaration(s), in
//! dependencies"*. That is a measurement of what a crate NAMES. #40(a) is a statement about what a
//! crate LINKS, and the two stop being the same thing at the second hop.
//!
//! The gap is not theoretical and it is not small. `busbar-transport-tls -> busbar-unit-transport-
//! key` carries a `[[dep]]` row that says `not-allowed`, because `tls` names the unit crate in its
//! own manifest. `busbar-transport-grpc`, `busbar-transport-http`, `busbar-transport-sse` and
//! `busbar-transport-ws` all LINK the same unit crate — through `tls` — and no row names any of
//! them, because none of them writes it down. One breach was reviewed and four identical ones were
//! invisible, and the difference between the five is a hop.
//!
//! Measured over this tree: of the closure memberships a plugin crate carries beyond
//! `busbar-contract`, the MAJORITY are reachable only transitively. A direct-edge ledger cannot see
//! them however many rows it has, because the row it would need is a row about a crate that names
//! nothing.
//!
//! ## A BREACH WITHOUT ITS PATH IS AN ASSERTION
//!
//! So every finding here carries the whole path, hop by hop, from the plugin crate to the crate it
//! must not reach. That is not decoration: the fix for `grpc -> http -> tls -> unit-transport-key`
//! is an edit to `tls`, not to `grpc`, and a finding that names only its endpoints sends the reader
//! to the wrong manifest.
//!
//! ## A FEATURE IS A SWITCH ON AN EDGE, NOT AN ABSENCE OF ONE
//!
//! The closure is computed TWICE: once over the edges that are unconditional, and once over the
//! union of every feature configuration — every `optional = true` edge on. The second is the honest
//! upper bound, and it is the one #40(a) is about, because #40(a) says *closure*, not *default
//! closure*. An `optional` edge that no feature in CI turns on is still an edge a third party turns
//! on; an `optional` edge that CI DOES turn on is a breach shipping today wearing the word
//! "optional". Each finding says which of the two it is, and names the feature.
//!
//! ## THE INSTRUMENT IS CROSS-CHECKED AGAINST CARGO, AND A DISAGREEMENT IS RED
//!
//! The closure is walked over the census — the same manifests every other rule reads, through the
//! same reader, so a planted tree moves this row like it moves the others. `cargo metadata` is then
//! run and its own answer compared against it, edge for edge. The two must agree.
//!
//! That ordering is deliberate. `cargo metadata` is a subprocess over the real filesystem: it
//! cannot see an overlay, so a rule that took it as its ONLY input would be a rule no self-test
//! could ever plant a violation into — falsifiable in CI and inert on the bench. And a
//! subprocess that fails, or resolves nothing, hands back an empty graph, which satisfies every
//! dependency ban vacuously. So the reader is the claim, cargo is the CHECK ON the claim, an
//! unreadable `cargo metadata` is RED rather than silent, and a graph smaller than the census is
//! RED rather than clean. The corroboration is not asked of an overlaid tree, for the one reason
//! that matters: an overlaid tree is not the tree cargo resolved, so a disagreement there is a
//! fact about the plant and not about the wall.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::ctx::Ctx;
use crate::ledger::Row;
use crate::manifest;

use super::truths::PLUGIN_KINDS;
use super::{
    refine, resolve_kind, CrateInfo, ARCHITECTURE_ALLOWED, ARCHITECTURE_TCB, PENDING_EDGES,
};

pub const ROW_CLOSURE: &str = "kind-isolation:closure";

/// THE ONE CRATE #40(a) ADMITS. Everything else in a plugin's closure is a finding.
const CONTRACT: &str = "busbar-contract";

/// A graph smaller than this is not this workspace, and a wall measured over it is a wall measured
/// over nothing. Mirrors the census floor (`kind_isolation::MIN_MANIFESTS`) for the same reason,
/// and moves with it: 30, not 40 (item F0b, same shape as F0's `workspace-deps`
/// `MIN_CRATE_MANIFESTS`, `98434a220`). The Phase 4 fold's planned end state is 35 crates under
/// `crates/` (34 / 33 in the roster variants); at 40 this row would have reddened around fold #11,
/// against a planned shrink. 30 sits three under the smallest planned roster variant, so no planned
/// fold trips it, while a graph collapsed to a third of today's census is still RED.
const MIN_GRAPH_CRATES: usize = 30;

// ------------------------------------------------------------------------------------------------
// the graph
// ------------------------------------------------------------------------------------------------

/// One workspace-internal SHIPPED edge, with the switch that is on it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Edge {
    /// Every declaration of this edge is `optional = true`, so the edge is live only under a
    /// feature. A crate that declares an edge twice — once plain, once optional — has it
    /// unconditionally, which is why this is an AND over the declarations and not an OR.
    optional: bool,
    /// The feature names in the FROM crate's own `[features]` table that switch it on.
    features: Vec<String>,
}

/// The workspace's shipped dependency graph: `from -> to -> the edge`.
type Graph = BTreeMap<String, BTreeMap<String, Edge>>;

/// One hop of a closure path, printed as the reader has to walk it.
#[derive(Clone, Debug)]
struct Hop {
    from: String,
    to: String,
    optional: bool,
    features: Vec<String>,
}

impl Hop {
    /// `a -> b` for an unconditional hop; ``a -*> b (feature `pack`)`` for a switched one.
    fn cite(&self) -> String {
        if !self.optional {
            return format!("{} -> {}", self.from, self.to);
        }
        let which = if self.features.is_empty() {
            "optional".to_string()
        } else {
            format!("feature `{}`", self.features.join("`/`"))
        };
        format!("{} -*> {} ({which})", self.from, self.to)
    }
}

/// THE SHIPPED GRAPH AND THE TEST GRAPH AS THE CENSUS SEES THEM — the same manifests, the same
/// reader, every other rule in this gate. BOTH HALVES IN ONE PASS OVER THE MANIFESTS, and one pass is not an optimisation detail: this
/// row runs inside a self-test that drives the gate ninety times, and a second read of sixty
/// manifests per run is the shape that puts a battery over its budget.
///
/// Returns `(shipped, test)`. The SHIPPED half is what #40(a) is about — what a third party links —
/// so `[dev-dependencies]` is out of it by construction, and `[build-dependencies]` is in on
/// [`crate::manifest::DepTable::shipped`]'s own reasoning: a build script's own links are compiled
/// into the making of the thing.
///
/// The TEST half is ONE HOP, which is what cargo does: a dev-dependency is a root of the
/// `cargo test` build graph and nothing deeper — the dev-deps of a DEPENDENCY are in nobody's
/// graph. So a crate's test closure is its own dev edges plus the SHIPPED closure under each, and
/// this returns the first of the two.
fn census_graphs(cx: &Ctx, crates: &[CrateInfo]) -> (Graph, Graph) {
    let present: BTreeSet<&str> = crates.iter().map(|c| c.name.as_str()).collect();
    let mut shipped: Graph = BTreeMap::new();
    let mut test: Graph = BTreeMap::new();
    for c in crates {
        let features = cx
            .read(&c.manifest)
            .map(|t| manifest::feature_table(&t))
            .unwrap_or_default();
        for (decls, g) in [(&c.deps, &mut shipped), (&c.dev_deps, &mut test)] {
            let row = g.entry(c.name.clone()).or_default();
            for decl in decls {
                if !present.contains(decl.pkg.as_str()) || decl.pkg == c.name {
                    continue;
                }
                let e = row.entry(decl.pkg.clone()).or_insert(Edge {
                    optional: true,
                    features: Vec::new(),
                });
                // A SECOND, UNCONDITIONAL DECLARATION TAKES THE SWITCH OFF THE EDGE.
                e.optional &= decl.optional;
                if decl.optional {
                    for f in switches(&features, &decl.key, &decl.pkg) {
                        if !e.features.contains(&f) {
                            e.features.push(f);
                        }
                    }
                }
            }
            for e in row.values_mut() {
                e.features.sort();
            }
        }
    }
    (shipped, test)
}

/// The features of one manifest that turn an optional dependency on.
///
/// Cargo spells the activation three ways and all three are read: `dep:<key>` (the explicit form),
/// `<key>` (the implicit feature an optional dependency gets for free), and `<key>/<their-feature>`
/// (which activates the dependency too, unless it is written `<key>?/…`). The KEY is what a feature
/// names, never the package — a renamed dependency is switched on by the word the manifest wrote.
fn switches(features: &BTreeMap<String, Vec<String>>, key: &str, pkg: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (feature, items) in features {
        for item in items {
            let names_it = item == &format!("dep:{key}")
                || item == &format!("dep:{pkg}")
                || item == key
                || item == pkg
                || item
                    .split_once('/')
                    .is_some_and(|(head, _)| head == key || head == pkg);
            if names_it {
                out.push(feature.clone());
                break;
            }
        }
    }
    out
}

/// THE SAME GRAPH AS CARGO RESOLVES IT — the corroboration, from `cargo metadata` itself.
///
/// Returns the DECLARED workspace-internal normal/build edge set out of `packages[].dependencies`,
/// which is the array #40(a)'s own sentence points at. `resolve.nodes` is a different and narrower
/// answer — the graph under the DEFAULT feature set — and reading it as if it were the closure is
/// how an optional breach becomes invisible.
fn cargo_graph(cx: &Ctx) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    graph_from_metadata(&cx.cargo_metadata("Cargo.toml")?)
}

/// The reading half of [`cargo_graph`], with the subprocess taken out so the FLOOR and the
/// shipped/test split can be proven without one.
fn graph_from_metadata(json: &str) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| format!("`cargo metadata` output did not parse: {e}"))?;
    let packages = value
        .get("packages")
        .and_then(|p| p.as_array())
        .ok_or("`cargo metadata` carried no `packages` array")?;
    let members: BTreeSet<&str> = packages
        .iter()
        .filter_map(|p| p.get("name").and_then(|v| v.as_str()))
        .collect();
    if members.len() < MIN_GRAPH_CRATES {
        return Err(format!(
            "`cargo metadata` named {} package(s), under the floor of {MIN_GRAPH_CRATES}. A graph \
             that small is not this workspace, and a closure walked over it satisfies every ban \
             vacuously",
            members.len()
        ));
    }
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for p in packages {
        let Some(from) = p.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let row = out.entry(from.to_string()).or_default();
        let Some(deps) = p.get("dependencies").and_then(|d| d.as_array()) else {
            continue;
        };
        for d in deps {
            // `kind` is ABSENT (or null) for a normal dependency, `"dev"` / `"build"` otherwise.
            // A dev edge is not in the shipped artifact; a build edge is.
            if d.get("kind").and_then(|k| k.as_str()) == Some("dev") {
                continue;
            }
            let Some(to) = d.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            if members.contains(to) && to != from {
                row.insert(to.to_string());
            }
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------------
// the walk
// ------------------------------------------------------------------------------------------------

/// The shortest path from `root` to every crate it can reach, PREFERRING A PATH WITH NO SWITCH ON
/// IT.
///
/// Two walks rather than one, and the order is the finding: a crate reachable without touching a
/// feature is reported by the route that needs no feature, so the reader is not sent looking for a
/// switch that is not on the path they have to cut. The second walk then adds whatever only a
/// feature reaches. `unconditional_only` is the whole difference between them.
fn walk(g: &Graph, root: &str, unconditional_only: bool) -> BTreeMap<String, Vec<Hop>> {
    let mut paths: BTreeMap<String, Vec<Hop>> = BTreeMap::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    seen.insert(root.to_string());
    let mut q: VecDeque<String> = VecDeque::new();
    q.push_back(root.to_string());
    while let Some(cur) = q.pop_front() {
        let Some(row) = g.get(&cur) else { continue };
        for (to, edge) in row {
            if unconditional_only && edge.optional {
                continue;
            }
            if !seen.insert(to.clone()) {
                continue;
            }
            let mut path = paths.get(&cur).cloned().unwrap_or_default();
            path.push(Hop {
                from: cur.clone(),
                to: to.clone(),
                optional: edge.optional,
                features: edge.features.clone(),
            });
            paths.insert(to.clone(), path);
            q.push_back(to.clone());
        }
    }
    paths
}

/// Which of #40(a)'s four named sets a crate in a plugin's closure lands in, in the rule's own
/// words. A crate in none of them is still a breach — #40(a)'s first clause is `= busbar-contract`
/// and nothing else — and saying which is which is what lets an owner read the list by weight.
fn banned_set(name: &str) -> &'static str {
    let (kind, remainder, _) = resolve_kind(name);
    match refine(kind, &remainder) {
        Some("kernel") => "THE KERNEL",
        Some("core") => "a `core-*` crate",
        Some("secret") => "a secret implementation",
        Some(k) if PLUGIN_KINDS.contains(&k) => "another plugin",
        Some(k) => match k {
            "api" | "plugin-abi" | "plugin-tooling" | "substrate" | "timing" | "codec" | "unit" => {
                "not `busbar-contract`"
            }
            _ => "not `busbar-contract`",
        },
        None => "not `busbar-contract` (and matches no kind)",
    }
}

// ------------------------------------------------------------------------------------------------
// the rule
// ------------------------------------------------------------------------------------------------

/// #40(a), COMPUTED.
pub fn rule_closure(cx: &Ctx, crates: &[CrateInfo]) -> Row {
    let mut offenders: Vec<String> = Vec::new();

    // A GRANT FOR A PLUGIN KIND NAMING ITSELF IS A RULE THAT CANNOT FAIL.
    //
    // #40(a) bans `closure ∩ {… any other plugin} = ∅`. A plane naming a plane, a store naming a
    // store and a transport naming a transport ARE that intersection being non-empty, so a class
    // table that grants one has written the exception into the instrument rather than into the
    // ledger where a reader would find it. This is checked rather than merely fixed, because a
    // grant that was deleted once can be added again by anyone who reads the citation and not the
    // rule it cites.
    let plugin_kinds: BTreeSet<&str> = PLUGIN_KINDS.iter().copied().collect();
    for (table, rows) in [
        ("ARCHITECTURE_ALLOWED", ARCHITECTURE_ALLOWED),
        ("PENDING_EDGES", PENDING_EDGES),
        ("ARCHITECTURE_TCB", ARCHITECTURE_TCB),
    ] {
        for (from, to) in rows {
            if from == to && plugin_kinds.contains(from) {
                offenders.push(format!(
                    "granted-self-edge\t{table}\t`({from}, {to})` grants one of the seven plugin \
                     kinds an edge to ITSELF. #40(a) bans `closure ∩ {{… any other plugin}}`, and \
                     a same-kind edge is exactly that intersection: the class cannot be granted \
                     wholesale here, because a granted class is a rule that cannot fail. If one \
                     instance of it is legitimate it owes a REVIEWED ROW naming the two crates, \
                     not a blanket grant covering every pair the kind will ever have."
                ));
            }
        }
    }

    let (census, dev) = census_graphs(cx, crates);
    let census_crates = census.len();
    if census_crates < MIN_GRAPH_CRATES {
        return Row::fail(
            ROW_CLOSURE,
            "the closure could not be walked over this tree",
            format!(
                "the census carried {census_crates} crate(s), under the floor of \
                 {MIN_GRAPH_CRATES}. A closure walked over a graph this small satisfies every \
                 dependency ban vacuously, and a ban satisfied vacuously is not a ban."
            ),
        );
    }

    // THE CORROBORATION. See this module's own note for why cargo is the check and not the claim,
    // and why an overlaid tree is not asked.
    let mut corroborated = "not asked (the tree is overlaid)".to_string();
    if cx.overlay().is_none() {
        match cargo_graph(cx) {
            Ok(cargo) => {
                let known: BTreeSet<&str> = census.keys().map(String::as_str).collect();
                let mut disagreements: Vec<String> = Vec::new();
                let mut checked = 0usize;
                for (from, tos) in &census {
                    let Some(theirs) = cargo.get(from) else {
                        disagreements.push(format!(
                            "`cargo metadata` does not carry `{from}` at all, and the census does"
                        ));
                        continue;
                    };
                    for to in tos.keys() {
                        checked += 1;
                        if !theirs.contains(to) {
                            disagreements.push(format!(
                                "the census reads `{from} -> {to}` and `cargo metadata` does not"
                            ));
                        }
                    }
                }
                for (from, tos) in &cargo {
                    if !known.contains(from.as_str()) {
                        continue;
                    }
                    for to in tos {
                        if !known.contains(to.as_str()) {
                            continue;
                        }
                        if !census.get(from).is_some_and(|m| m.contains_key(to)) {
                            disagreements.push(format!(
                                "`cargo metadata` reads `{from} -> {to}` and the census does not — \
                                 the manifest reader has a blind spot exactly the width of this edge"
                            ));
                        }
                    }
                }
                disagreements.sort();
                disagreements.dedup();
                if disagreements.is_empty() {
                    corroborated = format!("`cargo metadata` agrees, edge for edge ({checked})");
                } else {
                    corroborated = format!("{} DISAGREEMENT(S)", disagreements.len());
                    for d in disagreements {
                        offenders.push(format!(
                            "closure-graph-disagreement\tcargo metadata\t{d}. This row walks the \
                             census and `cargo metadata` checks it; when the two differ, one of \
                             them is reading an edge the other cannot see and neither answer is \
                             evidence about a wall."
                        ));
                    }
                }
            }
            Err(why) => {
                corroborated = "UNREADABLE".to_string();
                offenders.push(format!(
                    "closure-unverified\tcargo metadata\t{why}. #40(a) names `cargo metadata` as \
                     this wall's instrument; a run of it that did not resolve is a closure that is \
                     UNPROVEN rather than clean, and an unproven closure passes every ban in this \
                     row by saying nothing."
                ));
            }
        }
    }

    // THE WALL, CRATE BY CRATE.
    let mut plugins = 0usize;
    let mut held = 0usize;
    let mut memberships_default = 0usize;
    let mut memberships_union = 0usize;
    let mut transitive_only = 0usize;
    let mut test_only = 0usize;
    for c in crates {
        let Some(kind) = c.kind else { continue };
        if !plugin_kinds.contains(kind) {
            continue;
        }
        plugins += 1;
        let unconditional = walk(&census, &c.name, true);
        let union = walk(&census, &c.name, false);
        let mut breached = false;
        for reached in union.keys() {
            if reached == CONTRACT {
                continue;
            }
            breached = true;
            memberships_union += 1;
            let switched = !unconditional.contains_key(reached);
            if !switched {
                memberships_default += 1;
            }
            let path = unconditional
                .get(reached)
                .unwrap_or_else(|| &union[reached]);
            if path.len() > 1 {
                transitive_only += 1;
            }
            let hops: Vec<String> = path.iter().map(Hop::cite).collect();
            let reach = if path.len() == 1 {
                "DIRECT".to_string()
            } else {
                format!(
                    "TRANSITIVE, {} hops — `{}` names it in no manifest of its own",
                    path.len(),
                    c.name
                )
            };
            let switch = if switched {
                let which: Vec<&str> = path
                    .iter()
                    .filter(|h| h.optional)
                    .flat_map(|h| h.features.iter().map(String::as_str))
                    .collect();
                if which.is_empty() {
                    " FEATURE-GATED: the path crosses an `optional = true` edge, so this \
                     membership is live whenever that feature is on."
                        .to_string()
                } else {
                    format!(
                        " FEATURE-GATED: live whenever `{}` is on. A feature is a switch on an \
                         edge, not the absence of one — #40(a) is a statement about the closure, \
                         not about the default closure.",
                        which.join("`/`")
                    )
                }
            } else {
                " UNCONDITIONAL: no feature has to be on.".to_string()
            };
            offenders.push(format!(
                "closure-breach\t{} -> {}\t#40(a) (BUSBAR-1.6.0.md:364, OWNER-LOCKED): `{}`'s \
                 ENTIRE workspace dependency closure must be `{CONTRACT}` and nothing else, and it \
                 reaches `{}` — {}. {reach}. PATH: {}.{switch} Cut a hop, or the crate cannot be \
                 dropped in from a published contract alone.",
                c.name,
                reached,
                c.name,
                reached,
                banned_set(reached),
                hops.join(" | ")
            ));
        }
        if !breached {
            held += 1;
        }

        // THE TEST HALF OF THE BUILD GRAPH, WALKED — because a line that moves between two tables
        // is not a wall that moved.
        //
        // `:test-deps` scores the DECLARATIONS in `[dev-dependencies]`, and nothing walked what
        // they reach. The difference is the same one that produced this whole row: a crate's test
        // binary links its dev-dependencies' ENTIRE SHIPPED CLOSURES, so a plugin whose artifact
        // is clean can still compile against the kernel in `cargo test`, and every rule in this
        // gate would agree it was clean.
        //
        // THIS IS NOT REPORTED AS A #40(a) BREACH, and the distinction is the honest one: #40(a) is
        // about what a third party LINKS, a dev-dependency is absent from every release build, and
        // a rule that scored the two the same would tell a crate to delete the battery that proves
        // it works. It is reported because it is the ONLY place the reach is visible, and because
        // "which table the line is in" is a one-line edit while "the wall moved" is not.
        let mut test_reach: BTreeMap<String, Vec<Hop>> = BTreeMap::new();
        for (first, edge) in dev.get(&c.name).into_iter().flatten() {
            let root = Hop {
                from: c.name.clone(),
                to: first.clone(),
                optional: edge.optional,
                features: edge.features.clone(),
            };
            test_reach
                .entry(first.clone())
                .or_insert_with(|| vec![root.clone()]);
            for (onward, path) in walk(&census, first, false) {
                let mut full = vec![root.clone()];
                full.extend(path);
                test_reach.entry(onward).or_insert(full);
            }
        }
        for (reached, path) in &test_reach {
            if reached == CONTRACT || reached == &c.name || union.contains_key(reached) {
                continue;
            }
            let set = banned_set(reached);
            if set == "not `busbar-contract`"
                || set == "not `busbar-contract` (and matches no kind)"
            {
                continue;
            }
            test_only += 1;
            let hops: Vec<String> = path.iter().map(Hop::cite).collect();
            offenders.push(format!(
                "closure-test-reach\t{} -> {}\t`{}`'s SHIPPED closure does not carry `{}` and its \
                 `cargo test` build graph does — {}. A dev-dependency's own SHIPPED closure is \
                 linked into the test binary whole, so the reach is {} hop(s) deep and `:test-deps` \
                 scores only the first of them. PATH (hop 1 is `[dev-dependencies]`): {}. This is \
                 NOT a #40(a) artifact breach — a dev edge is absent from every release build — and \
                 it is the one place the reach is written down, because moving a line between two \
                 tables is a one-line edit and moving a wall is not.",
                c.name,
                reached,
                c.name,
                reached,
                set,
                path.len(),
                hops.join(" | ")
            ));
        }
    }

    let headline = format!(
        "{plugins} plugin-kind crate(s) over {census_crates} censused crate(s): {held} hold the \
         wall, {} breach it; {memberships_union} closure membership(s) beyond `{CONTRACT}` under \
         the union of feature configurations, {memberships_default} of them unconditional, \
         {transitive_only} reachable only through another crate; {test_only} more that only the \
         `cargo test` graph reaches; corroboration: {corroborated}",
        plugins - held
    );

    offenders.sort();
    offenders.dedup();
    if offenders.is_empty() {
        return Row::pass(
            ROW_CLOSURE,
            "every plugin crate's whole dependency closure is busbar-contract and nothing else",
            headline,
        );
    }
    Row::fail(
        ROW_CLOSURE,
        "a plugin crate's dependency closure reaches past busbar-contract",
        format!(
            "{} finding(s), {headline}: {}",
            offenders.len(),
            offenders.join(" | ")
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(edges: &[(&str, &str, bool, &[&str])]) -> Graph {
        let mut out: Graph = BTreeMap::new();
        for (from, to, optional, features) in edges {
            out.entry((*from).to_string()).or_default().insert(
                (*to).to_string(),
                Edge {
                    optional: *optional,
                    features: features.iter().map(|s| (*s).to_string()).collect(),
                },
            );
        }
        out
    }

    /// THE WHOLE POINT OF THE ROW: a crate two hops away is in the closure, and the path says so.
    #[test]
    fn a_crate_two_hops_away_is_in_the_closure_and_the_path_names_both_hops() {
        let graph = g(&[
            ("busbar-transport-ws", "busbar-transport-http", false, &[]),
            ("busbar-transport-http", "busbar-transport-tls", false, &[]),
            (
                "busbar-transport-tls",
                "busbar-unit-transport-key",
                false,
                &[],
            ),
        ]);
        let reached = walk(&graph, "busbar-transport-ws", false);
        let path = &reached["busbar-unit-transport-key"];
        assert_eq!(
            path.len(),
            3,
            "three hops, and the wall is breached at none of the manifests ws itself writes"
        );
        assert_eq!(
            path.iter().map(Hop::cite).collect::<Vec<_>>().join(" | "),
            "busbar-transport-ws -> busbar-transport-http | busbar-transport-http -> \
             busbar-transport-tls | busbar-transport-tls -> busbar-unit-transport-key"
        );
    }

    /// AND THE DIRECT-EDGE READING MISSES IT. This is F17 in one assertion.
    #[test]
    fn the_direct_edge_reading_does_not_carry_the_transitive_member() {
        let graph = g(&[
            ("busbar-transport-ws", "busbar-transport-http", false, &[]),
            (
                "busbar-transport-http",
                "busbar-unit-transport-key",
                false,
                &[],
            ),
        ]);
        let direct: Vec<&str> = graph["busbar-transport-ws"]
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(direct, ["busbar-transport-http"]);
        assert!(
            walk(&graph, "busbar-transport-ws", false).contains_key("busbar-unit-transport-key")
        );
    }

    /// A SWITCHED EDGE IS AN EDGE. The union walk carries it; the unconditional walk does not.
    #[test]
    fn an_optional_hop_is_in_the_union_closure_and_out_of_the_unconditional_one() {
        let graph = g(&[
            ("plugin", "busbar-plugin-sdk", false, &[]),
            ("busbar-plugin-sdk", "busbar-plugin-loader", true, &["pack"]),
            ("busbar-plugin-loader", "busbar-kernel-ledger", false, &[]),
        ]);
        assert!(!walk(&graph, "plugin", true).contains_key("busbar-kernel-ledger"));
        let union = walk(&graph, "plugin", false);
        let path = &union["busbar-kernel-ledger"];
        assert!(path.iter().any(|h| h.optional && h.features == ["pack"]));
        assert!(path[1]
            .cite()
            .contains("-*> busbar-plugin-loader (feature `pack`)"));
    }

    /// THE UNCONDITIONAL ROUTE IS PREFERRED, so the reader is not sent after a switch that is not
    /// on the path they have to cut.
    #[test]
    fn a_crate_reachable_both_ways_is_reported_by_the_route_with_no_switch() {
        let graph = g(&[
            ("a", "b", false, &[]),
            ("b", "z", false, &[]),
            ("a", "z", true, &["extra"]),
        ]);
        let unconditional = walk(&graph, "a", true);
        assert_eq!(unconditional["z"].len(), 2);
        assert!(unconditional["z"].iter().all(|h| !h.optional));
    }

    /// A SECOND, PLAIN DECLARATION TAKES THE SWITCH OFF AN EDGE.
    #[test]
    fn an_edge_declared_twice_is_optional_only_when_every_declaration_is() {
        let mut e = Edge {
            optional: true,
            features: vec!["pack".into()],
        };
        e.optional &= false;
        assert!(!e.optional);
    }

    /// EVERY FEATURE SPELLING CARGO ACCEPTS IS READ.
    #[test]
    fn a_feature_switches_a_dependency_by_every_spelling() {
        let mut t: BTreeMap<String, Vec<String>> = BTreeMap::new();
        t.insert("pack".into(), vec!["dep:busbar-plugin-loader".into()]);
        t.insert("implicit".into(), vec!["busbar-plugin-loader".into()]);
        t.insert("slash".into(), vec!["busbar-plugin-loader/std".into()]);
        t.insert("elsewhere".into(), vec!["dep:serde".into()]);
        assert_eq!(
            switches(&t, "busbar-plugin-loader", "busbar-plugin-loader"),
            ["implicit", "pack", "slash"]
        );
    }

    /// A RENAMED OPTIONAL DEPENDENCY IS SWITCHED ON BY THE WORD THE MANIFEST WROTE.
    #[test]
    fn a_renamed_optional_dependency_is_switched_by_its_key() {
        let mut t: BTreeMap<String, Vec<String>> = BTreeMap::new();
        t.insert("wire".into(), vec!["dep:loader".into()]);
        assert_eq!(switches(&t, "loader", "busbar-plugin-loader"), ["wire"]);
    }

    /// #40(a)'s FOUR NAMED SETS, each recognised by the kind table rather than by a second list.
    #[test]
    fn the_banned_sets_are_named_in_the_rules_own_words() {
        assert_eq!(banned_set("busbar-kernel-ledger"), "THE KERNEL");
        assert_eq!(banned_set("busbar-core-admin"), "a `core-*` crate");
        assert_eq!(
            banned_set("busbar-secret-example-plugin"),
            "a secret implementation"
        );
        assert_eq!(banned_set("busbar-transport-tcp"), "another plugin");
        assert_eq!(banned_set("busbar-api"), "not `busbar-contract`");
    }

    /// NO PLUGIN KIND IS GRANTED AN EDGE TO ITSELF, in any of the three class tables. The rule
    /// above reports one; this refuses one landing.
    #[test]
    fn no_class_table_grants_a_plugin_kind_an_edge_to_itself() {
        for (table, rows) in [
            ("ARCHITECTURE_ALLOWED", ARCHITECTURE_ALLOWED),
            ("PENDING_EDGES", PENDING_EDGES),
            ("ARCHITECTURE_TCB", ARCHITECTURE_TCB),
        ] {
            for (from, to) in rows {
                assert!(
                    !(from == to && PLUGIN_KINDS.contains(from)),
                    "{table} grants `{from} -> {to}`, a plugin kind naming itself — #40(a) bans \
                     `closure ∩ {{any other plugin}}`"
                );
            }
        }
    }

    /// THE FALSE ZERO, CONTROLLED. A `cargo metadata` that resolved almost nothing is an ERROR,
    /// never a clean graph: an empty closure satisfies every dependency ban vacuously, and a
    /// subprocess that half-ran is exactly how a wall reports itself standing over nothing.
    #[test]
    fn a_metadata_graph_under_the_floor_is_refused_rather_than_read_as_clean() {
        let tiny = r#"{"packages":[{"name":"busbar-contract","dependencies":[]}]}"#;
        let err = graph_from_metadata(tiny).expect_err("one package is not this workspace");
        assert!(err.contains("under the floor"), "{err}");
        assert!(err.contains("vacuously"), "{err}");
    }

    /// AND A DEV EDGE IS NOT A SHIPPED EDGE — `cargo metadata`'s own `kind` field is read, so the
    /// corroboration compares the same half of the graph the census walks.
    #[test]
    fn the_metadata_reader_takes_the_shipped_half_and_leaves_the_test_half() {
        let mut pkgs: Vec<String> = (0..MIN_GRAPH_CRATES)
            .map(|i| format!(r#"{{"name":"filler-{i}","dependencies":[]}}"#))
            .collect();
        pkgs.push(
            r#"{"name":"busbar-transport-tls","dependencies":[
                 {"name":"filler-0"},
                 {"name":"filler-1","kind":"dev"},
                 {"name":"filler-2","kind":"build"},
                 {"name":"serde"}]}"#
                .to_string(),
        );
        let json = format!(r#"{{"packages":[{}]}}"#, pkgs.join(","));
        let g = graph_from_metadata(&json).expect("the floor is cleared");
        let row: Vec<&str> = g["busbar-transport-tls"]
            .iter()
            .map(String::as_str)
            .collect();
        assert_eq!(
            row,
            ["filler-0", "filler-2"],
            "the dev edge is out, the build edge is in, and `serde` is not a workspace member"
        );
    }
}
