// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ADMIN ROUTE MATRIX IS SPELLED SIX TIMES, AND THIS IS THE CELL THAT SAYS THEY AGREE.
//!
//! One matrix — `(method, path) -> (verb, operation id, required scope, mutation class)` — is
//! transcribed in six places, in five crates, across four kinds:
//!
//! | # | spelling | file | shape |
//! | --- | --- | --- | --- |
//! | 1 | the CONTROL crate's table | `crates/busbar-plane-admin/src/generated/verb_table_1_5_5.rs` | 66 rows `(method, path, verb, read_only)` |
//! | 2 | the SCOPE table | `crates/busbar-unit-scope/src/lib.rs` (`ADMIN_SCOPE_TABLE`) | 66 rows `(method, path, scope)` |
//! | 3 | the VERB EXECUTOR's table | `crates/busbar-unit-verbs/src/verb.rs` (`LEGACY_VERBS`) | 66 rows `(verb, method, path, operation id)` |
//! | 4 | the OPENAPI GENERATOR's path list | `crates/busbar-core/src/admin/v1/json/openapi.json` | 81 operations over 60 paths, each carrying `x-busbar-required-scope` and `operationId` |
//! | 5 | the AXUM ROUTER's route literals | `crates/busbar-core/src/admin/v1/json/mod.rs` | the operations the adapter frame spells as literals |
//! | 6 | the MUTATION-CLASS carve-outs | `crates/busbar-unit-verbs/src/rate.rs` (`CONFIG_CLASS_RULES`) | 6 rules over `ADMIN_PREFIX`-relative paths |
//!
//! They agree today. Nothing makes them agree — no crate reads another's copy, and the kind rules
//! are why: `unit -> control` and `unit -> plane` are not edges the architecture grants, so the two
//! unit crates CANNOT read the control crate's table even though the control kind's declared open
//! vocabulary is *"its route table as data"*. Until the control seat exists, agreement is a
//! property of six independent transcriptions, which is a property that holds until someone edits
//! one of them.
//!
//! So this cell reads all six OFF DISK and asserts the one matrix. It is deliberately not a test
//! inside any of the five crates: the vocabulary matrix counts what a crate under `crates/` names,
//! and a cell that has to name four kinds at once would move four cells to be written. `xtask` is
//! outside `crates/`, so it is the one place the whole matrix is readable at zero cost — and a
//! cross-kind agreement cell belongs where the cross-kind view is legal, not where it is cheapest.
//!
//! WHEN THE COLLAPSE LANDS this file shrinks rather than dies: the rows that read a deleted copy go
//! with the copy, and what is left is the declaration against the two spellings that outlive it (the
//! served document, which is byte-pinned, and the router literals, which die with `App`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use xtask::json_lite::{self, Json};

/// The frozen Admin API v1 prefix. Spelled once here because this file compares ABSOLUTE paths from
/// four spellings against RELATIVE paths from two, and the join has to happen somewhere.
const ADMIN_PREFIX: &str = "/api/v1/admin";

/// The named-DEFINITION map section roots whose routes the adapter frame DERIVES rather than
/// spells: `named_map::routes()` loops `NamedMapSection::sections()` and mounts five routes per
/// section, so a section's operations are in the served document and in no route literal. Naming
/// them is what lets the router row below assert a SUBSET relation and still say what the gap is,
/// instead of pinning a count nobody can read.
const DERIVED_SECTION_ROOTS: &[&str] = &["export", "identity-providers", "tools", "agents"];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask/ has a parent")
        .to_path_buf()
}

fn read(rel: &str) -> String {
    let p = repo_root().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// The body of `<name> ... = &[ ... ];` with line comments stripped.
///
/// The slice bodies this file reads carry section comments (`// ---- config ----`) and, in one
/// case, prose about the rows; a comment that happens to hold a quote would otherwise be read as a
/// row. Block comments do not appear in any of them and are not handled, so a future one is a
/// parse failure rather than a silent misread — which is the direction this cell wants to fail in.
fn slice_body(src: &str, name: &str) -> String {
    let start = src
        .find(name)
        .unwrap_or_else(|| panic!("`{name}` is gone — the spelling it names moved or died"));
    let open = src[start..]
        .find("= &[")
        .unwrap_or_else(|| panic!("`{name}` is no longer a slice literal"))
        + start
        + "= &[".len();
    let end = src[open..]
        .find("\n];")
        .unwrap_or_else(|| panic!("`{name}` has no closing `\n];`"))
        + open;
    strip_line_comments(&src[open..end])
}

fn strip_line_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for line in s.lines() {
        let mut in_str = false;
        let mut cut = line.len();
        let b = line.as_bytes();
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'"' => in_str = !in_str,
                b'/' if !in_str && i + 1 < b.len() && b[i + 1] == b'/' => {
                    cut = i;
                    break;
                }
                b'\\' if in_str => i += 1,
                _ => {}
            }
            i += 1;
        }
        out.push_str(&line[..cut]);
        out.push('\n');
    }
    out
}

/// Every double-quoted literal in `s`, in source order. None of the rows this file reads carries an
/// escape, so a backslash is passed through rather than decoded — and a row that grows one will
/// mismatch loudly instead of being half-read.
fn string_literals(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'"' {
            let start = i + 1;
            let mut j = start;
            while j < b.len() && b[j] != b'"' {
                if b[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            out.push(s[start..j.min(b.len())].to_string());
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

// ------------------------------------------------------------------------------------------------
// the six spellings
// ------------------------------------------------------------------------------------------------

/// The row every spelling is compared as: the two halves of an operation's identity.
type Op = (String, String);

fn op(method: &str, path: &str) -> Op {
    (method.to_string(), path.to_string())
}

/// SPELLING 1 — the control crate's table: `(method, path) -> (verb, read_only)`.
fn control_claim() -> BTreeMap<Op, (String, bool)> {
    let src = read("crates/busbar-plane-admin/src/generated/verb_table_1_5_5.rs");
    let body = slice_body(&src, "VERB_TABLE_1_5_5");
    let lits = string_literals(&body);
    assert_eq!(
        lits.len() % 3,
        0,
        "the control claim's rows are `(method, path, verb, read_only)` — {} literals is not a \
         whole number of rows",
        lits.len()
    );
    // The trailing `bool` of each row, in source order: the only `true`/`false` tokens in the body.
    let flags: Vec<bool> = body
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter_map(|t| match t {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })
        .collect();
    assert_eq!(
        flags.len() * 3,
        lits.len(),
        "one `read_only` flag per row is what makes the read/write split readable"
    );
    lits.chunks(3)
        .zip(flags)
        .map(|(row, ro)| (op(&row[0], &row[1]), (row[2].clone(), ro)))
        .collect()
}

/// SPELLING 2 — the scope table: `(method, path) -> scope`.
fn scope_table() -> BTreeMap<Op, String> {
    let src = read("crates/busbar-unit-scope/src/lib.rs");
    let body = slice_body(&src, "pub static ADMIN_SCOPE_TABLE");
    let lits = string_literals(&body);
    let scopes: Vec<&str> = body
        .match_indices("Scope::")
        .map(|(i, _)| {
            let rest = &body[i + "Scope::".len()..];
            let end = rest
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(rest.len());
            &rest[..end]
        })
        .collect();
    assert_eq!(
        lits.len(),
        scopes.len() * 2,
        "the scope table's rows are `op(method, path, Scope::_)`"
    );
    lits.chunks(2)
        .zip(scopes)
        .map(|(row, sc)| (op(&row[0], &row[1]), sc.to_string()))
        .collect()
}

/// SPELLING 3 — the verb executor's table: `(method, path) -> (verb ident, operation id)`.
fn verb_executor_table() -> BTreeMap<Op, (String, String)> {
    let src = read("crates/busbar-unit-verbs/src/verb.rs");
    let body = slice_body(&src, "pub const LEGACY_VERBS");
    let mut out = BTreeMap::new();
    for row in body.split("legacy_row!(").skip(1) {
        let ident: String = row
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let lits = string_literals(&row[..row.find(')').unwrap_or(row.len())]);
        assert_eq!(
            lits.len(),
            3,
            "`legacy_row!` is `(verb, method, path, operation_id)` — `{ident}` reads {lits:?}"
        );
        out.insert(op(&lits[0], &lits[1]), (ident, lits[2].clone()));
    }
    out
}

/// SPELLING 4 — the openapi generator's path list, read through its committed output.
///
/// The generator itself is `#[cfg(feature = "openapi-schema")]` and is not in the shipped binary;
/// what ships is the embedded twin of this file. The two in-tree byte-identity tests
/// (`openapi_json_matches_committed_file`, `served_openapi_equals_committed_file`) are what make
/// reading the committed file a faithful read of the generator AND of the served document, so this
/// cell reads the file and does not need the feature.
fn served_document() -> BTreeMap<Op, (String, String)> {
    let src = read("crates/busbar-core/src/admin/v1/json/openapi.json");
    let doc = json_lite::parse(&src).expect("the committed openapi document parses");
    let paths = doc
        .as_object()
        .and_then(|o| o.get("paths"))
        .and_then(Json::as_object)
        .expect("the committed openapi document has a `paths` object");
    let mut out = BTreeMap::new();
    for (path, item) in paths.iter() {
        let methods = item.as_object().expect("a path item is an object");
        for (method, operation) in methods.iter() {
            let m = method.to_ascii_uppercase();
            if !matches!(m.as_str(), "GET" | "PUT" | "POST" | "PATCH" | "DELETE") {
                continue;
            }
            let o = operation.as_object().expect("an operation is an object");
            let scope = o
                .get("x-busbar-required-scope")
                .and_then(Json::as_str)
                .unwrap_or_else(|| panic!("{m} {path} carries no `x-busbar-required-scope`"))
                .to_string();
            let id = o
                .get("operationId")
                .and_then(Json::as_str)
                .unwrap_or_else(|| panic!("{m} {path} carries no `operationId`"))
                .to_string();
            out.insert(op(&m, path), (id, scope));
        }
    }
    out
}

/// SPELLING 5 — the operations the axum adapter frame spells as ROUTE LITERALS.
///
/// `named_map::routes()` derives its five-per-section routes from the section registry and
/// `mount_plane_admin_routes` contributes the planes' trust verbs, so this set is the frame's
/// literals and nothing else — which is exactly the spelling that would drift if someone added a
/// route here and nowhere else.
fn router_literals() -> BTreeSet<Op> {
    let consts_src = read("crates/busbar-core/src/admin/v1/contract/mod.rs");
    let mut consts: BTreeMap<String, String> = BTreeMap::new();
    for line in consts_src.lines() {
        let Some(rest) = line.trim().strip_prefix("pub(crate) const PATH_") else {
            continue;
        };
        let name = format!(
            "PATH_{}",
            rest.chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect::<String>()
        );
        if let Some(v) = string_literals(line).first() {
            consts.insert(name, v.clone());
        }
    }

    let src = read("crates/busbar-core/src/admin/v1/json/mod.rs");
    let start = src
        .find("let router = Router::new()")
        .expect("the adapter frame still builds one router");
    let end = src[start..]
        .find(".method_not_allowed_fallback")
        .expect("the frame still closes with the envelope fallbacks")
        + start;
    let body = strip_line_comments(&src[start..end]);

    let mut out = BTreeSet::new();
    let mut pos = 0;
    while let Some(j) = body[pos..].find(".route(") {
        let open = pos + j + ".route(".len();
        let mut depth = 1usize;
        let mut k = open;
        let b = body.as_bytes();
        while depth > 0 && k < b.len() {
            match b[k] {
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
            k += 1;
        }
        let arg = &body[open..k.saturating_sub(1)];
        pos = k;

        // The first argument is the path expression; the rest is the method router.
        let mut depth = 0i32;
        let split = arg
            .char_indices()
            .find(|&(_, c)| {
                match c {
                    '(' | '[' | '{' => depth += 1,
                    ')' | ']' | '}' => depth -= 1,
                    _ => {}
                }
                c == ',' && depth == 0
            })
            .map(|(i, _)| i)
            .unwrap_or(arg.len());
        let (path_expr, methods) = arg.split_at(split);
        let path_expr = path_expr.trim();
        let path = if path_expr.starts_with('"') {
            string_literals(path_expr)
                .into_iter()
                .next()
                .expect("a quoted path expression holds one literal")
        } else if let Some(v) = consts.get(path_expr) {
            v.clone()
        } else {
            panic!(
                "the adapter frame mounts `{path_expr}`, which is neither a path literal nor a \
                 `PATH_*` constant this cell can resolve — a route the cell cannot read is a \
                 spelling it cannot compare"
            );
        };

        for name in ["get", "post", "put", "patch", "delete"] {
            if method_called(methods, name) {
                out.insert(op(
                    &name.to_ascii_uppercase(),
                    &format!("{ADMIN_PREFIX}{path}"),
                ));
            }
        }
    }
    out
}

/// Whether `haystack` calls the axum method-router constructor `name` — as a bare `name(`, as
/// `.name(`, or fully qualified as `axum::routing::name(`, which the frame uses for the two routes
/// whose bare name would collide with a handler's.
fn method_called(haystack: &str, name: &str) -> bool {
    haystack.match_indices(name).any(|(i, _)| {
        let after = haystack[i + name.len()..].trim_start();
        if !after.starts_with('(') {
            return false;
        }
        let before = haystack[..i].chars().next_back();
        !matches!(before, Some(c) if c.is_ascii_alphanumeric() || c == '_')
    })
}

/// SPELLING 6 — the mutation-class carve-outs, as `ADMIN_PREFIX`-relative match rules.
///
/// `Exact`/`Prefix` are literals; `NamedMapRoot` is not in the constant at all (the composition
/// root folds the declared section keys in at boot), so the six frozen rows are what a file read
/// can see and are what this cell holds.
fn mutation_class_carve_outs() -> Vec<(String, String)> {
    let src = read("crates/busbar-unit-verbs/src/rate.rs");
    let body = slice_body(&src, "pub const CONFIG_CLASS_RULES");
    let mut out = Vec::new();
    for row in body.split("ConfigClassRule::").skip(1) {
        let kind: String = row
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        let lit = string_literals(&row[..row.find(')').map_or(row.len(), |i| i + 1)])
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("`ConfigClassRule::{kind}` carries no path literal"));
        out.push((kind, lit));
    }
    out
}

// ------------------------------------------------------------------------------------------------
// the cell
// ------------------------------------------------------------------------------------------------

/// `read_only` and `Scope::ReadOnly` and `"read-only"` are three spellings of one rung. This is the
/// only place the three are equated, so a spelling that grows a third rung fails here first.
fn rung(read_only: bool) -> &'static str {
    if read_only {
        "read-only"
    } else {
        "full"
    }
}

#[test]
fn the_control_claim_and_the_scope_table_are_one_matrix() {
    let claim = control_claim();
    let scope = scope_table();

    let claim_ops: BTreeSet<Op> = claim.keys().cloned().collect();
    let scope_ops: BTreeSet<Op> = scope.keys().cloned().collect();
    assert_eq!(
        claim_ops, scope_ops,
        "the control crate's table and the scope table name different operations — one matrix, \
         two spellings, and they have drifted"
    );
    assert_eq!(claim.len(), 66, "the pinned 1.5.5 tag is 66 operations");

    for (o, (_verb, read_only)) in &claim {
        let want = if *read_only { "ReadOnly" } else { "Full" };
        assert_eq!(
            scope[o],
            want,
            "{} {}: the control claim reads `{}` and the scope table reads `Scope::{}`",
            o.0,
            o.1,
            rung(*read_only),
            scope[o]
        );
    }
}

#[test]
fn the_control_claim_and_the_verb_executor_table_are_one_matrix() {
    let claim = control_claim();
    let verbs = verb_executor_table();

    let claim_ops: BTreeSet<Op> = claim.keys().cloned().collect();
    let verb_ops: BTreeSet<Op> = verbs.keys().cloned().collect();
    assert_eq!(
        claim_ops, verb_ops,
        "the control crate decodes a request into a verb and the unit executes that verb — the \
         two tables of what the verbs ARE have drifted"
    );

    // The control crate spells the verb snake-case (the pinned tag's `operationId`, lowered); the
    // executor spells it as a `KernelVerb` variant and carries the tag's `operationId` verbatim.
    // Same name, two casings, and this is where they are held to it.
    for (o, (verb, _)) in &claim {
        let (ident, operation_id) = &verbs[o];
        assert_eq!(
            ident, operation_id,
            "{} {}: the executor's variant and its pinned `operationId` disagree",
            o.0, o.1
        );
        assert_eq!(
            verb,
            &pascal_to_snake(ident),
            "{} {}: the control crate decodes to `{verb}` and the unit executes `{ident}`",
            o.0,
            o.1
        );
    }
}

fn pascal_to_snake(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i != 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[test]
fn the_control_claim_and_the_served_document_are_one_matrix() {
    let claim = control_claim();
    let served = served_document();
    let verbs = verb_executor_table();

    // The served document carries the 66 AND the 15 named-map operations the control crate does not
    // claim (`tools:`/`agents:` — served by the legacy adapter alone). So the claim is a SUBSET, and
    // the gap is named rather than counted.
    for (o, (verb, read_only)) in &claim {
        let (id, scope) = served.get(o).unwrap_or_else(|| {
            panic!(
                "{} {}: the control crate claims an operation the served document does not \
                 describe",
                o.0, o.1
            )
        });
        assert_eq!(
            scope,
            rung(*read_only),
            "{} {}: the served `x-busbar-required-scope` is `{scope}` and the control claim reads \
             `{}`",
            o.0,
            o.1,
            rung(*read_only)
        );
        assert_eq!(
            verb,
            &pascal_to_snake(id),
            "{} {}: the served `operationId` is `{id}` and the control claim decodes to `{verb}`",
            o.0,
            o.1
        );
        assert_eq!(&verbs[o].1, id, "{} {}: `operationId` drift", o.0, o.1);
    }

    let unclaimed: BTreeSet<&Op> = served.keys().filter(|o| !claim.contains_key(*o)).collect();
    for o in &unclaimed {
        let rel = o.1.strip_prefix(ADMIN_PREFIX).unwrap_or(&o.1);
        let root = rel.trim_start_matches('/').split('/').next().unwrap_or("");
        assert!(
            DERIVED_SECTION_ROOTS.contains(&root),
            "{} {}: the served document describes an operation the control crate does not claim \
             and that is not a named-map section — the 15 unclaimed operations are the named-map \
             surface and nothing else",
            o.0,
            o.1
        );
    }
    assert_eq!(
        unclaimed.len(),
        15,
        "the served document is 81 operations: the 66 the control crate claims and the 15 \
         named-map operations that bypass it"
    );
}

#[test]
fn the_axum_router_spells_no_route_the_claim_does_not_declare() {
    let served = served_document();
    let literals = router_literals();
    assert!(
        !literals.is_empty(),
        "the adapter frame spells no route literal at all — this cell stopped reading the router \
         rather than the router stopped having one"
    );

    for o in &literals {
        assert!(
            served.contains_key(o),
            "{} {}: the adapter frame mounts a route the served document does not describe",
            o.0,
            o.1
        );
    }

    // The other direction is a subset by construction, and the gap must be exactly the operations
    // the frame DERIVES: five routes per named-map section, plus the planes' trust verbs, which are
    // contributed through the registry and carry no literal here either.
    for o in served.keys().filter(|o| !literals.contains(*o)) {
        let rel = o.1.strip_prefix(ADMIN_PREFIX).unwrap_or(&o.1);
        let root = rel.trim_start_matches('/').split('/').next().unwrap_or("");
        assert!(
            DERIVED_SECTION_ROOTS.contains(&root),
            "{} {}: the served document describes an operation the adapter frame neither spells \
             nor derives from the section registry",
            o.0,
            o.1
        );
    }
}

#[test]
fn every_mutation_class_carve_out_names_a_declared_mutating_route() {
    let served = served_document();
    let carve_outs = mutation_class_carve_outs();
    assert_eq!(
        carve_outs.len(),
        6,
        "the CONFIG-class blast-radius set is the six frozen rows; the named-map roots are folded \
         in by the composition root and are not in the constant"
    );

    for (kind, pattern) in &carve_outs {
        let matched: Vec<&Op> = served
            .keys()
            .filter(|o| {
                let rel = o.1.strip_prefix(ADMIN_PREFIX).unwrap_or(&o.1);
                match kind.as_str() {
                    "Exact" => rel == pattern,
                    "Prefix" => rel.starts_with(pattern.as_str()),
                    other => panic!("unknown `ConfigClassRule::{other}`"),
                }
            })
            .collect();
        assert!(
            matched.iter().any(|o| served[*o].1 == "full"),
            "`ConfigClassRule::{kind}({pattern})` matches no MUTATING operation in the served \
             document — a blast-radius carve-out over routes that only read is a budget nothing \
             spends"
        );
        // THE CARVE-OUTS ARE PATH-ONLY AND THE METHOD FILTER IS SOMEWHERE ELSE. `for_path` is not
        // told the caller's method; the enforcement chokepoint tests
        // `POST|PUT|PATCH|DELETE` before it asks. So a rule MAY cover a read — but only a read the
        // method filter removes (`GET`/`HEAD`), or one of the two mutation-method dry-runs the
        // classifier carves out by name. A read-only `POST` under a rule and NOT named by the
        // classifier would spend the operator's config budget for looking.
        for o in matched {
            if served[o].1 == "full" {
                continue;
            }
            let rel = o.1.strip_prefix(ADMIN_PREFIX).unwrap_or(&o.1);
            let removed_by_method = o.0 == "GET" || o.0 == "HEAD";
            let named_dry_run = rel == "/config/validate" || rel == "/plugins/inspect";
            assert!(
                removed_by_method || named_dry_run,
                "{} {}: `ConfigClassRule::{kind}({pattern})` covers a `read-only` operation that \
                 the method filter does not remove and the classifier does not name — a read that \
                 spends a mutation budget refuses the operator who looked before they wrote",
                o.0,
                o.1
            );
        }
    }
}
