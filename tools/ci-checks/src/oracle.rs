// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `oracle <sub> ...`: the data logic `bin/oracle` runs over the shadow-oracle corpus (BLD-6: no
//! Python; the shim launches, this decides). Each subcommand answers on its own stdout and stderr
//! with its own exit status, the ones the shim's callers already read:
//!
//! - `widen-filter <data> <filter>`: the filter plus every premise cell its accepted differences
//!   probe (`(?:<filter>)|^(?:<cells>)$`), or the filter unchanged; a premise naming a cell the
//!   corpus lacks, or a filter that is not a regex, is a refusal (3).
//! - `withheld <data> <engine log> <filter>`: 3, naming each, when a forgiveness the filter selected
//!   was withheld because its premise could not be evaluated.
//! - `shard-ids <data> <k> <n>`, `shard-filter <data> <k> <n>`: the ids shard k of n owns (the
//!   corpus's sorted ids, the i-th to shard i mod n + 1), or the anchored regex selecting exactly
//!   them; a k outside 1..n is refused (1).
//! - `shard-cover <data> <n>`: the n filters select every id exactly once (else 3).
//! - `shard-verify <data> <k> <n> <report dir>`: the shard's report selected every cell it owns
//!   (else 3).
//! - `shard-merge <data> <report dir>...`: green only for shards 1..N of one N, each once, each
//!   green, together every cell (else 1; no dir named: 2).
//! - `needs-store <data> <filter or "">`: `yes` when a selected cell needs a store backend.
//! - `busbar-version`: the version of the one package that builds the `busbar` binary, from
//!   `cargo metadata` on stdin.
//! - `line-builds <data> <line>`: `yes` when the line's plugins build from source
//!   (plugin-digests.tsv) and none of its rows is a released asset.
//! - `fence-filter <ledger.tsv>`: `^(<id>|...)$` over the ledger's first column.
//! - `only-rebaselined <data> <filter> <families>`: 0 when the filter selects a cell and every
//!   selected cell's family has a dated baseline of its own.
//! - `family-selected <data> <filter> <family>`: 0 when the filter selects a cell of the family.
//! - `report-owed <report.json>`: 0 when the replay's report compared at least one owed cell.
//! - `regex-search <regex> <text>...`: 0 when the regex finds a match in every text.
//! - `run <sub> ...`: `bin/oracle` itself, its whole argv (`oracle_run.rs`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Write as _};
use std::io::Read as _;
use std::path::Path;
use std::process::ExitCode;

use busbar_contract::json::{self, JsonContainerTrait, JsonValueTrait};
use regex::{Regex, RegexBuilder};

/// A parsed JSON document, read through the `busbar_contract::json` facade (DEP-3) and held as a
/// plain tree: the oracle's Python-faithful readers (`falsy`, `py_repr_value`) match on its shape.
/// A number keeps its lexeme; an object keeps its members in document order, the last of duplicate
/// keys (as the facade's `parse_value` keeps it).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Node {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Node>),
    Object(Vec<(String, Node)>),
}

impl Node {
    /// The member `key` of an object.
    pub(crate) fn get(&self, key: &str) -> Option<&Node> {
        match self {
            Node::Object(members) => members
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, member)| member),
            _ => None,
        }
    }

    /// The text of a string.
    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Node::String(text) => Some(text),
            _ => None,
        }
    }

    /// The items of an array.
    pub(crate) fn as_array(&self) -> Option<&Vec<Node>> {
        match self {
            Node::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The tree of a facade value.
    fn of(value: &json::Value) -> Node {
        if value.is_null() {
            Node::Null
        } else if let Some(flag) = value.as_bool() {
            Node::Bool(flag)
        } else if let Some(number) = value.as_raw_number() {
            Node::Number(String::from(number.as_str()))
        } else if let Some(text) = value.as_str() {
            Node::String(String::from(text))
        } else if let Some(items) = value.as_array() {
            Node::Array(items.iter().map(Node::of).collect())
        } else if let Some(members) = value.as_object() {
            Node::Object(
                members
                    .iter()
                    .map(|(key, member)| (String::from(key), Node::of(member)))
                    .collect(),
            )
        } else {
            Node::Null
        }
    }

    /// One JSON document, parsed.
    pub(crate) fn parse(text: &str) -> Result<Node, String> {
        json::parse_value(text.as_bytes())
            .map(|value| Node::of(&value))
            .map_err(|error| error.to_string())
    }
}

impl Display for Node {
    /// Compact JSON, as a value is printed in a message.
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Node::Null => out.write_str("null"),
            Node::Bool(flag) => write!(out, "{flag}"),
            Node::Number(lexeme) => out.write_str(lexeme),
            Node::String(text) => write_json_text(out, text),
            Node::Array(items) => {
                out.write_str("[")?;
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.write_str(",")?;
                    }
                    write!(out, "{item}")?;
                }
                out.write_str("]")
            }
            Node::Object(members) => {
                out.write_str("{")?;
                for (index, (key, member)) in members.iter().enumerate() {
                    if index > 0 {
                        out.write_str(",")?;
                    }
                    write_json_text(out, key)?;
                    write!(out, ":{member}")?;
                }
                out.write_str("}")
            }
        }
    }
}

/// A JSON string literal.
fn write_json_text(out: &mut std::fmt::Formatter<'_>, text: &str) -> std::fmt::Result {
    out.write_str("\"")?;
    for c in text.chars() {
        match c {
            '"' => out.write_str("\\\"")?,
            '\\' => out.write_str("\\\\")?,
            '\n' => out.write_str("\\n")?,
            '\r' => out.write_str("\\r")?,
            '\t' => out.write_str("\\t")?,
            '\u{8}' => out.write_str("\\b")?,
            '\u{c}' => out.write_str("\\f")?,
            c if u32::from(c) < 0x20 => write!(out, "\\u{:04x}", u32::from(c))?,
            c => write!(out, "{c}")?,
        }
    }
    out.write_str("\"")
}

/// The store backends a cell may need (`needs_fixture` names its URL variable).
const STORE_URLS: [&str; 3] = [
    "BUSBAR_TEST_POSTGRES_URL",
    "BUSBAR_TEST_MYSQL_URL",
    "VALKEY_URL",
];
/// The subcommands, for the usage line.
const SUBCOMMANDS: [&str; 16] = [
    "run",
    "widen-filter",
    "withheld",
    "shard-ids",
    "shard-filter",
    "shard-cover",
    "shard-verify",
    "shard-merge",
    "needs-store",
    "busbar-version",
    "line-builds",
    "fence-filter",
    "only-rebaselined",
    "family-selected",
    "report-owed",
    "regex-search",
];
/// The line the engine prints for a forgiveness withheld over an unevaluable premise.
const WITHHELD_LINE: &str =
    r#"entry (.+?) is WITHHELD .*premise UNEVALUABLE: premise probes cell "([^"]+)""#;

/// What a subcommand answers: its stdout, its stderr and its exit status.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Answer {
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) code: u8,
}

impl Answer {
    /// Success, printing `stdout`.
    fn out(stdout: String) -> Self {
        Self {
            stdout,
            ..Self::default()
        }
    }

    /// A refusal: `message` (one line more) on stderr, and `code`.
    fn fail(code: u8, message: &str) -> Self {
        Self {
            stderr: format!("{message}\n"),
            code,
            ..Self::default()
        }
    }

    /// A bare exit status.
    fn status(code: u8) -> Self {
        Self {
            code,
            ..Self::default()
        }
    }
}

/// `busbar-ci-checks oracle <sub> ...`: run the subcommand and print its answer.
pub(crate) fn run(args: &[String]) -> ExitCode {
    // `run <sub> ...`: the launcher's contract (`oracle_run.rs`), `bin/oracle`'s whole argv.
    if args.first().map(String::as_str) == Some("run") {
        return crate::oracle_run::run(args.get(1..).unwrap_or_default());
    }
    let answer = answer(args);
    print!("{}", answer.stdout);
    eprint!("{}", answer.stderr);
    ExitCode::from(answer.code)
}

/// The answer to one subcommand line.
pub(crate) fn answer(args: &[String]) -> Answer {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["widen-filter", data, filter] => widen_filter(Path::new(data), filter),
        ["withheld", data, log, filter] => withheld(Path::new(data), Path::new(log), filter),
        ["shard-ids", data, k, n] => match shard_ids(Path::new(data), k, n) {
            Ok(ids) => Answer::out(format!("{}\n", ids.join("\n"))),
            Err(message) => Answer::fail(1, &message),
        },
        ["shard-filter", data, k, n] => match shard_ids(Path::new(data), k, n) {
            Ok(ids) => Answer::out(format!("{}\n", shard_filter(&ids))),
            Err(message) => Answer::fail(1, &message),
        },
        ["shard-cover", data, n] => shard_cover(Path::new(data), n),
        ["shard-verify", data, k, n, report] => shard_verify(Path::new(data), k, n, report),
        ["shard-merge", data, dirs @ ..] => shard_merge(Path::new(data), dirs),
        ["needs-store", data, filter] => needs_store(Path::new(data), filter),
        ["busbar-version"] => {
            let mut metadata = String::new();
            match std::io::stdin().read_to_string(&mut metadata) {
                Ok(_) => busbar_version(&metadata),
                Err(error) => {
                    Answer::fail(1, &format!("oracle: cannot read cargo metadata: {error}"))
                }
            }
        }
        ["line-builds", data, line] => line_builds(Path::new(data), line),
        ["fence-filter", ledger] => fence_filter(Path::new(ledger)),
        ["only-rebaselined", data, filter, families] => {
            only_rebaselined(Path::new(data), filter, families)
        }
        ["family-selected", data, filter, family] => {
            family_selected(Path::new(data), filter, family)
        }
        ["report-owed", report] => report_owed(report),
        ["regex-search", pattern, texts @ ..] => regex_search(pattern, texts),
        _ => Answer::fail(
            2,
            &format!(
                "oracle: usage: busbar-ci-checks oracle <{}> ...",
                SUBCOMMANDS.join("|")
            ),
        ),
    }
}

// ---- shared readers -----------------------------------------------------------------------------

/// A filter or a corpus pattern, compiled with room for a shard's alternation of every id it owns.
fn compile(pattern: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(pattern).size_limit(1 << 28).build()
}

/// A filter that compiles, else nothing (a `grep -E` that errors selects nothing).
pub(crate) fn compile_pattern(pattern: &str) -> Option<Regex> {
    compile(pattern).ok()
}

/// A JSON file, parsed.
fn read_json(path: &Path) -> Result<Node, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("oracle: cannot read {}: {error}", path.display()))?;
    Node::parse(&text).map_err(|error| format!("oracle: {} is not JSON: {error}", path.display()))
}

/// The list under `key` in `<data>/<file>`.
fn json_list(data: &Path, file: &str, key: &str) -> Result<Vec<Node>, String> {
    let path = data.join(file);
    let list = match read_json(&path)? {
        Node::Object(members) => members
            .into_iter()
            .find(|(name, _)| name == key)
            .map(|(_, member)| member),
        _ => None,
    };
    match list {
        Some(Node::Array(items)) => Ok(items),
        _ => Err(format!("oracle: {} has no \"{key}\" list", path.display())),
    }
}

/// The corpus: `<data>/cells.json`'s cells.
fn cell_list(data: &Path) -> Result<Vec<Node>, String> {
    json_list(data, "cells.json", "cells")
}

/// A cell's id (`""` when it has none).
fn id_of(cell: &Node) -> &str {
    cell.get("id").and_then(Node::as_str).unwrap_or_default()
}

/// Every cell's id, in corpus order; a cell without one is a refusal.
fn cell_ids(data: &Path) -> Result<Vec<String>, String> {
    let mut ids = Vec::new();
    for cell in cell_list(data)? {
        match cell.get("id").and_then(Node::as_str) {
            Some(id) => ids.push(String::from(id)),
            None => {
                return Err(format!(
                    "oracle: {} has a cell with no string \"id\"",
                    data.join("cells.json").display()
                ))
            }
        }
    }
    Ok(ids)
}

/// A JSON value Python would read as false.
fn falsy(value: &Node) -> bool {
    match value {
        Node::Null => true,
        Node::Bool(flag) => !flag,
        Node::Number(lexeme) => lexeme.parse::<f64>().ok() == Some(0.0),
        Node::String(text) => text.is_empty(),
        Node::Array(items) => items.is_empty(),
        Node::Object(map) => map.is_empty(),
    }
}

/// Python's `repr` of a str, as the shim's messages have always printed names.
pub(crate) fn py_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if u32::from(c) < 0x20 || u32::from(c) == 0x7f => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Python's `repr` of a JSON value that names an entry (`None` when absent).
fn py_repr_value(value: Option<&Node>) -> String {
    match value {
        None | Some(Node::Null) => String::from("None"),
        Some(Node::String(text)) => py_repr(text),
        Some(Node::Bool(true)) => String::from("True"),
        Some(Node::Bool(false)) => String::from("False"),
        Some(other) => other.to_string(),
    }
}

/// Python's `repr` of a list of str: `['a', 'b']`.
pub(crate) fn py_str_list<S: AsRef<str>>(items: &[S]) -> String {
    let mut out = String::from("[");
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&py_repr(item.as_ref()));
    }
    out.push(']');
    out
}

/// Python's `repr` of a list of numbers: `[1, 2]`.
pub(crate) fn py_num_list<T: Display>(items: &[T]) -> String {
    let mut out = String::from("[");
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "{item}");
    }
    out.push(']');
    out
}

/// An I/O error as Python's `OSError` printed it: `[Errno 2] No such file or directory: 'path'`.
pub(crate) fn py_oserror(path: &str, error: &std::io::Error) -> String {
    let text = error.to_string();
    match error.raw_os_error() {
        Some(errno) => {
            let reason = text.split(" (os error ").next().unwrap_or_default();
            format!("[Errno {errno}] {reason}: {}", py_repr(path))
        }
        None => text,
    }
}

// ---- premises: widen-filter, withheld -----------------------------------------------------------

/// Every `cell` string anywhere under a premise.
fn cells_of(node: &Node, out: &mut BTreeSet<String>) {
    match node {
        Node::Object(members) => {
            if let Some(Node::String(cell)) = node.get("cell") {
                out.insert(cell.clone());
            }
            for (_, value) in members {
                cells_of(value, out);
            }
        }
        Node::Array(items) => {
            for value in items {
                cells_of(value, out);
            }
        }
        _ => {}
    }
}

/// The premise cells the filter's forgivenesses need and the filter does not select, sorted; a
/// premise naming a cell the corpus lacks, or a filter that is not a regex, is a refusal.
pub(crate) fn premise_closure(data: &Path, filter: &str) -> Result<Vec<String>, String> {
    let ids = cell_ids(data)?;
    let universe: BTreeSet<&str> = ids.iter().map(String::as_str).collect();
    let selector = compile(filter).map_err(|error| {
        format!(
            "oracle: the filter {} is not a regex this shim can widen ({error})",
            py_repr(filter)
        )
    })?;
    let selected: Vec<&str> = ids
        .iter()
        .map(String::as_str)
        .filter(|id| selector.is_match(id))
        .collect();
    let mut need = BTreeSet::new();
    let mut bad = Vec::new();
    for entry in json_list(data, "accepted-differences.json", "accepted")? {
        let (Some(premise), Some(cells)) = (entry.get("premise"), entry.get("cells")) else {
            continue;
        };
        if falsy(premise) || falsy(cells) {
            continue;
        }
        let Some(Ok(pattern)) = cells.as_str().map(compile) else {
            continue;
        };
        if !selected.iter().any(|id| pattern.is_match(id)) {
            continue;
        }
        let mut probes = BTreeSet::new();
        cells_of(premise, &mut probes);
        for cell in probes {
            if !universe.contains(cell.as_str()) {
                bad.push(format!(
                    "{} probes premise cell {}, which cells.json does not have",
                    py_repr_value(entry.get("id")),
                    py_repr(&cell)
                ));
            } else if !selector.is_match(&cell) {
                need.insert(cell);
            }
        }
    }
    if !bad.is_empty() {
        return Err(format!(
            "oracle: a filtered run cannot evaluate a forgiveness it selects:\n  {}",
            bad.join("\n  ")
        ));
    }
    Ok(need.into_iter().collect())
}

/// `widen-filter`: the filter plus the premise cells it needs (named on stderr), or the filter.
fn widen_filter(data: &Path, filter: &str) -> Answer {
    let extra = match premise_closure(data, filter) {
        Ok(extra) => extra,
        Err(message) => return Answer::fail(3, &message),
    };
    let cells: Vec<&str> = extra
        .iter()
        .map(|cell| cell.trim())
        .filter(|cell| !cell.is_empty())
        .collect();
    if cells.is_empty() {
        return Answer::out(format!("{filter}\n"));
    }
    let alternation: Vec<String> = cells.iter().map(|cell| regex::escape(cell)).collect();
    Answer {
        stdout: format!("(?:{filter})|^(?:{})$\n", alternation.join("|")),
        stderr: format!(
            "oracle: the filter is widened to the premise cells its accepted differences probe: {}\n",
            extra.join(" ")
        ),
        code: 0,
    }
}

/// `withheld`: 3, naming each, when the engine log withholds a forgiveness the filter selected
/// because its premise could not be evaluated.
fn withheld(data: &Path, log: &Path, filter: &str) -> Answer {
    let closure = match premise_closure(data, filter) {
        Ok(closure) => closure,
        Err(message) => return Answer::fail(3, &message),
    };
    let (Ok(selector), Ok(line_pattern)) = (compile(filter), Regex::new(WITHHELD_LINE)) else {
        return Answer::fail(
            3,
            &format!("oracle: the filter {} is not a regex", py_repr(filter)),
        );
    };
    let bytes = match std::fs::read(log) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Answer::fail(
                3,
                &format!(
                    "oracle: cannot read the engine log {}: {error}",
                    log.display()
                ),
            )
        }
    };
    let text = String::from_utf8_lossy(&bytes);
    let mut hits = Vec::new();
    for line in text.lines() {
        let Some(found) = line_pattern.captures(line) else {
            continue;
        };
        let (Some(entry), Some(cell)) = (found.get(1), found.get(2)) else {
            continue;
        };
        let cell = cell.as_str();
        if closure.iter().any(|need| need == cell) || selector.is_match(cell) {
            hits.push(format!(
                "{} (premise cell {})",
                entry.as_str(),
                py_repr(cell)
            ));
        }
    }
    if hits.is_empty() {
        return Answer::default();
    }
    Answer::fail(
        3,
        &format!(
            "oracle: a filtered replay could not evaluate the premise of a forgiveness it selected, so \
             its cells would report FAIL for a difference the owner signed. Refusing instead:\n  {}\n\
             Record the premise cells (bin/oracle record widens its --filter to them) and replay again.",
            hits.join("\n  ")
        ),
    )
}

// ---- shards -------------------------------------------------------------------------------------

/// The ids shard `k` of `n` owns among the sorted ids: the i-th to shard i mod n + 1.
pub(crate) fn shard_slice(sorted: &[String], k: usize, n: usize) -> Vec<String> {
    sorted
        .iter()
        .enumerate()
        .filter(|(index, _)| index % n == k - 1)
        .map(|(_, id)| id.clone())
        .collect()
}

/// `shard-ids`: the ids shard k of n owns; a k outside 1..n is refused.
pub(crate) fn shard_ids(data: &Path, k: &str, n: &str) -> Result<Vec<String>, String> {
    let (Ok(k), Ok(n)) = (k.trim().parse::<usize>(), n.trim().parse::<usize>()) else {
        return Err(format!(
            "oracle: shard {} of {} is not a shard (1 <= k <= n)",
            k.trim(),
            n.trim()
        ));
    };
    if n == 0 || k == 0 || k > n {
        return Err(format!(
            "oracle: shard {k} of {n} is not a shard (1 <= k <= n)"
        ));
    }
    let mut ids = cell_ids(data)?;
    ids.sort();
    Ok(shard_slice(&ids, k, n))
}

/// The anchored regex selecting exactly these ids.
pub(crate) fn shard_filter(ids: &[String]) -> String {
    let escaped: Vec<String> = ids
        .iter()
        .filter(|id| !id.trim().is_empty())
        .map(|id| regex::escape(id))
        .collect();
    format!("^(?:{})$", escaped.join("|"))
}

/// `shard-cover`: the n shard filters select every id of cells.json exactly once.
fn shard_cover(data: &Path, n: &str) -> Answer {
    let Ok(count) = n.trim().parse::<i64>() else {
        return Answer::fail(
            3,
            &format!("oracle shard-cover: {n} is not a number of shards"),
        );
    };
    let Ok(shards) = usize::try_from(count) else {
        return Answer::fail(
            3,
            &format!("oracle shard-cover: 1 filters for {count} shards"),
        );
    };
    if shards == 0 {
        // No shard, no filter: the filter list read back as one empty line (the shim's old reader).
        return Answer::fail(
            3,
            &format!("oracle shard-cover: 1 filters for {count} shards"),
        );
    }
    let ids = match cell_ids(data) {
        Ok(ids) => ids,
        Err(message) => return Answer::fail(3, &message),
    };
    let mut sorted = ids.clone();
    sorted.sort();
    let mut filters = Vec::new();
    for k in 1..=shards {
        match compile(&shard_filter(&shard_slice(&sorted, k, shards))) {
            Ok(filter) => filters.push(filter),
            Err(error) => {
                return Answer::fail(
                    3,
                    &format!("oracle shard-cover: shard {k}'s filter is not a regex ({error})"),
                )
            }
        }
    }
    let mut bad = Vec::new();
    for id in &ids {
        let hits: Vec<usize> = filters
            .iter()
            .enumerate()
            .filter(|(_, filter)| filter.is_match(id))
            .map(|(index, _)| index + 1)
            .collect();
        if hits.len() != 1 {
            let named = if hits.is_empty() {
                String::from("none")
            } else {
                py_num_list(&hits)
            };
            bad.push(format!("{} is selected by shard(s) {named}", py_repr(id)));
        }
    }
    let unique: BTreeSet<&str> = ids.iter().map(String::as_str).collect();
    if unique.len() != ids.len() {
        bad.push(String::from("cells.json repeats an id"));
    }
    if !bad.is_empty() {
        bad.truncate(20);
        return Answer::fail(
            3,
            &format!(
                "oracle shard-cover: the shards do not cover the corpus exactly once:\n  {}",
                bad.join("\n  ")
            ),
        );
    }
    Answer::out(format!(
        "oracle shard-cover: {count} shards select all {} cells of cells.json, each exactly once\n",
        ids.len()
    ))
}

/// `shard-verify`: the shard's report (`<report>/selected-ids.txt`) selected every cell it owns.
fn shard_verify(data: &Path, k: &str, n: &str, report: &str) -> Answer {
    let owned: BTreeSet<String> = match shard_ids(data, k, n) {
        Ok(ids) => ids.into_iter().filter(|id| !id.is_empty()).collect(),
        Err(message) => return Answer::fail(3, &message),
    };
    let path = format!("{report}/selected-ids.txt");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            return Answer::fail(
                3,
                &format!(
                    "oracle shard-verify: shard {k}/{n} wrote no selected-ids.txt ({}); nothing \
                     proves what it judged. Refusing.",
                    py_oserror(&path, &error)
                ),
            )
        }
    };
    let selected: BTreeSet<&str> = text.split('\n').filter(|id| !id.is_empty()).collect();
    let missing: Vec<&str> = owned
        .iter()
        .map(String::as_str)
        .filter(|id| !selected.contains(id))
        .collect();
    if owned.is_empty() {
        return Answer::fail(
            3,
            &format!("oracle shard-verify: shard {k}/{n} owns no cell. Refusing."),
        );
    }
    if !missing.is_empty() {
        return Answer::fail(
            3,
            &format!(
                "oracle shard-verify: shard {k}/{n} did not select {} of its {} cells: {}. Refusing.",
                missing.len(),
                owned.len(),
                py_str_list(&missing[..missing.len().min(10)])
            ),
        );
    }
    Answer::out(format!(
        "oracle shard-verify: shard {k}/{n} selected all {} cells it owns\n",
        owned.len()
    ))
}

/// One shard report dir's verdict: `(k, n, exit)` from shard.tsv, and the ids it selected.
fn shard_report(dir: &str) -> Result<([String; 3], String), String> {
    let tsv = format!("{dir}/shard.tsv");
    let text = std::fs::read_to_string(&tsv).map_err(|error| py_oserror(&tsv, &error))?;
    let fields: Vec<&str> = text.split_whitespace().take(3).collect();
    let [k, n, rc] = fields.as_slice() else {
        return Err(format!(
            "not enough values to unpack (expected 3, got {})",
            fields.len()
        ));
    };
    let ids = format!("{dir}/selected-ids.txt");
    let selected = std::fs::read_to_string(&ids).map_err(|error| py_oserror(&ids, &error))?;
    Ok((
        [String::from(*k), String::from(*n), String::from(*rc)],
        selected,
    ))
}

/// `shard-merge`: one verdict from N shard reports.
fn shard_merge(data: &Path, dirs: &[&str]) -> Answer {
    if dirs.is_empty() {
        return Answer::fail(2, "oracle shard-merge: name the shard report dirs");
    }
    let ids: BTreeSet<String> = match cell_ids(data) {
        Ok(ids) => ids.into_iter().collect(),
        Err(message) => return Answer::fail(1, &message),
    };
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut counts: BTreeSet<i64> = BTreeSet::new();
    let mut bad = Vec::new();
    let mut selected: BTreeSet<String> = BTreeSet::new();
    for dir in dirs {
        let ([k, n, rc], text) = match shard_report(dir) {
            Ok(report) => report,
            Err(error) => {
                bad.push(format!("{dir}: no shard verdict ({error})"));
                continue;
            }
        };
        selected.extend(
            text.split('\n')
                .filter(|id| !id.is_empty())
                .map(String::from),
        );
        let Ok(count) = n.parse::<i64>() else {
            bad.push(format!(
                "{dir}: no shard verdict (invalid literal for int() with base 10: {})",
                py_repr(&n)
            ));
            continue;
        };
        counts.insert(count);
        if let Some(previous) = seen.get(&k) {
            bad.push(format!("shard {k} reported twice ({previous}, {dir})"));
        }
        seen.insert(k.clone(), String::from(*dir));
        if rc != "0" {
            bad.push(format!("shard {k}/{n} was red (exit {rc}): {dir}"));
        }
    }
    if counts.len() > 1 {
        let all: Vec<i64> = counts.iter().copied().collect();
        bad.push(format!("the reports disagree on N: {}", py_num_list(&all)));
    }
    let n = counts.last().copied().unwrap_or(0);
    let missing: Vec<String> = (1..=n)
        .map(|k| k.to_string())
        .filter(|k| !seen.contains_key(k))
        .collect();
    if !missing.is_empty() {
        bad.push(format!(
            "no report for shard(s) {} of {n}",
            missing.join(", ")
        ));
    }
    let unjudged: Vec<&str> = ids
        .iter()
        .map(String::as_str)
        .filter(|id| !selected.contains(*id))
        .collect();
    if !unjudged.is_empty() {
        bad.push(format!(
            "{} cell(s) no shard judged: {}",
            unjudged.len(),
            py_str_list(&unjudged[..unjudged.len().min(10)])
        ));
    }
    if !bad.is_empty() {
        return Answer::fail(
            1,
            &format!("oracle shard-merge: RED\n  {}", bad.join("\n  ")),
        );
    }
    Answer::out(format!(
        "oracle shard-merge: GREEN: {n} shards, each green, together judged all {} cells\n",
        ids.len()
    ))
}

// ---- ci-run: stores, the line, its plugins ------------------------------------------------------

/// `needs-store`: `yes` when a cell the filter selects (every cell, for `""`) needs a store backend.
fn needs_store(data: &Path, filter: &str) -> Answer {
    let selector = if filter.is_empty() {
        None
    } else {
        match compile(filter) {
            Ok(selector) => Some(selector),
            Err(error) => {
                return Answer::fail(
                    1,
                    &format!(
                        "oracle: the filter {} is not a regex ({error})",
                        py_repr(filter)
                    ),
                )
            }
        }
    };
    let cells = match cell_list(data) {
        Ok(cells) => cells,
        Err(message) => return Answer::fail(1, &message),
    };
    let needed = cells.iter().any(|cell| {
        cell.get("needs_fixture")
            .and_then(Node::as_str)
            .is_some_and(|url| STORE_URLS.contains(&url))
            && selector
                .as_ref()
                .is_none_or(|selector| selector.is_match(id_of(cell)))
    });
    Answer::out(String::from(if needed { "yes\n" } else { "no\n" }))
}

/// `busbar-version`: the version of the one package with a `busbar` bin target.
pub(crate) fn busbar_version(metadata: &str) -> Answer {
    let metadata: Node = match Node::parse(metadata) {
        Ok(metadata) => metadata,
        Err(error) => {
            return Answer::fail(1, &format!("oracle: cargo metadata is not JSON: {error}"))
        }
    };
    let builds_busbar = |package: &&Node| {
        package
            .get("targets")
            .and_then(Node::as_array)
            .into_iter()
            .flatten()
            .any(|target| {
                target.get("name").and_then(Node::as_str) == Some("busbar")
                    && target
                        .get("kind")
                        .and_then(Node::as_array)
                        .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("bin")))
            })
    };
    let versions: Vec<&str> = metadata
        .get("packages")
        .and_then(Node::as_array)
        .into_iter()
        .flatten()
        .filter(builds_busbar)
        .filter_map(|package| package.get("version").and_then(Node::as_str))
        .collect();
    match versions.as_slice() {
        [version] => Answer::out(format!("{version}\n")),
        _ => Answer::fail(1, "no package builds the busbar binary"),
    }
}

/// A plugin-digests.tsv row whose plugin builds from source: `src:<40 hex>` and `build:<name>`.
fn from_source(tag: &str, asset: &str) -> bool {
    tag.strip_prefix("src:")
        .is_some_and(|hex| hex.len() == 40 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        && asset.strip_prefix("build:").is_some_and(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}

/// Whether the line builds its plugins from source, from plugin-digests.tsv's text: some row of
/// the line does, and no row of it is a released asset. A row's line is its fifth column, else 1.5.
pub(crate) fn line_builds_from(text: &str, line: &str) -> bool {
    let rows: Vec<(&str, &str, &str)> = text
        .split('\n')
        .filter(|row| !row.is_empty() && !row.starts_with('#'))
        .filter_map(|row| {
            let columns: Vec<&str> = row.split('\t').collect();
            if columns.len() < 4 {
                return None;
            }
            let of_line = columns
                .get(4)
                .copied()
                .filter(|of_line| !of_line.is_empty())
                .unwrap_or("1.5");
            Some((columns[1], columns[2], of_line))
        })
        .collect();
    let released = rows
        .iter()
        .any(|&(tag, asset, of_line)| of_line == line && !from_source(tag, asset));
    !released
        && rows
            .iter()
            .any(|&(tag, asset, of_line)| of_line == line && from_source(tag, asset))
}

/// `line-builds`: `yes` or `no` (a missing plugin-digests.tsv has no rows).
fn line_builds(data: &Path, line: &str) -> Answer {
    let text = std::fs::read_to_string(data.join("plugin-digests.tsv")).unwrap_or_default();
    Answer::out(String::from(if line_builds_from(&text, line) {
        "yes\n"
    } else {
        "no\n"
    }))
}

// ---- replay: fences, dated baselines, the report ------------------------------------------------

/// `^(<id>|...)$` over the first column of a fence ledger's non-empty lines.
pub(crate) fn fence_filter_from(ledger: &str) -> String {
    let ids: Vec<String> = ledger
        .split('\n')
        .filter(|line| !line.is_empty())
        .map(|line| line.split('\t').next().unwrap_or_default().trim())
        .filter(|id| !id.is_empty())
        .map(regex::escape)
        .collect();
    format!("^({})$", ids.join("|"))
}

/// `fence-filter`: the regex selecting exactly a fence's ledger ids.
fn fence_filter(ledger: &Path) -> Answer {
    match std::fs::read_to_string(ledger) {
        Ok(text) => Answer::out(format!("{}\n", fence_filter_from(&text))),
        Err(error) => Answer::fail(
            1,
            &format!("oracle: cannot read {}: {error}", ledger.display()),
        ),
    }
}

/// The filter, compiled, or the refusal naming it (1).
fn selector_or_refusal(filter: &str) -> Result<Regex, Answer> {
    compile(filter).map_err(|error| {
        Answer::fail(
            1,
            &format!(
                "oracle: the filter {} is not a regex ({error})",
                py_repr(filter)
            ),
        )
    })
}

/// `only-rebaselined`: 0 when the filter selects a cell and every selected cell's family (its
/// `family`, else its `plane`) is one of `families` (whitespace-separated).
fn only_rebaselined(data: &Path, filter: &str, families: &str) -> Answer {
    let selector = match selector_or_refusal(filter) {
        Ok(selector) => selector,
        Err(refusal) => return refusal,
    };
    let families: BTreeSet<&str> = families.split_whitespace().collect();
    let cells = match cell_list(data) {
        Ok(cells) => cells,
        Err(message) => return Answer::fail(1, &message),
    };
    let chosen: Vec<&Node> = cells
        .iter()
        .filter(|cell| selector.is_match(id_of(cell)))
        .collect();
    let only = !chosen.is_empty()
        && chosen.iter().all(|cell| {
            cell.get("family")
                .or_else(|| cell.get("plane"))
                .and_then(Node::as_str)
                .is_some_and(|family| families.contains(family))
        });
    Answer::status(if only { 0 } else { 1 })
}

/// `family-selected`: 0 when the filter selects a cell whose `family` is `family`.
fn family_selected(data: &Path, filter: &str, family: &str) -> Answer {
    let selector = match selector_or_refusal(filter) {
        Ok(selector) => selector,
        Err(refusal) => return refusal,
    };
    let cells = match cell_list(data) {
        Ok(cells) => cells,
        Err(message) => return Answer::fail(1, &message),
    };
    let any = cells.iter().any(|cell| {
        selector.is_match(id_of(cell)) && cell.get("family").and_then(Node::as_str) == Some(family)
    });
    Answer::status(if any { 0 } else { 1 })
}

/// `report-owed`: 0 when the 1.5.5 replay's report compared at least one owed cell; a report
/// that cannot be read, or that compared none, is a refusal (1).
fn report_owed(report: &str) -> Answer {
    let refuse = |error: String| {
        Answer::fail(
            1,
            &format!(
                "oracle: the 1.5.5 replay wrote no readable report ({report}: {error}); nothing \
                 was judged. Refusing."
            ),
        )
    };
    let text = match std::fs::read_to_string(report) {
        Ok(text) => text,
        Err(error) => return refuse(py_oserror(report, &error)),
    };
    let doc: Node = match Node::parse(&text) {
        Ok(doc) => doc,
        Err(error) => return refuse(error.to_string()),
    };
    let Some(totals) = doc.get("totals") else {
        return refuse(py_repr("totals"));
    };
    let Some(owed) = totals.get("owed") else {
        return refuse(py_repr("owed"));
    };
    if falsy(owed) {
        return Answer::fail(
            1,
            &format!(
                "oracle: the 1.5.5 replay compared ZERO owed cells ({report}); a replay that judged \
                 nothing is not a verdict. Refusing."
            ),
        );
    }
    Answer::default()
}

/// `regex-search`: 0 when the regex finds a match in every text, 1 when not, 2 when it is no regex.
fn regex_search(pattern: &str, texts: &[&str]) -> Answer {
    match compile(pattern) {
        Ok(regex) => Answer::status(if texts.iter().all(|text| regex.is_match(text)) {
            0
        } else {
            1
        }),
        Err(error) => Answer::fail(
            2,
            &format!("oracle: {} is not a regex ({error})", py_repr(pattern)),
        ),
    }
}

#[cfg(test)]
#[path = "oracle_tests.rs"]
mod tests;
