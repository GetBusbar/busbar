//! Compiler witnesses: the positive and negative SDK examples in doc comments
//! named by `[[compiler_witnesses]]`. They are extracted structurally (the doc
//! attributes of the token stream, also inside macro bodies) and committed as
//! trybuild cases under `tools/busbar-arch/witnesses/cases/`, where
//! `cargo test -p busbar-arch-witnesses` proves each negative fails with its
//! named rustc error (the `.stderr` snapshot) and each positive compiles.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use toml::Value;

use crate::policy::{self, Policy};
use crate::py;
use crate::refuse::{Result, Rule, Violation};

/// Where the trybuild suite lives, relative to the core checkout.
pub const CASES: &str = "tools/busbar-arch/witnesses/cases";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    pub name: String,
    pub source: String,
    /// Expected rustc error codes; empty for a positive control.
    pub expected: Vec<String>,
    pub code: String,
    pub needs_loader: bool,
}

impl Case {
    pub fn directory(&self) -> &'static str {
        if self.expected.is_empty() {
            "pass"
        } else {
            "fail"
        }
    }
}

/// Doc attribute strings of a Rust source, in source order.
pub fn doc_strings(source: &str) -> std::result::Result<Vec<String>, String> {
    let stream = TokenStream::from_str(source).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    collect_docs(stream, &mut out);
    Ok(out)
}

fn collect_docs(stream: TokenStream, out: &mut Vec<String>) {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    let mut i = 0;
    while i < tokens.len() {
        if let TokenTree::Punct(p) = &tokens[i] {
            if p.as_char() == '#' {
                let mut j = i + 1;
                if matches!(tokens.get(j), Some(TokenTree::Punct(b)) if b.as_char() == '!') {
                    j += 1;
                }
                if let Some(TokenTree::Group(g)) = tokens.get(j) {
                    if g.delimiter() == Delimiter::Bracket {
                        if let Some(doc) = doc_value(g.stream()) {
                            out.push(doc);
                            i = j + 1;
                            continue;
                        }
                    }
                }
            }
        }
        if let TokenTree::Group(g) = &tokens[i] {
            collect_docs(g.stream(), out);
        }
        i += 1;
    }
}

fn doc_value(stream: TokenStream) -> Option<String> {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    match tokens.as_slice() {
        [TokenTree::Ident(ident), TokenTree::Punct(eq), TokenTree::Literal(lit)]
            if ident == "doc" && eq.as_char() == '=' =>
        {
            let lit: syn::LitStr = syn::parse2(TokenTree::Literal(lit.clone()).into()).ok()?;
            Some(lit.value())
        }
        _ => None,
    }
}

/// The doc text, one line per doc line (a single leading space removed), as
/// the line-oriented Python extraction saw it.
fn doc_text(source: &str) -> std::result::Result<String, String> {
    let mut lines = Vec::new();
    for doc in doc_strings(source)? {
        for line in doc.split('\n') {
            lines.push(line.strip_prefix(' ').unwrap_or(line).to_string());
        }
    }
    Ok(lines.join("\n"))
}

/// Fenced blocks: (info string, body), the non-greedy ```` ```info\n...``` ```` pairing.
fn fenced_blocks(docs: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = docs;
    while let Some(open) = rest.find("```") {
        let after = &rest[open + 3..];
        let Some(newline) = after.find('\n') else {
            break;
        };
        let flags = &after[..newline];
        let body_start = &after[newline + 1..];
        let Some(close) = body_start.find("```") else {
            // No closing fence for this opening: the regex retries one later.
            rest = &rest[open + 1..];
            continue;
        };
        out.push((flags.to_string(), body_start[..close].to_string()));
        rest = &body_start[close + 3..];
    }
    out
}

fn has_main(code: &str) -> bool {
    fn walk(stream: TokenStream) -> bool {
        let tokens: Vec<TokenTree> = stream.into_iter().collect();
        for (i, token) in tokens.iter().enumerate() {
            match token {
                TokenTree::Ident(fn_kw) if fn_kw == "fn" => {
                    if let (Some(TokenTree::Ident(name)), Some(TokenTree::Group(g))) =
                        (tokens.get(i + 1), tokens.get(i + 2))
                    {
                        if name == "main" && g.delimiter() == Delimiter::Parenthesis {
                            return true;
                        }
                    }
                }
                TokenTree::Group(g) if walk(g.stream()) => return true,
                _ => {}
            }
        }
        false
    }
    match TokenStream::from_str(code) {
        Ok(stream) => walk(stream),
        Err(_) => code.contains("fn main("),
    }
}

/// Error codes named in a fence info string (`compile_fail,E0277`).
fn error_codes(flags: &str) -> Vec<String> {
    let bytes = flags.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 5 <= bytes.len() {
        if bytes[i] == b'E' && bytes[i + 1..i + 5].iter().all(u8::is_ascii_digit) {
            out.push(flags[i..i + 5].to_string());
            i += 5;
        } else {
            i += 1;
        }
    }
    out
}

/// `check_compiler_witnesses` inventory: every case, in policy order.
pub fn extract(policy: &Policy, trusted: &Path) -> Result<Vec<Case>> {
    let rows = match policy.data.get("compiler_witnesses") {
        Some(Value::Array(rows)) => rows.clone(),
        _ => Vec::new(),
    };
    let contract_manifest = policy
        .core()
        .get("busbar-contract")
        .and_then(Value::as_table)
        .map(|e| policy::manifest(e).map(str::to_string))
        .transpose()?
        .unwrap_or_default();
    let contract_root = Path::new(&contract_manifest)
        .parent()
        .unwrap_or(Path::new(""))
        .to_path_buf();
    let mut cases = Vec::new();
    for row in rows {
        let row = row.as_table().cloned().unwrap_or_default();
        let source_path = policy::str_of(&row, "source")?.to_string();
        let markers = policy::strings(row.get("markers"))?;
        let count = row.get("count").and_then(Value::as_integer).unwrap_or(-1);
        let source = py::read_text(&py::join(trusted, &source_path))?;
        let docs = doc_text(&source).map_err(|e| {
            Violation::new(Rule::Parse, format!("cannot tokenize {source_path}: {e}"))
        })?;
        let selected: Vec<(String, String)> = fenced_blocks(&docs)
            .into_iter()
            .filter(|(_, code)| markers.iter().any(|m| code.contains(m.as_str())))
            .collect();
        if selected.len() as i64 != count {
            return Err(Violation::new(
                Rule::CompilerWitnessInventory,
                format!("trusted compiler witness inventory changed: {source_path}"),
            ));
        }
        for (flags, code) in selected {
            // `str.splitlines()`: no trailing empty line.
            let mut code = code
                .lines()
                .map(|line| line.strip_prefix("# ").unwrap_or(line))
                .collect::<Vec<_>>()
                .join("\n");
            if !has_main(&code) {
                code = format!("fn main() {{\n{code}\n}}\n");
            }
            let expected = error_codes(&flags);
            if flags.contains("compile_fail") && expected.is_empty() {
                return Err(Violation::new(
                    Rule::CompilerWitnessInventory,
                    "negative witness must name its expected compiler error",
                ));
            }
            let needs_loader = !Path::new(&source_path).starts_with(&contract_root)
                || code.contains("busbar_plugin_loader");
            cases.push(Case {
                name: format!("witness_{:02}", cases.len()),
                source: source_path.clone(),
                expected,
                code,
                needs_loader,
            });
        }
    }
    if cases.is_empty() || !cases.iter().any(|c| c.expected.is_empty()) {
        return Err(Violation::new(
            Rule::CompilerWitnessInventory,
            "compiler witnesses require a positive control",
        ));
    }
    Ok(cases)
}

/// The committed case file for a witness: a header naming its origin, then the
/// exact code the Python harness compiled.
pub fn case_file(case: &Case) -> String {
    let expectation = if case.expected.is_empty() {
        "positive control: must compile".to_string()
    } else {
        format!(
            "negative witness: must fail with {}",
            case.expected.join(" or ")
        )
    };
    format!(
        "// @generated by `busbar-arch witnesses --write` from {}; {}.\n{}",
        case.source, expectation, case.code
    )
}

fn case_path(checkout: &Path, case: &Case) -> PathBuf {
    py::join(
        checkout,
        format!("{CASES}/{}/{}.rs", case.directory(), case.name),
    )
}

/// Write the trybuild cases (and drop stale ones). `.stderr` snapshots are
/// produced by `TRYBUILD=overwrite cargo test -p busbar-arch-witnesses`.
pub fn write(checkout: &Path, cases: &[Case]) -> Result<usize> {
    for directory in ["pass", "fail"] {
        let dir = py::join(checkout, format!("{CASES}/{directory}"));
        std::fs::create_dir_all(&dir).map_err(|e| py::os_error(&e, &dir))?;
        for entry in std::fs::read_dir(&dir)
            .map_err(|e| py::os_error(&e, &dir))?
            .flatten()
        {
            let path = entry.path();
            let stem = path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            if !cases
                .iter()
                .any(|c| c.name == stem && c.directory() == directory)
            {
                std::fs::remove_file(&path).map_err(|e| py::os_error(&e, &path))?;
            }
        }
    }
    for case in cases {
        let path = case_path(checkout, case);
        std::fs::write(&path, case_file(case)).map_err(|e| py::os_error(&e, &path))?;
    }
    Ok(cases.len())
}

/// The snapshot must show one of the named error codes.
fn snapshot_names_code(snapshot: &str, expected: &[String]) -> bool {
    expected
        .iter()
        .any(|code| snapshot.contains(&format!("error[{code}]")))
}

/// Refuse unless the committed trybuild suite equals the extracted witnesses.
pub fn verify(checkout: &Path, cases: &[Case]) -> Result<usize> {
    let drift = |what: String| Violation::new(Rule::CompilerWitnessDrift, what);
    for case in cases {
        let path = case_path(checkout, case);
        let committed = std::fs::read_to_string(&path).unwrap_or_default();
        if committed != case_file(case) {
            return Err(drift(format!(
                "compiler witness {} ({}) differs from its trybuild case {}; run `busbar-arch witnesses --write`",
                case.name,
                case.source,
                path.display()
            )));
        }
        if !case.expected.is_empty() {
            let snapshot_path = path.with_extension("stderr");
            let snapshot = std::fs::read_to_string(&snapshot_path).unwrap_or_default();
            if !snapshot_names_code(&snapshot, &case.expected) {
                return Err(drift(format!(
                    "trybuild snapshot {} does not show {}",
                    snapshot_path.display(),
                    case.expected.join(" or ")
                )));
            }
        }
    }
    for directory in ["pass", "fail"] {
        let dir = py::join(checkout, format!("{CASES}/{directory}"));
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            let stem = path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            if !cases
                .iter()
                .any(|c| c.name == stem && c.directory() == directory)
            {
                return Err(drift(format!(
                    "stale trybuild case {}; run `busbar-arch witnesses --write`",
                    path.display()
                )));
            }
        }
    }
    Ok(cases.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docs_are_read_from_attributes_and_macro_bodies() {
        let source = "//! ```\n//! top\n//! ```\n/// outer\nfn f() {}\nmacro_rules! m { () => { /// inside\n fn g() {} } }\n// /// not a doc\n";
        assert_eq!(
            doc_strings(source).unwrap(),
            [" ```", " top", " ```", " outer", " inside"]
        );
    }

    #[test]
    fn blocks_codes_and_main_follow_the_python_harness() {
        let docs = "x\n```compile_fail,E0277\nlet a = 1;\n# use b;\n```\n```\nfn main() {}\n```";
        let blocks = fenced_blocks(docs);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].0, "compile_fail,E0277");
        assert_eq!(error_codes(&blocks[0].0), ["E0277"]);
        assert!(!has_main(&blocks[0].1));
        assert!(has_main(&blocks[1].1));
        assert!(error_codes("compile_fail").is_empty());
    }

    #[test]
    fn snapshots_must_show_the_named_code() {
        assert!(snapshot_names_code("error[E0277]: x", &["E0277".into()]));
        assert!(!snapshot_names_code("error[E0308]: x", &["E0277".into()]));
    }
}
