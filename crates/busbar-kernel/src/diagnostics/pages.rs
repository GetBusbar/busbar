// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ERROR PAGES: one docs page per catalog code plus an index, rendered from the catalog alone.
//!
//! Every operator message links `ERROR_DOCS_BASE` + its code (`busbar_contract::diagnostic`), so
//! every code needs a page at that URL. These pages are the website's `/docs/<major.minor>/errors/`
//! tree: committed under `docs/errors/<major.minor>/` in this repo and synced by the site build. A
//! test renders them afresh and fails on any drift; `UPDATE_ERROR_PAGES=1 cargo test -p
//! busbar-kernel error_pages` rewrites them (and `ERROR_PAGES_OUT=<dir>` writes a copy elsewhere).
//!
//! Format: Starlight Markdown. The frontmatter `slug` pins the route to
//! `docs/<major.minor>/errors/BUSBAR-NNNN`, exactly the path the message links, whatever directory
//! the file is synced into.

use busbar_contract::diagnostic::{error_docs_version, Class, Diagnostic, ErrorText};

/// The page's file name in the version directory: `BUSBAR-NNNN.md`.
#[must_use]
fn page_file(d: &Diagnostic) -> String {
    format!("{}.md", d.banner())
}

/// The route a page serves at (no leading or trailing slash).
#[must_use]
fn page_slug(d: &Diagnostic) -> String {
    format!("docs/{}/errors/{}", error_docs_version(), d.banner())
}

fn yaml_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// `{name}` placeholders shown as `<name>` for the page's message template.
fn shown_template(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                out.push('}');
            }
            '{' => out.push('<'),
            '}' => out.push('>'),
            c => out.push(c),
        }
    }
    out
}

/// One code's page.
#[must_use]
fn render_page(d: &Diagnostic, text: Option<&ErrorText>) -> String {
    let mut out = String::new();
    out.push_str("---\n");
    out.push_str(&format!(
        "title: {}\n",
        yaml_str(&format!("{}: {}", d.banner(), d.title))
    ));
    out.push_str(&format!(
        "description: {}\n",
        yaml_str(&format!(
            "What Busbar error {} means, why it happens, and how to fix it.",
            d.banner()
        ))
    ));
    out.push_str(&format!("slug: {}\n", page_slug(d)));
    out.push_str("---\n\n");
    out.push_str(&format!(
        "**Area:** {} ({}xxx) · **Severity:** {} · **Since:** {}\n\n",
        d.class.title(),
        d.class.ordinal(),
        d.severity.as_str(),
        d.since
    ));
    if d.retired {
        out.push_str(
            "> **Retired.** Busbar no longer reports this code. The page stays so an old log line \
             still resolves; the code is never reused.\n\n",
        );
    }
    if let Some(t) = text {
        out.push_str("## Message\n\n```text\n");
        out.push_str(&d.coded(shown_template(t.text)).to_string());
        out.push_str("\n```\n\n");
    }
    out.push_str("## What it means\n\n");
    out.push_str(d.summary);
    out.push_str("\n\n## How to fix it\n\n");
    out.push_str(d.action);
    out.push('\n');
    if let Some(t) = text.filter(|t| !t.example.is_empty() || !t.example_detail.is_empty()) {
        out.push_str("\n## Example\n\n");
        if !t.example.is_empty() {
            out.push_str("```text\n");
            out.push_str(t.example);
            out.push_str("\n```\n\n");
        }
        if !t.example_detail.is_empty() {
            out.push_str("Busbar reports:\n\n```text\n");
            out.push_str(&d.coded(t.example_detail).to_string());
            out.push_str("\n```\n");
        }
    }
    out.push_str(&format!(
        "\n---\n\n[All error codes](/docs/{}/errors/) · This page is generated from the Busbar \
         source; do not edit it by hand.\n",
        error_docs_version()
    ));
    out
}

fn cell(s: &str) -> String {
    s.replace('|', "\\|")
}

/// The index page: every code, grouped by class, linking each page.
#[must_use]
fn render_index(catalog: &[&Diagnostic]) -> String {
    let version = error_docs_version();
    let mut out = String::new();
    out.push_str("---\n");
    out.push_str("title: \"Error codes\"\n");
    out.push_str(&format!(
        "description: {}\n",
        yaml_str(&format!(
            "Every Busbar {version} error and warning code: what it means and how to fix it."
        ))
    ));
    out.push_str(&format!("slug: docs/{version}/errors\n"));
    out.push_str("---\n\n");
    out.push_str(
        "Every operator-facing error and warning Busbar prints carries a permanent `BUSBAR-NNNN` \
         code: config refusals at `--validate` and startup (the one-time upgrade included), CLI \
         errors, admin API error responses (the `code` field) and warn/error log lines (the `diag` field). \
         A message reads `BUSBAR-NNNN: <what is wrong>. See <link>`; the link is the code's page \
         below. Codes are never reused: a retired code keeps its page.\n\n",
    );
    out.push_str("The thousands digit is the area.\n\n");
    for class in Class::ALL {
        let mut rows: Vec<&Diagnostic> = catalog
            .iter()
            .copied()
            .filter(|d| d.class == class)
            .collect();
        if rows.is_empty() {
            continue;
        }
        rows.sort_by_key(|d| d.code);
        out.push_str(&format!(
            "## {}xxx: {}\n\n| Code | What it reports | Since |\n|---|---|---|\n",
            class.ordinal(),
            class.title()
        ));
        for d in rows {
            out.push_str(&format!(
                "| [{b}](/docs/{version}/errors/{b}/) | {title}{retired} | {since} |\n",
                b = d.banner(),
                title = cell(d.title),
                retired = if d.retired { " *(retired)*" } else { "" },
                since = d.since,
            ));
        }
        out.push('\n');
    }
    out.push_str("This page is generated from the Busbar source; do not edit it by hand.\n");
    out
}

/// Every page of `catalog` as `(file name, contents)`, the index (`index.md`) first.
#[must_use]
pub fn render_all(catalog: &[&Diagnostic], texts: &[ErrorText]) -> Vec<(String, String)> {
    let mut out = vec![("index.md".to_string(), render_index(catalog))];
    let mut sorted = catalog.to_vec();
    sorted.sort_by_key(|d| d.code);
    for d in sorted {
        let text = texts.iter().find(|t| t.code == d.code);
        out.push((page_file(d), render_page(d, text)));
    }
    out
}
