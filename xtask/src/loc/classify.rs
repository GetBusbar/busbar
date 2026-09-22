//! ONE FILE, FIVE BUCKETS, AND A PARSE RATHER THAN A SCAN.
//!
//! Three instruments in this tree each answered "how many lines of production Rust is this" and
//! each gave a different number — 2.08x, 2.90x and 2.60x for the same growth ratio — because each
//! was a line-oriented scanner with its own ad-hoc rule. The rules were not subtly different; they
//! were differently WRONG, and every one of the ways they were wrong is a lexical case that a
//! parser does not have:
//!
//! * `/* /* */ */` is legal, nested Rust. A scanner that closes on the first `*/` resumes counting
//!   comment prose as code.
//! * `r#"…"#` takes an arbitrary number of hashes and may contain `//`, `/*`, `#[cfg(test)]` and
//!   unbalanced braces. A scanner that does not track the hash count terminates the literal early.
//! * `'{'` is a char literal and `'a` is a lifetime, one character apart, and a brace-depth counter
//!   that cannot tell them apart drifts for the rest of the file.
//!
//! So this module does not scan. [`syn::parse_file`] decides the file is Rust at all — **a file
//! that does not parse is an ERROR and is counted as nothing**, because silence-as-success is the
//! failure mode behind every instrument defect this replaces — and the buckets are read off the
//! parse:
//!
//! * `proc_macro2` token SPANS say which lines carry tokens. A line no token covers is, by
//!   construction, a comment or whitespace: those are the only two things the lexer discards.
//!   Nested block comments, multi-line raw strings and char literals are handled because the lexer
//!   handled them, not because this module knows about them.
//! * Doc comments are the one comment form that becomes tokens (`/// x` lexes as `#[doc = "x"]`),
//!   and `proc_macro2` gives every synthesised token the ORIGINAL comment's span. So a token whose
//!   span starts at `//` or `/*` in the source is a doc comment, exactly, with no text heuristic.
//! * `#[cfg(test)]` spans come from the AST through [`syn::visit`], which reaches every node that
//!   can carry an attribute — including a `fn` nested inside another `fn`'s body, which is the
//!   shape that hid from every line-oriented rule.
//!
//! ## THE BUCKETS, IN PRECEDENCE ORDER
//!
//! Every line lands in exactly one, and the ORDER is the definition:
//!
//! 1. `blank`   — whitespace only. A blank line is a blank line wherever it sits.
//! 2. `doc`     — the line carries doc-comment text and no other token: `///`, `//!`, `/** */`,
//!               `/*! */`.
//! 3. `comment` — the line carries no token at all and is not blank: `//`, `/* */`.
//! 4. `test`    — what is left, in a test PATH or inside a `#[cfg(test)]` item span.
//! 5. `code`    — what is left. **This is the number the invariant is about.**
//!
//! `blank`/`doc`/`comment` are facts about a line's SHAPE and come first; `test` vs `code` is the
//! proof/production split of the lines that are actually Rust. That ordering is why a comment
//! inside a test module is `comment` and not `test`: a reader asking "how big are the tests" is
//! asking about test CODE, and a reader asking "how big is production" gets `code` either way.
//!
//! **A LINE INSIDE A STRING LITERAL IS `code`.** It is covered by the literal's token span, so it
//! falls out of the rule above rather than being a special case, and that is the right answer: a
//! multi-line literal is a value the program carries and a reader has to read. The decision is
//! called out because the two instruments this replaces DISAGREED about it —
//! `scripts/loc-surface.py` blanked literal bodies and the construction gate's tree scanner kept
//! them, so `busbar-substrate-values/src/diagnostics/mod.rs` measured 2,940 by one and 3,447 by the
//! other, a 507-line gap in one file, entirely made of `\`-continued diagnostic remedy text. Every
//! line counter in general use (cloc, tokei, scc) counts them; so does this one.
//!
//! ## WHY THE `#[cfg(test)]` SPAN IS BRACE-MATCHED AND NOT "TO END OF FILE"
//!
//! v1.5.5's `crates/busbar/src/main.rs` is 3,989 lines and carries `#[cfg(test)] mod test_support;`
//! — a ONE-LINE declaration — at line 93. A "first `#[cfg(test)]` to EOF" rule calls 3,897 of those
//! lines test, including `fn build_split_routers_with_limits` at line 3900, the split-listener
//! router builder, which ships. Worse, it over-subtracts UNEQUALLY between trees — 1.5.5 is 21%
//! inline-tested and trunk only 2%, because trunk migrated its tests into `src/**/tests/*.rs` — so
//! the rule corrupts a RATIO between two trees even where it happens to be defensible on one.
//! Taking the span from the AST makes that class of error unrepresentable: the span is the item's,
//! and the item ends where the grammar says it ends.

use std::collections::BTreeSet;
use std::str::FromStr;

use proc_macro2::{Delimiter, LineColumn, TokenStream, TokenTree};
use syn::spanned::Spanned;
use syn::visit::Visit;

/// The five buckets. Exhaustive and disjoint: `code + doc + comment + blank + test` is the file's
/// line count, always, which is the assertion [`Counts::total`] exists to make cheap.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub code: u64,
    pub doc: u64,
    pub comment: u64,
    pub blank: u64,
    pub test: u64,
}

impl Counts {
    pub fn total(&self) -> u64 {
        self.code + self.doc + self.comment + self.blank + self.test
    }

    pub fn add(&mut self, other: &Counts) {
        self.code += other.code;
        self.doc += other.doc;
        self.comment += other.comment;
        self.blank += other.blank;
        self.test += other.test;
    }

    pub fn tally(&mut self, kind: Kind) {
        match kind {
            Kind::Code => self.code += 1,
            Kind::Doc => self.doc += 1,
            Kind::Comment => self.comment += 1,
            Kind::Blank => self.blank += 1,
            Kind::Test => self.test += 1,
        }
    }
}

/// One line's bucket. Named rather than an index so a fixture can assert the SHAPE of a file
/// line by line, which is how the traps below are pinned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Code,
    Doc,
    Comment,
    Blank,
    Test,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Code => "code",
            Kind::Doc => "doc",
            Kind::Comment => "comment",
            Kind::Blank => "blank",
            Kind::Test => "test",
        }
    }
}

/// The counting rule, in the words the report prints. Kept beside the code that implements it so a
/// reader of the JSON and a reader of this file cannot be told two different things.
pub const DEFINITION: [(&str, &str); 5] = [
    (
        "blank",
        "whitespace only. Checked FIRST, so a blank line is blank wherever it sits.",
    ),
    (
        "doc",
        "carries doc-comment text and no other token: `///`, `//!`, `/** */`, `/*! */`.",
    ),
    (
        "comment",
        "carries no token at all and is not blank: `//`, `/* */` (nesting included).",
    ),
    (
        "test",
        "a path with a `tests` or `benches` segment at ANY depth, `tests.rs`, `*_tests.rs`, \
         `*_test.rs`, or inside the AST span of a `#[cfg(test)]` item.",
    ),
    (
        "code",
        "everything left. THIS is the production-surface number every ceiling is about.",
    ),
];

/// Is this repo-relative path test code by its PATH alone, before anything is parsed?
///
/// `tests` and `benches` match at ANY depth. The bug this replaces matched only the top-level
/// `src/tests/`, so `src/<module>/tests/**` — where this tree actually keeps its proofs — was
/// billed as production surface: 192,813 lines of it, more than the whole tree's real production
/// code.
pub fn is_test_path(rel: &str) -> bool {
    let norm = rel.replace('\\', "/");
    if norm
        .split('/')
        .any(|seg| seg == "tests" || seg == "benches")
    {
        return true;
    }
    let name = norm.rsplit('/').next().unwrap_or(norm.as_str());
    name == "tests.rs" || name.ends_with("_tests.rs") || name.ends_with("_test.rs")
}

/// What one file measured, or why it could not be measured.
#[derive(Clone, Debug)]
pub struct FileVerdict {
    pub counts: Counts,
    pub kinds: Vec<Kind>,
}

/// Classify every line of `text`.
///
/// `path_is_test` is [`is_test_path`]'s answer for the file, threaded in rather than recomputed so
/// a fixture can drive the classifier on text alone.
///
/// `Err` means the file is not parseable Rust. The caller must surface it; it must never be
/// silently counted, in either direction.
pub fn classify(text: &str, path_is_test: bool) -> Result<FileVerdict, String> {
    let lines = split_lines(text);

    // ── THE PARSE IS THE GATE ─────────────────────────────────────────────────────────────────
    // `TokenStream::from_str` succeeds on `fn fn fn` — balanced tokens are not a grammar. Only the
    // full parse can say "this is Rust", and only the token stream carries the spans, so both run.
    let file = syn::parse_file(text).map_err(|e| {
        let at = e.span().start();
        format!("not parseable Rust at line {}: {e}", at.line)
    })?;
    let tokens = TokenStream::from_str(text)
        .map_err(|e| format!("not lexable Rust at line {}: {e}", e.span().start().line))?;

    let mut code_lines: BTreeSet<usize> = BTreeSet::new();
    let mut doc_lines: BTreeSet<usize> = BTreeSet::new();
    mark_tokens(tokens, &lines, &mut code_lines, &mut doc_lines);

    // A file-level `#![cfg(test)]` makes the WHOLE file a proof; no inner span can say that.
    let whole_file_is_test = path_is_test || has_cfg_test(&file.attrs);

    let mut test_lines: BTreeSet<usize> = BTreeSet::new();
    if !whole_file_is_test {
        let mut spans = TestSpans {
            out: &mut test_lines,
        };
        spans.visit_file(&file);
    }

    let mut kinds = Vec::with_capacity(lines.len());
    let mut counts = Counts::default();
    for (idx, line) in lines.iter().enumerate() {
        let n = idx + 1;
        let kind = if line.trim().is_empty() {
            Kind::Blank
        } else if !code_lines.contains(&n) && doc_lines.contains(&n) {
            Kind::Doc
        } else if !code_lines.contains(&n) {
            Kind::Comment
        } else if whole_file_is_test || test_lines.contains(&n) {
            Kind::Test
        } else {
            Kind::Code
        };
        counts.tally(kind);
        kinds.push(kind);
    }

    Ok(FileVerdict { counts, kinds })
}

/// The file's lines, WITHOUT the phantom empty line a trailing newline otherwise produces.
///
/// `"a\n".split('\n')` is `["a", ""]`, and counting that second element is a free blank line on
/// every well-formed file in the tree — 1,441 of them here, which is 1,441 lines of pure
/// arithmetic error in a number the release is read against.
fn split_lines(text: &str) -> Vec<&str> {
    let body = text.strip_suffix('\n').unwrap_or(text);
    if body.is_empty() && text.is_empty() {
        return Vec::new();
    }
    body.split('\n').collect()
}

/// Walk the token stream, marking the lines each token occupies.
///
/// GROUPS ARE WALKED BY THEIR DELIMITERS, not by their whole span: a `{ … }` spanning two hundred
/// lines would otherwise mark every blank line and every comment inside it as code. The delimiters
/// are marked, the interior is recursed into, and what neither touches is what the lexer threw
/// away — which is exactly the comment-or-blank set this wants.
fn mark_tokens(
    ts: TokenStream,
    lines: &[&str],
    code: &mut BTreeSet<usize>,
    doc: &mut BTreeSet<usize>,
) {
    for tt in ts {
        match tt {
            TokenTree::Group(g) => {
                let whole = g.span();
                // A doc comment lexes into `#`, `[`, `doc`, `=`, "text", `]` — a Group among them —
                // and proc-macro2 gives every one of those the ORIGINAL comment's span. So the
                // group's own span pointing at `//` or `/*` in the source is the exact, textless
                // test for "this token came from a doc comment".
                if starts_comment(lines, whole.start()) {
                    mark_range(doc, whole.start(), whole.end());
                    continue;
                }
                let open = g.span_open();
                let close = g.span_close();
                mark_range(code, open.start(), open.end());
                mark_range(code, close.start(), close.end());
                mark_tokens(g.stream(), lines, code, doc);
            }
            other => {
                let span = other.span();
                if starts_comment(lines, span.start()) {
                    mark_range(doc, span.start(), span.end());
                } else {
                    mark_range(code, span.start(), span.end());
                }
            }
        }
    }
}

fn mark_range(set: &mut BTreeSet<usize>, from: LineColumn, to: LineColumn) {
    for line in from.line..=to.line.max(from.line) {
        set.insert(line);
    }
}

/// Does the source at `at` begin a comment?
///
/// `LineColumn.line` is 1-based and `.column` is a 0-based CHARACTER index, so this indexes chars
/// and not bytes — a file with a `—` in a doc comment above the span would otherwise read the
/// wrong two characters and mis-bucket the line.
///
/// Two characters is enough and cannot false-positive: `//` and `/*` never lex as two punctuation
/// tokens, because the lexer takes them as a comment first. A real `/` token is followed by
/// whitespace, an operand or `=`.
fn starts_comment(lines: &[&str], at: LineColumn) -> bool {
    let Some(line) = lines.get(at.line.wrapping_sub(1)) else {
        return false;
    };
    let mut it = line.chars().skip(at.column);
    matches!(it.next(), Some('/')) && matches!(it.next(), Some('/') | Some('*'))
}

/// Collects the line span of every `#[cfg(test)]`-guarded node, at every depth.
///
/// It does NOT recurse into a node it has already claimed: the whole item is test, and re-walking
/// its children can only re-mark lines that are already marked.
struct TestSpans<'a> {
    out: &'a mut BTreeSet<usize>,
}

impl TestSpans<'_> {
    fn claim<T: Spanned>(&mut self, node: &T) {
        let span = node.span();
        mark_range(self.out, span.start(), span.end());
    }
}

impl<'ast> Visit<'ast> for TestSpans<'_> {
    fn visit_item(&mut self, node: &'ast syn::Item) {
        if item_attrs(node).is_some_and(has_cfg_test) {
            self.claim(node);
            return;
        }
        syn::visit::visit_item(self, node);
    }

    fn visit_impl_item(&mut self, node: &'ast syn::ImplItem) {
        if impl_item_attrs(node).is_some_and(has_cfg_test) {
            self.claim(node);
            return;
        }
        syn::visit::visit_impl_item(self, node);
    }

    fn visit_trait_item(&mut self, node: &'ast syn::TraitItem) {
        if trait_item_attrs(node).is_some_and(has_cfg_test) {
            self.claim(node);
            return;
        }
        syn::visit::visit_trait_item(self, node);
    }

    fn visit_foreign_item(&mut self, node: &'ast syn::ForeignItem) {
        if foreign_item_attrs(node).is_some_and(has_cfg_test) {
            self.claim(node);
            return;
        }
        syn::visit::visit_foreign_item(self, node);
    }

    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        let attrs = match node {
            syn::Stmt::Local(l) => Some(l.attrs.as_slice()),
            syn::Stmt::Macro(m) => Some(m.attrs.as_slice()),
            _ => None,
        };
        if attrs.is_some_and(has_cfg_test) {
            self.claim(node);
            return;
        }
        syn::visit::visit_stmt(self, node);
    }

    fn visit_field(&mut self, node: &'ast syn::Field) {
        if has_cfg_test(&node.attrs) {
            self.claim(node);
            return;
        }
        syn::visit::visit_field(self, node);
    }

    fn visit_variant(&mut self, node: &'ast syn::Variant) {
        if has_cfg_test(&node.attrs) {
            self.claim(node);
            return;
        }
        syn::visit::visit_variant(self, node);
    }

    fn visit_arm(&mut self, node: &'ast syn::Arm) {
        if has_cfg_test(&node.attrs) {
            self.claim(node);
            return;
        }
        syn::visit::visit_arm(self, node);
    }
}

// ── THE ATTRIBUTE ACCESSORS ──────────────────────────────────────────────────────────────────────
// syn gives no uniform `attrs()`, and a wildcard arm here would silently stop seeing a variant the
// next syn release adds. Each is spelled out, `Verbatim` (which genuinely has no attrs) included, so
// the reader can check the list against the grammar rather than trust it.

fn item_attrs(item: &syn::Item) -> Option<&[syn::Attribute]> {
    use syn::Item::*;
    Some(match item {
        Const(i) => &i.attrs,
        Enum(i) => &i.attrs,
        ExternCrate(i) => &i.attrs,
        Fn(i) => &i.attrs,
        ForeignMod(i) => &i.attrs,
        Impl(i) => &i.attrs,
        Macro(i) => &i.attrs,
        Mod(i) => &i.attrs,
        Static(i) => &i.attrs,
        Struct(i) => &i.attrs,
        Trait(i) => &i.attrs,
        TraitAlias(i) => &i.attrs,
        Type(i) => &i.attrs,
        Union(i) => &i.attrs,
        Use(i) => &i.attrs,
        _ => return None,
    })
}

fn impl_item_attrs(item: &syn::ImplItem) -> Option<&[syn::Attribute]> {
    use syn::ImplItem::*;
    Some(match item {
        Const(i) => &i.attrs,
        Fn(i) => &i.attrs,
        Type(i) => &i.attrs,
        Macro(i) => &i.attrs,
        _ => return None,
    })
}

fn trait_item_attrs(item: &syn::TraitItem) -> Option<&[syn::Attribute]> {
    use syn::TraitItem::*;
    Some(match item {
        Const(i) => &i.attrs,
        Fn(i) => &i.attrs,
        Type(i) => &i.attrs,
        Macro(i) => &i.attrs,
        _ => return None,
    })
}

fn foreign_item_attrs(item: &syn::ForeignItem) -> Option<&[syn::Attribute]> {
    use syn::ForeignItem::*;
    Some(match item {
        Fn(i) => &i.attrs,
        Static(i) => &i.attrs,
        Type(i) => &i.attrs,
        Macro(i) => &i.attrs,
        _ => return None,
    })
}

/// Does any attribute in `attrs` gate its item on `test`?
pub fn has_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        // `cfg_attr(test, …)` applies an attribute in test builds; it does not REMOVE the item from
        // production ones, so it is not a test gate and this deliberately does not match it.
        if !a.path().is_ident("cfg") {
            return false;
        }
        match &a.meta {
            syn::Meta::List(list) => predicate_is_test(list.tokens.clone()),
            _ => false,
        }
    })
}

/// Is this cfg PREDICATE a test gate?
///
/// Walked as the tree it is, not matched as a substring, because the difference decides whether
/// production code is counted:
///
/// * `test`                                  -> yes
/// * `all(test, feature = "x")`              -> yes (the item exists only in test builds)
/// * `any(test, feature = "test-support")`   -> yes (same rule `xtask`'s purity scanner applies)
/// * `not(test)`                             -> **NO**. This is the arm that SHIPS. Twelve of them
///   in this tree, and the regex it replaces — `\btest\b` anywhere inside the attribute — dropped
///   every one as if it were a test module.
/// * `not(any(test, …))`, `all(not(test), …)` -> no, for the same reason, at any depth.
/// * `feature = "test-support"`              -> no. A feature whose NAME contains "test" is a
///   feature; `\btest\b` matched that too, because `test-support` has a word boundary after `test`.
fn predicate_is_test(tokens: TokenStream) -> bool {
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    let mut i = 0;
    while i < trees.len() {
        let TokenTree::Ident(id) = &trees[i] else {
            i += 1;
            continue;
        };
        let name = id.to_string();
        let paren = match trees.get(i + 1) {
            Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis => {
                Some(g.stream())
            }
            _ => None,
        };
        let is_kv = matches!(trees.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == '=');
        match (name.as_str(), paren) {
            // NEGATION IS NOT DESCENDED INTO. Whatever `test` does inside a `not(...)`, the item it
            // guards is the one that exists when tests are NOT being built: production code.
            ("not", Some(_)) => i += 2,
            ("all", Some(inner)) | ("any", Some(inner)) => {
                if predicate_is_test(inner) {
                    return true;
                }
                i += 2;
            }
            ("test", None) if !is_kv => return true,
            (_, Some(_)) => i += 2,
            _ => i += if is_kv { 3 } else { 1 },
        }
    }
    false
}
