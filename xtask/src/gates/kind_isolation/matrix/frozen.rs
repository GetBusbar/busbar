//! FROZEN 1.5.5 CUSTOMER-OBSERVABLE BYTES ARE EXEMPT FROM LAW 0 ONLY IN PLACE (ARCHITECT ruling
//! 2026-10-21 as amended, docs/design/BUSBAR-1.6.0.md l.4323-4332; per its l.4329 it overrides the
//! l.4318 "still count everywhere" clause for these bytes alone).
//!
//! THE BASIS IS CUSTOMER-OBSERVABLE BYTES ONLY. Part 0 (BUSBAR-1.6.0.md l.79, l.1790) holds what a
//! customer sees to 1.5.5's bytes, and DoD item 6 (l.2022) holds the config and the admin API to it.
//! Five 1.5.5 surfaces carry plugin names a customer reads: the admin API's OpenAPI document, the
//! config schema snapshot, the `--migrate-config` translation (which must read 1.5.x module names)
//! and the `{ env: VAR }` / `{ file: path }` secret shorthand. Counting a name the release wrote there
//! charges core with a reference it cannot drain without changing those bytes. Only the named
//! [`ARTIFACTS`] are read; nothing else is exempt. Test code is never one: no customer observes it.
//!
//! WHAT ON A FROZEN LINE IS EXEMPT ([`Scope`]). In the two JSON documents the whole line is the
//! customer's bytes. In the three Rust artifacts only the bytes INSIDE A STRING LITERAL are: the
//! module names and keys the release reads and writes. An identifier, a comment, a doc comment or a
//! local on the same line is source, never served, and counts exactly as anywhere else.
//!
//! THE EXEMPTION IS POSITIONAL: A LINE, NOT A STRING. A hit is exempt only when its line is THE SAME
//! LINE the artifact carried at [`RELEASE`], unchanged: the line is matched (byte-equal, whole) in a
//! minimal line diff of the artifact against its own bytes at the release ([`line_mask`], Myers'
//! O(ND) alignment). An equal string written anywhere else in the file is an insertion of that diff
//! and counts; so does an edited line, a moved line and a new one. The 1.6.0 `"streams"` key of the
//! schema snapshot, whose text matched another 1.5.5 line, is the case this rules out.
//!
//! THE RELEASE IS PINNED, NOT NAMED. Its bytes are read at [`RELEASE_COMMIT`] only after
//! [`RELEASE_TAG_REF`] (`refs/tags/v1.5.5`, never the bare name a branch can shadow) resolves to the
//! pinned tag object [`RELEASE_TAG_OBJECT`] and that tag peels to the pinned commit. A missing tag, a
//! moved tag, or a branch named `v1.5.5` freezes nothing.
//!
//! WHY A DIFF AGAINST THE RELEASE AND NOT `git blame`. Blame's attribution IS diff alignment, applied
//! commit by commit; this is the same alignment taken once, from the release to the bytes under
//! judgement. It reads one pinned object, so it needs no history between the two (a shallow clone
//! answers the same), no rename heuristics (every artifact moved crates since 1.5.5, which blame
//! follows only with `-C` guessing), and it judges the tree the gate is handed, overlays included,
//! so a self-test plants both sides and a working tree is judged as written rather than as
//! committed. If the release cannot be read the artifact exempts nothing: when an instrument must
//! choose, it false-fails.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::ctx::Ctx;

/// The released tag whose bytes are frozen.
pub(super) const RELEASE: &str = "v1.5.5";

/// The one ref the release is read through: the tag namespace, so a branch named [`RELEASE`] is
/// never consulted.
pub(super) const RELEASE_TAG_REF: &str = "refs/tags/v1.5.5";

/// The annotated tag object [`RELEASE_TAG_REF`] must resolve to (`git rev-parse refs/tags/v1.5.5`).
pub(super) const RELEASE_TAG_OBJECT: &str = "d3c50432995b8f4b4582380b6c4415308ed44cfc";

/// The commit that tag peels to (`git rev-parse refs/tags/v1.5.5^{commit}`): the bytes are read here.
pub(super) const RELEASE_COMMIT: &str = "a71b21e9fa0e8a35bd0c86f53f8a79eac2974d05";

/// The overlay key a self-test plants to answer `git rev-parse --verify <ref>` (an empty answer is a
/// ref that does not resolve).
pub(super) fn rev_parse_key(r: &str) -> String {
    format!("git-rev-parse:{r}")
}

/// What on a frozen line is exempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Scope {
    /// The whole line: a served document, every byte of which the customer reads.
    Line,
    /// Only the bytes inside a string literal: identifiers, comments and locals still count.
    Literal,
}

/// One frozen artifact: where it lives now, where it lived at [`RELEASE`], and the surface it is.
pub(super) struct Artifact {
    /// The path in this tree.
    pub(super) path: &'static str,
    /// The path of the same artifact at [`RELEASE_COMMIT`].
    pub(super) released: &'static str,
    /// What on a frozen line is exempt.
    pub(super) scope: Scope,
    /// The 1.5.5 surface, cited.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) surface: &'static str,
}

/// THE NAMED ARTIFACTS, each a customer-observable 1.5.5 surface. Nothing else is exempt.
pub(super) const ARTIFACTS: &[Artifact] = &[
    Artifact {
        path: "crates/busbar-core-admin/src/v1/json/openapi.json",
        // qa-names: crates/busbar/src/admin/v1/json/openapi.json -- xtask/src/gates/kind_isolation/matrix/frozen.rs -- v1.5.5 path read via git show at the pinned tag
        released: "crates/busbar/src/admin/v1/json/openapi.json",
        scope: Scope::Line,
        surface: "the admin API's OpenAPI document, served at GET /v1/openapi.json (v1.5.5 \
                  crates/busbar/src/admin/v1/json/openapi.json)",
    },
    Artifact {
        path: "crates/busbar-kernel/src/config/config-schema.snapshot.json",
        // qa-names: crates/busbar/src/config/config-schema.snapshot.json -- xtask/src/gates/kind_isolation/matrix/frozen.rs -- v1.5.5 path read via git show at the pinned tag
        released: "crates/busbar/src/config/config-schema.snapshot.json",
        scope: Scope::Line,
        surface:
            "the operator config schema snapshot the config-schema gate holds additive (v1.5.5 \
                  crates/busbar/src/config/config-schema.snapshot.json)",
    },
    Artifact {
        path: "crates/busbar-kernel/src/config/migrate.rs",
        // qa-names: crates/busbar/src/config/migrate.rs -- xtask/src/gates/kind_isolation/matrix/frozen.rs -- v1.5.5 path read via git show at the pinned tag
        released: "crates/busbar/src/config/migrate.rs",
        scope: Scope::Literal,
        surface: "the --migrate-config translation, which reads 1.5.x module names (v1.5.5 \
                  crates/busbar/src/config/migrate.rs)",
    },
    Artifact {
        path: "crates/busbar-kernel/src/config/migrate_export.rs",
        // qa-names: crates/busbar/src/config/migrate_export.rs -- xtask/src/gates/kind_isolation/matrix/frozen.rs -- v1.5.5 path read via git show at the pinned tag
        released: "crates/busbar/src/config/migrate_export.rs",
        scope: Scope::Literal,
        surface: "the --migrate-config export translation: 1.5.x export modules and their streams \
                  (v1.5.5 crates/busbar/src/config/migrate_export.rs)",
    },
    Artifact {
        path: "crates/busbar-contract/src/secret_ref.rs",
        // qa-names: crates/secret-ref/src/lib.rs -- xtask/src/gates/kind_isolation/matrix/frozen.rs -- v1.5.5 path read via git show at the pinned tag
        released: "crates/secret-ref/src/lib.rs",
        scope: Scope::Literal,
        surface:
            "the { env: VAR } / { file: path } secret shorthand and its built-in module names \
                  (v1.5.5 crates/secret-ref/src/lib.rs)",
    },
];

/// The artifact at `path`, if it is one.
pub(super) fn artifact(path: &str) -> Option<&'static Artifact> {
    ARTIFACTS.iter().find(|a| a.path == path)
}

/// The overlay key a self-test plants to answer the artifact's bytes at the release.
pub(super) fn show_key(a: &Artifact) -> String {
    format!("git-show:{RELEASE_COMMIT}:{}", a.released)
}

/// Per artifact path, its text at the release.
pub(super) type Frozen = BTreeMap<&'static str, Arc<String>>;

type RevMemo = std::sync::Mutex<BTreeMap<(std::path::PathBuf, String), Option<String>>>;
static REV_MEMO: std::sync::OnceLock<RevMemo> = std::sync::OnceLock::new();

/// `git rev-parse --verify --quiet <r>`, a planted answer first (never memoised), else git's,
/// read once per (root, ref) and process. `None` when it does not resolve.
fn rev_parse(cx: &Ctx, r: &str) -> Option<String> {
    if let Some(planted) = cx.overlay_command(&rev_parse_key(r)) {
        let t = planted.trim().to_string();
        return (!t.is_empty()).then_some(t);
    }
    let key = (cx.root().to_path_buf(), r.to_string());
    let memo = REV_MEMO.get_or_init(Default::default);
    if let Some(held) = memo
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&key)
    {
        return held.clone();
    }
    let read = cx
        .git_lines(&["rev-parse", "--verify", "--quiet", r])
        .ok()
        .and_then(|l| l.into_iter().next())
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty());
    memo.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(key, read.clone());
    read
}

/// THE PINNED RELEASE, VERIFIED: [`RELEASE_TAG_REF`] resolves to [`RELEASE_TAG_OBJECT`] and peels to
/// [`RELEASE_COMMIT`], or the release is refused and nothing is frozen.
pub(super) fn release_commit(cx: &Ctx) -> Result<&'static str, String> {
    let tag = rev_parse(cx, RELEASE_TAG_REF)
        .ok_or_else(|| format!("{RELEASE_TAG_REF} does not resolve: nothing is frozen"))?;
    if tag != RELEASE_TAG_OBJECT {
        return Err(format!(
            "{RELEASE_TAG_REF} resolves to {tag}, not the pinned {RELEASE_TAG_OBJECT}: nothing is \
             frozen"
        ));
    }
    let peeled = format!("{RELEASE_TAG_REF}^{{commit}}");
    let commit = rev_parse(cx, &peeled)
        .ok_or_else(|| format!("{peeled} does not resolve: nothing is frozen"))?;
    if commit != RELEASE_COMMIT {
        return Err(format!(
            "{peeled} is {commit}, not the pinned {RELEASE_COMMIT}: nothing is frozen"
        ));
    }
    Ok(RELEASE_COMMIT)
}

/// The artifact's bytes at the verified release, read afresh (the self-test's plants).
pub(super) fn released_bytes(cx: &Ctx, a: &Artifact) -> Result<String, String> {
    let commit = release_commit(cx)?;
    cx.git_show(commit, a.released)
}

type ReleasedMemo = std::sync::Mutex<BTreeMap<&'static str, Option<Arc<String>>>>;
static RELEASED_MEMO: std::sync::OnceLock<ReleasedMemo> = std::sync::OnceLock::new();

/// The text of `a` at the verified release, read with `git show` once per process; a self-test's
/// planted answer is read first and never memoised. The release is verified on every call, so a
/// plant that moves or removes the tag is never answered from the memo.
fn released_text(cx: &Ctx, a: &'static Artifact) -> Option<Arc<String>> {
    let commit = release_commit(cx).ok()?;
    if let Some(planted) = cx.overlay_command(&show_key(a)) {
        return Some(Arc::new(planted));
    }
    let memo = RELEASED_MEMO.get_or_init(Default::default);
    if let Some(held) = memo
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(a.path)
    {
        return held.clone();
    }
    let read = cx.git_show(commit, a.released).ok().map(Arc::new);
    memo.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(a.path, read.clone());
    read
}

/// The released text of every artifact, for this tree.
pub(super) fn load(cx: &Ctx) -> Frozen {
    ARTIFACTS
        .iter()
        .filter_map(|a| released_text(cx, a).map(|t| (a.path, t)))
        .collect()
}

/// Per line of a file (index `i` is line `i + 1`), whether it is a frozen 1.5.5 line in place.
pub(super) type Mask = Arc<Vec<bool>>;

type MaskMemo = std::sync::Mutex<BTreeMap<(String, u64, u64), Mask>>;
static MASK_MEMO: std::sync::OnceLock<MaskMemo> = std::sync::OnceLock::new();

fn digest(text: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut h);
    h.finish()
}

/// The frozen-line mask of `text`, the file at `rel`, whatever its [`Scope`]: `None` when `rel` is
/// no artifact or its release could not be read (nothing is exempt). Computed once per (path,
/// bytes, released bytes).
pub(super) fn line_mask(frozen: &Frozen, rel: &str, text: &str) -> Option<Mask> {
    let released = frozen.get(rel)?;
    let key = (rel.to_string(), digest(text), digest(released));
    let memo = MASK_MEMO.get_or_init(Default::default);
    if let Some(held) = memo
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&key)
    {
        return Some(held.clone());
    }
    let m = Arc::new(aligned(released, text));
    memo.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(key, m.clone());
    Some(m)
}

/// The lines of `text` whose EVERY hit is exempt: the frozen lines of a [`Scope::Line`] artifact.
/// `None` for a [`Scope::Literal`] artifact, whose lines are never exempt whole ([`literals_struck`]).
pub(super) fn exempt_lines(frozen: &Frozen, rel: &str, text: &str) -> Option<Mask> {
    match artifact(rel)?.scope {
        Scope::Line => line_mask(frozen, rel, text),
        Scope::Literal => None,
    }
}

/// THE LITERAL-ONLY EXEMPTION of a [`Scope::Literal`] artifact: `reading` (the file's text, or a
/// same-length masked reading of it) with the CONTENT of every string literal on a frozen line
/// filled with `x`, so the scanners read the line's identifiers, comments and locals and nothing
/// the literal held. The literals are found in `text` by [`literal_spans`]. `None` when `rel` is no
/// literal-scope artifact or its release could not be read: nothing is struck, every hit counts.
pub(super) fn literals_struck(
    frozen: &Frozen,
    rel: &str,
    text: &str,
    reading: &str,
) -> Option<String> {
    if artifact(rel)?.scope != Scope::Literal {
        return None;
    }
    let mask = line_mask(frozen, rel, text)?;
    // The mask chain fills ASCII for ASCII, so its reading keeps every byte offset of `text`; a
    // reading that does not is lexed on its own bytes.
    let spans = if reading.len() == text.len() {
        literal_spans(text)
    } else {
        literal_spans(reading)
    };
    let mut buf = reading.as_bytes().to_vec();
    let starts: Vec<usize> = std::iter::once(0)
        .chain(
            reading
                .bytes()
                .enumerate()
                .filter(|(_, b)| *b == b'\n')
                .map(|(i, _)| i + 1),
        )
        .collect();
    for (s, e) in spans {
        for (k, byte) in buf.iter_mut().enumerate().take(e).skip(s) {
            if *byte == b'\n' {
                continue;
            }
            // `starts` holds every line's first byte; the line holding `k` is the last start <= k.
            let line = starts.partition_point(|&st| st <= k);
            if at(&mask, line) {
                *byte = b'x';
            }
        }
    }
    // Whole characters are filled (a span runs between two ASCII quotes and every byte of it but a
    // newline is replaced), so the buffer is still UTF-8.
    String::from_utf8(buf).ok()
}

/// The byte ranges of the CONTENT of every Rust string literal in `text` (`"…"`, `b"…"`, `c"…"`
/// and their raw forms `r#"…"#`), skipping line comments, nested block comments, doc comments, and
/// char and byte literals (`'"'`), so a quote inside any of those opens nothing.
pub(super) fn literal_spans(text: &str) -> Vec<(usize, usize)> {
    let b = text.as_bytes();
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let mut depth = 1usize;
                i += 2;
                while i < b.len() && depth > 0 {
                    if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        i += 2;
                    } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            }
            b'\'' => {
                if b.get(i + 1) == Some(&b'\\') {
                    // An escaped char literal: `'\''`, `'\n'`, `'\u{2028}'`.
                    let mut j = i + 3;
                    while j < b.len() && j < i + 16 && b[j] != b'\'' {
                        j += 1;
                    }
                    i = j + 1;
                } else {
                    let width = text
                        .get(i + 1..)
                        .and_then(|t| t.chars().next())
                        .map_or(1, char::len_utf8);
                    // `'x'` is a char literal; `'a` with no closing quote is a lifetime or a label.
                    i += if b.get(i + 1 + width) == Some(&b'\'') {
                        width + 2
                    } else {
                        1
                    };
                }
            }
            b'"' => i = string_end(b, i + 1, &mut out),
            c if ident(c) => {
                let prev_ident = i > 0 && ident(b[i - 1]);
                let mut j = i;
                if !prev_ident && (c == b'b' || c == b'c') {
                    j += 1;
                }
                let raw = !prev_ident && b.get(j) == Some(&b'r');
                if raw {
                    j += 1;
                }
                let mut hashes = 0usize;
                while raw && b.get(j) == Some(&b'#') {
                    hashes += 1;
                    j += 1;
                }
                if !prev_ident && j > i && b.get(j) == Some(&b'"') {
                    i = if raw {
                        raw_end(b, j + 1, hashes, &mut out)
                    } else {
                        string_end(b, j + 1, &mut out)
                    };
                } else if !prev_ident && c == b'b' && b.get(i + 1) == Some(&b'\'') {
                    // A byte literal `b'"'`: the char-literal arm reads it from its quote.
                    i += 1;
                } else {
                    while i < b.len() && ident(b[i]) {
                        i += 1;
                    }
                }
            }
            _ => i += 1,
        }
    }
    out
}

/// Records the content of a `"…"` literal opened before `from`, and returns the byte after it.
fn string_end(b: &[u8], from: usize, out: &mut Vec<(usize, usize)>) -> usize {
    let mut j = from;
    while j < b.len() && b[j] != b'"' {
        j += if b[j] == b'\\' { 2 } else { 1 };
    }
    let end = j.min(b.len());
    out.push((from, end));
    end + 1
}

/// Records the content of a raw literal closed by `"` and `hashes` `#`, and returns the byte after.
fn raw_end(b: &[u8], from: usize, hashes: usize, out: &mut Vec<(usize, usize)>) -> usize {
    let mut j = from;
    while j < b.len() {
        if b[j] == b'"' && (1..=hashes).all(|h| b.get(j + h) == Some(&b'#')) {
            out.push((from, j));
            return j + 1 + hashes;
        }
        j += 1;
    }
    out.push((from, b.len()));
    b.len()
}

/// Whether line `line` (1-based; 0 is the path, never frozen) is frozen under `mask`.
pub(super) fn at(mask: &[bool], line: usize) -> bool {
    line.checked_sub(1)
        .and_then(|i| mask.get(i))
        .copied()
        .unwrap_or(false)
}

/// Per line of `now`, whether a minimal line diff from `then` to `now` keeps it (matched, not
/// inserted). Lines compare whole and byte-equal: an edit of any byte, indentation included, is
/// an edit.
fn aligned(then: &str, now: &str) -> Vec<bool> {
    let mut ids: BTreeMap<&str, u32> = BTreeMap::new();
    let mut id = |l| {
        let next = u32::try_from(ids.len()).unwrap_or(u32::MAX);
        *ids.entry(l).or_insert(next)
    };
    let a: Vec<u32> = then.lines().map(&mut id).collect();
    let b: Vec<u32> = now.lines().map(&mut id).collect();
    let mut out = vec![false; b.len()];
    align(&a, &b, 0, &mut out);
    out
}

/// Marks in `out` (indexed from `b_at`) every line of `b` a minimal edit script from `a` keeps:
/// the common prefix and suffix, then the halves either side of Myers' middle split.
fn align(a: &[u32], b: &[u32], b_at: usize, out: &mut [bool]) {
    let pre = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    for o in &mut out[b_at..b_at + pre] {
        *o = true;
    }
    let (a, b, b_at) = (&a[pre..], &b[pre..], b_at + pre);
    let suf = a
        .iter()
        .rev()
        .zip(b.iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    for o in &mut out[b_at + b.len() - suf..b_at + b.len()] {
        *o = true;
    }
    let (a, b) = (&a[..a.len() - suf], &b[..b.len() - suf]);
    if a.is_empty() || b.is_empty() {
        return;
    }
    if let Some((x, y)) = split(a, b) {
        align(&a[..x], &b[..y], b_at, out);
        align(&a[x..], &b[y..], b_at + y, out);
    }
}

/// Myers' middle split of a minimal edit script from `a` to `b` (both non-empty, sharing no prefix
/// or suffix): a point `(x, y)` such that a minimal script passes through it, or `None` when the
/// two share no line at all.
fn split(a: &[u32], b: &[u32]) -> Option<(usize, usize)> {
    let n = isize::try_from(a.len()).ok()?;
    let m = isize::try_from(b.len()).ok()?;
    let max_d = (n + m + 1) / 2;
    let off = max_d + 1;
    let len = usize::try_from(2 * max_d + 3).ok()?;
    let mut v1 = vec![-1isize; len];
    let mut v2 = vec![-1isize; len];
    let ix = |k: isize| usize::try_from(off + k).ok();
    v1[ix(1)?] = 0;
    v2[ix(1)?] = 0;
    let delta = n - m;
    // With an odd delta the forward path meets the reverse one; with an even, the reverse meets.
    let front = delta % 2 != 0;
    let (mut k1start, mut k1end, mut k2start, mut k2end) = (0isize, 0isize, 0isize, 0isize);
    let at = |s: &[u32], i: isize| s[usize::try_from(i).unwrap_or(0)];
    for d in 0..max_d {
        let mut k1 = -d + k1start;
        while k1 <= d - k1end {
            let k = ix(k1)?;
            let mut x1 = if k1 == -d || (k1 != d && v1[k - 1] < v1[k + 1]) {
                v1[k + 1]
            } else {
                v1[k - 1] + 1
            };
            let mut y1 = x1 - k1;
            while x1 < n && (0..m).contains(&y1) && at(a, x1) == at(b, y1) {
                x1 += 1;
                y1 += 1;
            }
            v1[k] = x1;
            if x1 > n {
                k1end += 2;
            } else if y1 > m {
                k1start += 2;
            } else if front {
                if let Some(k2) = ix(delta - k1).filter(|k2| *k2 < len) {
                    if v2[k2] != -1 && x1 >= n - v2[k2] {
                        return Some((usize::try_from(x1).ok()?, usize::try_from(y1).ok()?));
                    }
                }
            }
            k1 += 2;
        }
        let mut k2 = -d + k2start;
        while k2 <= d - k2end {
            let k = ix(k2)?;
            let mut x2 = if k2 == -d || (k2 != d && v2[k - 1] < v2[k + 1]) {
                v2[k + 1]
            } else {
                v2[k - 1] + 1
            };
            let mut y2 = x2 - k2;
            while x2 < n && (0..m).contains(&y2) && at(a, n - x2 - 1) == at(b, m - y2 - 1) {
                x2 += 1;
                y2 += 1;
            }
            v2[k] = x2;
            if x2 > n {
                k2end += 2;
            } else if y2 > m {
                k2start += 2;
            } else if !front {
                if let Some(k1) = ix(delta - k2).filter(|k1| *k1 < len) {
                    let x1 = v1[k1];
                    if x1 != -1 {
                        let y1 = x1 - (delta - k2);
                        if x1 >= n - x2 {
                            return Some((usize::try_from(x1).ok()?, usize::try_from(y1).ok()?));
                        }
                    }
                }
            }
            k2 += 2;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_entry_cites_its_surface_and_names_a_file_of_this_tree() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask sits in the repository root");
        for a in ARTIFACTS {
            assert!(
                a.surface.contains("v1.5.5"),
                "{} cites no 1.5.5 surface",
                a.path
            );
            assert!(
                !a.released.contains(':'),
                "{} names a path, not a ref",
                a.released
            );
            assert!(root.join(a.path).is_file(), "{} is not in the tree", a.path);
            // Test code is not customer-observable: no test file is ever an artifact.
            assert!(
                !a.path.contains("/tests/") && !a.path.ends_with("_tests.rs"),
                "{} is test code",
                a.path
            );
            // Only the JSON documents are served whole; a Rust artifact exempts its literals only.
            let json = a.path.ends_with(".json");
            assert_eq!(a.scope == Scope::Line, json, "{}", a.path);
        }
    }

    #[test]
    fn the_release_is_pinned_by_tag_object_and_commit() {
        assert_eq!(RELEASE_TAG_REF, format!("refs/tags/{RELEASE}"));
        for sha in [RELEASE_TAG_OBJECT, RELEASE_COMMIT] {
            assert_eq!(sha.len(), 40, "{sha} is a full sha");
            assert!(sha.bytes().all(|b| b.is_ascii_hexdigit()), "{sha}");
        }
    }

    fn spans_of(text: &str) -> Vec<&str> {
        literal_spans(text)
            .into_iter()
            .map(|(s, e)| &text[s..e])
            .collect()
    }

    #[test]
    fn only_string_literal_content_is_a_literal() {
        assert_eq!(
            spans_of("pub const SECRET_MODULE_ENV: &str = \"env\"; // the \"file\" one"),
            ["env"]
        );
        assert_eq!(
            spans_of("/// the `streams:` key, \"llm\"\nlet x = 1;"),
            Vec::<&str>::new()
        );
        assert_eq!(
            spans_of("/* a \"mcp\" /* nested \"x\" */ */ f(\"a\\\"b\")"),
            ["a\\\"b"]
        );
        assert_eq!(spans_of("let q = '\"'; let s = \"otlp\";"), ["otlp"]);
        assert_eq!(
            spans_of("let q = b'\"'; let l: &'a str = r#\"x\"y\"#;"),
            ["x\"y"]
        );
        assert_eq!(
            spans_of("let a = b\"llm\"; let e = '\\''; let c = \"\";"),
            ["llm", ""]
        );
    }

    #[test]
    fn a_literal_scope_artifact_strikes_only_literals_on_frozen_lines() {
        let rs = ARTIFACTS
            .iter()
            .find(|a| a.scope == Scope::Literal)
            .expect("a Rust artifact");
        let then = "const MCP_ROUTE: &str = \"mcp\"; // mcp\n";
        let now = "const MCP_ROUTE: &str = \"mcp\"; // mcp\nconst X: &str = \"mcp\";\n";
        let mut frozen = Frozen::new();
        frozen.insert(rs.path, Arc::new(then.to_string()));
        let struck = literals_struck(&frozen, rs.path, now, now).expect("a literal-scope artifact");
        // The frozen line keeps its identifier and comment; the new line keeps everything.
        assert_eq!(
            struck,
            "const MCP_ROUTE: &str = \"xxx\"; // mcp\nconst X: &str = \"mcp\";\n"
        );
        assert!(exempt_lines(&frozen, rs.path, now).is_none());
        let json = ARTIFACTS
            .iter()
            .find(|a| a.scope == Scope::Line)
            .expect("a JSON artifact");
        frozen.insert(json.path, Arc::new(then.to_string()));
        assert!(literals_struck(&frozen, json.path, now, now).is_none());
        assert!(exempt_lines(&frozen, json.path, now).is_some());
    }

    fn kept(then: &[&str], now: &[&str]) -> Vec<bool> {
        aligned(&then.join("\n"), &now.join("\n"))
    }

    #[test]
    fn an_unchanged_line_is_frozen_in_place_and_an_equal_string_elsewhere_is_not() {
        let then = ["{", "  \"x\": \"llm\",", "  \"z\": 1", "}"];
        // Unchanged, with a line inserted before it: still the same line.
        let now = ["{", "  \"w\": 0,", "  \"x\": \"llm\",", "  \"z\": 1", "}"];
        assert_eq!(kept(&then, &now), [true, false, true, true, true]);
        // COPIED: the 1.5.5 string written again at a new position counts there.
        let now = [
            "{",
            "  \"x\": \"llm\",",
            "  \"z\": 1",
            "  \"x\": \"llm\",",
            "}",
        ];
        let m = kept(&then, &now);
        assert!(m[1], "the original stays in place");
        assert!(!m[3], "the copy is new: {m:?}");
        // EDITED: one byte, indentation included.
        let now = ["{", "   \"x\": \"llm\",", "  \"z\": 1", "}"];
        assert_eq!(kept(&then, &now), [true, false, true, true]);
    }

    #[test]
    fn a_moved_line_is_not_frozen() {
        let then = ["a", "llm", "b", "c", "d", "e"];
        let now = ["a", "b", "c", "d", "e", "llm"];
        assert_eq!(kept(&then, &now), [true, true, true, true, true, false]);
        let then = ["a", "b", "c", "d", "llm", "e"];
        let now = ["llm", "a", "b", "c", "d", "e"];
        assert_eq!(kept(&then, &now), [false, true, true, true, true, true]);
    }

    #[test]
    fn the_alignment_is_minimal_on_interleaved_edits() {
        // A longest common subsequence of these is 5 lines (a b d f g).
        let then = ["a", "b", "c", "d", "e", "f", "g"];
        let now = ["x", "a", "b", "d", "y", "f", "z", "g"];
        let m = kept(&then, &now);
        assert_eq!(m.iter().filter(|k| **k).count(), 5, "{m:?}");
        assert_eq!(m, [false, true, true, true, false, true, false, true]);
        // Nothing shared, and an empty side.
        assert_eq!(kept(&["a"], &["b", "c"]), [false, false]);
        assert_eq!(kept(&[], &["a"]), [false]);
        assert!(kept(&["a"], &[]).is_empty());
    }

    #[test]
    fn only_a_listed_artifact_has_a_mask_and_line_zero_is_never_frozen() {
        let mut frozen = Frozen::new();
        frozen.insert(ARTIFACTS[0].path, Arc::new("a\nllm\nb\n".to_string()));
        let m = line_mask(&frozen, ARTIFACTS[0].path, "a\nllm\nb\nllm\n").expect("listed");
        assert!(at(&m, 2));
        assert!(!at(&m, 4));
        assert!(!at(&m, 0));
        assert!(!at(&m, 9));
        assert!(line_mask(&frozen, "crates/busbar-kernel/src/lib.rs", "llm\n").is_none());
    }
}
