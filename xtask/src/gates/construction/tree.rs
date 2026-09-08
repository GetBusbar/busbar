//! THE CONSTRUCTION GATE'S TREE: every scanned file, its lines and its functions, read once.
//!
//! A port of `scripts/construction-gate/rules.py`'s scanning half, which is itself the purity
//! lint's `strip()` plus test-scope tracking. It is NOT [`crate::scan`]: that scanner drops test
//! code, and half the rules here need to COUNT it (`ports-only-tests`, `kernel-seal-impls`), so
//! every line is kept and carries a flag instead.
//!
//! Three properties are load-bearing and each is a fault this scanner's Python original had to
//! learn:
//!
//! * **THE WALK IS SORTED ALL THE WAY DOWN.** The directory sequence, not just the names inside a
//!   directory. Everything downstream reads the file map in order — which offender a row names
//!   first, which of two tied files a "worst offenders" list picks — so an unsorted walk makes a
//!   row's text a function of the filesystem rather than of the tree.
//! * **RAW STRING LITERALS ARE ONE LITERAL.** `br#"…"#` read by a plain `"…"` matcher ends at the
//!   first inner quote, and the braces after it land in the `#[cfg(test)]` depth counter, closing
//!   the test module early and re-filing every line after it as production (or the reverse). A
//!   gate that mis-attributes the code it reads is worse than one that does not read it.
//! * **BLANKING PRESERVES THE LITERAL'S DELIMITERS AND ITS BODY LENGTH.** The function finder
//!   computes offsets by summing `len(blank) + 1` per line, so a blanking pass that changed a
//!   line's length would move every function's reported line number.

use std::collections::BTreeMap;
use std::path::Path;

use crate::ctx::Ctx;
use crate::rx::Regex;

#[derive(Clone)]
pub struct Line {
    /// 1-based.
    pub no: usize,
    /// The line with comments stripped and string literals intact.
    pub code: String,
    /// The same with literal bodies blanked, so braces inside them do not disturb structure.
    pub blank: String,
    pub intest: bool,
}

impl Line {
    pub fn code_bytes(&self) -> &[u8] {
        self.code.as_bytes()
    }
}

#[derive(Clone)]
pub struct Fnc {
    pub name: String,
    pub path: String,
    /// The line of the `fn` keyword.
    pub start: usize,
    /// The line of the closing brace.
    pub end: usize,
    pub intest: bool,
    /// The line of the opening brace.
    pub body_start: usize,
}

impl Fnc {
    pub fn lines(&self) -> usize {
        self.end - self.start + 1
    }
}

/// Every Rust string literal form, RAW FIRST. The alternation order is load-bearing: the longer
/// prefixes must be tried first, and a raw literal closes only on a quote followed by the SAME run
/// of hashes it opened with — spelled as a backreference, which is why `r#"a "quoted" b"#` stays
/// one literal.
const STR_PATTERN: &str = concat!(
    r#"(?<![A-Za-z0-9_])b?r(?P<hashes>#*)"(?P<rawbody>(?:[^"]|"(?!(?P=hashes)))*)"(?P=hashes)"#,
    r#"|(?<![A-Za-z0-9_])b?"(?P<body>(?:\\.|[^"\\])*)""#,
);

const CHAR_PATTERN: &str = r"'(?:\\.|[^'\\])'";
const CFG_TEST_WORD: &str = r"[^a-z0-9_]test[^a-z0-9_]";
const MOD_WORD: &str = r"(^|[^A-Za-z0-9_])mod([^A-Za-z0-9_])";
const FN_PATTERN: &str = r"(?<![A-Za-z0-9_])fn\s+([A-Za-z_][A-Za-z0-9_]*)";

/// The compiled scanners, built once per run rather than once per line.
pub struct Lexer {
    strings: Regex,
    chars: Regex,
    cfg_test_word: Regex,
    mod_word: Regex,
    fns: Regex,
    rawbody: usize,
    body: usize,
}

impl Lexer {
    pub fn new() -> Result<Lexer, String> {
        let strings = Regex::new(STR_PATTERN)?;
        let rawbody = strings
            .group_index("rawbody")
            .ok_or("rx: no `rawbody` group")?;
        let body = strings.group_index("body").ok_or("rx: no `body` group")?;
        Ok(Lexer {
            strings,
            chars: Regex::new(CHAR_PATTERN)?,
            cfg_test_word: Regex::new(CFG_TEST_WORD)?,
            mod_word: Regex::new(MOD_WORD)?,
            fns: Regex::new(FN_PATTERN)?,
            rawbody,
            body,
        })
    }

    /// Every string literal on a line, as (whole-match span, body span).
    pub fn string_literals(&self, code: &str) -> Vec<((usize, usize), (usize, usize))> {
        let bytes = code.as_bytes();
        self.strings
            .find_iter(bytes)
            .iter()
            .map(|m| {
                let body = m
                    .group(self.rawbody)
                    .or_else(|| m.group(self.body))
                    .unwrap_or((m.start, m.start));
                ((m.start, m.end), body)
            })
            .collect()
    }

    /// The line with string and char literal CONTENTS blanked out. The delimiters stay, and the
    /// body's length is preserved exactly, so offsets computed from the blanked text keep pointing
    /// at the same columns.
    fn blank_literals(&self, code: &str) -> String {
        // A line carrying no delimiter carries no literal. The scanner asks this once per line of a
        // 660k-line tree and the answer is `no` for most of them, so it is answered by a byte scan
        // rather than by the backtracking matcher.
        if !code.contains('"') && !code.contains('\'') {
            return code.to_string();
        }
        let bytes = code.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut at = 0usize;
        for ((ms, me), (bs, be)) in self.string_literals(code) {
            out.extend_from_slice(&bytes[at..ms]);
            out.extend_from_slice(&bytes[ms..bs]);
            out.extend(std::iter::repeat_n(b' ', be - bs));
            out.extend_from_slice(&bytes[be..me]);
            at = me;
        }
        out.extend_from_slice(&bytes[at..]);
        // Char literals are replaced by `' '` wholesale, exactly as the Python does — an escaped
        // `'\n'` therefore shortens by one, and every offset downstream is computed from this same
        // text, so the shortening is consistent rather than a drift.
        let staged = String::from_utf8_lossy(&out).into_owned();
        if !staged.contains('\'') {
            return staged;
        }
        let sb = staged.as_bytes();
        let mut final_out = Vec::with_capacity(sb.len());
        let mut at = 0usize;
        for m in self.chars.find_iter(sb) {
            final_out.extend_from_slice(&sb[at..m.start]);
            final_out.extend_from_slice(b"' '");
            at = m.end;
        }
        final_out.extend_from_slice(&sb[at..]);
        String::from_utf8_lossy(&final_out).into_owned()
    }
}

/// Drop `//`-to-EOL and `/* … */` (which may span lines) while leaving string literals intact, so
/// a `//` inside a string is not a comment.
fn strip_comments(line: &str, in_block: &mut bool) -> String {
    let b = line.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        let two = &b[i..(i + 2).min(b.len())];
        if *in_block {
            if two == b"*/" {
                *in_block = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if in_str {
            out.push(c);
            if c == b'\\' {
                if let Some(n) = b.get(i + 1) {
                    out.push(*n);
                }
                i += 2;
                continue;
            }
            if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if two == b"/*" {
            *in_block = true;
            i += 2;
            continue;
        }
        if two == b"//" {
            break;
        }
        if c == b'"' {
            in_str = true;
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_test_path(path: &str, fragments: &[String]) -> bool {
    fragments.iter().any(|f| path.contains(f.as_str()))
}

/// One file's lines. `path` is the path as the scan sees it — the same string the Python hands to
/// `is_test_path`, so a `/tests/` segment anywhere in it classifies the file the same way.
pub fn scan_text(lx: &Lexer, path: &str, text: &str, test_fragments: &[String]) -> Vec<Line> {
    let mut in_block = false;
    let testfile = is_test_path(path, test_fragments);
    let mut testdepth: i64 = 0;
    let mut pend = false;
    let mut lines = Vec::new();
    for (idx, raw) in text.split('\n').enumerate() {
        let code = strip_comments(raw, &mut in_block);
        let blank = lx.blank_literals(&code);
        let nopen = blank.matches('{').count() as i64;
        let nclose = blank.matches('}').count() as i64;
        let is_cfgtest = code.contains("#[cfg(")
            && lx
                .cfg_test_word
                .is_match_str(&format!(" {} ", code.to_lowercase()));
        let has_mod = code.contains("mod") && lx.mod_word.is_match_str(&code);
        let mut entered = false;
        // The two arms are deliberately the same body under two different conditions, and the
        // ladder's ORDER is what distinguishes them: `#[cfg(test)] mod x {` opens on its own line,
        // while `#[cfg(test)]` on one line and `mod x {` on the next opens through `pend`. Merging
        // them into one condition would put `pend && has_mod` ahead of the `pend && … && !is_cfgtest`
        // arm below, which clears a pending attribute that a non-`mod` line interrupted.
        if (is_cfgtest && has_mod) || (pend && has_mod) {
            testdepth = (nopen - nclose).max(0);
            entered = testdepth > 0;
            pend = false;
        } else if pend && !code.trim().is_empty() && !is_cfgtest {
            pend = false;
        } else if testdepth > 0 {
            testdepth = (testdepth + nopen - nclose).max(0);
        }
        if is_cfgtest && !has_mod {
            pend = true;
        }
        let intest = testfile || testdepth > 0 || entered;
        lines.push(Line {
            no: idx + 1,
            code,
            blank,
            intest,
        });
    }
    lines
}

/// Locate every function with a body and its extent, by brace matching on the blanked text.
pub fn find_fns(lx: &Lexer, path: &str, lines: &[Line]) -> Vec<Fnc> {
    let joined: String = lines
        .iter()
        .map(|l| l.blank.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let text = joined.as_bytes();
    let mut starts = Vec::with_capacity(lines.len());
    let mut off = 0usize;
    for l in lines {
        starts.push(off);
        off += l.blank.len() + 1;
    }
    let line_of = |pos: usize| -> usize {
        match starts.binary_search(&pos) {
            Ok(i) => i,
            Err(0) => 0,
            Err(i) => i - 1,
        }
    };

    let mut out = Vec::new();
    for m in lx.fns.find_iter(text) {
        let Some((ns, ne)) = m.group(1) else { continue };
        let name = String::from_utf8_lossy(&text[ns..ne]).into_owned();
        let mut i = m.end;
        let mut depth: i64 = 0;
        let mut body: i64 = -1;
        while i < text.len() {
            let c = text[i];
            if c == b'(' {
                depth += 1;
            } else if c == b')' {
                depth -= 1;
            } else if depth == 0 && c == b';' {
                break;
            } else if depth == 0 && c == b'{' {
                body = i as i64;
                break;
            }
            i += 1;
        }
        if body < 0 {
            continue;
        }
        let body = body as usize;
        let mut depth: i64 = 0;
        let mut j = body;
        let mut end: i64 = -1;
        while j < text.len() {
            match text[j] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = j as i64;
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        if end < 0 {
            continue;
        }
        let sl = line_of(m.start);
        out.push(Fnc {
            name,
            path: path.to_string(),
            start: lines[sl].no,
            end: lines[line_of(end as usize)].no,
            intest: lines[sl].intest,
            body_start: lines[line_of(body)].no,
        });
    }
    out
}

/// THE PER-FILE SCAN MEMO, and the reason it exists is the SELF-TEST.
///
/// Every planted case re-runs the whole gate, and a plant edits one file. [`Tree::load`] lexes
/// every `.rs` file under the scan roots — a 660k-line tree through a backtracking string-literal
/// matcher — so forty plants paid for forty full lexes of a tree that differed from itself by one
/// file. That is where the xtask test shard's wall clock went.
///
/// The key is a hash of everything the answer depends on: the file's absolute path (the
/// test-classification reads it), its workspace-relative path (the function index records it), the
/// test path fragments in force, and the file's bytes. `scan_text` and `find_fns` are pure
/// functions of exactly those, so a hit is a memo and never a stale reading — a plant that changes
/// a byte changes the key.
type Scanned = (std::sync::Arc<Vec<Line>>, std::sync::Arc<Vec<Fnc>>);

static SCAN_MEMO: std::sync::OnceLock<std::sync::Mutex<BTreeMap<u64, Scanned>>> =
    std::sync::OnceLock::new();

fn scan_file(
    lexer: &Lexer,
    abs: &str,
    rel: &str,
    text: &str,
    test_fragments: &[String],
) -> Scanned {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    abs.hash(&mut h);
    rel.hash(&mut h);
    test_fragments.hash(&mut h);
    text.hash(&mut h);
    let key = h.finish();
    let memo = SCAN_MEMO.get_or_init(Default::default);
    if let Some(found) = memo
        .lock()
        .expect("the scan memo mutex is never poisoned")
        .get(&key)
    {
        return found.clone();
    }
    let lines = scan_text(lexer, abs, text, test_fragments);
    let fns = find_fns(lexer, rel, &lines);
    let entry = (std::sync::Arc::new(lines), std::sync::Arc::new(fns));
    memo.lock()
        .expect("the scan memo mutex is never poisoned")
        .insert(key, entry.clone());
    entry
}

pub struct Tree {
    pub root: std::path::PathBuf,
    /// rel path (`/`-separated) -> lines, in sorted path order.
    ///
    /// SHARED WITH THE SCAN MEMO rather than copied out of it: a plant edits one file, and deep
    /// copying 660k `Line`s (two `String`s each) per case to hand a rule a `Vec` it only ever
    /// reads was most of what the memo saved.
    pub files: BTreeMap<String, std::sync::Arc<Vec<Line>>>,
    pub fns: BTreeMap<String, std::sync::Arc<Vec<Fnc>>>,
    pub lexer: Lexer,
}

impl Tree {
    /// Scan the tree `cx` shows, over `scan_roots` (directory globs relative to the root).
    pub fn load(
        cx: &Ctx,
        scan_roots: &[String],
        test_fragments: &[String],
    ) -> Result<Tree, String> {
        let lexer = Lexer::new()?;
        let mut rels: Vec<String> = Vec::new();
        for pattern in scan_roots {
            for dir in glob_dirs(cx, pattern) {
                collect_rs(cx, &dir, &mut rels);
            }
        }
        // The overlay may add a file under a root the real tree does not carry it under; a plant
        // that the walk cannot see is a plant that proves nothing.
        if let Some(ov) = cx.overlay() {
            for p in ov.paths() {
                let s = p.to_string_lossy().replace('\\', "/");
                if s.ends_with(".rs")
                    && cx.exists(&s)
                    && !rels.contains(&s)
                    && under_any(&s, scan_roots)
                {
                    rels.push(s);
                }
            }
        }
        rels.sort();
        rels.dedup();

        let mut files = BTreeMap::new();
        let mut fns = BTreeMap::new();
        for rel in rels {
            if !cx.exists(&rel) {
                continue;
            }
            let text = cx.read(&rel)?;
            let abs = cx.abs(&rel).to_string_lossy().into_owned();
            let (lines, fns_of) = scan_file(&lexer, &abs, &rel, &text, test_fragments);
            fns.insert(rel.clone(), fns_of);
            files.insert(rel, lines);
        }
        Ok(Tree {
            root: cx.root().to_path_buf(),
            files,
            fns,
            lexer,
        })
    }

    pub fn crate_of(&self, rel: &str) -> String {
        let parts: Vec<&str> = rel.split('/').collect();
        if parts.len() > 1 && parts[0] == "crates" {
            parts[1].to_string()
        } else {
            parts[0].to_string()
        }
    }

    /// The innermost function containing the line, or `None`.
    pub fn enclosing_fn(&self, rel: &str, lineno: usize) -> Option<&Fnc> {
        let mut best: Option<&Fnc> = None;
        for f in self.fns.get(rel).into_iter().flat_map(|v| v.iter()) {
            if f.start <= lineno
                && lineno <= f.end
                && best.is_none_or(|b: &Fnc| f.lines() < b.lines())
            {
                best = Some(f);
            }
        }
        best
    }

    pub fn find_fn_by_name(&self, name: &str) -> Vec<&Fnc> {
        self.fns
            .values()
            .flat_map(|v| v.iter())
            .filter(|f| f.name == name && !f.intest)
            .collect()
    }

    /// `(rel, line)` for every line whose stripped code matches.
    pub fn grep<'t>(
        &'t self,
        rx: &Regex,
        production_only: bool,
        files: Option<&[String]>,
    ) -> Vec<(&'t str, &'t Line)> {
        let mut out = Vec::new();
        let names: Vec<String> = match files {
            Some(f) => f.to_vec(),
            None => self.files.keys().cloned().collect(),
        };
        for rel in names {
            let Some((key, lines)) = self.files.get_key_value(&rel) else {
                continue;
            };
            for l in lines.iter() {
                if production_only && l.intest {
                    continue;
                }
                if rx.is_match(l.code_bytes()) {
                    out.push((key.as_str(), l));
                }
            }
        }
        out
    }

    pub fn crate_files(&self, crate_name: &str) -> Vec<String> {
        let pre = format!("crates/{crate_name}/");
        self.files
            .keys()
            .filter(|r| r.starts_with(&pre))
            .cloned()
            .collect()
    }
}

/// Is an overlay-planted path one the walk would have yielded had it been on disk? The scan roots
/// are DIRECTORY globs, so a file under one of them matches the same glob with `/*` appended.
fn under_any(rel: &str, scan_roots: &[String]) -> bool {
    scan_roots.iter().any(|g| fnmatch(rel, &format!("{g}/*")))
}

fn collect_rs(cx: &Ctx, dir: &str, out: &mut Vec<String>) {
    let abs = cx.abs(dir);
    let Ok(rd) = std::fs::read_dir(&abs) else {
        return;
    };
    let mut entries: Vec<std::path::PathBuf> =
        rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    entries.sort();
    for path in entries {
        let Ok(rel) = path.strip_prefix(cx.root()) else {
            continue;
        };
        let rel = rel.to_string_lossy().replace('\\', "/");
        if path.is_dir() {
            collect_rs(cx, &rel, out);
        } else if rel.ends_with(".rs") {
            out.push(rel);
        }
    }
}

/// Directories matching a `*`-glob whose `*` does NOT cross a path separator — `glob.glob`'s rule,
/// which is the one `scan_roots` and `plugin_kinds` are written against.
pub fn glob_dirs(cx: &Ctx, pattern: &str) -> Vec<String> {
    let mut current = vec![String::new()];
    for seg in pattern.split('/') {
        let mut next = Vec::new();
        for base in &current {
            if !seg.contains(['*', '?', '[']) {
                let cand = if base.is_empty() {
                    seg.to_string()
                } else {
                    format!("{base}/{seg}")
                };
                if cx.abs(&cand).exists() {
                    next.push(cand);
                }
                continue;
            }
            let dir = if base.is_empty() {
                cx.root().to_path_buf()
            } else {
                cx.abs(base)
            };
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            let mut names: Vec<String> = rd
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            for nm in names {
                if glob_segment(seg, &nm) {
                    next.push(if base.is_empty() {
                        nm.clone()
                    } else {
                        format!("{base}/{nm}")
                    });
                }
            }
        }
        current = next;
    }
    current.sort();
    current.dedup();
    current
}

/// `fnmatch.fnmatch`: `*` matches anything INCLUDING a separator, which is what makes
/// `crates/busbar-unit-*/src/*` reach nested modules.
pub fn fnmatch(name: &str, pattern: &str) -> bool {
    glob_match(pattern.as_bytes(), name.as_bytes(), true)
}

/// One path segment against a `glob.glob` segment: `*` stops at a separator (there is none inside
/// a segment, so this differs from [`fnmatch`] only in intent).
fn glob_segment(pattern: &str, name: &str) -> bool {
    glob_match(pattern.as_bytes(), name.as_bytes(), false)
}

fn glob_match(pat: &[u8], name: &[u8], star_crosses: bool) -> bool {
    fn go(p: &[u8], n: &[u8], cross: bool) -> bool {
        if p.is_empty() {
            return n.is_empty();
        }
        match p[0] {
            b'*' => {
                for k in 0..=n.len() {
                    if !cross && n[..k].contains(&b'/') {
                        break;
                    }
                    if go(&p[1..], &n[k..], cross) {
                        return true;
                    }
                }
                false
            }
            b'?' => !n.is_empty() && go(&p[1..], &n[1..], cross),
            b'[' => {
                let Some(close) = p.iter().position(|c| *c == b']') else {
                    return !n.is_empty() && n[0] == b'[' && go(&p[1..], &n[1..], cross);
                };
                if n.is_empty() {
                    return false;
                }
                let mut set = &p[1..close];
                let neg = set.first() == Some(&b'!');
                if neg {
                    set = &set[1..];
                }
                let mut hit = false;
                let mut i = 0;
                while i < set.len() {
                    if i + 2 < set.len() && set[i + 1] == b'-' {
                        if n[0] >= set[i] && n[0] <= set[i + 2] {
                            hit = true;
                        }
                        i += 3;
                    } else {
                        if n[0] == set[i] {
                            hit = true;
                        }
                        i += 1;
                    }
                }
                hit != neg && go(&p[close + 1..], &n[1..], cross)
            }
            c => !n.is_empty() && n[0] == c && go(&p[1..], &n[1..], cross),
        }
    }
    go(pat, name, star_crosses)
}

/// Existing directories matching a list of globs, sorted, de-duplicated. A glob matching nothing is
/// silently empty (the kind has no crate yet), never an error.
///
/// A pattern prefixed with `!` EXCLUDES, and every exclusion is applied after every inclusion, so
/// order in the list does not change the answer. It exists for one shape this glob syntax otherwise
/// cannot say: `*` does not cross a path separator but it does cross a hyphen, so
/// `crates/busbar-plane-*` matches `busbar-plane-llm` and `busbar-plane-llm-anthropic` alike — a
/// plane and a DIALECT OF THAT PLANE, two different kinds, one glob. Without the exclusion the
/// narrower kind is silently scored against the wider one's rules.
pub fn dirs_for_globs(cx: &Ctx, patterns: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for pat in patterns {
        if pat.starts_with('!') {
            continue;
        }
        for d in glob_dirs(cx, pat) {
            if cx.abs(&d).is_dir() && !out.contains(&d) {
                out.push(d);
            }
        }
    }
    for pat in patterns {
        let Some(neg) = pat.strip_prefix('!') else {
            continue;
        };
        let excluded = glob_dirs(cx, neg);
        out.retain(|d| !excluded.contains(d));
    }
    out
}

pub fn crate_name_of_dir(dir: &str) -> String {
    dir.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(dir)
        .to_string()
}

/// THE SHIPPED DEPENDENCY NAMES OF ONE MANIFEST — every dependency table, in every spelling.
///
/// It was "a deliberately small `[dependencies]` reader: the exact-name keys under
/// `[dependencies]` only, never `[dev-dependencies]` or a target-cfg table", and the shape it
/// shared with `kind_isolation::deps_of` was the shape they were BOTH blind in: a red-team pass
/// carried a plane into a transport through `[build-dependencies]`, through
/// `[target.'cfg(unix)'.dependencies]` and through `package = "…"`, and the two gates that read the
/// manifests were green in all three. Fixing one copy would have left the other, so there is now
/// one reader: [`crate::manifest`]. A missing file still reads as no dependencies.
pub fn read_cargo_deps(path: &Path) -> Vec<String> {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    read_cargo_deps_text(&raw)
}

pub fn read_cargo_deps_text(raw: &str) -> Vec<String> {
    crate::manifest::shipped_dep_names(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lex() -> Lexer {
        Lexer::new().expect("the lexer compiles")
    }

    /// The fault the raw-literal alternation exists for: a `br#"…"#` holding unbalanced braces
    /// inside a `#[cfg(test)]` module must not close that module early and re-file the production
    /// code after it as test code.
    #[test]
    fn a_raw_byte_string_cannot_unbalance_the_cfg_test_counter() {
        let src = "\
pub fn before() {}

#[cfg(test)]
mod tests {
    const J: &[u8] = br#\"{\"a\": \"{{\"}\"#;
    #[test]
    fn t() {}
}

pub fn after() {
    let _ = busbar_core::thing();
}
";
        let lines = scan_text(&lex(), "crates/x/src/lib.rs", src, &["/tests/".to_string()]);
        let reach = lines
            .iter()
            .find(|l| l.code.contains("busbar_core::thing"))
            .expect("the production reach is present");
        assert!(
            !reach.intest,
            "the raw literal's braces swallowed the production code after the test module"
        );
        let inside = lines
            .iter()
            .find(|l| l.code.contains("fn t()"))
            .expect("the test fn is present");
        assert!(inside.intest, "the test module's own body is test code");
    }

    /// Comment stripping leaves string literals alone, so a `//` inside one is not a comment.
    #[test]
    fn a_slash_slash_inside_a_string_is_not_a_comment() {
        let lines = scan_text(&lex(), "x.rs", "let u = \"http://x\"; // real\n", &[]);
        assert_eq!(lines[0].code.trim(), "let u = \"http://x\";");
    }

    /// Blanking keeps the delimiters and the body's length, because every offset the function
    /// finder computes is a sum of `len(blank) + 1`.
    #[test]
    fn blanking_preserves_length_and_delimiters() {
        let lx = lex();
        let code = "let s = \"ab{cd\";";
        let blanked = lx.blank_literals(code);
        assert_eq!(blanked.len(), code.len());
        assert_eq!(blanked, "let s = \"     \";");
        assert_eq!(blanked.matches('{').count(), 0);
    }

    #[test]
    fn functions_are_found_with_their_extent() {
        let src = "\
pub fn one(a: u32) -> u32 {
    a + 1
}

trait T {
    fn bodiless(&self);
}
";
        let lx = lex();
        let lines = scan_text(&lx, "x.rs", src, &[]);
        let fns = find_fns(&lx, "x.rs", &lines);
        assert_eq!(
            fns.len(),
            1,
            "a bodiless trait method is not a function here"
        );
        assert_eq!(fns[0].name, "one");
        assert_eq!((fns[0].start, fns[0].body_start, fns[0].end), (1, 1, 3));
    }

    #[test]
    fn fnmatch_star_crosses_separators_and_glob_star_does_not() {
        assert!(fnmatch(
            "crates/busbar-unit-x/src/a/b.rs",
            "crates/busbar-unit-*/src/*"
        ));
        assert!(!glob_segment("busbar-unit-*", "busbar-llm"));
        assert!(glob_segment("busbar-unit-*", "busbar-unit-cost"));
    }

    /// EVERY SHIPPED TABLE, AND ONLY THE SHIPPED ONES. `[dev-dependencies]` stays out — a test edge
    /// is not a shipped edge, and `kind-isolation:test-deps` is the row that scores it — while
    /// `[build-dependencies]` and the per-target forms are in, because `cfg(unix)` is true in every
    /// artifact this tree ships and a red-team pass carried a whole plane through that table.
    ///
    /// The `[dependencies.tracing]` long form used to leave the old reader inside `dependencies`,
    /// so that sub-table's own keys came back as dependency names and `version` was reported as a
    /// crate. It is a name no allow-list should ever have had to carry, and it is gone.
    #[test]
    fn cargo_deps_reads_every_shipped_table_and_no_test_one() {
        let deps = read_cargo_deps_text(
            "[package]\nname = \"x\"\n\n[dependencies]\nserde = \"1\"\nbusbar-contract = { path = \"..\" }\n\n[dev-dependencies]\ntokio = \"1\"\n\n[dependencies.tracing]\nversion = \"0.1\"\n\n[build-dependencies]\ncc = \"1\"\n\n[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n",
        );
        assert_eq!(
            deps,
            vec!["busbar-contract", "cc", "libc", "serde", "tracing"]
        );
    }
}
