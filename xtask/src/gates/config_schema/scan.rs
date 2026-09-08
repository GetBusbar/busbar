//! THE RUST-SOURCE SCANNERS THE FINGERPRINT IS BUILT OUT OF.
//!
//! `scripts/config-schema.py` reached its answer through eight Python regexes, several of them
//! carrying named groups and one of them non-greedy. `xtask` has no regex crate and
//! [`crate::ere`] is a POSIX-ERE matcher with no capture groups, so the scrape is hand-written —
//! but hand-written AS A PORT, one function per regex, with the original spelled out above each so
//! the two can be diffed by eye.
//!
//! ## Everything here is indexed in CHARACTERS, not bytes
//!
//! The Python's `strip_comments` blanks a comment span by replacing each character with a space and
//! keeps the newlines, which is length-preserving in CHARACTERS. `match_block` then counts braces by
//! character index into that same string. A port that indexed bytes would agree on every ASCII file
//! and disagree on the first source that carries a non-ASCII character in a doc comment — which the
//! tracked set does, in quantity. So the whole module works on `&[char]` and the fingerprint's byte
//! identity does not depend on which characters happen to be ASCII today.
//!
//! ## The one deliberate narrowing
//!
//! Python's `re` backtracks; these scanners do not. The single place that matters is the attribute
//! cluster in front of a `struct`/`enum`, where `(?:^[ \t]*#\[[^\n]*\]\s*)*` needs the trailing
//! `\s*` to give back everything past the last newline so the following `^` can match. That is
//! reproduced explicitly: the whitespace run after an attribute is consumed greedily and then walked
//! back to the position just after its LAST newline, which is exactly the split the backtracking
//! engine settles on. Every other construct in the eight is deterministic as written.

/// A Rust identifier character.
pub fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

/// `\b` — a word boundary at `i`, reading the character before and the character at `i`.
fn boundary(src: &[char], i: usize) -> bool {
    let before = i.checked_sub(1).map(|j| is_word(src[j])).unwrap_or(false);
    let at = src.get(i).copied().map(is_word).unwrap_or(false);
    before != at
}

pub fn starts_with(src: &[char], at: usize, word: &str) -> bool {
    (at..)
        .zip(word.chars())
        .all(|(i, c)| src.get(i) == Some(&c))
}

pub fn text(src: &[char], range: std::ops::Range<usize>) -> String {
    src[range.start.min(src.len())..range.end.min(src.len())]
        .iter()
        .collect()
}

fn skip_ws(src: &[char], mut i: usize) -> usize {
    while i < src.len() && src[i].is_whitespace() {
        i += 1;
    }
    i
}

fn skip_blank(src: &[char], mut i: usize) -> usize {
    while i < src.len() && (src[i] == ' ' || src[i] == '\t') {
        i += 1;
    }
    i
}

/// Every position that `^` matches under `re.MULTILINE`: the start of the string and every position
/// just after a newline.
pub fn line_starts(src: &[char]) -> Vec<usize> {
    let mut out = vec![0usize];
    for (i, c) in src.iter().enumerate() {
        if *c == '\n' {
            out.push(i + 1);
        }
    }
    out
}

fn at_line_start(src: &[char], i: usize) -> bool {
    i == 0 || src.get(i - 1) == Some(&'\n')
}

// ── strip_comments ───────────────────────────────────────────────────────────────────────────────

/// Remove `//` line comments and `/* */` block comments, replacing each comment character with a
/// space (newlines kept) so every downstream character index stays valid. String and char literals
/// are left intact — the config types have string defaults with `//` inside URLs.
pub fn strip_comments(src: &[char]) -> Vec<char> {
    let n = src.len();
    let mut out: Vec<char> = Vec::with_capacity(n);
    let mut i = 0usize;
    let mut in_str = false;
    let mut in_char = false;
    while i < n {
        let c = src[i];
        if in_str {
            out.push(c);
            if c == '\\' && i + 1 < n {
                out.push(src[i + 1]);
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if in_char {
            out.push(c);
            if c == '\\' && i + 1 < n {
                out.push(src[i + 1]);
                i += 2;
                continue;
            }
            if c == '\'' {
                in_char = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
            continue;
        }
        if c == '/' && i + 1 < n && src[i + 1] == '/' {
            while i < n && src[i] != '\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }
        if c == '/' && i + 1 < n && src[i + 1] == '*' {
            let mut j = None;
            let mut k = i + 2;
            while k + 1 < n {
                if src[k] == '*' && src[k + 1] == '/' {
                    j = Some(k + 2);
                    break;
                }
                k += 1;
            }
            let j = j.unwrap_or(n);
            for item in src.iter().take(j).skip(i) {
                out.push(if *item == '\n' { '\n' } else { ' ' });
            }
            i = j;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

// ── match_block ──────────────────────────────────────────────────────────────────────────────────

/// Given the index of a `{`, the index just past its matching `}`.
///
/// Braces inside string literals are counted, exactly as the Python counts them: `strip_comments`
/// deliberately leaves literals intact, so this is a shared and reproduced limitation rather than a
/// port defect.
pub fn match_block(src: &[char], open_idx: usize) -> usize {
    let n = src.len();
    let mut depth = 0i64;
    let mut i = open_idx;
    while i < n {
        match src[i] {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    n
}

// ── strip_cfg_test_mods ──────────────────────────────────────────────────────────────────────────

/// `#\[cfg\(test\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{`
fn find_cfg_test_mod(src: &[char]) -> Option<(usize, usize)> {
    const HEAD: &str = "#[cfg(test)]";
    let n = src.len();
    for start in 0..n {
        if !starts_with(src, start, HEAD) {
            continue;
        }
        let mut i = skip_ws(src, start + HEAD.chars().count());
        if starts_with(src, i, "pub") {
            let mut j = i + 3;
            if src.get(j) == Some(&'(') {
                let mut e = j + 1;
                while e < n && src[e] != ')' {
                    e += 1;
                }
                if e < n {
                    j = e + 1;
                }
            }
            let w = skip_ws(src, j);
            if w > j {
                i = w;
            }
        }
        if !starts_with(src, i, "mod") {
            continue;
        }
        let j = i + 3;
        let w = skip_ws(src, j);
        if w == j {
            continue;
        }
        let mut k = w;
        if !src.get(k).copied().is_some_and(is_ident_start) {
            continue;
        }
        while k < n && is_word(src[k]) {
            k += 1;
        }
        let k = skip_ws(src, k);
        if src.get(k) != Some(&'{') {
            continue;
        }
        return Some((start, k));
    }
    None
}

/// Blank out every `#[cfg(test)] mod … { … }` body, length-preserving. A test-only
/// `#[derive(Deserialize)]` fixture is not config grammar, and — the extractor being
/// last-definition-wins for declarations — a fixture sharing a real type's name would replace the
/// real grammar in the fingerprint.
pub fn strip_cfg_test_mods(src: &[char]) -> Vec<char> {
    let mut src = src.to_vec();
    while let Some((start, brace)) = find_cfg_test_mod(&src) {
        let end = match_block(&src, brace);
        for item in src.iter_mut().take(end).skip(start) {
            if *item != '\n' {
                *item = ' ';
            }
        }
    }
    src
}

// ── ITEM_RE ──────────────────────────────────────────────────────────────────────────────────────

/// One `#[…] … struct|enum Name … {` or `;` declaration, whatever it derives.
#[derive(Debug, Clone)]
pub struct Item {
    /// The attribute cluster in front of the declaration, verbatim.
    pub attrs: String,
    pub kw: &'static str,
    pub name: String,
    /// `{` or `;`.
    pub open: char,
    pub open_idx: usize,
}

/// The `(?P<attrs>(?:^[ \t]*#\[[^\n]*\]\s*)*)` half: consume attribute lines and hand back the
/// LINE-START position the declaration itself must begin at.
fn attribute_cluster(src: &[char], start: usize) -> Option<usize> {
    let n = src.len();
    let mut pos = start;
    loop {
        let k = skip_blank(src, pos);
        if !(src.get(k) == Some(&'#') && src.get(k + 1) == Some(&'[')) {
            return Some(pos);
        }
        let mut le = k;
        while le < n && src[le] != '\n' {
            le += 1;
        }
        // `[^\n]*\]` is greedy: the LAST `]` on the line closes the attribute.
        let close = (k + 2..le).rev().find(|i| src[*i] == ']');
        let Some(close) = close else {
            // The attribute did not close on its line, so this iteration of the repeat fails and
            // the cluster ends where it stands — which is still a line start.
            return Some(pos);
        };
        let attr_end = close + 1;
        let w = skip_ws(src, attr_end);
        // `\s*` gives back everything past its LAST newline so the following `^` can match.
        match (attr_end..w).rev().find(|i| src[*i] == '\n') {
            Some(nl) => pos = nl + 1,
            None if at_line_start(src, attr_end) => pos = attr_end,
            // No newline to give back: the declaration cannot be at a line start, and with zero
            // attributes the cluster's own start is an attribute, so nothing matches here.
            None => return None,
        }
    }
}

fn match_item(src: &[char], start: usize) -> Option<(Item, usize)> {
    let n = src.len();
    let decl = attribute_cluster(src, start)?;
    let attrs = text(src, start..decl);

    let k = skip_blank(src, decl);
    let mut at = k;
    if starts_with(src, k, "pub") {
        let mut j = k + 3;
        if src.get(j) == Some(&'(') {
            let mut e = j + 1;
            while e < n && src[e] != ')' {
                e += 1;
            }
            if e < n {
                j = e + 1;
            }
        }
        let w = skip_ws(src, j);
        if w > j {
            at = w;
        }
    }

    let kw = if starts_with(src, at, "struct") {
        "struct"
    } else if starts_with(src, at, "enum") {
        "enum"
    } else {
        return None;
    };
    let mut j = at + kw.len();
    let w = skip_ws(src, j);
    if w == j {
        return None;
    }
    j = w;
    if !src.get(j).copied().is_some_and(is_ident_start) {
        return None;
    }
    let ns = j;
    while j < n && is_word(src[j]) {
        j += 1;
    }
    let name = text(src, ns..j);

    // `(?P<generics><[^{;]*>)?`
    if src.get(j) == Some(&'<') {
        let mut e = j + 1;
        while e < n && src[e] != '{' && src[e] != ';' {
            e += 1;
        }
        if let Some(gt) = (j + 1..e).rev().find(|i| src[*i] == '>') {
            j = gt + 1;
        }
    }
    j = skip_ws(src, j);
    let open = *src.get(j)?;
    if open != '{' && open != ';' {
        return None;
    }
    Some((
        Item {
            attrs,
            kw,
            name,
            open,
            open_idx: j,
        },
        j + 1,
    ))
}

/// `ITEM_RE.finditer(src)` — leftmost, non-overlapping.
pub fn items(src: &[char]) -> Vec<Item> {
    let mut out = Vec::new();
    let mut guard = 0usize;
    for p in line_starts(src) {
        if p < guard {
            continue;
        }
        if let Some((item, end)) = match_item(src, p) {
            out.push(item);
            guard = end;
        }
    }
    out
}

// ── MANUAL_DE_RE ─────────────────────────────────────────────────────────────────────────────────

/// `^\s*impl\s*<\s*'de\s*>\s*(?:serde::|de::)?Deserialize\s*<\s*'de\s*>\s+for\s+(?P<name>…)`
///
/// Returns `(name, end)` per match, `end` being where `src.find("{", m.end())` starts looking.
pub fn manual_de_impls(src: &[char]) -> Vec<(String, usize)> {
    let n = src.len();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < n {
        if !starts_with(src, i, "impl") || !at_line_start_modulo_blanks(src, i) {
            i += 1;
            continue;
        }
        match match_manual_de(src, i) {
            Some((name, end)) => {
                out.push((name, end));
                i = end;
            }
            None => i += 1,
        }
    }
    out
}

/// `^\s*` in front of an `impl`: some line start reaches it over whitespace alone.
///
/// WALK BACK OVER BLANKS ONLY, NEVER OVER THE NEWLINE. Consuming the newline too walks out of the
/// `impl`'s own line and lands after the previous line's last non-blank character, which is not a
/// line start — so an `impl` at COLUMN 0, which is how every one of these is written, failed the
/// test and no hand-written `Deserialize` was found at all. The regex reaches `impl` from the
/// nearest `^` across `\s*`; that `^` is this line's start when the run in front of `impl` is
/// spaces and tabs, and there is no other `^` a non-blank line can be reached from.
fn at_line_start_modulo_blanks(src: &[char], i: usize) -> bool {
    let mut j = i;
    while j > 0 && (src[j - 1] == ' ' || src[j - 1] == '\t') {
        j -= 1;
    }
    at_line_start(src, j)
}

fn match_manual_de(src: &[char], start: usize) -> Option<(String, usize)> {
    let n = src.len();
    let mut i = skip_ws(src, start + 4);
    if src.get(i) != Some(&'<') {
        return None;
    }
    i = skip_ws(src, i + 1);
    if !starts_with(src, i, "'de") {
        return None;
    }
    i = skip_ws(src, i + 3);
    if src.get(i) != Some(&'>') {
        return None;
    }
    i = skip_ws(src, i + 1);
    for prefix in ["serde::", "de::"] {
        if starts_with(src, i, prefix) {
            i += prefix.chars().count();
            break;
        }
    }
    if !starts_with(src, i, "Deserialize") {
        return None;
    }
    i = skip_ws(src, i + "Deserialize".len());
    if src.get(i) != Some(&'<') {
        return None;
    }
    i = skip_ws(src, i + 1);
    if !starts_with(src, i, "'de") {
        return None;
    }
    i = skip_ws(src, i + 3);
    if src.get(i) != Some(&'>') {
        return None;
    }
    let j = i + 1;
    let w = skip_ws(src, j);
    if w == j || !starts_with(src, w, "for") {
        return None;
    }
    let j = w + 3;
    let w = skip_ws(src, j);
    if w == j {
        return None;
    }
    if !src.get(w).copied().is_some_and(is_ident_start) {
        return None;
    }
    let mut e = w;
    while e < n && is_word(src[e]) {
        e += 1;
    }
    Some((text(src, w..e), e))
}

// ── ALIAS_RE ─────────────────────────────────────────────────────────────────────────────────────

/// `^(?:pub(?:\([^)]*\))?\s+)?type\s+(?P<name>…)\s*=\s*(?P<target>[^;]+);`
///
/// Anchored at column 0 on purpose: an indented `type Value = …;` is a local alias inside a fn or
/// an impl, not config grammar.
pub fn type_aliases(src: &[char]) -> Vec<(String, String)> {
    let n = src.len();
    let mut out = Vec::new();
    let mut guard = 0usize;
    for p in line_starts(src) {
        if p < guard {
            continue;
        }
        let mut at = p;
        if starts_with(src, p, "pub") {
            let mut j = p + 3;
            if src.get(j) == Some(&'(') {
                let mut e = j + 1;
                while e < n && src[e] != ')' {
                    e += 1;
                }
                if e < n {
                    j = e + 1;
                }
            }
            let w = skip_ws(src, j);
            if w > j {
                at = w;
            }
        }
        if !starts_with(src, at, "type") {
            continue;
        }
        let j = at + 4;
        let w = skip_ws(src, j);
        if w == j || !src.get(w).copied().is_some_and(is_ident_start) {
            continue;
        }
        let ns = w;
        let mut e = w;
        while e < n && is_word(src[e]) {
            e += 1;
        }
        let name = text(src, ns..e);
        let e2 = skip_ws(src, e);
        if src.get(e2) != Some(&'=') {
            continue;
        }
        let ts = skip_ws(src, e2 + 1);
        let mut te = ts;
        while te < n && src[te] != ';' {
            te += 1;
        }
        if te >= n || te == ts {
            continue;
        }
        out.push((name, text(src, ts..te)));
        guard = te + 1;
    }
    out
}

// ── LIFT_LIST_RE ─────────────────────────────────────────────────────────────────────────────────

/// `const\s+LIFTED_[A-Z0-9_]*KEYS\s*:\s*&\[&(?:'static\s+)?str\]\s*=\s*&\[(.*?)\]\s*;`
pub fn lift_lists(src: &[char]) -> Vec<String> {
    let n = src.len();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < n {
        if !(starts_with(src, i, "const") && boundary(src, i)) {
            i += 1;
            continue;
        }
        let j = i + 5;
        let w = skip_ws(src, j);
        if w == j || !starts_with(src, w, "LIFTED_") {
            i += 1;
            continue;
        }
        // `[A-Z0-9_]*KEYS` — greedy, then backtracked to the LAST `KEYS` inside the run.
        let rs = w + 7;
        let mut run_end = rs;
        while run_end < n
            && (src[run_end].is_ascii_uppercase()
                || src[run_end].is_ascii_digit()
                || src[run_end] == '_')
        {
            run_end += 1;
        }
        let Some(kend) = (rs..run_end.saturating_sub(3))
            .rev()
            .find(|p| starts_with(src, *p, "KEYS"))
            .map(|p| p + 4)
        else {
            i += 1;
            continue;
        };
        let mut k = skip_ws(src, kend);
        if src.get(k) != Some(&':') {
            i += 1;
            continue;
        }
        k = skip_ws(src, k + 1);
        if !starts_with(src, k, "&[&") {
            i += 1;
            continue;
        }
        k += 3;
        if starts_with(src, k, "'static") {
            let w = skip_ws(src, k + 7);
            if w == k + 7 {
                i += 1;
                continue;
            }
            k = w;
        }
        if !starts_with(src, k, "str]") {
            i += 1;
            continue;
        }
        k = skip_ws(src, k + 4);
        if src.get(k) != Some(&'=') {
            i += 1;
            continue;
        }
        k = skip_ws(src, k + 1);
        if !starts_with(src, k, "&[") {
            i += 1;
            continue;
        }
        k += 2;
        // `(.*?)\]\s*;` — the FIRST `]` that is followed by optional whitespace and a `;`.
        let body_start = k;
        let mut end = None;
        let mut c = k;
        while c < n {
            if src[c] == ']' && src.get(skip_ws(src, c + 1)) == Some(&';') {
                end = Some(c);
                break;
            }
            c += 1;
        }
        match end {
            Some(e) => {
                out.push(text(src, body_start..e));
                i = e + 1;
            }
            None => i += 1,
        }
    }
    out
}

// ── STR_LIT_RE ───────────────────────────────────────────────────────────────────────────────────

/// `re.findall(r'"([^"\n]*)"', s)` — non-overlapping, left to right.
pub fn string_literals(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] != '"' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < chars.len() && chars[j] != '"' && chars[j] != '\n' {
            j += 1;
        }
        if chars.get(j) == Some(&'"') {
            out.push(chars[i + 1..j].iter().collect());
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

// ── MATCH_ARM_RE ─────────────────────────────────────────────────────────────────────────────────

/// `((?:"[^"\n]*"\s*\|\s*)*"[^"\n]*")\s*=>` — every string-literal match arm of a hand-written
/// `Deserialize`, which is the set of wire keys a document may use.
/// Read from the `=>` BACKWARDS. The pattern's variable-length half is the `"a" | "b" | …` run in
/// front of the arrow, and walking back from the fixed `=>` finds exactly that run without the
/// forward scanner's ambiguity about where a run begins.
pub fn match_arm_literals(src: &[char]) -> Vec<String> {
    let n = src.len();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 1 < n {
        if !(src[i] == '=' && src[i + 1] == '>') {
            i += 1;
            continue;
        }
        let mut lits: Vec<String> = Vec::new();
        let mut at = i;
        loop {
            let close = rskip_ws(src, at);
            if close == 0 || src[close - 1] != '"' {
                break;
            }
            let Some(open) = string_open(src, close - 1) else {
                break;
            };
            lits.push(text(src, open + 1..close - 1));
            let bar = rskip_ws(src, open);
            if bar > 0 && src[bar - 1] == '|' {
                at = bar - 1;
                continue;
            }
            break;
        }
        lits.reverse();
        out.extend(lits);
        i += 2;
    }
    out
}

/// The whitespace run ending at `at`, walked back to its start.
fn rskip_ws(src: &[char], mut at: usize) -> usize {
    while at > 0 && src[at - 1].is_whitespace() {
        at -= 1;
    }
    at
}

/// The opening quote of the `"[^"\n]*"` literal whose closing quote is at `close`.
fn string_open(src: &[char], close: usize) -> Option<usize> {
    let mut j = close;
    while j > 0 {
        j -= 1;
        if src[j] == '\n' {
            return None;
        }
        if src[j] == '"' {
            return Some(j);
        }
    }
    None
}

// ── VISIT_FN_RE ──────────────────────────────────────────────────────────────────────────────────

/// `\bfn\s+visit_([a-z0-9_]+)\s*(?:<[^>()]*>)?\s*\(` over `src[start..end]`.
pub fn visit_fns(src: &[char], start: usize, end: usize) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    let mut i = start;
    while i < end {
        if !(starts_with(src, i, "fn") && boundary(src, i)) {
            i += 1;
            continue;
        }
        let j = i + 2;
        let w = skip_ws(src, j);
        if w == j || !starts_with(src, w, "visit_") {
            i += 1;
            continue;
        }
        let ns = w + 6;
        let mut e = ns;
        while e < end && (src[e].is_ascii_lowercase() || src[e].is_ascii_digit() || src[e] == '_') {
            e += 1;
        }
        if e == ns {
            i += 1;
            continue;
        }
        let name = text(src, ns..e);
        let mut k = skip_ws(src, e);
        if src.get(k) == Some(&'<') {
            let mut g = k + 1;
            while g < end && src[g] != '>' && src[g] != '(' && src[g] != ')' {
                g += 1;
            }
            if src.get(g) == Some(&'>') {
                k = skip_ws(src, g + 1);
            }
        }
        if src.get(k) == Some(&'(') {
            out.push((name, k + 1));
            i = k + 1;
        } else {
            i += 1;
        }
    }
    out
}

// ── THE `#[serde(…)]` READERS ────────────────────────────────────────────────────────────────────

/// Every `#[serde(` span in an attribute cluster, as `(start, end)` over the characters between the
/// paren and the first `)` after it — the exact reach of `[^)]*` in the Python's patterns.
fn serde_spans(attrs: &[char]) -> Vec<(usize, usize)> {
    let n = attrs.len();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < n {
        if starts_with(attrs, i, "#[serde(") {
            let s = i + 8;
            let mut e = s;
            while e < n && attrs[e] != ')' {
                e += 1;
            }
            out.push((s, e));
            i = s;
        } else {
            i += 1;
        }
    }
    out
}

/// Which positions of `attrs[s..e]` sit INSIDE a `"…"` string literal.
///
/// THE HOLE THIS CLOSES. The Python's knob readers are plain substring regexes over the whole
/// `#[serde(…)]` span, so `\bdefault\b` matches the six letters of `#[serde(rename = "default")]`
/// just as happily as it matches the knob. A field renamed to the wire key `default` — a perfectly
/// ordinary thing for an operator-facing grammar to have — was therefore recorded `optional: true`
/// while serde still REQUIRES it, and the fingerprint said a document omitting that key parses when
/// it does not. It is silent in both directions: adding the field renders no delta the classifier
/// can call breaking, and making it genuinely optional later renders none either.
///
/// The same reading applies to every knob spelled as a bare word — `flatten`, `skip`,
/// `transparent`, `deny_unknown_fields` — so the mask is applied to all of them rather than special
/// cased for `default`.
fn literal_mask(attrs: &[char], s: usize, e: usize) -> Vec<bool> {
    let mut mask = vec![false; e.saturating_sub(s)];
    let mut inside = false;
    for i in s..e {
        if attrs[i] == '"' {
            inside = !inside;
            continue;
        }
        if inside {
            mask[i - s] = true;
        }
    }
    mask
}

/// `#\[serde\([^)]*\bWORD\b`, and never inside a string literal — see [`literal_mask`].
pub fn serde_flag(attrs: &str, word: &str) -> bool {
    let a: Vec<char> = attrs.chars().collect();
    for (s, e) in serde_spans(&a) {
        let mask = literal_mask(&a, s, e);
        let mut i = s;
        while i + word.chars().count() <= e {
            if !mask[i - s]
                && starts_with(&a, i, word)
                && boundary(&a, i)
                && boundary(&a, i + word.chars().count())
            {
                return true;
            }
            i += 1;
        }
    }
    false
}

/// `#\[serde\([^)]*\bskip(_deserializing)?\b` — and NOT `skip_serializing_if`, whose `\b` fails.
pub fn serde_skip(attrs: &str) -> bool {
    serde_flag(attrs, "skip") || serde_flag(attrs, "skip_deserializing")
}

/// `#\[serde\([^)]*WORD\s*=\s*"([^"]+)"`, with `\b` in front of `WORD` when `boundary` is set.
pub fn serde_string(attrs: &str, word: &str, word_boundary: bool) -> Option<String> {
    let a: Vec<char> = attrs.chars().collect();
    let wlen = word.chars().count();
    for (s, e) in serde_spans(&a) {
        let mask = literal_mask(&a, s, e);
        let mut i = s;
        while i + wlen <= e {
            // The KNOB is outside the literal; its VALUE is the literal. `rename = "rename"` must
            // read the knob once, not twice.
            if !mask[i - s] && starts_with(&a, i, word) && (!word_boundary || boundary(&a, i)) {
                let mut k = skip_ws(&a, i + wlen);
                if a.get(k) == Some(&'=') {
                    k = skip_ws(&a, k + 1);
                    if a.get(k) == Some(&'"') {
                        let mut j = k + 1;
                        while j < a.len() && a[j] != '"' {
                            j += 1;
                        }
                        if j < a.len() && j > k + 1 {
                            return Some(text(&a, k + 1..j));
                        }
                    }
                }
            }
            i += 1;
        }
    }
    None
}

/// `re.findall(r"#\[derive\(([^)]*)\)\]", attrs)`, joined with a space.
pub fn derive_list(attrs: &str) -> String {
    let a: Vec<char> = attrs.chars().collect();
    let n = a.len();
    let mut parts: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < n {
        if starts_with(&a, i, "#[derive(") {
            let s = i + 9;
            let mut e = s;
            while e < n && a[e] != ')' {
                e += 1;
            }
            if e + 1 < n && a[e] == ')' && a[e + 1] == ']' {
                parts.push(text(&a, s..e));
                i = e + 2;
                continue;
            }
        }
        i += 1;
    }
    parts.join(" ")
}
