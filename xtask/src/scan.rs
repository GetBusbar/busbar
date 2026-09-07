//! THE ONE SOURCE SCANNER. Comment stripping and `#[cfg(test)]`-scope stripping, moved out of
//! `denylist.rs` unchanged so every text gate points at one implementation instead of the seven
//! copies of `TEST_SCOPE_AWK` the shell carried (`structure-lint.sh`, `plane-purity-lint.sh`,
//! `blocking-ffi-lint.sh`, `settings-leak-lint.sh`, `response-header-lint.sh`, `tracing-lint.sh`,
//! `kernel-token-wire-purity-lint.sh`).
//!
//! It is a single point of failure by design — which is why it carries its own cases in
//! `xtask/tests/infra.rs` and why the denylist's own self-test, which was written against this
//! code when it lived in `denylist.rs`, still drives it byte-for-byte.

/// Comments stripped (line + block, string contents preserved), `#[cfg(test)] mod { .. }` bodies
/// dropped, one production-code line per output entry, 1-based line numbers.
pub fn production_lines(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut in_block_comment = false;
    let mut pending_test_attr = false;
    let mut test_mod_depth: Option<i32> = None;
    let mut depth: i32 = 0;

    for (i, raw_line) in src.lines().enumerate() {
        let stripped = strip_comment_line(raw_line, &mut in_block_comment);
        let trimmed = stripped.trim();

        let this_line_is_test = test_mod_depth.is_some();

        if !this_line_is_test && trimmed.contains("#[cfg(test)]") {
            pending_test_attr = true;
        } else if !this_line_is_test && !trimmed.is_empty() && !trimmed.starts_with('#') {
            // an attribute only pends across attribute/blank lines; anything else clears it
            if !trimmed.contains("mod ") {
                pending_test_attr = false;
            }
        }

        if !this_line_is_test
            && pending_test_attr
            && trimmed.contains("mod ")
            && trimmed.contains('{')
        {
            test_mod_depth = Some(depth);
            pending_test_attr = false;
        }

        let opens = stripped.matches('{').count() as i32;
        let closes = stripped.matches('}').count() as i32;
        depth += opens - closes;

        let was_test = test_mod_depth.is_some();
        if let Some(d) = test_mod_depth {
            if depth <= d && (opens > 0 || closes > 0) {
                test_mod_depth = None;
            }
        }

        if !was_test && !this_line_is_test {
            out.push((i + 1, stripped));
        }
    }
    out
}

/// One line as `TEST_SCOPE_AWK` saw it: the raw text, the CODE portion, and the two answers the
/// structure-lint scanners branch on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeLine {
    /// 1-based, per file — awk's `FNR`, not `NR`.
    pub no: usize,
    pub raw: String,
    /// Empty for a whole-line comment; a trailing `// …` stripped only when the line holds no
    /// string literal, so a `//` inside a `"…"` cannot eat the line's braces.
    pub code: String,
    pub is_comment: bool,
    pub gated: bool,
}

/// `structure-lint.sh`'s `TEST_SCOPE_AWK`, THE ONE ANSWER TO "IS THIS LINE TEST CODE?", ported line
/// for line.
///
/// It is a second entry point beside [`production_lines`] rather than a replacement for it, and the
/// difference is deliberate. [`production_lines`] answers "give me the production code" and hands
/// back the STRIPPED text; the structure-lint scanners match their patterns against the RAW line
/// (awk's `$0`) and need `is_comment` and `gated` as separate facts — the inline-test rule's entire
/// trigger is the EDGE from ungated to gated, which a filtered list cannot express. Porting the
/// answers rather than approximating them is what lets the parity run compare hit sets instead of
/// hoping two state machines agree.
///
/// The two bugs the shell's own self-test proved exploitable are fixed here for the same reasons:
/// the attribute is read only off a line that IS the attribute (a doc comment MENTIONING
/// `#[cfg(test)]` does not arm it), and it is resolved against the item it applies to — brace-less
/// items included — with a bounded search that fails CLOSED rather than shadowing the rest of a
/// file it does not model.
pub fn test_scope(src: &str) -> Vec<ScopeLine> {
    let mut out = Vec::new();
    let mut in_test = false;
    let mut pending = false;
    let mut pend_age = 0u32;
    let mut depth: i32 = 0;

    for (i, raw) in src.lines().enumerate() {
        let is_comment = raw.trim_start().starts_with("//");
        let code = code_of(raw);
        let mut gated = false;

        if in_test {
            gated = true;
            depth += braces(&code);
            if depth <= 0 {
                in_test = false;
                depth = 0;
            }
        } else if pending {
            gated = true;
            let t = code.trim_start();
            if code.trim().is_empty() || t.starts_with("#[") {
                pend_age += 1;
            } else if code.contains('{') {
                pending = false;
                depth = braces(&code);
                if depth > 0 {
                    in_test = true;
                } else {
                    depth = 0;
                }
            } else if code.trim_end().ends_with(';') {
                // A BRACE-LESS item: gates this line and no more.
                pending = false;
            } else {
                pend_age += 1;
            }
            // An attribute never applies across arbitrary distance. Unresolved after a handful of
            // lines, the file is shaped in a way this scanner does not model: drop the arm and go
            // back to scanning production rather than shadowing everything after it.
            if pending && pend_age > 10 {
                pending = false;
                pend_age = 0;
            }
        }

        if !in_test && !pending && arms_test_cfg(&code) {
            gated = true;
            let rest = strip_cfg_attr(&code);
            if rest.trim().is_empty() {
                pending = true;
                pend_age = 0;
            } else if rest.contains('{') {
                depth = braces(&rest);
                if depth > 0 {
                    in_test = true;
                } else {
                    depth = 0;
                }
            } else if rest.trim_end().ends_with(';') {
                // `#[cfg(test)] use x;` — gates its own line and stops.
            } else {
                pending = true;
                pend_age = 0;
            }
        }

        out.push(ScopeLine {
            no: i + 1,
            raw: raw.to_string(),
            code,
            is_comment,
            gated,
        });
    }
    out
}

/// The code content of a line: empty for a whole-line comment, and with a trailing `//` comment
/// stripped when the line holds no string literal (so a `// }` in a trailer cannot skew brace
/// depth, and a `"//"` inside a literal is not mistaken for one).
fn code_of(line: &str) -> String {
    if line.trim_start().starts_with("//") {
        return String::new();
    }
    if line.contains('"') {
        return line.to_string();
    }
    match line.find("//") {
        Some(at) => line[..at].to_string(),
        None => line.to_string(),
    }
}

fn braces(s: &str) -> i32 {
    s.matches('{').count() as i32 - s.matches('}').count() as i32
}

/// Arm only on a line that IS the attribute: anchored at the start of a CODE line, with `test` as a
/// cfg predicate (`#[cfg(test)]`, `#[cfg(all(test, …))]`) — never `#[cfg(not(test))]`, which is
/// production-only code, and never `#[cfg(feature = "test-utils")]`, which is not a test gate.
fn arms_test_cfg(code: &str) -> bool {
    if !code.trim_start().starts_with("#[cfg(") {
        return false;
    }
    if !has_test_predicate(code) {
        return false;
    }
    !has_not_test(code)
}

/// `[(,][[:space:]]*test[[:space:]]*[,)]`, spelled out.
fn has_test_predicate(code: &str) -> bool {
    let c: Vec<char> = code.chars().collect();
    for i in 0..c.len() {
        if c[i] != '(' && c[i] != ',' {
            continue;
        }
        let mut j = i + 1;
        while j < c.len() && c[j].is_whitespace() {
            j += 1;
        }
        if !c[j..].starts_with(&['t', 'e', 's', 't']) {
            continue;
        }
        let mut k = j + 4;
        while k < c.len() && c[k].is_whitespace() {
            k += 1;
        }
        if matches!(c.get(k), Some(',') | Some(')')) {
            return true;
        }
    }
    false
}

/// `not[[:space:]]*\([[:space:]]*test[[:space:]]*\)`, spelled out.
fn has_not_test(code: &str) -> bool {
    let c: Vec<char> = code.chars().collect();
    for i in 0..c.len() {
        if !c[i..].starts_with(&['n', 'o', 't']) {
            continue;
        }
        let mut j = i + 3;
        while j < c.len() && c[j].is_whitespace() {
            j += 1;
        }
        if c.get(j) != Some(&'(') {
            continue;
        }
        j += 1;
        while j < c.len() && c[j].is_whitespace() {
            j += 1;
        }
        if !c[j..].starts_with(&['t', 'e', 's', 't']) {
            continue;
        }
        j += 4;
        while j < c.len() && c[j].is_whitespace() {
            j += 1;
        }
        if c.get(j) == Some(&')') {
            return true;
        }
    }
    false
}

/// `sub(/^[[:space:]]*#\[cfg\(.*\)\][[:space:]]*/, "", rest)` — the GREEDY `.*`, so `#[cfg(test)]`
/// followed by a second attribute leaves the second one as the remainder.
fn strip_cfg_attr(code: &str) -> String {
    let trimmed = code.trim_start();
    if !trimmed.starts_with("#[cfg(") {
        return code.to_string();
    }
    // The greedy answer: the LAST `)]` on the line.
    let Some(end) = code.rfind(")]") else {
        return code.to_string();
    };
    code[end + 2..].trim_start().to_string()
}

/// Blank the CONTENTS of every double-quoted string literal, keeping the quotes and the line's
/// length. `tracing-lint.sh` counted parens inside string literals, so a message containing `"f("`
/// started a runaway that absorbed the rest of the file and reported every later `#[instrument]`
/// as clean. Any rule that counts delimiters, or that looks for a token that could equally be a
/// literal (a scanner searching for `use busbar_` must not match its own needle), blanks first.
pub fn blank_literals(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    let mut in_str = false;
    while i < chars.len() {
        let c = chars[i];
        if in_str {
            if c == '\\' {
                out.push(' ');
                if i + 1 < chars.len() {
                    out.push(' ');
                }
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
                out.push('"');
            } else {
                out.push(' ');
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_str = true;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// One line with `//` and `/* */` comments removed. `in_block` carries block-comment state across
/// lines. String literals are preserved verbatim, so a `//` inside a `"…"` is not a comment.
pub fn strip_comment_line(line: &str, in_block: &mut bool) -> String {
    let mut out = String::new();
    let bytes: Vec<char> = line.chars().collect();
    let mut i = 0;
    let mut in_str = false;
    while i < bytes.len() {
        if *in_block {
            if bytes[i] == '*' && bytes.get(i + 1) == Some(&'/') {
                *in_block = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if in_str {
            out.push(bytes[i]);
            if bytes[i] == '\\' {
                if let Some(c) = bytes.get(i + 1) {
                    out.push(*c);
                }
                i += 2;
                continue;
            }
            if bytes[i] == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if bytes[i] == '/' && bytes.get(i + 1) == Some(&'*') {
            *in_block = true;
            i += 2;
            continue;
        }
        if bytes[i] == '/' && bytes.get(i + 1) == Some(&'/') {
            break;
        }
        if bytes[i] == '"' {
            in_str = true;
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}
