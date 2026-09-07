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
