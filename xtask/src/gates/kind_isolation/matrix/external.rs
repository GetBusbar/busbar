//! EXTERNAL CRATES' PATHS, AND THE KERNEL FACADE'S MODULES, ARE NOT PLUGIN NAMES.
//!
//! Two matcher false positives (ARCHITECT, KI-DEBT), both measured on the real tree:
//!
//! * `std::process::Stdio` was counted as the `stdio` transport, and a third-party crate's
//!   `ApprovalDecision` / `RegistrationDecision` as the `decision` plane. A name that sits in a path
//!   rooted at an EXTERNAL crate (the standard library, or a dependency a manifest declares that is
//!   not a crate of this tree and not a `busbar-*` crate) is that crate's word, not ours. The same
//!   word imported by a `use` of such a path (`use std::process::Stdio;`, then `Stdio::piped()`)
//!   is masked where the file uses it bare.
//! * `busbar_kernel::audit` and `busbar_kernel::egress` are modules of the kernel facade. The
//!   segment scanner read them as the sibling crate names `busbar-kernel-audit` and
//!   `busbar-kernel-egress`. They name `busbar-kernel`: the facade's module segment is masked so
//!   the span counts once, as the `busbar_kernel` it is (kernel-family paths, owner ruling Q3).
//!
//! WHAT IS NOT MASKED, on purpose (the owner prefers a false fail to a missed hit): any path whose
//! head is a crate of this tree, a `busbar-*` crate or a plugin crate (`busbar_plane_mcp::X`,
//! `busbar_kernel_audit::X`), a local module that happens to share a word (`mod stdio;`,
//! `stdio::run()`), a string literal, and everything in a file that is not Rust. The masks are
//! same-length `x` filler, so lines and columns hold.

use std::borrow::Cow;
use std::collections::BTreeSet;

/// The standard library's roots: external to every crate, declared by none.
const STD_ROOTS: &[&str] = &["std", "core", "alloc"];

/// The external crate roots a crate's manifest declares, spelled as Rust paths write them (`-` is
/// `_`). `declared` is `(package, key)` per dependency declaration of the crate. A dependency is
/// external unless it is a crate of this tree (`tree`) or a `busbar-*` crate: the plugin crates a
/// root pulls in by git are `busbar-*`, and they are exactly what the matrix exists to count.
pub(super) fn external_roots<'a>(
    declared: impl IntoIterator<Item = (&'a str, &'a str)>,
    tree: &BTreeSet<&str>,
) -> BTreeSet<String> {
    let mut roots: BTreeSet<String> = STD_ROOTS.iter().map(|s| (*s).to_string()).collect();
    for (pkg, key) in declared {
        if pkg.starts_with("busbar") || tree.contains(pkg) {
            continue;
        }
        roots.insert(key.replace('-', "_"));
    }
    roots
}

fn is_id(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// The end of the identifier starting at `i`.
fn ident_end(b: &[u8], i: usize) -> usize {
    let mut k = i;
    while k < b.len() && is_id(b[k]) {
        k += 1;
    }
    k
}

/// Fill every identifier byte of `b[from..to]` with `x`, leaving punctuation as it is.
fn fill_idents(buf: &mut [u8], from: usize, to: usize) {
    for c in &mut buf[from..to] {
        if is_id(*c) {
            *c = b'x';
        }
    }
}

/// The end of the `{ … }` group opening at `b[open]` (one line), or the line's end if unclosed.
fn group_end(b: &[u8], open: usize) -> usize {
    let mut depth = 0usize;
    for (k, &c) in b.iter().enumerate().skip(open) {
        match c {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return k + 1;
                }
            }
            _ => {}
        }
    }
    b.len()
}

/// The span `[start, end)` of the path chain rooted at an external root beginning at `start`, or
/// `None` if `b[start..]` is not `root::…` for a root in `roots`. The chain is `ident(::ident)*`
/// and may end in a `::{ … }` group.
fn external_chain(b: &[u8], start: usize, roots: &BTreeSet<String>) -> Option<usize> {
    let head_end = ident_end(b, start);
    let head = std::str::from_utf8(&b[start..head_end]).ok()?;
    if !roots.contains(head) || !b[head_end..].starts_with(b"::") {
        return None;
    }
    let mut end = head_end;
    while b[end..].starts_with(b"::") {
        let next = end + 2;
        match b.get(next) {
            Some(c) if is_id(*c) => end = ident_end(b, next),
            Some(b'{') => return Some(group_end(b, next)),
            _ => break,
        }
    }
    Some(end)
}

/// The names a `use` of an external path brings into the file, whole. `use std::process::Stdio;`
/// brings `Stdio`; `use oauth_as::{ApprovalDecision, RegistrationDecision as Reg};` brings
/// `ApprovalDecision`, `RegistrationDecision` and `Reg`. `self`, `as` and `*` bring nothing.
fn imported_names(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let flush = |cur: &mut String, followed_by_path: bool, out: &mut Vec<String>| {
        if !cur.is_empty()
            && !followed_by_path
            && !matches!(cur.as_str(), "self" | "as" | "super" | "crate")
            && cur.len() > 1
        {
            out.push(std::mem::take(cur));
        } else {
            cur.clear();
        }
    };
    let b = path.as_bytes();
    for (k, &c) in b.iter().enumerate() {
        if is_id(c) {
            cur.push(c as char);
        } else {
            let followed = c == b':' && b.get(k + 1) == Some(&b':');
            flush(&mut cur, followed, &mut out);
        }
    }
    flush(&mut cur, false, &mut out);
    out
}

/// `text` (a Rust file) with every path rooted at an external crate masked, and every name such a
/// path IMPORTED masked where the file uses it bare. Non-Rust files are returned as they are.
pub(super) fn mask_external_paths<'a>(
    rel: &str,
    text: &'a str,
    roots: &BTreeSet<String>,
) -> Cow<'a, str> {
    if !rel.ends_with(".rs") {
        return Cow::Borrowed(text);
    }
    let b = text.as_bytes();
    let mut buf = b.to_vec();
    let mut imported: BTreeSet<String> = BTreeSet::new();
    let mut changed = false;
    let mut i = 0;
    while i < b.len() {
        let starts_path = is_id(b[i]) && (i == 0 || !(is_id(b[i - 1]) || b[i - 1] == b':'));
        if !starts_path {
            i += 1;
            continue;
        }
        match external_chain(b, i, roots) {
            Some(end) => {
                // A `use` line imports the chain's leaf names; collect them before masking.
                let line_start = b[..i]
                    .iter()
                    .rposition(|c| *c == b'\n')
                    .map_or(0, |p| p + 1);
                let lead = String::from_utf8_lossy(&b[line_start..i]);
                let lead = lead.trim();
                if matches!(
                    lead,
                    "use" | "pub use" | "pub(crate) use" | "pub(super) use"
                ) {
                    imported.extend(imported_names(&String::from_utf8_lossy(&b[i..end])));
                }
                fill_idents(&mut buf, i, end);
                changed = true;
                i = end;
            }
            None => i = ident_end(b, i),
        }
    }
    // The imported names, bare, anywhere else in the file: whole identifier only, never behind a
    // `::` (a local `mine::Stdio` is not the standard library's).
    if !imported.is_empty() {
        let mut i = 0;
        while i < b.len() {
            if is_id(b[i]) && (i == 0 || !is_id(b[i - 1])) {
                let end = ident_end(b, i);
                let behind_path = i >= 2 && &b[i - 2..i] == b"::";
                let word = String::from_utf8_lossy(&b[i..end]);
                if !behind_path && imported.contains(word.as_ref()) {
                    fill_idents(&mut buf, i, end);
                    changed = true;
                }
                i = end;
            } else {
                i += 1;
            }
        }
    }
    if !changed {
        return Cow::Borrowed(text);
    }
    Cow::Owned(String::from_utf8(buf).expect("ascii-for-ascii"))
}

/// The kernel facade's crate root as a Rust path writes it.
const KERNEL_ROOT: &str = "busbar_kernel";

/// `text` (a Rust file) with the MODULE segment after `busbar_kernel::` masked (`busbar_kernel::audit`
/// reads `busbar_kernel::xxxxx`; `use busbar_kernel::{audit, egress::X}` masks each group item's
/// first segment). Only a lowercase-initial segment is a module; items (`busbar_kernel::Kernel`) and
/// every other crate root are left alone.
pub(super) fn mask_kernel_facade<'a>(rel: &str, text: &'a str) -> Cow<'a, str> {
    if !rel.ends_with(".rs") || !text.contains(KERNEL_ROOT) {
        return Cow::Borrowed(text);
    }
    let b = text.as_bytes();
    let mut buf = b.to_vec();
    let mut changed = false;
    let mask_module = |buf: &mut [u8], at: usize, changed: &mut bool| {
        if b.get(at).is_some_and(|c| c.is_ascii_lowercase()) {
            fill_idents(buf, at, ident_end(b, at));
            *changed = true;
        }
    };
    let mut from = 0;
    while let Some(off) = text[from..].find(KERNEL_ROOT) {
        let i = from + off;
        let j = i + KERNEL_ROOT.len();
        from = j;
        let whole = (i == 0 || !(is_id(b[i - 1]) || b[i - 1] == b':'))
            && !b.get(j).is_some_and(|c| is_id(*c));
        if !whole || !b[j..].starts_with(b"::") {
            continue;
        }
        let at = j + 2;
        if b.get(at) == Some(&b'{') {
            let end = group_end(b, at);
            let mut depth = 0usize;
            let mut item_start = true;
            for (k, &c) in b.iter().enumerate().take(end).skip(at) {
                match c {
                    b'{' => {
                        depth += 1;
                        item_start = depth == 1;
                    }
                    b'}' => depth = depth.saturating_sub(1),
                    b',' if depth == 1 => item_start = true,
                    _ if c.is_ascii_whitespace() => {}
                    _ if item_start && depth == 1 => {
                        mask_module(&mut buf, k, &mut changed);
                        item_start = false;
                    }
                    _ => {}
                }
            }
        } else {
            mask_module(&mut buf, at, &mut changed);
        }
    }
    if !changed {
        return Cow::Borrowed(text);
    }
    Cow::Owned(String::from_utf8(buf).expect("ascii-for-ascii"))
}

#[cfg(test)]
#[path = "external_tests.rs"]
mod tests;
