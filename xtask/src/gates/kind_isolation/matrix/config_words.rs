//! THE 1.5.x CUSTOMER CONFIG WORDS ARE EXEMPT FROM LAW 0 ONLY WHERE A CUSTOMER'S CONFIG SPELLS THEM
//! (architect ruling 2026-10-23 (R-3), L0-1, applying the amended 2026-10-21 ruling,
//! docs/design/BUSBAR-1.6.0.md l.4323-4332: frozen 1.5.5 bytes, "the 1.5.5 config words customers
//! write" among them, are exempt POSITIONALLY; everything else counts).
//!
//! THE WORDS. v1.5.5 gave an `export:` entry a `streams:` key, a list of
//! stream tokens of which `decisions` is one (v1.5.5 crates/busbar/src/config/mod.rs:3303-3313,
//! crates/busbar/src/config/migrate_export.rs:17, :178, crates/plugin-abi/src/export.rs:105). Every
//! 1.5.x config a customer wrote carries them, and DoD item 6 (l.2022) holds that config to its
//! bytes, so they are not renamed. They are also spellings of two planes (`streams` the streaming
//! plane's alias, `decisions` the decisions plane's id; `PLANE_ALIASES`), and 1.6.0 gave both
//! planes a section of their own (`streams:`, `decisions:` over a mapping), which 1.5.5 never had:
//! there the word is the plane, and it counts.
//!
//! WHERE `streams` IS THE CUSTOMER'S WORD ([`Position`]), each read off the bytes around it; it is
//! masked there (same-length filler, so lines and columns hold) and nowhere else:
//! - [`Position::KeyOverAList`]: the export entry's key itself, `streams:` taking a flow list
//!   (`streams: [logs, costs]`). A plane's section takes a mapping and is not this position.
//! - [`Position::ExportPath`]: the key addressed by its config path, `export.<entry>.streams`, as a
//!   diagnostic or a document prints it to the customer.
//! - [`Position::ExportKeyLiteral`]: the key as a lookup reads it, the string literal `"streams"`
//!   closing a key path rooted at `"export"` (`["export", name, "streams"]`).
//! - [`Position::TokenListField`]: the one Rust spelling of the key, the deserialized field that IS
//!   it (`streams: Option<Vec<String>>`, v1.5.5 config/mod.rs:3313).
//!
//! An identifier (`fn from_parts(streams: …)`, `self.streams`), a plane's section key or path
//! (`streams:` over a mapping, `streams.fees`), a literal of its own and every joined spelling
//! (`plane-streams`, `streams_route`) still count. English prose is the 2026-09-27 ruling's
//! (`ENGLISH_INSTANCE_WORDS`), unchanged.
//!
//! ONE MORE FROZEN CONFIG WORD IS A LITERAL, NOT A KEY ([`FROZEN_CONFIG_LITERALS`]): the store
//! module the migrator writes for 1.5.5's implicit store (`MIGRATED_STORE_MODULE = "memory"`),
//! exempt on the instance-literal axes only at its declaration.
//!
//! `decisions` NEEDS NO POSITION HERE: the bare word is no needle at all (`BARE_WORD_COLLISIONS`,
//! which strikes it for this same export stream token), so the token in a stream list is not read.
//! The decisions plane's own spellings (`decision`, `plane-decisions`, `busbar-plane-decisions`)
//! are needles everywhere, a stream list included; the self-test proves it.

/// A 1.5.x CONFIG WORD THE 1.6.0 MIGRATOR WRITES INTO A CUSTOMER'S CONFIG, held as one named
/// constant (architect ruling 2026-10-23, addition to R-3 for #1371). On the `instance:<kind>`
/// literal axes its literal is exempt in ONE position: the declaration of [`FrozenLiteral::holder`]
/// in [`FrozenLiteral::file`], written exactly as [`FrozenLiteral::declaration`] spells it. The same
/// literal on any other line, in any other file, under any other name, or on an edited declaration
/// counts.
pub(super) struct FrozenLiteral {
    /// The file the declaration stands in.
    pub file: &'static str,
    /// The constant that holds the word.
    pub holder: &'static str,
    /// The word, the whole content of the literal.
    pub word: &'static str,
}

impl FrozenLiteral {
    /// The declaration line, trimmed, byte for byte.
    pub(super) fn declaration(&self) -> String {
        format!("pub const {}: &str = \"{}\";", self.holder, self.word)
    }
}

/// The frozen config literals. `memory` is the store a 1.5.x config with no `store:` block ran on
/// (v1.5.5 crates/busbar/src/config/mod.rs:3026 `GOVERNANCE_STORE_MEMORY`), which
/// `busbar --migrate-config` writes into that config as its `store: { module: memory }`: 1.5.5's
/// implicit behaviour made explicit, frozen 1.5.5 config vocabulary.
pub(super) const FROZEN_CONFIG_LITERALS: &[FrozenLiteral] = &[FrozenLiteral {
    file: "crates/busbar-kernel/src/config/sections.rs",
    holder: "MIGRATED_STORE_MODULE",
    word: "memory",
}];

/// Whether `rel` holds a [`FROZEN_CONFIG_LITERALS`] declaration (so its lines are worth reading).
pub(super) fn holds_frozen_literal(rel: &str) -> bool {
    FROZEN_CONFIG_LITERALS.iter().any(|f| f.file == rel)
}

/// Whether the literal `lit` on `line` (its text) of file `rel` is a frozen config literal in its
/// one position.
pub(super) fn frozen_literal(rel: &str, line: &str, lit: &str) -> bool {
    FROZEN_CONFIG_LITERALS
        .iter()
        .any(|f| f.file == rel && f.word == lit && line.trim() == f.declaration())
}

/// The export entry's 1.5.x key: the one frozen config word with a position to mask (the stream
/// token `decisions` is no needle; see the module doc).
pub(super) const FROZEN_CONFIG_KEY: &str = "streams";

/// Where a `streams` is the export entry's 1.5.x key (see the module doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Position {
    /// `streams:` taking a flow list.
    KeyOverAList,
    /// `export.<entry>.streams`.
    ExportPath,
    /// `"streams"` closing `["export", …, "streams"]`.
    ExportKeyLiteral,
    /// `streams: Option<Vec<String>>`.
    TokenListField,
}

/// `text` with every `streams` standing in a [`Position`] masked, or `None` when none does.
pub(super) fn mask(text: &str) -> Option<String> {
    if !text.contains(FROZEN_CONFIG_KEY) {
        return None;
    }
    let b = text.as_bytes();
    let mut out = b.to_vec();
    let mut changed = false;
    let mut from = 0;
    while let Some(off) = text[from..].find(FROZEN_CONFIG_KEY) {
        let i = from + off;
        let j = i + FROZEN_CONFIG_KEY.len();
        from = j;
        if position(b, i, j).is_some() {
            out[i..j].fill(b'x');
            changed = true;
        }
    }
    changed.then(|| String::from_utf8(out).expect("ascii-for-ascii"))
}

/// The [`Position`] of the `streams` at `b[i..j]`, or `None` where it is no customer's word.
pub(super) fn position(b: &[u8], i: usize, j: usize) -> Option<Position> {
    let name = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'-';
    // Joined after (`streams_route`, `streamsX`, `streams.fees`): another name, never the key.
    match b.get(j) {
        Some(&c) if name(c) => return None,
        Some(b'.') if b.get(j + 1).is_some_and(|c| name(*c)) => return None,
        _ => {}
    }
    match i.checked_sub(1).map(|k| b[k]) {
        Some(b'.') => return in_export_path(b, i).then_some(Position::ExportPath),
        Some(c) if name(c) => return None,
        Some(b'"') if closes_export_key_path(b, i, j) => return Some(Position::ExportKeyLiteral),
        _ => {}
    }
    // Key position: one `:` (not `::`), then past blanks a flow list or the token-list type.
    if b.get(j) != Some(&b':') || b.get(j + 1) == Some(&b':') {
        return None;
    }
    let k = skip_blanks(b, j + 1);
    if b.get(k) == Some(&b'[') {
        return Some(Position::KeyOverAList);
    }
    b[k..]
        .starts_with(b"Option<Vec<String>>")
        .then_some(Position::TokenListField)
}

/// Whether the `.` before `b[i]` closes `export.<entry>.`: one entry segment (any run without a
/// dot, blank or quote, `{name}` included) under an `export` that is not itself joined to a name.
fn in_export_path(b: &[u8], i: usize) -> bool {
    let stop = |c: u8| matches!(c, b'.' | b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' | b'`');
    let dot = i - 1;
    let mut k = dot;
    while k > 0 && !stop(b[k - 1]) {
        k -= 1;
    }
    if k == dot || k == 0 || b[k - 1] != b'.' {
        return false;
    }
    let Some(start) = (k - 1).checked_sub(6) else {
        return false;
    };
    &b[start..k - 1] == b"export"
        && start
            .checked_sub(1)
            .is_none_or(|p| !(b[p].is_ascii_alphanumeric() || matches!(b[p], b'_' | b'-' | b'.')))
}

/// Whether the literal `"streams"` opening at `b[i - 1]` is the last element of a bracketed key
/// path, on its line, whose first element is the literal `"export"`.
fn closes_export_key_path(b: &[u8], i: usize, j: usize) -> bool {
    if b.get(j) != Some(&b'"') || b.get(skip_blanks(b, j + 1)) != Some(&b']') {
        return false;
    }
    let mut k = i - 1;
    while k > 0 {
        k -= 1;
        match b[k] {
            b'\n' | b']' => return false,
            b'[' => return b[skip_blanks(b, k + 1)..].starts_with(b"\"export\""),
            _ => {}
        }
    }
    false
}

fn skip_blanks(b: &[u8], mut k: usize) -> usize {
    while matches!(b.get(k), Some(b' ' | b'\t')) {
        k += 1;
    }
    k
}

#[cfg(test)]
#[path = "config_words_tests.rs"]
mod tests;
