// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STATEMENT'S CANONICAL RENDERING: the one byte form of a [`Statement`], signed into a dropped
//! plugin's manifest by the pack tool and compared, byte for byte, against the door's own Statement
//! when the plugin is admitted (a compiled-in row is compared the same way). Every reader that must
//! not open the plugin (`--validate`, `--list-plugins`, the Discover stage) reads the signed
//! manifest's rendering. There is one source (the door), one signed copy (the manifest) and one
//! check at load.
//!
//! THE FORMAT. Deterministic, little-endian, no padding, and never a pointer:
//!
//! ```text
//! magic            8 bytes  "BBSTMT01"
//! mechanism        u32      MECHANISM_VERSION the rendering was made under
//! kind             u32
//! kind_abi         u32
//! max_inflight     u32
//! name             str
//! version          str
//! families         list of { name str, help str, unit str, label_keys list of str, kind u8 }
//! diag_ids         list of str
//! kind_tail        u32      the tail's stated size; 0 = no tail (its contents are the kind's)
//! extensions       blob
//! secret_refs      list of str
//! settings_schema  blob
//! marks            u64
//! mark_words       list of { class u32, word str }
//! rewrites         list of { class u32, from str, to str }
//! sections         list of { name str, flags u32 }
//! needs            list of { direction u32, egress_class u32, transport str, auth str,
//!                            target_from str, trust_from str, details blob, timeout_ms u64 }
//! target_from      str
//! trust_from       str
//! answers          list of str
//! claims           list of str
//!
//! str   = u32 length, then the bytes
//! list  = u32 count, then each item
//! blob  = u32 fmt, u32 flags, u32 length, then the bytes
//! ```
//!
//! The fields follow [`Statement`]'s declaration order (`size` is not rendered: it is the layout's,
//! not the plugin's). A field appended to the Statement is appended here in the same commit, and the
//! golden (`abi/tests/rendering_tests.rs`) is regenerated with it.

use super::call::{AbiStr, Blob};
use super::door::{MarkWord, MetricFamily, Rewrite, Section, Statement};
use super::MECHANISM_VERSION;
use crate::abi::host::conn::connector::Need;

/// The rendering's first eight bytes.
pub const RENDERING_MAGIC: &[u8; 8] = b"BBSTMT01";

/// One of the rendering's lengths or counts was above `u32::MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooLong(pub &'static str);

struct Out(Vec<u8>);

impl Out {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn len(&mut self, n: usize, field: &'static str) -> Result<(), TooLong> {
        self.u32(u32::try_from(n).map_err(|_| TooLong(field))?);
        Ok(())
    }
    /// # Safety
    /// A non-NULL `ptr` points at `len` live bytes.
    unsafe fn bytes(
        &mut self,
        ptr: *const u8,
        len: usize,
        field: &'static str,
    ) -> Result<(), TooLong> {
        self.len(len, field)?;
        if len > 0 && !ptr.is_null() {
            // SAFETY: the caller's contract.
            self.0
                .extend_from_slice(unsafe { core::slice::from_raw_parts(ptr, len) });
        }
        Ok(())
    }
    /// # Safety
    /// As [`Out::bytes`].
    unsafe fn str(&mut self, s: AbiStr, field: &'static str) -> Result<(), TooLong> {
        // SAFETY: the caller's contract.
        unsafe { self.bytes(s.ptr, s.len, field) }
    }
    /// # Safety
    /// As [`Out::bytes`].
    unsafe fn blob(&mut self, b: Blob, field: &'static str) -> Result<(), TooLong> {
        self.u32(b.fmt);
        self.u32(b.flags);
        // SAFETY: the caller's contract.
        unsafe { self.bytes(b.ptr, b.len, field) }
    }
}

/// A `'static` list as a slice.
///
/// # Safety
/// A non-NULL `ptr` points at `len` live `T`s.
unsafe fn items<'a, T>(ptr: *const T, len: usize) -> &'a [T] {
    if len == 0 || ptr.is_null() {
        return &[];
    }
    // SAFETY: the caller's contract.
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

/// THE CANONICAL RENDERING of `st` (the format above).
///
/// # Errors
///
/// [`TooLong`], naming the field whose length or count does not fit a `u32`.
///
/// # Safety
///
/// `st` passed [`super::check::check_statement`]: every non-NULL list and string points at its
/// stated count of live entries (a door's `'static` Statement does). A NULL list with a count is
/// rendered as empty, never read.
pub unsafe fn render(st: &Statement) -> Result<Vec<u8>, TooLong> {
    let mut o = Out(Vec::with_capacity(256));
    o.0.extend_from_slice(RENDERING_MAGIC);
    o.u32(MECHANISM_VERSION);
    o.u32(st.kind);
    o.u32(st.kind_abi);
    o.u32(st.max_inflight);
    // SAFETY (every read below): the caller's contract.
    unsafe {
        o.str(st.name, "name")?;
        o.str(st.version, "version")?;
        let families: &[MetricFamily] = items(st.families, st.families_len);
        o.len(families.len(), "families")?;
        for f in families {
            o.str(f.name, "family.name")?;
            o.str(f.help, "family.help")?;
            o.str(f.unit, "family.unit")?;
            let keys = items(f.label_keys, f.label_keys_len);
            o.len(keys.len(), "family.label_keys")?;
            for k in keys {
                o.str(*k, "family.label_key")?;
            }
            o.u8(f.kind);
        }
        let diags = items(st.diag_ids, st.diag_ids_len);
        o.len(diags.len(), "diag_ids")?;
        for d in diags {
            o.str(*d, "diag_id")?;
        }
        o.u32(if st.kind_tail.is_null() {
            0
        } else {
            (*st.kind_tail).size
        });
        o.blob(st.extensions, "extensions")?;
        let refs = items(st.secret_refs, st.secret_refs_len);
        o.len(refs.len(), "secret_refs")?;
        for r in refs {
            o.str(*r, "secret_ref")?;
        }
        o.blob(st.settings_schema, "settings_schema")?;
        o.u64(st.marks);
        let words: &[MarkWord] = items(st.mark_words, st.mark_words_len);
        o.len(words.len(), "mark_words")?;
        for w in words {
            o.u32(w.class);
            o.str(w.word, "mark_word.word")?;
        }
        let rewrites: &[Rewrite] = items(st.rewrites, st.rewrites_len);
        o.len(rewrites.len(), "rewrites")?;
        for r in rewrites {
            o.u32(r.class);
            o.str(r.from, "rewrite.from")?;
            o.str(r.to, "rewrite.to")?;
        }
        let sections: &[Section] = items(st.sections, st.sections_len);
        o.len(sections.len(), "sections")?;
        for s in sections {
            o.str(s.name, "section.name")?;
            o.u32(s.flags);
        }
        let needs: &[Need] = items(st.needs, st.needs_len);
        o.len(needs.len(), "needs")?;
        for n in needs {
            o.u32(n.direction);
            o.u32(n.egress_class);
            o.str(n.transport, "need.transport")?;
            o.str(n.auth, "need.auth")?;
            o.str(n.target_from, "need.target_from")?;
            o.str(n.trust_from, "need.trust_from")?;
            o.blob(n.details, "need.details")?;
            o.u64(n.timeout_ms);
        }
        o.str(st.target_from, "target_from")?;
        o.str(st.trust_from, "trust_from")?;
        let answers = items(st.answers, st.answers_len);
        o.len(answers.len(), "answers")?;
        for a in answers {
            o.str(*a, "answer")?;
        }
        let claims = items(st.claims, st.claims_len);
        o.len(claims.len(), "claims")?;
        for c in claims {
            o.str(*c, "claim")?;
        }
    }
    Ok(o.0)
}

// ── reading a rendering back (every no-dlopen reader: `--validate`, `--list-plugins`, Discover) ───

/// A blob, read back: its format, its flags and its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadBlob {
    /// `BLOB_*`.
    pub fmt: u32,
    /// `BLOB_SECRET`.
    pub flags: u32,
    /// The bytes.
    pub bytes: Vec<u8>,
}

/// One metric family, read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadFamily {
    /// Its name.
    pub name: String,
    /// Its help.
    pub help: String,
    /// Its unit.
    pub unit: String,
    /// Its label keys.
    pub label_keys: Vec<String>,
    /// `FAMILY_*`.
    pub kind: u8,
}

/// One need, read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadNeed {
    /// `DIRECTION_*`.
    pub direction: u32,
    /// Its egress class.
    pub egress_class: u32,
    /// The transport claim.
    pub transport: String,
    /// The auth style; empty = none.
    pub auth: String,
    /// Where the target comes from; empty = the plugin names it.
    pub target_from: String,
    /// Where the trust anchors come from; empty = the host's default.
    pub trust_from: String,
    /// Its details.
    pub details: ReadBlob,
    /// Its establish and reply-wait bound, milliseconds; `0` = the host's default.
    pub timeout_ms: u64,
}

/// A Statement read back from its rendering: every fact the rendering carries, owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Read {
    /// The mechanism version it was rendered under.
    pub mechanism_version: u32,
    /// Its kind, as its number.
    pub kind: u32,
    /// Its kind's ABI version.
    pub kind_abi: u32,
    /// The most calls one instance holds in flight.
    pub max_inflight: u32,
    /// Its name.
    pub name: String,
    /// Its version.
    pub version: String,
    /// Its metric families.
    pub families: Vec<ReadFamily>,
    /// Its diagnostic ids.
    pub diag_ids: Vec<String>,
    /// Its kind tail's stated size; `0` = none.
    pub kind_tail_size: u32,
    /// Its extensions.
    pub extensions: ReadBlob,
    /// Its secret-reference settings keys.
    pub secret_refs: Vec<String>,
    /// Its settings schema.
    pub settings_schema: ReadBlob,
    /// Its flag marks.
    pub marks: u64,
    /// Its word marks, `(class, word)`.
    pub mark_words: Vec<(u32, String)>,
    /// Its rewrites, `(class, from, to)`.
    pub rewrites: Vec<(u32, String, String)>,
    /// Its sections, `(name, flags)`.
    pub sections: Vec<(String, u32)>,
    /// Its needs.
    pub needs: Vec<ReadNeed>,
    /// Its settings target path.
    pub target_from: String,
    /// Its settings trust path.
    pub trust_from: String,
    /// Its declared answers.
    pub answers: Vec<String>,
    /// The URL schemes it claims.
    pub claims: Vec<String>,
}

/// Why a rendering could not be read back: the byte offset and what was expected there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable {
    /// Where.
    pub at: usize,
    /// What was expected.
    pub what: &'static str,
}

struct In<'a> {
    b: &'a [u8],
    at: usize,
}

impl In<'_> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&[u8], Unreadable> {
        let err = Unreadable { at: self.at, what };
        let end = self.at.checked_add(n).ok_or(err.clone())?;
        let s = self.b.get(self.at..end).ok_or(err)?;
        self.at = end;
        Ok(s)
    }
    fn u8(&mut self, what: &'static str) -> Result<u8, Unreadable> {
        Ok(self.take(1, what)?[0])
    }
    fn u32(&mut self, what: &'static str) -> Result<u32, Unreadable> {
        let s = self.take(4, what)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self, what: &'static str) -> Result<u64, Unreadable> {
        let s = self.take(8, what)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }
    fn count(&mut self, what: &'static str) -> Result<usize, Unreadable> {
        let at = self.at;
        let n = self.u32(what)? as usize;
        // Every item is at least four bytes: a count no rest could hold is refused before any
        // allocation is sized by it.
        if n > self.b.len().saturating_sub(self.at) / 4 {
            return Err(Unreadable { at, what });
        }
        Ok(n)
    }
    fn bytes(&mut self, what: &'static str) -> Result<Vec<u8>, Unreadable> {
        let n = self.u32(what)? as usize;
        Ok(self.take(n, what)?.to_vec())
    }
    fn str(&mut self, what: &'static str) -> Result<String, Unreadable> {
        let at = self.at;
        String::from_utf8(self.bytes(what)?).map_err(|_| Unreadable { at, what })
    }
    fn blob(&mut self, what: &'static str) -> Result<ReadBlob, Unreadable> {
        Ok(ReadBlob {
            fmt: self.u32(what)?,
            flags: self.u32(what)?,
            bytes: self.bytes(what)?,
        })
    }
    fn strs(&mut self, what: &'static str) -> Result<Vec<String>, Unreadable> {
        let n = self.count(what)?;
        (0..n).map(|_| self.str(what)).collect()
    }
}

/// THE RENDERING READ BACK: the inverse of [`render`], for a reader that must not open the plugin.
/// The whole input must be one rendering: trailing bytes are refused.
///
/// # Errors
///
/// [`Unreadable`], at the first byte that is not what the format states.
pub fn read(bytes: &[u8]) -> Result<Read, Unreadable> {
    let mut i = In { b: bytes, at: 0 };
    if i.take(RENDERING_MAGIC.len(), "the magic")? != RENDERING_MAGIC {
        return Err(Unreadable {
            at: 0,
            what: "the magic",
        });
    }
    let mechanism_version = i.u32("mechanism")?;
    let kind = i.u32("kind")?;
    let kind_abi = i.u32("kind_abi")?;
    let max_inflight = i.u32("max_inflight")?;
    let name = i.str("name")?;
    let version = i.str("version")?;
    let n = i.count("families")?;
    let mut families = Vec::with_capacity(n);
    for _ in 0..n {
        families.push(ReadFamily {
            name: i.str("family.name")?,
            help: i.str("family.help")?,
            unit: i.str("family.unit")?,
            label_keys: i.strs("family.label_keys")?,
            kind: i.u8("family.kind")?,
        });
    }
    let diag_ids = i.strs("diag_ids")?;
    let kind_tail_size = i.u32("kind_tail")?;
    let extensions = i.blob("extensions")?;
    let secret_refs = i.strs("secret_refs")?;
    let settings_schema = i.blob("settings_schema")?;
    let marks = i.u64("marks")?;
    let n = i.count("mark_words")?;
    let mut mark_words = Vec::with_capacity(n);
    for _ in 0..n {
        mark_words.push((i.u32("mark_word.class")?, i.str("mark_word.word")?));
    }
    let n = i.count("rewrites")?;
    let mut rewrites = Vec::with_capacity(n);
    for _ in 0..n {
        rewrites.push((
            i.u32("rewrite.class")?,
            i.str("rewrite.from")?,
            i.str("rewrite.to")?,
        ));
    }
    let n = i.count("sections")?;
    let mut sections = Vec::with_capacity(n);
    for _ in 0..n {
        sections.push((i.str("section.name")?, i.u32("section.flags")?));
    }
    let n = i.count("needs")?;
    let mut needs = Vec::with_capacity(n);
    for _ in 0..n {
        needs.push(ReadNeed {
            direction: i.u32("need.direction")?,
            egress_class: i.u32("need.egress_class")?,
            transport: i.str("need.transport")?,
            auth: i.str("need.auth")?,
            target_from: i.str("need.target_from")?,
            trust_from: i.str("need.trust_from")?,
            details: i.blob("need.details")?,
            timeout_ms: i.u64("need.timeout_ms")?,
        });
    }
    let target_from = i.str("target_from")?;
    let trust_from = i.str("trust_from")?;
    let answers = i.strs("answers")?;
    let claims = i.strs("claims")?;
    if i.at != bytes.len() {
        return Err(Unreadable {
            at: i.at,
            what: "the end",
        });
    }
    Ok(Read {
        mechanism_version,
        kind,
        kind_abi,
        max_inflight,
        name,
        version,
        families,
        diag_ids,
        kind_tail_size,
        extensions,
        secret_refs,
        settings_schema,
        marks,
        mark_words,
        rewrites,
        sections,
        needs,
        target_from,
        trust_from,
        answers,
        claims,
    })
}

#[cfg(test)]
#[path = "../tests/rendering_tests.rs"]
mod tests;
