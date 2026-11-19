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
//! magic            8 bytes  "BBSTMT04" ("BBSTMT03" omitted common units; "BBSTMT02" omitted need
//!                           retention policy; "BBSTMT01" stated the tail's size alone)
//! mechanism        u32      MECHANISM_VERSION the rendering was made under
//! kind             u32
//! kind_abi         u32
//! max_inflight     u32
//! name             str
//! version          str
//! families         list of { name str, help str, unit str, label_keys list of str, kind u8 }
//! diag_ids         list of str
//! kind_tail        u32      the tail's stated size; 0 = no tail
//! kind_tail_facts  bytes    u32 length, then THE KIND TAIL'S FACTS: every field of the kind's tail
//!                           (`rendering/tail.rs`), so the signed manifest carries the tail itself
//! extensions       blob
//! secret_refs      list of str
//! settings_schema  blob
//! marks            u64
//! mark_words       list of { class u32, word str }
//! rewrites         list of { class u32, from str, to str }
//! sections         list of { name str, flags u32 }
//! needs            list of { direction u32, egress_class u32, transport str, auth str,
//!                            target_from str, trust_from str, details blob,
//!                            keep_response_headers list of str, timeout_ms u64, keep_mode u32,
//!                            deny_response_headers list of str }
//! target_from      str
//! trust_from       str
//! answers          list of str
//! claims           list of str
//! measurement_classes list of { class str, family str }, at most 64
//!
//! str   = u32 length, then the bytes
//! list  = u32 count, then each item
//! blob  = u32 fmt, u32 flags, u32 length, then the bytes
//! ```
//!
//! THE KIND TAIL IS RENDERED WHOLE: a
//! reader that must not open the plugin reads a dropped-in row's tail facts (an auth row's outbound
//! styles, `FACT_*` flags, operator principal and credential kinds; every other kind's tail alike)
//! from the signed manifest, and the admit comparison covers them, so a manifest that states another
//! tail than the door's refuses the load. A tail is read by THE KIND TAIL GROWTH RULE (the plugin's
//! first `min(size, host)` bytes, the rest zero) and rendered field by field in declaration order,
//! every pointer followed: padding is never rendered, and no address is. A tail list or string is
//! bounded before it is read ([`RenderError::Tail`]).
//!
//! The fields follow [`Statement`]'s declaration order (`size` is not rendered: it is the layout's,
//! not the plugin's). A field appended to the Statement is appended here in the same commit, and the
//! golden (`abi/tests/rendering_tests.rs`) is regenerated with it.

use super::call::{AbiStr, Blob};
use super::check::Fault;
use super::door::{MarkWord, MetricFamily, Rewrite, Section, Statement};
use super::MECHANISM_VERSION;
use crate::abi::host::conn::connector::Need;

mod tail;
pub use tail::{
    read_auth_tail, read_plane_cli_help, read_plane_records, ReadAuthTail, ReadPlaneRecords,
    ReadStyle,
};

pub use busbar_artifact_metadata::rendering::{
    RENDERING_MAGIC, RENDERING_MAGIC_TAIL_SIZE_ONLY, RENDERING_MAGIC_WITHOUT_MEASUREMENTS,
    RENDERING_MAGIC_WITHOUT_NEED_RETENTION,
};

/// Why a Statement does not render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderError {
    /// A string or blob has a nonzero length and a NULL pointer; the field.
    NullWithCount(&'static str),
    /// One of the rendering's lengths or counts was above `u32::MAX`; the field.
    TooLong(&'static str),
    /// A kind tail list or string that is not read: NULL with a count, above
    /// [`STATEMENT_LIST_MAX`](super::check::STATEMENT_LIST_MAX) entries or
    /// [`HARD_MAX_BYTES`](super::check::HARD_MAX_BYTES) bytes, or misaligned.
    Tail(Fault),
}

impl core::fmt::Display for RenderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NullWithCount(field) => write!(f, "{field} is NULL with a nonzero length"),
            Self::TooLong(field) => write!(f, "{field} is too long"),
            Self::Tail(fault) => {
                write!(f, "the kind tail's {} breaks {:?}", fault.field, fault.rule)
            }
        }
    }
}

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
    fn len(&mut self, n: usize, field: &'static str) -> Result<(), RenderError> {
        self.u32(u32::try_from(n).map_err(|_| RenderError::TooLong(field))?);
        Ok(())
    }
    /// # Safety
    /// A non-NULL `ptr` points at `len` live bytes.
    unsafe fn bytes(
        &mut self,
        ptr: *const u8,
        len: usize,
        field: &'static str,
    ) -> Result<(), RenderError> {
        if len > 0 && ptr.is_null() {
            return Err(RenderError::NullWithCount(field));
        }
        self.len(len, field)?;
        if len > 0 {
            // SAFETY: the caller's contract.
            self.0
                .extend_from_slice(unsafe { core::slice::from_raw_parts(ptr, len) });
        }
        Ok(())
    }
    /// # Safety
    /// As [`Out::bytes`].
    unsafe fn str(&mut self, s: AbiStr, field: &'static str) -> Result<(), RenderError> {
        // SAFETY: the caller's contract.
        unsafe { self.bytes(s.ptr, s.len, field) }
    }
    /// # Safety
    /// As [`Out::bytes`].
    unsafe fn blob(&mut self, b: Blob, field: &'static str) -> Result<(), RenderError> {
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
/// [`RenderError::NullWithCount`], naming a string or blob with a length but no bytes;
/// [`RenderError::TooLong`], naming the field whose length or count does not fit a `u32`;
/// [`RenderError::Tail`], naming the kind tail's list or string that is not read.
///
/// # Safety
///
/// `st` passed [`super::check::check_statement`]: every non-NULL list and string points at its
/// stated count of live entries (a door's `'static` Statement does). A NULL list with a count is
/// rendered as empty, never read. A non-NULL `kind_tail` is `'static` plugin data of at least its
/// stated size whose lists and strings point at their stated counts of live entries (each is
/// bounded before it is read).
pub unsafe fn render(st: &Statement) -> Result<Vec<u8>, RenderError> {
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
            core::ptr::addr_of!((*st.kind_tail).size).read_unaligned()
        });
        tail::render(&mut o, st.kind, st.kind_tail)?;
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
            let kept = items(n.keep_response_headers, n.keep_response_headers_len);
            o.len(kept.len(), "need.keep_response_headers")?;
            for name in kept {
                o.str(*name, "need.keep_response_headers")?;
            }
            o.u64(n.timeout_ms);
            o.u32(n.keep_mode);
            let denied = items(n.deny_response_headers, n.deny_response_headers_len);
            o.len(denied.len(), "need.deny_response_headers")?;
            for name in denied {
                o.str(*name, "need.deny_response_headers")?;
            }
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
    // SAFETY: same signed Statement storage contract as above.
    if st.measurement_classes_len > crate::abi::measurement::MAX_MEASUREMENT_CLASSES {
        return Err(RenderError::Tail(super::check::fault(
            super::check::Rule::OverMax,
            "statement.measurement_classes",
        )));
    }
    super::check::listed(
        st.measurement_classes,
        st.measurement_classes_len,
        "statement.measurement_classes",
    )
    .map_err(RenderError::Tail)?;
    super::check::bounded(
        st.measurement_classes,
        st.measurement_classes_len,
        "statement.measurement_classes",
    )
    .map_err(RenderError::Tail)?;
    let classes = unsafe { items(st.measurement_classes, st.measurement_classes_len) };
    unsafe { crate::abi::measurement::check_declarations(classes) }.map_err(RenderError::Tail)?;
    o.len(classes.len(), "measurement_classes")?;
    for class in classes {
        // SAFETY: validated live strings under the caller's contract.
        unsafe {
            o.str(class.class, "measurement_class.class")?;
            o.str(class.family, "measurement_class.family")?;
        }
    }
    Ok(o.0)
}

use busbar_artifact_metadata::rendering::In;
pub use busbar_artifact_metadata::rendering::{
    read, Read, ReadBlob, ReadFamily, ReadMeasurementClass, ReadNeed, Unreadable,
};

