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
//! THE OPTIONAL TAIL: each field present is `u32 tag` then its body, in strictly ascending tag
//! order; an absent field writes nothing. The tags, in the one order they are written:
//!   1 claim_flags  list of u32  a transport's Statement whose claim rows state a non-zero
//!                               `flags`: claim i's row's flags
//!   2 auth         { caps u32, facts u32, login_kind u32, inbound_points u32,
//!                    operator_principal str, credential_kinds list of str,
//!                    styles list of { name str, flags u32, points u32 } }
//!                               an auth Statement whose tail states anything: its tail's facts
//!
//! str   = u32 length, then the bytes
//! list  = u32 count, then each item
//! blob  = u32 fmt, u32 flags, u32 length, then the bytes
//! ```
//!
//! The fields follow [`Statement`]'s declaration order (`size` is not rendered: it is the layout's,
//! not the plugin's). A field appended to the Statement is appended here in the same commit, and the
//! golden (`abi/tests/rendering_tests.rs`) is regenerated with it.
//!
//! THE OPTIONAL TAIL carries the kind facts a reader that must not open the plugin needs to judge
//! it as the same plugin compiled in is judged (Part 2 #2), one tagged field each, read by ONE
//! routine ([`read`]'s `optional_tail`) so the order is fixed in one place. Each field is canonical:
//! absent is the ONLY spelling of "nothing stated", so a rendering signed before a field existed is
//! byte-identical to its door's rendering today, and every Statement has exactly one signed byte
//! form. The reader refuses an unknown tag, a tag not above the one before it and a byte that is no
//! tag (at "the end"), and each field's own non-canonical body (at its name).
//!
//! `claim_flags`: a transport's claim-row `flags` (`abi::transport::CLAIM_SECURE`, BUSBAR-1.6.0.md
//! #50). Refused present on another kind, of another count than `claims`, all zero, or stating any
//! bit but `CLAIM_SECURE`.
//!
//! `auth`: an auth plugin's tail (`abi::auth::AuthTail`: capabilities, facts, login kind, inbound
//! points, operator principal, credential kinds and outbound styles), so the host selects and
//! judges a dropped auth plugin from its signed rendering without opening it (Law 7, as a linked one
//! is read off its door's Statement). Refused present on another kind, all empty, or stating an
//! unknown capability, fact or login kind, or a style `abi::auth::check_style_decl` refuses.

use super::call::{AbiStr, Blob};
use super::door::{MarkWord, MetricFamily, Rewrite, Section, Statement};
use super::MECHANISM_VERSION;
use crate::abi::host::conn::connector::Need;

/// The rendering's first eight bytes.
pub const RENDERING_MAGIC: &[u8; 8] = b"BBSTMT01";

/// THE OPTIONAL TAIL's tag of a transport's claim-row `flags` (module docs: the tagged fields after
/// `claims`, in strictly ascending tag order).
pub const TAIL_CLAIM_FLAGS: u32 = 1;

/// THE OPTIONAL TAIL's tag of an auth plugin's tail facts ([`ReadAuth`]).
pub const TAIL_AUTH: u32 = 2;

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
        let flags = claim_flags(st);
        if flags.iter().any(|f| *f != 0) {
            o.u32(TAIL_CLAIM_FLAGS);
            o.len(flags.len(), "claim_flags")?;
            for f in flags {
                o.u32(f);
            }
        }
        if let Some(t) = auth_tail(st) {
            o.u32(TAIL_AUTH);
            o.u32(t.caps);
            o.u32(t.facts);
            o.u32(t.login_kind);
            o.u32(t.inbound_points);
            o.str(t.operator_principal, "auth.operator_principal")?;
            let kinds = items(t.credential_kinds, t.credential_kinds_len);
            o.len(kinds.len(), "auth.credential_kinds")?;
            for k in kinds {
                o.str(*k, "auth.credential_kind")?;
            }
            let styles = items(t.styles, t.styles_len);
            o.len(styles.len(), "auth.styles")?;
            for s in styles {
                o.str(s.name, "auth.style.name")?;
                o.u32(s.flags);
                o.u32(s.points);
            }
        }
    }
    Ok(o.0)
}

/// A transport Statement's claim-row `flags`, row by row; empty for any other kind, or for a tail
/// too short to state its rows.
///
/// # Safety
///
/// As [`render`]: a non-NULL kind tail is live data of its stated size, and its row list points at
/// its stated count of live rows.
unsafe fn claim_flags(st: &Statement) -> Vec<u32> {
    use crate::abi::transport::{Claim, TransportTail};
    if st.kind != super::KindCode::Transport as u32 || st.kind_tail.is_null() {
        return Vec::new();
    }
    let covers =
        core::mem::offset_of!(TransportTail, claim_rows_len) + core::mem::size_of::<usize>();
    // SAFETY: the caller's contract (a non-NULL tail is live).
    let size = unsafe { (*st.kind_tail).size } as usize;
    if size < covers {
        return Vec::new();
    }
    // SAFETY: a transport's kind tail is a `TransportTail` of at least `covers` bytes (checked), and
    // the two fields read lie within them.
    let tail = st.kind_tail.cast::<TransportTail>();
    let (rows, len) = unsafe { ((*tail).claim_rows, (*tail).claim_rows_len) };
    // SAFETY: the caller's contract.
    let rows: &[Claim] = unsafe { items(rows, len) };
    rows.iter().map(|r| r.flags).collect()
}

/// An auth Statement's tail, as far as its stated size covers it (a field appended after the tail
/// froze reads empty on an older tail), when it states anything; `None` for any other kind, no
/// tail, or a tail stating nothing.
///
/// # Safety
///
/// As [`render`]: a non-NULL kind tail is live data of its stated size.
unsafe fn auth_tail(st: &Statement) -> Option<crate::abi::auth::AuthTail> {
    use crate::abi::auth::AuthTail;
    if st.kind != super::KindCode::Auth as u32 || st.kind_tail.is_null() {
        return None;
    }
    // SAFETY: the caller's contract (a non-NULL tail is live).
    let size = (unsafe { (*st.kind_tail).size } as usize).min(core::mem::size_of::<AuthTail>());
    if size < crate::abi::auth::AUTH_TAIL_FROZEN {
        return None;
    }
    // SAFETY: an all-zero `AuthTail` is valid (integers, NULL pointers, empty strings); the first
    // `size` bytes are the plugin's own tail, live and of at least that size.
    let mut t: AuthTail = unsafe { core::mem::zeroed() };
    unsafe {
        core::ptr::copy_nonoverlapping(
            st.kind_tail.cast::<u8>(),
            core::ptr::from_mut(&mut t).cast::<u8>(),
            size,
        );
    }
    let states = t.caps != 0
        || t.facts != 0
        || t.login_kind != 0
        || t.inbound_points != 0
        || t.operator_principal.len != 0
        || t.credential_kinds_len != 0
        || t.styles_len != 0;
    states.then_some(t)
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
    /// Each claim's row `flags` (`abi::transport::CLAIM_SECURE`), parallel to `claims`; every one
    /// `0` when the rendering states none.
    pub claim_flags: Vec<u32>,
    /// An auth plugin's tail facts; `None` when the rendering states none.
    pub auth: Option<ReadAuth>,
}

/// AN AUTH PLUGIN'S TAIL, read back ([`TAIL_AUTH`]): every fact `abi::auth::AuthTail` states.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReadAuth {
    /// `abi::auth::CAP_*`.
    pub caps: u32,
    /// `abi::auth::FACT_*`.
    pub facts: u32,
    /// `abi::auth::LOGIN_KIND_*`.
    pub login_kind: u32,
    /// The auth points `verify` needs inbound.
    pub inbound_points: u32,
    /// The operator principal; empty when none.
    pub operator_principal: String,
    /// The credential kinds `verify` reads.
    pub credential_kinds: Vec<String>,
    /// The outbound styles, in the tail's order.
    pub styles: Vec<ReadStyle>,
}

/// ONE OUTBOUND STYLE, read back: `abi::auth::StyleDecl`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReadStyle {
    /// The style name.
    pub name: String,
    /// `abi::auth::STYLE_*` and the list rank.
    pub flags: u32,
    /// Its auth points.
    pub points: u32,
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

/// The optional tail's fields, read back: each `None` when absent.
#[derive(Default)]
struct OptionalTail {
    claim_flags: Option<Vec<u32>>,
    auth: Option<ReadAuth>,
}

/// THE OPTIONAL TAIL (module docs), read to the end of `i`: each tagged field present, in strictly
/// ascending tag order, each body under its own canonical rules. A byte that is no tag, an unknown
/// tag, or a tag not above the one before it is refused at "the end"; nothing can trail the tail.
fn optional_tail(i: &mut In<'_>, kind: u32, claims: usize) -> Result<OptionalTail, Unreadable> {
    let mut tail = OptionalTail::default();
    let mut last = 0;
    while i.at < i.b.len() {
        let at = i.at;
        let end = Unreadable {
            at,
            what: "the end",
        };
        let tag = i.u32("the end").map_err(|_| end.clone())?;
        if tag <= last {
            return Err(end);
        }
        last = tag;
        match tag {
            TAIL_CLAIM_FLAGS => tail.claim_flags = Some(claim_flags_body(i, kind, claims, at)?),
            TAIL_AUTH => tail.auth = Some(auth_body(i, kind, at)?),
            _ => return Err(end),
        }
    }
    Ok(tail)
}

/// The `claim_flags` body: a list of one `u32` per claim, on a transport's Statement only, not all
/// zero, no bit but `CLAIM_SECURE`; refused at `at` (its tag) otherwise.
fn claim_flags_body(
    i: &mut In<'_>,
    kind: u32,
    claims: usize,
    at: usize,
) -> Result<Vec<u32>, Unreadable> {
    let refused = Unreadable {
        at,
        what: "claim_flags",
    };
    let n = i.count("claim_flags")?;
    let flags = (0..n)
        .map(|_| i.u32("claim_flags"))
        .collect::<Result<Vec<u32>, _>>()?;
    let secure = crate::abi::transport::CLAIM_SECURE;
    if kind != super::KindCode::Transport as u32
        || n != claims
        || flags.iter().all(|f| *f == 0)
        || flags.iter().any(|f| f & !secure != 0)
    {
        return Err(refused);
    }
    Ok(flags)
}

/// The `auth` body: an auth Statement's tail facts, not all empty, every capability, fact, login
/// kind and style one the contract knows; refused at `at` (its tag) otherwise.
fn auth_body(i: &mut In<'_>, kind: u32, at: usize) -> Result<ReadAuth, Unreadable> {
    use crate::abi::auth::{
        check_style_decl, CAP_INBOUND, CAP_LOGIN, CAP_OUTBOUND, FACT_CACHEABLE,
        FACT_DEFAULT_INBOUND_STYLE, FACT_INBOUND_ALL_HEADERS, FACT_INBOUND_NEEDS_BODY_HASH,
        FACT_OPERATOR, FACT_READS_CREDENTIALS, LOGIN_KIND_CREDENTIAL,
    };
    let refused = Unreadable { at, what: "auth" };
    let caps = i.u32("auth")?;
    let facts = i.u32("auth")?;
    let login_kind = i.u32("auth")?;
    let inbound_points = i.u32("auth")?;
    let operator_principal = i.str("auth")?;
    let credential_kinds = i.strs("auth")?;
    let n = i.count("auth")?;
    let mut styles = Vec::with_capacity(n);
    for _ in 0..n {
        styles.push(ReadStyle {
            name: i.str("auth")?,
            flags: i.u32("auth")?,
            points: i.u32("auth")?,
        });
    }
    let known_facts = FACT_CACHEABLE
        | FACT_INBOUND_NEEDS_BODY_HASH
        | FACT_INBOUND_ALL_HEADERS
        | FACT_OPERATOR
        | FACT_READS_CREDENTIALS
        | FACT_DEFAULT_INBOUND_STYLE;
    let read = ReadAuth {
        caps,
        facts,
        login_kind,
        inbound_points,
        operator_principal,
        credential_kinds,
        styles,
    };
    if kind != super::KindCode::Auth as u32
        || read == ReadAuth::default()
        || caps & !(CAP_INBOUND | CAP_LOGIN | CAP_OUTBOUND) != 0
        || facts & !known_facts != 0
        || login_kind > LOGIN_KIND_CREDENTIAL
        || read
            .styles
            .iter()
            .any(|s| check_style_decl(s.flags, s.points).is_err())
    {
        return Err(refused);
    }
    Ok(read)
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
    let tail = optional_tail(&mut i, kind, claims.len())?;
    let claim_flags = tail.claim_flags.unwrap_or_else(|| vec![0; claims.len()]);
    let auth = tail.auth;
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
        claim_flags,
        auth,
    })
}

#[cfg(test)]
#[path = "../tests/rendering_tests.rs"]
mod tests;
