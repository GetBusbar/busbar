// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

const MECHANISM_VERSION: u32 = crate::versions::MECHANISM.raw();

/// The rendering's first eight bytes.
pub const RENDERING_MAGIC: &[u8; 8] = b"BBSTMT04";

/// The rendering before common unit declarations were signed.
pub const RENDERING_MAGIC_WITHOUT_MEASUREMENTS: &[u8; 8] = b"BBSTMT03";

/// The rendering before a need's response-header retention policy was rendered: its signed facts
pub const RENDERING_MAGIC_WITHOUT_NEED_RETENTION: &[u8; 8] = b"BBSTMT02";

/// The first eight bytes of the rendering before the kind tail was rendered whole: a manifest that
pub const RENDERING_MAGIC_TAIL_SIZE_ONLY: &[u8; 8] = b"BBSTMT01";

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
    /// The response-header names kept under `KEEP_NAMED`, in declaration order.
    pub keep_response_headers: Vec<String>,
    /// Its establish and reply-wait bound, milliseconds; `0` = the host's default.
    pub timeout_ms: u64,
    /// The response-header retention policy, `KEEP_*`.
    pub keep_mode: u32,
    /// The response-header names denied under `KEEP_ALL_EXCEPT_DENIED`, in declaration order.
    pub deny_response_headers: Vec<String>,
}

/// One immutable common unit declaration, read from the signed rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadMeasurementClass {
    /// Raw class name.
    pub class: String,
    /// Unit family, never a price or attribution selector.
    pub family: String,
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
    /// Its kind tail's facts, as rendered (`rendering/tail.rs`; `read_auth_tail` reads an auth
    /// row's).
    pub kind_tail: Vec<u8>,
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
    /// Signed common raw unit declarations, bounded at 64.
    pub measurement_classes: Vec<ReadMeasurementClass>,
}

impl Read {
    /// Its reference-capable, not-secret settings paths: what its extensions state under
    pub fn reference_fields(&self) -> Result<Vec<String>, String> {
        crate::extensions::reference_fields(&self.extensions.bytes)
    }
}

/// Why a rendering could not be read back: the byte offset and what was expected there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable {
    /// Where.
    pub at: usize,
    /// What was expected.
    pub what: &'static str,
}

/// Shared bounded cursor for the contract's legacy kind-tail readers.
#[doc(hidden)]
pub struct In<'a> {
    pub b: &'a [u8],
    pub at: usize,
}

impl In<'_> {
    pub fn take(&mut self, n: usize, what: &'static str) -> Result<&[u8], Unreadable> {
        let err = Unreadable { at: self.at, what };
        let end = self.at.checked_add(n).ok_or(err.clone())?;
        let s = self.b.get(self.at..end).ok_or(err)?;
        self.at = end;
        Ok(s)
    }
    pub fn u8(&mut self, what: &'static str) -> Result<u8, Unreadable> {
        Ok(self.take(1, what)?[0])
    }
    pub fn u32(&mut self, what: &'static str) -> Result<u32, Unreadable> {
        let s = self.take(4, what)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    pub fn u64(&mut self, what: &'static str) -> Result<u64, Unreadable> {
        let s = self.take(8, what)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }
    pub fn count(&mut self, what: &'static str) -> Result<usize, Unreadable> {
        let at = self.at;
        let n = self.u32(what)? as usize;

        if n > self.b.len().saturating_sub(self.at) / 4 {
            return Err(Unreadable { at, what });
        }
        Ok(n)
    }
    pub fn bytes(&mut self, what: &'static str) -> Result<Vec<u8>, Unreadable> {
        let n = self.u32(what)? as usize;
        Ok(self.take(n, what)?.to_vec())
    }
    pub fn str(&mut self, what: &'static str) -> Result<String, Unreadable> {
        let at = self.at;
        String::from_utf8(self.bytes(what)?).map_err(|_| Unreadable { at, what })
    }
    pub fn blob(&mut self, what: &'static str) -> Result<ReadBlob, Unreadable> {
        Ok(ReadBlob {
            fmt: self.u32(what)?,
            flags: self.u32(what)?,
            bytes: self.bytes(what)?,
        })
    }
    pub fn strs(&mut self, what: &'static str) -> Result<Vec<String>, Unreadable> {
        let n = self.count(what)?;
        (0..n).map(|_| self.str(what)).collect()
    }
}

/// THE RENDERING READ BACK: the inverse of the contract's rendering writer, for a reader that must not open the plugin.
pub fn read(bytes: &[u8]) -> Result<Read, Unreadable> {
    let mut i = In { b: bytes, at: 0 };
    let magic = i.take(RENDERING_MAGIC.len(), "the magic")?;
    if magic == RENDERING_MAGIC_WITHOUT_MEASUREMENTS {
        return Err(Unreadable {
            at: 0,
            what: "a rendering with common measurement declarations; repack the plugin",
        });
    }
    if magic == RENDERING_MAGIC_WITHOUT_NEED_RETENTION {
        return Err(Unreadable {
            at: 0,
            what: "a rendering with need retention policy; repack the plugin",
        });
    }
    if magic == RENDERING_MAGIC_TAIL_SIZE_ONLY {
        return Err(Unreadable {
            at: 0,
            what: "a rendering with kind tail facts; repack the plugin",
        });
    }
    if magic != RENDERING_MAGIC {
        return Err(Unreadable {
            at: 0,
            what: "the magic",
        });
    }
    let mechanism_version = i.u32("mechanism")?;
    if mechanism_version != MECHANISM_VERSION {
        return Err(Unreadable {
            at: 8,
            what: "the current mechanism version; repack the plugin",
        });
    }
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
    let kind_tail = i.bytes("kind_tail_facts")?;
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
            keep_response_headers: i.strs("need.keep_response_headers")?,
            timeout_ms: i.u64("need.timeout_ms")?,
            keep_mode: i.u32("need.keep_mode")?,
            deny_response_headers: i.strs("need.deny_response_headers")?,
        });
    }
    let target_from = i.str("target_from")?;
    let trust_from = i.str("trust_from")?;
    let answers = i.strs("answers")?;
    let claims = i.strs("claims")?;
    let n = i.count("measurement_classes")?;
    if n > crate::measurement::MAX_MEASUREMENT_CLASSES {
        return Err(Unreadable {
            at: i.at,
            what: "at most 64 measurement classes",
        });
    }
    let mut measurement_classes = Vec::with_capacity(n);
    for _ in 0..n {
        let class = i.str("measurement_class.class")?;
        let family = i.str("measurement_class.family")?;
        if !crate::measurement::valid_name(class.as_bytes())
            || !crate::measurement::valid_name(family.as_bytes())
            || measurement_classes
                .iter()
                .any(|prior: &ReadMeasurementClass| prior.class == class)
        {
            return Err(Unreadable {
                at: i.at,
                what: "distinct valid measurement classes and families",
            });
        }
        measurement_classes.push(ReadMeasurementClass { class, family });
    }
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
        kind_tail,
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
        measurement_classes,
    })
}
