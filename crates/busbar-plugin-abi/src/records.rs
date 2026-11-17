// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The records codec: RecHead, generic tags, record Pods, the reader and the writers (IF §3, §3.1, §3.2).

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
use zeroize::Zeroize;

/// Round 8: the one bound for every record payload (replaces `bytemuck::Pod`; zerocopy is already in every lock,
/// §1). Blanket-implemented, so no type implements it by hand. Reads are `T::read_from_prefix` (a copy: no
/// alignment assumption about the body); writes are `v.as_bytes()`. `IntoBytes`'s derive refuses a struct with
/// padding at compile time (I7).
///
/// W1-A1: written out per record Pod below instead of the blanket impl the IF names. The kernel's A3 check
/// (R-CHECKS) fails a trait with exactly one production impl, and a blanket impl is one; the impls add no bound
/// (each is the supertraits, which the derives give), so the reads and writes are the IF's. `kind!` writes the
/// impl for each `pods {}` struct it declares.
pub trait Pod: FromBytes + IntoBytes + Immutable + KnownLayout + Copy {}

mechanism! {
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct RecHead {
    pub tag: u16,
    pub _r: u16,
    pub len: u32,
} // _r must be 0; else BadRecords

/// Generic tags 0x0000..=0x00FF (same meaning in every kind). Kind tags are 0x0100..=0x01FF:
/// 0x0100..=0x017F for call records and 0x0180..=0x01FF for describe items. A tag the reader does not know
/// for that kind and position is FAULT (UnknownTag). There are no extension keys.
pub mod tag {
    /// UTF-8 text; meaning set by the record before it.
    pub const TEXT: u16 = 0x0001;
    /// Body: Pod FailRec + UTF-8 detail (≤ `FAIL_TEXT_WIRE_MAX` = 3,072 bytes, cut at a char boundary by the
    /// shim only to fit the first buffer; round 15: core scrubs the whole detail and only then cuts it to the
    /// 512 bytes it shows, §12.16 `scrub::fail_text`). Exactly one with REFUSED/FAILED, first. Round 21: a
    /// FAILED answer may follow it with at most two FACT records whose keys are in `FAIL_FACT_KEYS`, each key
    /// at most once (the backend's own facts, §4.1 `Fail::with_fact`); any other record, or any FACT after a
    /// REFUSED FAIL, is FAULT BadRecords. Round 34 (PLUGIN-ERROR-CODES): the tail is FAIL, then at most one ERROR,
    /// then (FAILED only) at most two FACTs; REFUSED still carries no facts.
    pub const FAIL: u16 = 0x0002;
    /// Body: Pod TokenRec. Exactly one with NEED, and first in a session-opening answer (§8.6, §8.7).
    pub const TOKEN: u16 = 0x0003;
    /// Body: Pod NeedRec + argument bytes (§6.1).
    pub const NEED: u16 = 0x0004;
    /// Body: Pod NeedResRec + result bytes (§6.1). Host-written only.
    pub const NEED_RES: u16 = 0x0005;
    /// Body: Pod FactRec.
    pub const FACT: u16 = 0x0006;
    /// Body: Pod FactTextRec + UTF-8 value.
    pub const FACT_TEXT: u16 = 0x0007;
    /// Body: pair shape (PairRec + name + value). Headers by default.
    pub const PAIR: u16 = 0x0008;
    /// Body: Pod InstanceRec. Only in the final answer of an `open` chain.
    pub const INSTANCE: u16 = 0x0009;
    /// Round 31: 0x000A (round 5's MIGRATED, the answer of the withdrawn `migrate` method) is retired and never
    /// reused; core keeps no per-plugin version (§7.2). It is FAULT UnknownTag everywhere.
    /// Round 31: optional, only in the final answer of a non-DRY_RUN `open`, after INSTANCE, at most one: the
    /// instance's settings bag in its canonical shape when the bag `open` was given was an older shape (UTF-8
    /// JSON; `{"$secret": n}`/`{"$trust": n}` exactly where core put them, or moved, never invented: core maps
    /// them back to the operator's references). Absent = the bag is already canonical. Core writes it back
    /// without interpreting it (§7.2). Anywhere else: FAULT UnknownTag.
    pub const CONFIG: u16 = 0x000B;
    /// A fragment of **core's** config that this plugin's older settings used to hold (Pod CoreCfgRec + name +
    /// value). Core vocabulary only: core files it by `section` without knowing which plugin sent it (257b,
    /// §12.10). Round 31: only in a non-DRY_RUN `open`'s final answer, after a CONFIG (the bag it came out of);
    /// anywhere else FAULT UnknownTag.
    pub const CORE_CFG: u16 = 0x000C;
    /// Round 34 (PLUGIN-ERROR-CODES). Body: Pod U32Rec, the plugin's error number (D_ERRORS). Optional, at most
    /// one, directly after FAIL, with REFUSED or FAILED. Anywhere else FAULT UnknownTag. Display only: core never
    /// decides on it (§12.3 stays on `code` and facts); core renders it as `BUSBAR-<identity>-NNNN` (§11.2).
    pub const ERROR: u16 = 0x000D;
    /// HTTP-like head records, shared by plane and transport.
    pub const H_METHOD: u16 = 0x0020; // TEXT shape
    pub const H_PATH: u16 = 0x0021; // TEXT shape, path + query as received
    pub const H_AUTHORITY: u16 = 0x0022; // TEXT shape
    pub const H_SCHEME: u16 = 0x0023; // TEXT shape
    pub const H_STATUS: u16 = 0x0024; // Pod U32Rec
    /// Round 22, core-written only, last in a ROLE_CLIENT `emit(E_HEAD)` head (§8.7): H_BUDGET_NS = the request's
    /// remaining deadline in ns at the emit (≥ 1; absent = no deadline); H_BODY_LEN = the body's total length when
    /// core holds it before the head goes (absent = streamed). Anywhere else a plugin sees neither.
    pub const H_BUDGET_NS: u16 = 0x0025;
    pub const H_BODY_LEN: u16 = 0x0026; // Pod U64Rec each
    /// Dialect-neutral conversation, produced by planes and read by hooks (and the REWRITE a hook returns,
    /// consumed by the plane). UTF-8 JSON, exactly this shape (today's plane-llm `{messages, tools}` contract):
    /// `{"system": string?, "messages": [{"role": string, "content": string | array}], "tools": [object]?}`.
    pub const CONVERSATION: u16 = 0x0030;
    /// Verified identity, produced by auth and read by planes (PlaneReq.identity) and hooks. One ID_SUBJECT
    /// (text), then ID_GROUP* (text), then ID_CLAIM* (pair shape). Generic, so no kind reads another kind's tags.
    pub const ID_SUBJECT: u16 = 0x0050;
    pub const ID_GROUP: u16 = 0x0051;
    pub const ID_CLAIM: u16 = 0x0052;
    /// Describe items (only in a describe answer).
    pub const D_METHODS: u16 = 0x0040; // Pod MaskRec: method bits the host may call
    pub const D_FACTS: u16 = 0x0041; // Pod MaskRec: kind fact bits
    pub const D_SCHEMA: u16 = 0x0042; // UTF-8 JSON Schema of the config
    pub const D_MAX_OUT: u16 = 0x0043; // Pod U64Rec, clamped by core
    pub const D_CEILING: u16 = 0x0044; // Pod CeilingRec, clamped by core
    /// RFC 6901 JSON Pointer text, `*` = every array element: a config position holding a secret reference.
    /// Core's config binder (§12.7) rewrites that node to `{"$secret": n}` before `check`/`open`.
    pub const D_SECRET_PATH: u16 = 0x0045;
    /// Same, for a PEM trust anchor (operator CA). Rewritten to `{"$trust": n}`.
    pub const D_TRUST_PATH: u16 = 0x0046;
    /// Round 7. Same, for a file-sink destination (`{path, rotate_mb?, keep?}`, DEST grammar §12.7; `""` = the
    /// whole bag). Rewritten to `{"$dest": n}`; only an export instance may declare it (else DescribeInvalid).
    pub const D_DEST_PATH: u16 = 0x0048;
    /// Round 13. Same, for a **reference-capable plain value** (a store path or URL, a collector or webhook URL):
    /// the operator may write the plain value or a secret reference (`{env: X}`, a declared shorthand, a
    /// SourceReference); core resolves a reference through custody to plaintext and writes that JSON string at
    /// the node **before** `check`/`open` (§12.7 `resolve_refs`). The plugin always sees a plain string.
    pub const D_REF_PATH: u16 = 0x0049;
    /// Round 14. A config position where core writes its own top-level `public_url` (the gateway's externally
    /// visible base URL, busbar-kernel config/mod.rs:354-358) as a JSON string, or JSON `null` when the operator
    /// set none, **before** D_SCHEMA validation, `check` and `open` (§12.7 core values). Only a plane may declare it
    /// (else DescribeInvalid), at most once; the operator may not write that position in the plane's bag (CONFIG,
    /// core text: "`<kind>.<name><pointer>` is core's `public_url`; set the top-level `public_url`"). A change of
    /// core's `public_url` reopens (R6) every plane instance whose image declares it. Generic core value, no
    /// plugin identity (I2).
    pub const D_PUBLIC_URL_PATH: u16 = 0x004A;
    /// Round 22. A config position where core writes, as a JSON array of strings (possibly empty), the names of
    /// the configured upstreams whose outbound binding core resolved to the caller's own connection (§12.18
    /// "credential mode": the binding's style declared `auth::STYLE_CALLER`), sorted, **before** D_SCHEMA
    /// validation, `check` and `open`, exactly as D_PUBLIC_URL_PATH (plane only, at most once, the operator may
    /// not write it, a change reopens every declaring plane instance, R6). Operator vocabulary only: upstream
    /// names, never a style, a plugin or a mode word (I2, 236).
    pub const D_CALLER_UPSTREAMS_PATH: u16 = 0x004B;
    /// Round 34 (PLUGIN-ERROR-CODES). The plugin's own error numbers, u16 little-endian, strictly ascending,
    /// 1..=256 of them, each 1..=9999. At most one. Any kind. Core renders a number n of this image as
    /// BUSBAR-<identity>-<n as 4 digits> (§11.2 `ErrorBook`). A bad list drops that image's codes; the image is
    /// still admitted (never DescribeInvalid for this item's content).
pub const D_ERRORS: u16 = 0x004C;
/// RFC 6901 pointer to this plane's registrations. Final decoded token is `*` (object members),
/// with no earlier wildcard. Plane only, at most four; duplicates and ancestor overlap refuse describe.
/// Core consumes url, command, tls, auth, upstream_credentials and allow_private at each member before
/// schema/check/open. Other path declarations may name plugin-owned siblings, never consumed core fields.
/// Absence declares no registration upstreams. No ABI layout or version change.
pub const D_UPSTREAM_PATH: u16 = 0x004D;
    /// Describe: one metric this plugin may report (Pod MetricDecl; tail = nested TEXT name, TEXT help,
    /// TEXT label key*). Any kind may declare metrics; core owns the series, retention and exposition (§12.17).
    pub const D_METRIC: u16 = 0x0047;
    /// Answer: one metric observation (Pod MetricObs; tail = nested PAIR* label values, keys as declared).
    /// Allowed in any OK answer of any kind. Undeclared ids are dropped and audited `plugin_metric_undeclared`.
    pub const METRIC: u16 = 0x0060;
    /// Atomic record commit (§12.5): nested REC_PRED* then REC_PUT*/REC_DEL*, all applied or none.
    /// Body of the plane COMMIT record (after CommitRec) and of a RECORD(REC_COMMIT) Need's arg0.
    pub const REC_PRED: u16 = 0x0068; // Pod RecPredRec + key + expected value (PRED_EQUALS only)
    pub const REC_PUT: u16 = 0x0069; // Pod RecPutRec + key + value
    pub const REC_DEL: u16 = 0x006A; // Pod RecDelRec + key
    /// Round 32 (TRANSPORT-SECURITY-POLICY §2): `check`'s answer, zero or more: Pod EndpointRec + the dest as
    /// tail (`host:port`, `unix:/abs`, or the FETCH URL). At most 16, dest ≤ 2,048 bytes; anything else INVALID.
    pub const ENDPOINT: u16 = 0x0075;
}
/// Round 32: op = need op::OPEN | op::FETCH; flags = NeedRec.flags' encoding unchanged (TLS_* bits 0..=3, egress
/// bits 16..=19); 0x200 stays retired (INVALID).
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct EndpointRec {
    pub op: u32,
    pub flags: u32,
}

/// JSON Schemas a plugin embeds in its D_SCHEMA at every D_SECRET_PATH / D_TRUST_PATH position.
pub const SECRET_SCHEMA: &str = r#"{"type":"object","required":["$secret"],"properties":{"$secret":{"type":"integer","minimum":1,"maximum":65535}},"additionalProperties":false}"#;
pub const TRUST_SCHEMA: &str = r#"{"type":"object","required":["$trust"],"properties":{"$trust":{"type":"integer","minimum":1,"maximum":65535}},"additionalProperties":false}"#;
pub const DEST_SCHEMA: &str = r#"{"type":"object","required":["$dest"],"properties":{"$dest":{"type":"integer","minimum":1,"maximum":65535}},"additionalProperties":false}"#;

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FailRec {
    pub status: u32,
    pub code: u32,
}
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct TokenRec {
    pub token: u64,
}
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FactRec {
    pub key: u32,
    pub _r: u32,
    pub value: u64,
}
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FactTextRec {
    pub key: u32,
    pub _r: u32,
}
/// Pair shape: PairRec, then `name_len` bytes of name, then the value (the rest of the body).
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct PairRec {
    pub name_len: u32,
    pub _r: u32,
}
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct InstanceRec {
    pub inst: u64,
} // opaque; the host stores it and never dereferences it
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct U32Rec {
    pub value: u32,
    pub _r: u32,
}
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct U64Rec {
    pub value: u64,
}
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct MaskRec {
    pub mask: u64,
}
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
/// method = exactly one M_ bit of the kind (the ceiling of a sync call of it, and of the first poll of an async
/// chain of it, both watched under the method's index), or `CEIL_OPEN` (the first poll of the `open` chain,
/// watched under ENTRY_OPEN; round 31: it covers the plugin's own migration too, §7.2). Resumes are
/// ENTRY_RESUME's (§10.6).
/// micros is clamped by core into the §10.6 range for that entry (round 11); any other method value is
/// DescribeInvalid.
pub struct CeilingRec {
    pub method: u64,
    pub micros: u64,
}
/// Round 11: CeilingRec.method values naming the cold chains (bits outside every kind's 0..=55 method bits).
pub const CEIL_OPEN: u64 = 1 << 57; /* round 31: 1 << 61 (CEIL_MIGRATE) retired, never reused: DescribeInvalid */
/// kind = MX_COUNTER | MX_GAUGE | MX_SUMMARY. `id` is the plugin's own number (unique per describe), echoed
/// by MetricObs. Name `[a-z_][a-z0-9_]{0,63}`, ≤ 8 label keys; core refuses anything else (DescribeInvalid).
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct MetricDecl {
    pub id: u32,
    pub kind: u32,
}
/// op = MX_ADD (counter, value ≥ 0), MX_SET (gauge), MX_OBSERVE (summary sample). value is finite, else dropped.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct MetricObs {
    pub id: u32,
    pub op: u32,
    pub value: f64,
}
/// flags = PRED_ABSENT | PRED_PRESENT | PRED_EQUALS, plus REC_CALLER (key in the request subject's scope,
/// plane only). Tail = key (key_len), then the expected value (PRED_EQUALS).
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct RecPredRec {
    pub flags: u32,
    pub key_len: u32,
}
/// flags = REC_CALLER?. ttl_s 0 = no expiry (round 12; a non-zero value is clamped to core's records maximum,
/// §12.5). Tail = key (key_len), then value.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct RecPutRec {
    pub flags: u32,
    pub key_len: u32,
    pub ttl_s: u64,
}
/// flags = REC_CALLER?. Tail = key.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct RecDelRec {
    pub flags: u32,
    pub _r: u32,
}
/// Round 31: `MigratedRec` is deleted with MIGRATED (0x000A retired).
/// section = core_cfg::*. Tail = name (name_len bytes, `[a-z0-9_.-]{1,64}`), then the value: UTF-8 JSON in the
/// exact grammar of that core config section (secret positions as `{"$secret": n}` from the bag).
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct CoreCfgRec {
    pub section: u32,
    pub name_len: u32,
}
/// The only core config a plugin's `open` may hand back (round 31; each is a section core already owns, §12.10):
/// UPSTREAM = `upstreams.<name>` (§12.1 UpstreamDef: url, tls pins, client identity, stdio command; round 21:
/// `auth`, an auth instance name or one of the core-vocabulary forms `bearer`/`api_key`/`token_exchange`/
/// `connection` of §12.18, never a style word or a plugin's settings key);
/// TRUST_APPROVAL = `trust.<this instance>.<name>` (§12.14: name = the configured upstream; value = authenticity
/// root and per-item `sha256:` digests); ROUTE_MEDIA = `routes.<name>.media` (§12.13: name = the D_ROUTE id as
/// decimal text). Core prefixes nothing the plugin chose except where stated ("this instance" is core's).
/// Round 8: LIMITS = this instance's core-owned `limits` object (§12.22; name = empty: always the migrating
/// instance itself), where a 1.x bag's timeout, concurrency and plaintext settings go. Round 12: 5 (round 8's
/// RETIRE) is retired and never reused; core refuses it CONFIG like any unknown section (§8.7, §12.10).
/// Round 18: 6 (round 11's ALLOW_DEST) is retired and never reused; core refuses it CONFIG like any unknown
/// section. The hosts it carried (`base_url`/`token_url` of 1.5.5 providers) are core's own provider config
/// (§8.6 provider keys), so K9 computes and judges them itself (§12.10 item 3); no plugin states them.
/// Round 13 (MIGRATE-ON-BOOT r16 item (i)): LIFT = "the slot at this JSON Pointer of the CONFIG bag I answered
/// holds a 1.x literal secret" (name = empty; value = one JSON string, the RFC 6901 pointer into that CONFIG,
/// matching one of this image's D_SECRET_PATH pointers). Core writes the slot's exact UTF-8 bytes to a 0600
/// private secret file at r6 §3 step 5a and replaces the slot with a reference to it, the same lift core applies
/// to its own literal credentials (today's migrate_plugins.rs:655-701). Any kind, any count; the value never
/// enters a report.
pub mod core_cfg {
    pub const UPSTREAM: u32 = 1;
    pub const TRUST_APPROVAL: u32 = 2;
    pub const ROUTE_MEDIA: u32 = 3;
    pub const LIMITS: u32 = 4; /* 5 retired (r12), 6 retired (r18) */
    pub const LIFT: u32 = 7;
}
pub mod metric {
    pub const MX_COUNTER: u32 = 1;
    pub const MX_GAUGE: u32 = 2;
    pub const MX_SUMMARY: u32 = 3;
    pub const MX_ADD: u32 = 1;
    pub const MX_SET: u32 = 2;
    pub const MX_OBSERVE: u32 = 3;
}
/// A commit holds at most 64 records (predicates + mutations); more is REFUSED R_INVALID by core.
pub mod commit {
    pub const PRED_ABSENT: u32 = 1;
    pub const PRED_PRESENT: u32 = 2;
    pub const PRED_EQUALS: u32 = 3;
    pub const PRED_MASK: u32 = 0xF;
    pub const REC_CALLER: u32 = 0x100;
    pub const MAX_OPS: u32 = 64;
    /// Commit outcomes (NeedResRec.a, plane CommittedRec.outcome).
    pub const APPLIED: u32 = 1;
    pub const CONFLICT: u32 = 2;
}
}

impl Pod for RecHead {}
impl Pod for EndpointRec {}
impl Pod for FailRec {}
impl Pod for TokenRec {}
impl Pod for FactRec {}
impl Pod for FactTextRec {}
impl Pod for PairRec {}
impl Pod for InstanceRec {}
impl Pod for U32Rec {}
impl Pod for U64Rec {}
impl Pod for MaskRec {}
impl Pod for CeilingRec {}
impl Pod for MetricDecl {}
impl Pod for MetricObs {}
impl Pod for RecPredRec {}
impl Pod for RecPutRec {}
impl Pod for RecDelRec {}
impl Pod for CoreCfgRec {}
impl Pod for crate::need::NeedRec {}
impl Pod for crate::need::NeedResRec {}
impl Pod for crate::need::DirFacts {}
impl Pod for crate::versions::EngineVersion {}

// Round 31 (IF §7.2, §7.6): `abi::settled` is two plain functions a plugin's `Open::settled` calls to write
// its canonical settings (CONFIG) and the core config fragments its older settings held (CORE_CFG). The IF
// names them `config(w, bag: &[u8])` and `core_cfg(w, section, name, value_json: &[u8])` without spelling `w`;
// it is the `&mut Out<'_>` that `Open::settled` receives.
pub mod settled {
    use zerocopy::IntoBytes;

    use super::{CoreCfgRec, Full, Out, put_parts, tag};

    /// One CONFIG record: the instance's settings bag in its canonical shape (UTF-8 JSON).
    pub fn config(w: &mut Out<'_>, bag: &[u8]) -> Result<(), Full> {
        put_parts(w, tag::CONFIG, &[bag])
    }
    /// One CORE_CFG record: `section` (`core_cfg::*`), the name and the value in that section's grammar.
    pub fn core_cfg(
        w: &mut Out<'_>,
        section: u32,
        name: &str,
        value_json: &[u8],
    ) -> Result<(), Full> {
        let head = CoreCfgRec {
            section,
            name_len: u32::try_from(name.len()).map_err(|_| Full)?,
        };
        put_parts(
            w,
            tag::CORE_CFG,
            &[head.as_bytes(), name.as_bytes(), value_json],
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecErr {
    Truncated,
    Reserved,
    Size,
    Utf8,
    Unknown(u16),
}

/// Every record starts on a multiple of this, relative to the buffer it is read from.
const ALIGN: usize = 8;
/// The record head: tag, reserved, body length.
const HEAD: usize = size_of::<RecHead>();
/// The bytes a record's padding comes from.
const ZEROS: [u8; ALIGN] = [0; ALIGN];
/// The Reply cap (§3.2).
const REPLY_CAP: usize = 16 << 20;
/// The smallest block a growing Reply allocates (§3.2).
const REPLY_MIN: usize = 256;

/// The bytes one record takes: head, `len` body bytes, zero padding to the next multiple of 8.
pub const fn record_size(len: usize) -> Option<usize> {
    match HEAD.checked_add(len) {
        Some(n) => match n.checked_add(ALIGN - 1) {
            Some(n) => Some(n & !(ALIGN - 1)),
            None => None,
        },
        None => None,
    }
}

#[derive(Clone, Copy)]
pub struct Records<'a> {
    bytes: &'a [u8],
    at: usize,
    fused: bool,
}
impl<'a> Records<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Records {
            bytes,
            at: 0,
            fused: false,
        }
    }
    /// The bytes not yet read, from the next record on. W1-A5: `decode_settled` hands the CORE_CFG tail of an
    /// answer on as `Records` over the answer's own bytes.
    pub fn rest(&self) -> &'a [u8] {
        self.bytes.get(self.at..).unwrap_or_default()
    }
    /// Bounds-checked iteration. After the first Err the iterator is fused.
    ///
    /// Framing only: `_r` must be 0 (else Reserved); the head, the body and its zero padding must lie inside the
    /// bytes (else Truncated; non-zero padding is Reserved). The tag is handed through as written: whether it is
    /// known for that kind and position is the decoder's question (FAULT UnknownTag, §3).
    pub fn next_rec(&mut self) -> Option<Result<Rec<'a>, RecErr>> {
        if self.fused || self.at >= self.bytes.len() {
            return None;
        }
        match Self::split(&self.bytes[self.at..]) {
            Ok((rec, used)) => {
                self.at += used;
                Some(Ok(rec))
            }
            Err(e) => {
                self.fused = true;
                Some(Err(e))
            }
        }
    }
    /// The first record of `rest` and the bytes it takes, padding included.
    fn split(rest: &'a [u8]) -> Result<(Rec<'a>, usize), RecErr> {
        let (head, _) = RecHead::read_from_prefix(rest).map_err(|_| RecErr::Truncated)?;
        if head._r != 0 {
            return Err(RecErr::Reserved);
        }
        let len = usize::try_from(head.len).map_err(|_| RecErr::Truncated)?;
        let size = record_size(len).ok_or(RecErr::Truncated)?;
        let record = rest.get(..size).ok_or(RecErr::Truncated)?;
        let (body, padding) = record[HEAD..].split_at(len);
        if padding.iter().any(|&byte| byte != 0) {
            return Err(RecErr::Reserved);
        }
        Ok((
            Rec {
                tag: head.tag,
                body,
            },
            size,
        ))
    }
}
impl<'a> Iterator for Records<'a> {
    type Item = Result<Rec<'a>, RecErr>;
    fn next(&mut self) -> Option<Self::Item> {
        self.next_rec()
    }
}

#[derive(Clone, Copy)]
pub struct Rec<'a> {
    pub tag: u16,
    pub body: &'a [u8],
}
impl<'a> Rec<'a> {
    /// Body must be exactly size_of::<T>(). Copies (try_pod_read_unaligned), so alignment never matters.
    pub fn pod<T: Pod>(&self) -> Result<T, RecErr> {
        T::read_from_bytes(self.body).map_err(|_| RecErr::Size)
    }
    /// Body is T followed by a tail.
    pub fn pod_tail<T: Pod>(&self) -> Result<(T, &'a [u8]), RecErr> {
        T::read_from_prefix(self.body).map_err(|_| RecErr::Size)
    }
    pub fn text(&self) -> Result<&'a str, RecErr> {
        core::str::from_utf8(self.body).map_err(|_| RecErr::Utf8)
    }
    /// Pair shape.
    pub fn pair(&self) -> Result<(&'a str, &'a [u8]), RecErr> {
        let (head, tail) = self.pod_tail::<PairRec>()?;
        if head._r != 0 {
            return Err(RecErr::Reserved);
        }
        let name_len = usize::try_from(head.name_len).map_err(|_| RecErr::Size)?;
        let (name, value) = tail.split_at_checked(name_len).ok_or(RecErr::Size)?;
        let name = core::str::from_utf8(name).map_err(|_| RecErr::Utf8)?;
        Ok((name, value))
    }
    /// The body read as nested records.
    pub fn nested(&self) -> Records<'a> {
        Records::new(self.body)
    }
}

/// Over max_out (Out) or over the Reply cap (16 MiB). Converts to Fail::failed(F_LIMIT). On a sync method's
/// Err the shim zeroes `[0, out.len)` (the bytes the method wrote: O(bytes written), I11) and then discards them
/// (`out.len = 0`) before it writes the one FAIL record (and, round 21, the Fail's ≤ 2 facts), and
/// every OutBuf an entry receives has ≥ 4 KiB capacity before any grow, so FAIL (≤ 3,096 bytes: record head,
/// FailRec and ≤ 3,072 bytes of detail, round 15) plus two FACT records (48 bytes) always fits
/// without `grow` and is never refused by max_out (§6.4 step 2, §10.1).
#[derive(Clone, Copy, Debug)]
pub struct Full;

pub trait Writer {
    fn put(&mut self, tag: u16, body: &[u8]) -> Result<(), Full>;
    /// One atomic record from borrowed body segments, without collecting or copying them first.
    fn put_parts(&mut self, tag: u16, parts: &[&[u8]]) -> Result<(), Full>;
    /// A POD prefix followed by nested records. Full wipes and rolls back the whole outer record.
    fn put_pod_nested<T: Pod>(
        &mut self,
        tag: u16,
        prefix: &T,
        fill: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
    ) -> Result<(), Full>;

    /// One flat body of little-endian u32 words. Any failed push, caller error or unwind
    /// rolls back this record, including when `fill` ignores a failed push.
    fn put_u32s(
        &mut self,
        tag: u16,
        fill: impl FnOnce(&mut U32s<'_>) -> Result<(), Full>,
    ) -> Result<(), Full>;
    fn put_pod<T: Pod>(&mut self, tag: u16, v: &T) -> Result<(), Full>;
    fn put_pod_tail<T: Pod>(&mut self, tag: u16, v: &T, tail: &[u8]) -> Result<(), Full>;
    fn put_text(&mut self, tag: u16, s: &str) -> Result<(), Full>;
    fn put_pair(&mut self, tag: u16, name: &str, value: &[u8]) -> Result<(), Full>;
    fn put_fact(&mut self, key: u32, value: u64) -> Result<(), Full>;
    fn put_fact_text(&mut self, key: u32, value: &str) -> Result<(), Full>;
    /// One METRIC observation (generic, §3): `labels` are values for the declared label keys, in order.
    /// W1-A1: each label value is one nested PAIR with an empty name (the key is the declared one at that
    /// position).
    fn put_metric(&mut self, id: u32, op: u32, value: f64, labels: &[&str]) -> Result<(), Full>;
    /// Writes a record whose body is nested records. The head's len is back-patched.
    fn put_nested(
        &mut self,
        tag: u16,
        f: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
    ) -> Result<(), Full>;
}

/// The byte sink under every `Writer`: `Out` (the host buffer), `Reply` (an owned block) and the host's pooled
/// buffer. A record is written as `room` for all of it, then `append`s; a write that fails leaves nothing
/// (`truncate` zeroes what a half-written record left, I11).
pub(crate) trait RawWrite {
    /// Bytes written so far.
    fn written(&self) -> usize;
    /// Room for `need` more bytes after `written`, or Full with nothing changed.
    fn room(&mut self, need: usize) -> Result<(), Full>;
    /// Appends `bytes` inside the room the last `room` made.
    fn append(&mut self, bytes: &[u8]);
    /// Overwrites already written bytes at `at`.
    fn patch(&mut self, at: usize, bytes: &[u8]);
    /// Zeroes `[len, written)` and makes `len` the end.
    fn truncate(&mut self, len: usize);
}

/// The flat word body of one record. A failed push poisons the enclosing write.
pub struct U32s<'a> {
    w: &'a mut dyn RawWrite,
    body: &'a mut usize,
    failed: &'a mut bool,
}

impl U32s<'_> {
    pub fn push(&mut self, value: u32) -> Result<(), Full> {
        if *self.failed {
            return Err(Full);
        }
        let next = self
            .body
            .checked_add(4)
            .filter(|&len| u32::try_from(len).is_ok());
        let Some(next) = next else {
            *self.failed = true;
            return Err(Full);
        };
        if self.w.room(4).is_err() {
            *self.failed = true;
            return Err(Full);
        }
        self.w.append(&value.to_le_bytes());
        *self.body = next;
        Ok(())
    }
}

/// Lives outside the user callback, so dropping or forgetting its U32s borrow cannot commit.
struct WordRecord<'a> {
    w: &'a mut dyn RawWrite,
    start: usize,
    committed: bool,
}

impl Drop for WordRecord<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.w.truncate(self.start);
        }
    }
}

pub(crate) fn put_u32s_in(
    w: &mut dyn RawWrite,
    tag: u16,
    fill: impl FnOnce(&mut U32s<'_>) -> Result<(), Full>,
) -> Result<(), Full> {
    let start = w.written();
    let patch_at = start
        .checked_add(core::mem::offset_of!(RecHead, len))
        .ok_or(Full)?;
    start.checked_add(HEAD).ok_or(Full)?;
    w.room(HEAD)?;
    let mut record = WordRecord {
        w,
        start,
        committed: false,
    };
    record.w.append(RecHead { tag, _r: 0, len: 0 }.as_bytes());
    let mut body = 0;
    let mut failed = false;
    fill(&mut U32s {
        w: &mut *record.w,
        body: &mut body,
        failed: &mut failed,
    })?;
    if failed {
        return Err(Full);
    }
    let len = u32::try_from(body).map_err(|_| Full)?;
    let size = record_size(body).ok_or(Full)?;
    start.checked_add(size).ok_or(Full)?;
    let padding = size - HEAD - body;
    record.w.room(padding)?;
    record.w.append(&ZEROS[..padding]);
    record.w.patch(patch_at, len.as_bytes());
    record.committed = true;
    Ok(())
}

/// One whole record from `parts` (the body, back to back), or Full with nothing written.
pub(crate) fn put_parts<W: RawWrite + ?Sized>(
    w: &mut W,
    tag: u16,
    parts: &[&[u8]],
) -> Result<(), Full> {
    put_parts_iter(w, tag, parts.iter().copied())
}

pub(crate) fn put_parts_iter<'a, W: RawWrite + ?Sized>(
    w: &mut W,
    tag: u16,
    parts: impl Iterator<Item = &'a [u8]> + Clone,
) -> Result<(), Full> {
    let len = parts
        .clone()
        .try_fold(0usize, |len, part| len.checked_add(part.len()))
        .ok_or(Full)?;
    let head = RecHead {
        tag,
        _r: 0,
        len: u32::try_from(len).map_err(|_| Full)?,
    };
    let size = record_size(len).ok_or(Full)?;
    w.room(size)?;
    w.append(head.as_bytes());
    for part in parts {
        w.append(part);
    }
    w.append(&ZEROS[..size - HEAD - len]);
    Ok(())
}

/// Starts a record whose body is `fixed` and then whatever the caller appends; `close_record` back-patches the
/// length. Returns the record's start.
fn open_record<W: RawWrite + ?Sized>(w: &mut W, tag: u16, fixed: &[u8]) -> Result<usize, Full> {
    let start = w.written();
    w.room(HEAD.checked_add(fixed.len()).ok_or(Full)?)?;
    w.append(RecHead { tag, _r: 0, len: 0 }.as_bytes());
    w.append(fixed);
    Ok(start)
}

/// Pads the record opened at `start` and writes its length into its head.
fn close_record<W: RawWrite + ?Sized>(w: &mut W, start: usize) -> Result<(), Full> {
    let len = w.written() - start - HEAD;
    let len32 = u32::try_from(len).map_err(|_| Full)?;
    let padding = record_size(len).ok_or(Full)? - HEAD - len;
    w.room(padding)?;
    w.append(&ZEROS[..padding]);
    w.patch(
        start + core::mem::offset_of!(RecHead, len),
        len32.as_bytes(),
    );
    Ok(())
}

/// One nested record: `f` writes its body in place through a `Nested` over `w`; on Full nothing is left (the
/// half-written record is truncated, which zeroes it). The host's `PooledOut` writes through this too (IF §10.1).
pub(crate) fn put_nested_in(
    w: &mut dyn RawWrite,
    tag: u16,
    f: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
) -> Result<(), Full> {
    put_prefixed_nested_in(w, tag, &[], f)
}

pub(crate) fn put_prefixed_nested_in(
    w: &mut dyn RawWrite,
    tag: u16,
    prefix: &[u8],
    f: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
) -> Result<(), Full> {
    let start = open_record(w, tag, prefix)?;
    let filled = f(&mut Nested { w: &mut *w });
    let done = filled.and_then(|()| close_record(w, start));
    if done.is_err() {
        w.truncate(start);
    }
    done
}

pub(crate) fn put_pair_in<W: RawWrite + ?Sized>(
    w: &mut W,
    tag: u16,
    name: &str,
    value: &[u8],
) -> Result<(), Full> {
    let head = PairRec {
        name_len: u32::try_from(name.len()).map_err(|_| Full)?,
        _r: 0,
    };
    put_parts(w, tag, &[head.as_bytes(), name.as_bytes(), value])
}

pub(crate) fn put_fact_in<W: RawWrite + ?Sized>(
    w: &mut W,
    key: u32,
    value: u64,
) -> Result<(), Full> {
    put_parts(w, tag::FACT, &[FactRec { key, _r: 0, value }.as_bytes()])
}

pub(crate) fn put_fact_text_in<W: RawWrite + ?Sized>(
    w: &mut W,
    key: u32,
    value: &str,
) -> Result<(), Full> {
    put_parts(
        w,
        tag::FACT_TEXT,
        &[FactTextRec { key, _r: 0 }.as_bytes(), value.as_bytes()],
    )
}

pub(crate) fn put_metric_in<W: RawWrite + ?Sized>(
    w: &mut W,
    id: u32,
    op: u32,
    value: f64,
    labels: &[&str],
) -> Result<(), Full> {
    let obs = MetricObs { id, op, value };
    let start = open_record(w, tag::METRIC, obs.as_bytes())?;
    let filled = labels
        .iter()
        .try_for_each(|label| put_pair_in(w, tag::PAIR, "", label.as_bytes()));
    let done = filled.and_then(|()| close_record(w, start));
    if done.is_err() {
        w.truncate(start);
    }
    done
}

/// A writer into the enclosing record's body. Implements Writer.
pub struct Nested<'w> {
    w: &'w mut dyn RawWrite,
}
impl Writer for Nested<'_> {
    fn put_parts(&mut self, tag: u16, parts: &[&[u8]]) -> Result<(), Full> {
        put_parts(self.w, tag, parts)
    }
    fn put_pod_nested<T: Pod>(
        &mut self,
        tag: u16,
        prefix: &T,
        fill: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
    ) -> Result<(), Full> {
        put_prefixed_nested_in(self.w, tag, prefix.as_bytes(), fill)
    }
    fn put(&mut self, tag: u16, body: &[u8]) -> Result<(), Full> {
        put_parts(self.w, tag, &[body])
    }
    fn put_u32s(
        &mut self,
        tag: u16,
        fill: impl FnOnce(&mut U32s<'_>) -> Result<(), Full>,
    ) -> Result<(), Full> {
        put_u32s_in(self.w, tag, fill)
    }
    fn put_pod<T: Pod>(&mut self, tag: u16, v: &T) -> Result<(), Full> {
        put_parts(self.w, tag, &[v.as_bytes()])
    }
    fn put_pod_tail<T: Pod>(&mut self, tag: u16, v: &T, tail: &[u8]) -> Result<(), Full> {
        put_parts(self.w, tag, &[v.as_bytes(), tail])
    }
    fn put_text(&mut self, tag: u16, s: &str) -> Result<(), Full> {
        put_parts(self.w, tag, &[s.as_bytes()])
    }
    fn put_pair(&mut self, tag: u16, name: &str, value: &[u8]) -> Result<(), Full> {
        put_pair_in(self.w, tag, name, value)
    }
    fn put_fact(&mut self, key: u32, value: u64) -> Result<(), Full> {
        put_fact_in(self.w, key, value)
    }
    fn put_fact_text(&mut self, key: u32, value: &str) -> Result<(), Full> {
        put_fact_text_in(self.w, key, value)
    }
    fn put_metric(&mut self, id: u32, op: u32, value: f64, labels: &[&str]) -> Result<(), Full> {
        put_metric_in(self.w, id, op, value, labels)
    }
    fn put_nested(
        &mut self,
        tag: u16,
        f: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
    ) -> Result<(), Full> {
        put_nested_in(&mut *self.w, tag, f)
    }
}

/// Sync-method output: writes straight into the host buffer, growing it through Host::grow (r4 H2). The write
/// view, the raw channel and the grow call are busbar-ffi's `Out` (UNSAFE-MIN r3.1); this wraps it 1:1 so the
/// records codec stays the safe `Writer` over four sink operations. The shims mint it from the ffi `Out` they are
/// handed (`From`); a plugin never builds one.
pub struct Out<'a> {
    sink: busbar_ffi::Out<'a>,
}
impl<'a> From<busbar_ffi::Out<'a>> for Out<'a> {
    fn from(sink: busbar_ffi::Out<'a>) -> Self {
        Out { sink }
    }
}
impl RawWrite for Out<'_> {
    fn written(&self) -> usize {
        self.sink.written()
    }
    fn room(&mut self, need: usize) -> Result<(), Full> {
        if self.sink.room(need) {
            Ok(())
        } else {
            Err(Full)
        }
    }
    fn append(&mut self, bytes: &[u8]) {
        // `put_parts` made `room` for the whole record first, so the append fits; a false is a host that
        // shrank its buffer mid-entry, which the debug build refuses.
        let appended = self.sink.append(bytes);
        debug_assert!(appended, "append inside the room the last `room` made");
    }
    fn patch(&mut self, at: usize, bytes: &[u8]) {
        let patched = self.sink.patch(at, bytes);
        debug_assert!(patched, "patch inside what was written");
    }
    fn truncate(&mut self, len: usize) {
        self.sink.truncate(len);
    }
}
impl Writer for Out<'_> {
    fn put_parts(&mut self, tag: u16, parts: &[&[u8]]) -> Result<(), Full> {
        put_parts(self, tag, parts)
    }
    fn put_pod_nested<T: Pod>(
        &mut self,
        tag: u16,
        prefix: &T,
        fill: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
    ) -> Result<(), Full> {
        put_prefixed_nested_in(self, tag, prefix.as_bytes(), fill)
    }
    fn put(&mut self, tag: u16, body: &[u8]) -> Result<(), Full> {
        put_parts(self, tag, &[body])
    }
    fn put_u32s(
        &mut self,
        tag: u16,
        fill: impl FnOnce(&mut U32s<'_>) -> Result<(), Full>,
    ) -> Result<(), Full> {
        put_u32s_in(self, tag, fill)
    }
    fn put_pod<T: Pod>(&mut self, tag: u16, v: &T) -> Result<(), Full> {
        put_parts(self, tag, &[v.as_bytes()])
    }
    fn put_pod_tail<T: Pod>(&mut self, tag: u16, v: &T, tail: &[u8]) -> Result<(), Full> {
        put_parts(self, tag, &[v.as_bytes(), tail])
    }
    fn put_text(&mut self, tag: u16, s: &str) -> Result<(), Full> {
        put_parts(self, tag, &[s.as_bytes()])
    }
    fn put_pair(&mut self, tag: u16, name: &str, value: &[u8]) -> Result<(), Full> {
        put_pair_in(self, tag, name, value)
    }
    fn put_fact(&mut self, key: u32, value: u64) -> Result<(), Full> {
        put_fact_in(self, key, value)
    }
    fn put_fact_text(&mut self, key: u32, value: &str) -> Result<(), Full> {
        put_fact_text_in(self, key, value)
    }
    fn put_metric(&mut self, id: u32, op: u32, value: f64, labels: &[&str]) -> Result<(), Full> {
        put_metric_in(self, id, op, value, labels)
    }
    fn put_nested(
        &mut self,
        tag: u16,
        f: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
    ) -> Result<(), Full> {
        put_nested_in(self, tag, f)
    }
}

/// Canonical record encoding into caller-owned, already funded storage. This writer allocates
/// nothing and never grows. The caller retains the backing's custody and wipes it on abandonment;
/// only the prefix returned by `as_bytes` is a complete published record sequence.
pub struct Fixed<'a> {
    bytes: &'a mut [u8],
    len: usize,
}
impl<'a> Fixed<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, len: 0 }
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn capacity(&self) -> usize {
        self.bytes.len()
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl RawWrite for Fixed<'_> {
    fn written(&self) -> usize {
        self.len
    }
    fn room(&mut self, need: usize) -> Result<(), Full> {
        self.len
            .checked_add(need)
            .filter(|end| *end <= self.bytes.len())
            .map(|_| ())
            .ok_or(Full)
    }
    fn append(&mut self, bytes: &[u8]) {
        let end = self.len + bytes.len();
        self.bytes[self.len..end].copy_from_slice(bytes);
        self.len = end;
    }
    fn patch(&mut self, at: usize, bytes: &[u8]) {
        self.bytes[at..at + bytes.len()].copy_from_slice(bytes);
    }
    fn truncate(&mut self, len: usize) {
        self.bytes[len..self.len].zeroize();
        self.len = len;
    }
}
impl Writer for Fixed<'_> {
    fn put(&mut self, tag: u16, body: &[u8]) -> Result<(), Full> {
        put_parts(self, tag, &[body])
    }
    fn put_u32s(
        &mut self,
        tag: u16,
        fill: impl FnOnce(&mut U32s<'_>) -> Result<(), Full>,
    ) -> Result<(), Full> {
        put_u32s_in(self, tag, fill)
    }
    fn put_pod<T: Pod>(&mut self, tag: u16, value: &T) -> Result<(), Full> {
        put_parts(self, tag, &[value.as_bytes()])
    }
    fn put_pod_tail<T: Pod>(&mut self, tag: u16, value: &T, tail: &[u8]) -> Result<(), Full> {
        put_parts(self, tag, &[value.as_bytes(), tail])
    }
    fn put_text(&mut self, tag: u16, value: &str) -> Result<(), Full> {
        put_parts(self, tag, &[value.as_bytes()])
    }
    fn put_pair(&mut self, tag: u16, name: &str, value: &[u8]) -> Result<(), Full> {
        put_pair_in(self, tag, name, value)
    }
    fn put_fact(&mut self, key: u32, value: u64) -> Result<(), Full> {
        put_fact_in(self, key, value)
    }
    fn put_fact_text(&mut self, key: u32, value: &str) -> Result<(), Full> {
        put_fact_text_in(self, key, value)
    }
    fn put_metric(&mut self, id: u32, op: u32, value: f64, labels: &[&str]) -> Result<(), Full> {
        put_metric_in(self, id, op, value, labels)
    }
    fn put_nested(
        &mut self,
        tag: u16,
        fill: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
    ) -> Result<(), Full> {
        put_nested_in(self, tag, fill)
    }
}

/// Async-method output: an owned record buffer. On Ready the shim copies it into the terminal call's Out.
/// Zeroized on drop (it may hold secrets, rows or tokens). Cap 16 MiB; the host's max_out applies on copy.
/// Growth never reallocates in place: when a write needs capacity, Reply allocates max(2 × cap, need, 256)
/// bytes, copies `[0, len)`, zeroes the whole old block and frees it (I11). `with_capacity` pre-sizes it so a
/// plugin that knows its answer size grows zero times. Its bytes are never exposed past `len`.
pub struct Reply {
    buf: Vec<u8>,
}
impl Reply {
    pub fn new() -> Self {
        Reply { buf: Vec::new() }
    }
    pub fn with_capacity(n: usize) -> Self {
        Reply {
            buf: Vec::with_capacity(n.min(REPLY_CAP)),
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
    pub fn len(&self) -> usize {
        self.buf.len()
    }
    /// Consume an empty reply as bounded unframed scratch. Invalid entry consumes and wipes
    /// the reply. Finishing the scratch wipes its bytes and returns this allocation for records.
    pub fn into_scratch(self, limit: usize) -> Result<Scratch, Full> {
        if !self.buf.is_empty() || limit > REPLY_CAP {
            return Err(Full);
        }
        Ok(Scratch { reply: self, limit })
    }
}

/// One call's unframed bytes. Owns its reply through awaits; cancellation and unwind wipe
/// through Reply's Drop. This phase cannot write records or be returned as an answer.
pub struct Scratch {
    reply: Reply,
    limit: usize,
}

impl Scratch {
    pub fn as_bytes(&self) -> &[u8] {
        self.reply.as_bytes()
    }

    /// Append within the supplied limit. Full leaves the current bytes unchanged.
    pub fn put(&mut self, bytes: &[u8]) -> Result<(), Full> {
        let end = self.reply.len().checked_add(bytes.len()).ok_or(Full)?;
        if end > self.limit {
            return Err(Full);
        }
        self.reply.room(bytes.len())?;
        self.reply.append(bytes);
        Ok(())
    }

    /// Wipe the entire scratch allocation, retaining its capacity for terminal records.
    /// The returned reply has its normal record limit, independent of this scratch limit.
    pub fn finish(mut self) -> Reply {
        self.reply.buf.zeroize();
        self.reply
    }
}
impl Default for Reply {
    fn default() -> Self {
        Self::new()
    }
}
impl RawWrite for Reply {
    fn written(&self) -> usize {
        self.buf.len()
    }
    fn room(&mut self, need: usize) -> Result<(), Full> {
        let want = self.buf.len().checked_add(need).ok_or(Full)?;
        if want > REPLY_CAP {
            return Err(Full);
        }
        let cap = self.buf.capacity();
        if want <= cap {
            return Ok(());
        }
        // A fresh block, the bytes copied over, the old block wiped whole (`Zeroize` on a Vec wipes its
        // capacity, volatile) before it is freed: never `reserve`, which could move the bytes and leave a copy.
        let mut grown = Vec::with_capacity(
            cap.saturating_mul(2)
                .min(REPLY_CAP)
                .max(want)
                .max(REPLY_MIN),
        );
        grown.extend_from_slice(&self.buf);
        let mut old = core::mem::replace(&mut self.buf, grown);
        old.zeroize();
        Ok(())
    }
    fn append(&mut self, bytes: &[u8]) {
        assert!(
            self.buf.capacity() - self.buf.len() >= bytes.len(),
            "a record write past the room it made"
        );
        self.buf.extend_from_slice(bytes);
    }
    fn patch(&mut self, at: usize, bytes: &[u8]) {
        self.buf[at..at + bytes.len()].copy_from_slice(bytes);
    }
    fn truncate(&mut self, len: usize) {
        if let Some(tail) = self.buf.get_mut(len..) {
            tail.zeroize();
        }
        self.buf.truncate(len);
    }
}
impl Writer for Reply {
    fn put_parts(&mut self, tag: u16, parts: &[&[u8]]) -> Result<(), Full> {
        put_parts(self, tag, parts)
    }
    fn put_pod_nested<T: Pod>(
        &mut self,
        tag: u16,
        prefix: &T,
        fill: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
    ) -> Result<(), Full> {
        put_prefixed_nested_in(self, tag, prefix.as_bytes(), fill)
    }
    fn put(&mut self, tag: u16, body: &[u8]) -> Result<(), Full> {
        put_parts(self, tag, &[body])
    }
    fn put_u32s(
        &mut self,
        tag: u16,
        fill: impl FnOnce(&mut U32s<'_>) -> Result<(), Full>,
    ) -> Result<(), Full> {
        put_u32s_in(self, tag, fill)
    }
    fn put_pod<T: Pod>(&mut self, tag: u16, v: &T) -> Result<(), Full> {
        put_parts(self, tag, &[v.as_bytes()])
    }
    fn put_pod_tail<T: Pod>(&mut self, tag: u16, v: &T, tail: &[u8]) -> Result<(), Full> {
        put_parts(self, tag, &[v.as_bytes(), tail])
    }
    fn put_text(&mut self, tag: u16, s: &str) -> Result<(), Full> {
        put_parts(self, tag, &[s.as_bytes()])
    }
    fn put_pair(&mut self, tag: u16, name: &str, value: &[u8]) -> Result<(), Full> {
        put_pair_in(self, tag, name, value)
    }
    fn put_fact(&mut self, key: u32, value: u64) -> Result<(), Full> {
        put_fact_in(self, key, value)
    }
    fn put_fact_text(&mut self, key: u32, value: &str) -> Result<(), Full> {
        put_fact_text_in(self, key, value)
    }
    fn put_metric(&mut self, id: u32, op: u32, value: f64, labels: &[&str]) -> Result<(), Full> {
        put_metric_in(self, id, op, value, labels)
    }
    fn put_nested(
        &mut self,
        tag: u16,
        f: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
    ) -> Result<(), Full> {
        put_nested_in(self, tag, f)
    }
}
impl Drop for Reply {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

#[cfg(test)]
#[path = "records_buffer_tests.rs"]
mod buffer_tests;
