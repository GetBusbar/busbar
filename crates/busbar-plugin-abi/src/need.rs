// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Need steps: the wire, chain-scoped argument handles and the plugin-side Need API (IF §6.1, §6.2, §6.3). W1-A3:
//! the Need futures write their NEED records into the polling chain's mail and read their NEED_RES from it
//! (`bridge.rs`); every record they write or read is framed by `records.rs`.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// A borrowed destination, with no heap-owned descriptor array for the legacy one-piece case.
#[derive(Clone, Copy)]
pub(crate) enum Destination<'a> {
    One(&'a str),
    Parts(&'a [&'a str]),
}

impl Destination<'_> {
    pub(crate) fn parts(&self) -> impl Iterator<Item = &[u8]> + Clone {
        let (one, many) = match *self {
            Self::One(text) => (Some(text), &[][..]),
            Self::Parts(parts) => (None, parts),
        };
        one.into_iter()
            .chain(many.iter().copied())
            .map(str::as_bytes)
    }

    pub(crate) fn checked_len(&self) -> Option<usize> {
        sum_lengths(self.parts().map(<[u8]>::len))
    }
}

fn sum_lengths(mut lengths: impl Iterator<Item = usize>) -> Option<usize> {
    lengths.try_fold(0usize, usize::checked_add)
}

// ---- §6.1 Wire (inside `mechanism!`) ----
mechanism! {

/// One step request. Body = NeedRec, then arg0..arg3 bytes back to back (lengths in `lens`).
/// `secret` = a SecretHandle (SECRET; the client cert for OPEN/STARTTLS/FETCH with TLS_MUTUAL), 0 = none.
/// `trust` = a TrustHandle (OPEN/STARTTLS/FETCH: an operator CA added to policy roots), 0 = none.
/// Both are indices into the *calling instance's own* binding table (§12.7); there is no other way to name one.
/// `flags` bits 16..=19 (OPEN, FETCH only; round 7) = the egress class the plugin states for this destination
/// (`egress::*`, today's per-need `egress_class`, same numbers); zero on every other op. A value > 4 is INVALID.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct NeedRec {
    pub op: u32,
    pub flags: u32,
    pub a: u64,
    pub b: u64,
    pub secret: u32,
    pub trust: u32,
    pub lens: [u32; 4],
}
/// One step result, in Need order. Body = NeedResRec, then data0 and data1 (lengths in `lens`).
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct NeedResRec {
    pub op: u32,
    pub status: u32,
    pub a: u64,
    pub b: u64,
    pub lens: [u32; 2],
    pub _r: u64,
}

pub mod op {
    pub const OPEN: u32 = 1;
    pub const STARTTLS: u32 = 2;
    pub const WRITE: u32 = 3;
    pub const READ: u32 = 4;
    pub const CLOSE: u32 = 5;
    pub const FETCH: u32 = 6;
    pub const SECRET: u32 = 7;
    pub const RECORD: u32 = 8;
    /// Round 29 (auth v4 provisioning, §8.3 `serve`): one kernel directory operation (`dir::*`).
    pub const DIRECTORY: u32 = 9;
}
/// Round 29: the DIRECTORY Need (dev's seven `directory.*` host services, busbar-contract abi/host/directory.rs at
/// f6e2cf05d7, same numbers and caps, as one Need). NeedRec.flags = `op | kind << KIND_SHIFT | apply << APPLY_SHIFT
/// | state << STATE_SHIFT | (PULL if the plugin pulled it)`; `a` = expected version (APPLY, DELETE; 0 = any) or scan
/// limit (SCAN; 0 or > MAX_SCAN = MAX_SCAN); `b` = 0; `secret` = `trust` = 0. Args: 0 = id (GET, APPLY, DELETE),
/// index name (LOOKUP) or group id (SCAN/COUNT of MEMBER; else empty); 1 = value (LOOKUP), cursor (SCAN, the last id
/// seen; empty = first) or document (CREATE, APPLY with APPLY_DOCUMENT); 2 = nested PAIR* index name → value (CREATE,
/// APPLY with APPLY_INDEXES); 3 = nested TEXT* member ids, each record's tag one of DM_ADD/DM_REMOVE/DM_REPLACE
/// (APPLY on a GROUP). Result: a = `code | (index as u64) << 32`, b = version (GET, CREATE, APPLY) or count (COUNT;
/// SCAN: rows); data0 = GET: nested ID text, DOC bytes, PAIR* indexes; LOOKUP and CREATE: the id; SCAN: nested PAIR*
/// id → document (MEMBER: id → empty); data1 = `DirFacts` (exactly 16 bytes on every OK DIRECTORY).
pub mod dir {
    pub const GET: u32 = 1;
    pub const LOOKUP: u32 = 2;
    pub const SCAN: u32 = 3;
    pub const COUNT: u32 = 4;
    pub const CREATE: u32 = 5;
    pub const APPLY: u32 = 6;
    pub const DELETE: u32 = 7;
    pub const OP_MASK: u32 = 0xF;
    pub const SUBJECT: u32 = 1;
    pub const GROUP: u32 = 2;
    pub const MEMBER: u32 = 3;
    pub const KIND_SHIFT: u32 = 4;
    pub const APPLY_DOCUMENT: u32 = 1;
    pub const APPLY_INDEXES: u32 = 2;
    pub const APPLY_STATE: u32 = 4;
    pub const APPLY_REPLACE_MEMBERS: u32 = 8;
    pub const APPLY_SHIFT: u32 = 8;
    pub const STATE_ACTIVE: u32 = 1;
    pub const STATE_INACTIVE: u32 = 2;
    pub const STATE_SHIFT: u32 = 12;
    pub const PULL: u32 = 0x1_0000;
    /// Nested-record tags used only inside DIRECTORY args and data0 (generic range 0x0070..=0x0074, which records.rs
    /// `tag` reserves for them and nothing else): ID and DOC (TEXT and bytes shapes), the three member-change lists.
    pub const ID: u16 = 0x0070;
    pub const DOC: u16 = 0x0071;
    pub const DM_ADD: u16 = 0x0072;
    pub const DM_REMOVE: u16 = 0x0073;
    pub const DM_REPLACE: u16 = 0x0074;
    /// Domain outcomes: an OK Need with this code in `a` (never a NeedErr). Nothing is written unless OK.
    /// GUARD = core's mass-deprovision guard holds (an operator releases it; the plugin never can).
    pub const OK: u32 = 0;
    pub const NOT_FOUND: u32 = 1;
    pub const CONFLICT: u32 = 2;
    pub const PRECONDITION: u32 = 3;
    pub const TOO_MANY: u32 = 4;
    pub const INVALID: u32 = 5;
    pub const GUARD: u32 = 6;
    pub const MAX_INDEXES: u32 = 4;
    pub const MAX_ID: u32 = 64;
    pub const MAX_DOCUMENT: u32 = 65_536;
    pub const MAX_MEMBERS_PER_APPLY: u32 = 10_000;
    pub const MAX_SCAN: u32 = 500;
}
/// Round 29: DIRECTORY's data1. `state` = the record's state (GET/CREATE/APPLY on a SUBJECT), `more` = 1 when a SCAN
/// has rows after the last one written, `active` = active subjects (COUNT of SUBJECT); 0 otherwise.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct DirFacts {
    pub state: u32,
    pub more: u32,
    pub active: u64,
}
pub mod need_flag {
    pub const TLS_NONE: u32 = 0;
    pub const TLS_REQUIRED: u32 = 1;
    pub const TLS_MUTUAL: u32 = 2;
    pub const TLS_MASK: u32 = 0xF;
    /// OPEN only: connect in plaintext, and the plugin will STARTTLS in band with exactly the SNI, ALPN,
    /// `trust` and `secret` given on this OPEN. Part of the pool key, so OPEN(TLS_INBAND) may come back REUSED
    /// with TLS_DONE (an already-upgraded conn: skip the in-band negotiation). A STARTTLS whose parameters differ
    /// from the OPEN's gets INVALID. Combine with TLS_MUTUAL semantics by setting `secret`.
    pub const TLS_INBAND: u32 = 3;
    // 0x10 is retired (round 1's UDP flag). Datagram I/O is core-owned, delivered to transports (§8.7).
    /// CLOSE: protocol state is clean; the host may pool the connection.
    pub const REUSABLE: u32 = 0x100;
    // 0x200 is retired (round 29, AGREED 133): round 24's TLS_UNVERIFIED is deleted. Every TLS conn core dials is
    // verified; a Need with bit 0x200 is INVALID like any unknown bit (§10.3 decode table). Unverified store dials
    // are refused at boot by the store's own `check` (§12.10 item 5).
    pub const REC_GET: u32 = 1;
    pub const REC_PUT: u32 = 2;
    pub const REC_CLAIM: u32 = 3;
    pub const REC_DEL: u32 = 4;
    pub const REC_LIST: u32 = 5;
    /// arg0 = nested REC_PRED*, REC_PUT*, REC_DEL* (generic tags, §3): one atomic commit (§12.5). Result a =
    /// commit::APPLIED or CONFLICT, b = 0-based index of the first failed predicate (CONFLICT only).
    pub const REC_COMMIT: u32 = 6;
    /// OPEN/FETCH: the stated egress class lives in bits 16..=19 (`(class << EGRESS_SHIFT) & EGRESS_MASK`).
    pub const EGRESS_SHIFT: u32 = 16;
    pub const EGRESS_MASK: u32 = 0xF_0000;
}
/// Round 7. What the plugin says the destination IS (intent, not a verdict): busbar-contract
/// abi/host/conn/connector.rs:15-23 EGRESS_*, same numbers, same meaning. Core's guard judges the destination
/// under `guard::judged_class(stated, configured)` (§12.1); the plugin never learns the verdict's reason.
pub mod egress {
    pub const DEFAULT: u32 = 0;
    pub const PROVIDER: u32 = 1;
    pub const OPERATOR_INFRASTRUCTURE: u32 = 2;
    pub const OPEN_WEB: u32 = 3;
    pub const LOOPBACK_ALLOWED: u32 = 4;
}
pub mod need_status {
    pub const OK: u32 = 0;
    pub const DENIED: u32 = 1; // egress, custody or policy said no (never says who or why beyond a fixed text)
    pub const UNAVAILABLE: u32 = 2; // DNS, connect or backend down
    pub const TIMEOUT: u32 = 3; // host timeout for this step
    pub const ABSENT: u32 = 4; // SECRET/RECORD not found
    pub const TAKEN: u32 = 5; // RECORD CLAIM lost
    pub const LIMIT: u32 = 6; // size, count or quota limit
    pub const TLS: u32 = 7; // handshake or certificate failure
    pub const CLOSED: u32 = 8; // peer reset or conn already closed
    pub const SKIPPED: u32 = 9; // an earlier Need in the same step failed; this one did not run
    pub const INVALID: u32 = 10; // malformed Need, unknown conn, or conn from another chain
}
pub mod open_flag {
    pub const REUSED: u64 = 1;
    pub const TLS_RESUMED: u64 = 2;
    /// OPEN(TLS_INBAND) returned a pooled conn on which STARTTLS already completed with the same parameters.
    /// Round 29: an OPEN(TLS_INBAND) answer is either fresh (not REUSED: plaintext, the plugin upgrades in band) or
    /// REUSED with TLS_DONE; REUSED without TLS_DONE never happens (round 24's plaintext-fallback pooling is deleted).
    pub const TLS_DONE: u64 = 4;
    /// Round 19. Every OK OPEN's data1 is exactly this many bytes: the **pooled-conn id**, a u64 little-endian,
    /// minted by core when the conn is dialled: non-zero, unique among the calling instance's conns and never
    /// reused for the life of that instance, and carried unchanged through STARTTLS, CLOSE(REUSABLE) and every
    /// REUSED OPEN (TLS_DONE included) that hands the same conn back. A fresh dial always gets a new id; core never
    /// reports retirement. It names the server-side session (prepared statements, bind identity, session
    /// variables), so a plugin keys its own bounded per-connection state on it (§6.1 rules). Any other data1
    /// length on an OK OPEN is a host bug the shim answers with a BadRecords FAULT.
    pub const POOLED_ID_LEN: u32 = 8;
}
}

// W0-ABI: `PoolKey` (§6.1) is C1's (busbar-core-connector, §13), not an abi item; it is not written here.

// ---- §6.2 Chain-scoped argument handles ----

/// An async argument (IF §6.2). busbar-ffi owns it: the check value, the `CURRENT` restore and the one read of
/// host memory are the plugin boundary (UNSAFE-MIN r3.1), so this is its type under the frozen path.
pub use busbar_ffi::ChainBytes;

// ---- §6.3 Plugin-side Need API ----

/// A secret position in this instance's config, as core wrote it: `{"$secret": n}` (§12.7). The plugin reads n
/// with the config parser it already uses (jiter or sonic-rs, AGREED 223; abi has no JSON parser) and never sees
/// the reference behind it. Core validated the object against SECRET_SCHEMA before `open`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SecretHandle(pub u32);
/// A trust-anchor position: `{"$trust": n}`, read the same way. `TrustHandle(0)` = policy roots only.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TrustHandle(pub u32);
impl TrustHandle {
    pub const NONE: TrustHandle = TrustHandle(0);
}

pub mod need {
    use core::pin::Pin;
    use core::task::{Context, Poll};

    use crate::secure::SecureVec;
    use zerocopy::{FromBytes, IntoBytes};

    use super::{
        DirFacts, NeedRec, NeedResRec, SecretHandle, TrustHandle, dir, need_flag, need_status, op,
        open_flag,
    };
    use crate::bridge::{self, ChainKey, Mail};
    use crate::records::{
        Full, PairRec, RawWrite, Rec, RecDelRec, RecHead, RecPredRec, RecPutRec, Records, Reply,
        commit, tag,
    };

    /// A host connection, scoped to the current chain. Not Copy. Dropping it without close is fine (host closes at chain end, round 16: whatever status ends the chain, §6.1).
    /// `chain` is the plugin-side `ChainId` serial (§6.2), a plugin-local misuse check only; the host scopes conns by
    /// its own `Caller::chain` (§10.3, round 15), and neither value is ever derived from the other.
    pub struct Conn {
        id: u64,
        chain: u64,
    }
    #[derive(Clone, Copy)]
    pub enum Tls<'a> {
        None,
        Required {
            sni: &'a str,
            alpn: &'a [&'a str],
            trust: TrustHandle,
        },
        /// `cert` names a secret holding the PEM cert chain + key; never key material.
        Mutual {
            sni: &'a str,
            alpn: &'a [&'a str],
            trust: TrustHandle,
            cert: SecretHandle,
        },
        /// OPEN only (TLS_INBAND): plaintext now, `starttls` later with exactly these values (as `Required` or
        /// `Mutual`). `Opened::tls_done` = a pooled conn already upgraded: skip SSLRequest/StartTLS.
        Inband {
            sni: &'a str,
            alpn: &'a [&'a str],
            trust: TrustHandle,
            cert: Option<SecretHandle>,
        },
        // Round 29 (AGREED 133): round 24's `Unverified` arm is deleted; there is no unverified TLS.
    }
    /// Round 19: `pooled` = the pooled-conn id (§6.1 `open_flag::POOLED_ID_LEN`, decoded from data1): the same value
    /// on every REUSED OPEN of this conn, a new one on every dial. Key per-connection state on it (§6.1 rules).
    pub struct Opened {
        pub conn: Conn,
        pub reused: bool,
        pub tls_resumed: bool,
        pub tls_done: bool,
        pub pooled: u64,
        pub alpn: Option<String>,
    }
    pub struct Fetch<'a> {
        pub method: &'a str,
        pub url: &'a str,
        pub headers: &'a [(&'a str, &'a [u8])],
        pub body: &'a [u8],
        pub max_body: u64,
        pub trust: TrustHandle,
        pub cert: Option<SecretHandle>,
        /// Round 7: the stated egress class (`crate::need::egress::*`), e.g. OPEN_WEB for OIDC discovery and
        /// JWKS, DEFAULT for the token call of the same instance.
        pub egress: u32,
    }
    pub struct Fetched {
        pub status: u16,
        pub headers: Vec<(String, SecureVec)>,
        pub body: SecureVec,
    }
    #[derive(Clone, Copy)]
    pub enum Record<'a> {
        Get {
            key: &'a [u8],
        },
        Put {
            key: &'a [u8],
            value: &'a [u8],
            ttl_s: u64,
        },
        Claim {
            key: &'a [u8],
            value: &'a [u8],
            ttl_s: u64,
        },
        Del {
            key: &'a [u8],
        },
        List {
            prefix: &'a [u8],
            limit: u32,
        },
        /// One atomic commit: every predicate holds, then every mutation applies; else nothing applies.
        Commit(&'a Commit<'a>),
    }
    /// Predicates and mutations of one commit (≤ commit::MAX_OPS in total). Encoded by abi as the generic
    /// REC_PRED/REC_PUT/REC_DEL records (the same bytes a plane writes inside COMMIT, §8.6).
    pub struct Commit<'a> {
        pub preds: &'a [Pred<'a>],
        pub muts: &'a [Mut<'a>],
    }
    #[derive(Clone, Copy)]
    pub enum Pred<'a> {
        Absent { key: &'a [u8] },
        Present { key: &'a [u8] },
        Equals { key: &'a [u8], value: &'a [u8] },
    }
    #[derive(Clone, Copy)]
    pub enum Mut<'a> {
        Put {
            key: &'a [u8],
            value: &'a [u8],
            ttl_s: u64,
        },
        Del {
            key: &'a [u8],
        },
    }
    pub enum RecordOut {
        Value(Option<Vec<u8>>),
        Won(bool),
        Done,
        List(Vec<(Vec<u8>, Vec<u8>)>),
        /// Ok(()) = applied; Err(i) = predicate i failed and nothing was applied.
        Committed(Result<(), u32>),
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum NeedErr {
        Denied,
        Unavailable,
        Timeout,
        Absent,
        Taken,
        Limit,
        Tls,
        Closed,
        Skipped,
        Invalid,
    }
    // From<NeedErr> for Fail: Denied -> refused(R_DENIED); Absent -> refused(R_NOT_FOUND); Taken -> refused(R_CONFLICT);
    // Unavailable/Closed/Tls -> failed(F_UNAVAILABLE); Timeout -> failed(F_TIMEOUT); Limit -> failed(F_LIMIT);
    // Skipped/Invalid -> failed(F_INTERNAL). Texts are fixed strings.

    /// The future every step returns. Polling it outside a chain poll panics -> FAULT NeedOutsideAsync.
    /// Round 13 (H6/I2): on the poll that writes its NEED it records `(ChainId, step, index)` = CURRENT's chain,
    /// that chain's step counter (§6.4 step 4) and the NEED's index in the step. Every later poll checks
    /// CURRENT.id == ChainId and CURRENT.step == step + 1 before it reads `inbox[index]` (a re-poll in the same
    /// chain at the same step is Pending and writes nothing); anything else
    /// (another chain, another instance, a resume of another image's chain, a poll two steps late) panics ->
    /// FAULT StaleHandle and reads nothing. One TLS load and four compares; no RMW, no allocation (I5).
    pub struct NeedFut<'a, T> {
        /// What to write, and what the answer decodes into (`read_into`'s buffer, a batch's items).
        req: Req<'a>,
        at: At,
        decode: fn(&mut Req<'a>, &mut Results<'_>) -> Result<T, NeedErr>,
    }
    impl<T> core::future::Future for NeedFut<'_, T> {
        type Output = Result<T, NeedErr>;
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let _ = cx;
            self.get_mut().step()
        }
    }

    /// `egress` = the stated class (`egress::*`; round 7): OPERATOR_INFRASTRUCTURE for a database, directory or
    /// secret service, LOOPBACK_ALLOWED for a local collector, and so on. Out of range => INVALID. Round 24:
    /// `dest` = `host:port`, or `unix:/abs/path` with `Tls::None` and OPERATOR_INFRASTRUCTURE (§12.1).
    pub fn open<'a>(dest: &'a str, tls: Tls<'a>, egress: u32) -> NeedFut<'a, Opened> {
        NeedFut::new(
            Req::Open {
                dest: super::Destination::One(dest),
                tls,
                egress,
            },
            opened,
        )
    }
    /// OPEN from borrowed destination segments. Both the segment storage and descriptor slice
    /// must live through await; dropping the future releases those borrows.
    ///
    /// ```
    /// use busbar_plugin_abi::need::{Tls, need};
    /// use std::future::Future;
    /// fn legacy(dest: &str) -> impl Future<Output = Result<need::Opened, need::NeedErr>> + '_ {
    ///     need::open(dest, Tls::None, 2)
    /// }
    /// async fn local() {
    ///     let port = [b'8', b'0'];
    ///     let port = std::str::from_utf8(&port).unwrap();
    ///     let parts = ["example.test", ":", port];
    ///     let _ = need::open_parts(&parts, Tls::None, 2).await;
    /// }
    /// ```
    /// ```compile_fail
    /// use busbar_plugin_abi::need::{Tls, need};
    /// let future = {
    ///     let parts = ["example.test", ":80"];
    ///     need::open_parts(&parts, Tls::None, 2)
    /// };
    /// drop(future);
    /// ```
    /// ```compile_fail
    /// use busbar_plugin_abi::need::{Tls, need};
    /// let mut parts = ["example.test", ""];
    /// let future = {
    ///     let port = [b'8', b'0'];
    ///     parts[1] = std::str::from_utf8(&port).unwrap();
    ///     need::open_parts(&parts, Tls::None, 2)
    /// };
    /// drop(future);
    /// ```
    pub fn open_parts<'a>(dest: &'a [&'a str], tls: Tls<'a>, egress: u32) -> NeedFut<'a, Opened> {
        NeedFut::new(
            Req::Open {
                dest: super::Destination::Parts(dest),
                tls,
                egress,
            },
            opened,
        )
    }

    pub fn starttls<'a>(c: &'a Conn, tls: Tls<'a>) -> NeedFut<'a, ()> {
        NeedFut::new(
            Req::StartTls {
                conn: c.id,
                chain: c.chain,
                tls,
            },
            unit,
        )
    }
    pub fn write<'a>(c: &'a Conn, bytes: &'a [u8]) -> NeedFut<'a, ()> {
        NeedFut::new(
            Req::Write {
                conn: c.id,
                chain: c.chain,
                bytes,
            },
            unit,
        )
    }
    /// Ok(empty) = EOF.
    pub fn read(c: &Conn, max: u32) -> NeedFut<'_, SecureVec> {
        NeedFut::new(
            Req::Read {
                conn: c.id,
                chain: c.chain,
                max,
            },
            read_bytes,
        )
    }
    /// Appends to `buf` (reuse it across reads: no allocation once it has capacity). Ok(true) = EOF.
    /// When `buf` lacks capacity, abi grows it by allocate, copy, zero the old block, free (I11), never `reserve`.
    pub fn read_into<'a>(c: &'a Conn, max: u32, buf: &'a mut SecureVec) -> NeedFut<'a, bool> {
        NeedFut::new(
            Req::ReadInto {
                conn: c.id,
                chain: c.chain,
                max,
                buf,
            },
            read_appended,
        )
    }
    pub fn close(c: Conn, reusable: bool) -> NeedFut<'static, ()> {
        NeedFut::new(
            Req::Close {
                conn: c.id,
                chain: c.chain,
                reusable,
            },
            unit,
        )
    }
    pub fn fetch<'a>(req: &'a Fetch<'a>) -> NeedFut<'a, Fetched> {
        NeedFut::new(Req::Fetch(req), fetched)
    }
    pub fn secret(handle: SecretHandle) -> NeedFut<'static, SecureVec> {
        NeedFut::new(Req::Secret(handle), secret_value)
    }
    pub fn record(op: Record<'_>) -> NeedFut<'_, RecordOut> {
        NeedFut::new(Req::Record(op), record_answer)
    }

    /// Round 29: one kernel directory operation (§6.1 DIRECTORY; auth only, `serve`/`refresh` of an FB_PROVISION
    /// image). `kind` = `dir::SUBJECT | GROUP | MEMBER` (MEMBER: SCAN and COUNT only, `scope` = the group id). Ids are
    /// core-minted (CREATE answers it); index values are compared byte for byte (the plugin normalises them).
    /// `pull: true` marks a record the plugin pulled itself (from `refresh`), false one a client pushed (`serve`).
    #[derive(Clone, Copy)]
    pub enum Dir<'a> {
        Get {
            kind: u32,
            id: &'a str,
        },
        Lookup {
            kind: u32,
            index: &'a str,
            value: &'a [u8],
        },
        Scan {
            kind: u32,
            scope: &'a str,
            after: &'a str,
            limit: u32,
        },
        Count {
            kind: u32,
            scope: &'a str,
        },
        Create {
            kind: u32,
            state: u32,
            pull: bool,
            document: &'a [u8],
            indexes: &'a [(&'a str, &'a [u8])],
        },
        Apply {
            kind: u32,
            id: &'a str,
            expected_version: u64,
            apply: u32,
            state: u32,
            document: &'a [u8],
            indexes: &'a [(&'a str, &'a [u8])],
            add: &'a [&'a str],
            remove: &'a [&'a str],
            replace: &'a [&'a str],
        },
        Delete {
            kind: u32,
            id: &'a str,
            expected_version: u64,
        },
    }
    /// `code` = `dir::OK..=GUARD` (a domain outcome; only OK wrote anything); `index` = the colliding index slot
    /// (CONFLICT); `id` = GET/LOOKUP/CREATE's id; `document`/`indexes` = GET's record; `rows` = SCAN's (id, document).
    pub struct DirOut {
        pub code: u32,
        pub index: u32,
        pub version: u64,
        pub count: u64,
        pub facts: DirFacts,
        pub id: String,
        pub document: Vec<u8>,
        pub indexes: Vec<(String, Vec<u8>)>,
        pub rows: Vec<(String, Vec<u8>)>,
    }
    /// NeedErr::Denied: the instance has no `provisioning:` block. Unavailable/Timeout: the directory did not answer.
    pub fn directory(op: Dir<'_>) -> NeedFut<'_, DirOut> {
        NeedFut::new(Req::Directory(op), directory_answer)
    }

    /// Pipelining: several Needs in one step (one resume). Results come back in push order.
    #[derive(Default)]
    pub struct Batch<'a> {
        items: Vec<Req<'a>>,
    }
    pub enum Done {
        Opened(Opened),
        Unit,
        Read(SecureVec),
        Fetched(Fetched),
        Secret(SecureVec),
        Record(RecordOut),
    }
    impl<'a> Batch<'a> {
        pub fn new() -> Self {
            Batch { items: Vec::new() }
        }
        pub fn write(&mut self, c: &'a Conn, bytes: &'a [u8]) -> &mut Self {
            self.items.push(Req::Write {
                conn: c.id,
                chain: c.chain,
                bytes,
            });
            self
        }
        pub fn read(&mut self, c: &'a Conn, max: u32) -> &mut Self {
            self.items.push(Req::Read {
                conn: c.id,
                chain: c.chain,
                max,
            });
            self
        }
        pub fn fetch(&mut self, req: &'a Fetch<'a>) -> &mut Self {
            self.items.push(Req::Fetch(req));
            self
        }
        pub fn secret(&mut self, handle: SecretHandle) -> &mut Self {
            self.items.push(Req::Secret(handle));
            self
        }
        pub fn record(&mut self, op: Record<'a>) -> &mut Self {
            self.items.push(Req::Record(op));
            self
        }
        /// One NEED per item, in push order, all in this step. An item on a conn of another chain is answered
        /// `Invalid` here and is not sent, and the items after it `Skipped`, exactly as core answers a failed
        /// NEED and the rest of its step (§6.1 rules); an empty batch is Ready at once.
        pub fn run(self) -> NeedFut<'a, Vec<Result<Done, NeedErr>>> {
            NeedFut::new(
                Req::Batch {
                    items: self.items,
                    sent: 0,
                },
                batch_answer,
            )
        }
    }

    // ---- what a Need future holds ----

    /// One request, with what its answer needs to decode.
    enum Req<'a> {
        Open {
            dest: super::Destination<'a>,
            tls: Tls<'a>,
            egress: u32,
        },
        StartTls {
            conn: u64,
            chain: u64,
            tls: Tls<'a>,
        },
        Write {
            conn: u64,
            chain: u64,
            bytes: &'a [u8],
        },
        Read {
            conn: u64,
            chain: u64,
            max: u32,
        },
        ReadInto {
            conn: u64,
            chain: u64,
            max: u32,
            buf: &'a mut SecureVec,
        },
        Close {
            conn: u64,
            chain: u64,
            reusable: bool,
        },
        Fetch(&'a Fetch<'a>),
        Secret(SecretHandle),
        Record(Record<'a>),
        Directory(Dir<'a>),
        /// `sent` = how many leading items went out (the rest stopped at a conn of another chain).
        Batch {
            items: Vec<Req<'a>>,
            sent: usize,
        },
    }

    impl Req<'_> {
        /// The conn op's chain serial (its plugin-local misuse check).
        fn chain(&self) -> Option<u64> {
            match self {
                Req::StartTls { chain, .. }
                | Req::Write { chain, .. }
                | Req::Read { chain, .. }
                | Req::ReadInto { chain, .. }
                | Req::Close { chain, .. } => Some(*chain),
                _ => None,
            }
        }
        /// The op its NEED_RES must echo.
        fn op(&self) -> u32 {
            match self {
                Req::Open { .. } => op::OPEN,
                Req::StartTls { .. } => op::STARTTLS,
                Req::Write { .. } => op::WRITE,
                Req::Read { .. } | Req::ReadInto { .. } => op::READ,
                Req::Close { .. } => op::CLOSE,
                Req::Fetch(_) => op::FETCH,
                Req::Secret(_) => op::SECRET,
                Req::Record(_) => op::RECORD,
                Req::Directory(_) => op::DIRECTORY,
                Req::Batch { .. } => 0,
            }
        }
    }

    /// Where a Need future is: not yet written, written at (chain, step, index), or answered.
    #[derive(Clone, Copy)]
    enum At {
        Fresh,
        Sent {
            key: ChainKey,
            step: u32,
            index: u32,
        },
        Done,
    }

    /// What writing a request came to.
    enum Wrote {
        /// The NEED(s) went out; the first one's index in this step.
        Sent(u32),
        /// Answered without a NEED (a conn of another chain, a STARTTLS without TLS, a request over the cap).
        Local(NeedErr),
        /// Nothing to send (an empty batch, or one whose first item stopped): decode at once.
        Ready,
    }

    fn outside() -> ! {
        panic!("busbar-plugin-abi: a Need future polled outside a chain poll (NeedOutsideAsync)")
    }
    fn stale() -> ! {
        panic!("busbar-plugin-abi: a Need future polled in another chain or step (StaleHandle)")
    }
    fn bad() -> ! {
        panic!("busbar-plugin-abi: a malformed Need result (BadRecords)")
    }

    impl<'a, T> NeedFut<'a, T> {
        fn new(
            req: Req<'a>,
            decode: fn(&mut Req<'a>, &mut Results<'_>) -> Result<T, NeedErr>,
        ) -> Self {
            NeedFut {
                req,
                at: At::Fresh,
                decode,
            }
        }

        fn step(&mut self) -> Poll<Result<T, NeedErr>> {
            match self.at {
                At::Fresh => {
                    let req = &mut self.req;
                    let Some((wrote, key, step)) =
                        bridge::with_mail(|mail| (send(req, mail), mail.key, mail.step))
                    else {
                        outside()
                    };
                    match wrote {
                        Wrote::Sent(index) => {
                            self.at = At::Sent { key, step, index };
                            Poll::Pending
                        }
                        Wrote::Local(err) => {
                            self.at = At::Done;
                            Poll::Ready(Err(err))
                        }
                        Wrote::Ready => {
                            self.at = At::Done;
                            let mut none = Results {
                                recs: Records::new(&[]),
                                serial: key.serial,
                            };
                            Poll::Ready((self.decode)(&mut self.req, &mut none))
                        }
                    }
                }
                At::Sent { key, step, index } => {
                    let decode = self.decode;
                    let req = &mut self.req;
                    let read = bridge::with_mail(|mail| {
                        if mail.key != key {
                            stale()
                        }
                        if mail.step == step {
                            return None;
                        }
                        if step.checked_add(1) != Some(mail.step) {
                            stale()
                        }
                        let Some(results) = mail.results.as_ref() else {
                            bad()
                        };
                        Some(results.with(|bytes| {
                            let mut results = Results::at(bytes, index, key.serial);
                            decode(req, &mut results)
                        }))
                    });
                    match read {
                        None => outside(),
                        Some(None) => Poll::Pending,
                        Some(Some(answer)) => {
                            self.at = At::Done;
                            Poll::Ready(answer)
                        }
                    }
                }
                At::Done => panic!("busbar-plugin-abi: a Need future polled after it completed"),
            }
        }
    }

    // ---- writing NEED records into the chain's mail ----

    /// Writes `req`'s NEED record(s) at the end of this step's NEEDs.
    fn send(req: &mut Req<'_>, mail: &mut Mail) -> Wrote {
        let start = mail.needs.len();
        let first = mail.count;
        let serial = mail.key.serial;
        let sent = match req {
            Req::Batch { items, sent } => {
                *sent = 0;
                for item in items.iter() {
                    let Wire::Need(rec, args) = wire(item, serial) else {
                        break;
                    };
                    if put_need(&mut mail.needs, rec, args).is_err() {
                        mail.needs.truncate(start);
                        return Wrote::Local(NeedErr::Limit);
                    }
                    *sent += 1;
                }
                if *sent == 0 {
                    return Wrote::Ready;
                }
                *sent
            }
            single => match wire(single, serial) {
                Wire::Need(rec, args) => {
                    if put_need(&mut mail.needs, rec, args).is_err() {
                        mail.needs.truncate(start);
                        return Wrote::Local(NeedErr::Limit);
                    }
                    1
                }
                Wire::Local(err) => return Wrote::Local(err),
            },
        };
        mail.count = first.saturating_add(u32::try_from(sent).unwrap_or(u32::MAX));
        Wrote::Sent(first)
    }

    /// One argument of a NEED, as it goes on the wire.
    #[derive(Clone, Copy)]
    enum Arg<'x> {
        Destination(super::Destination<'x>),
        Bytes(&'x [u8]),
        /// ALPN ids, comma-separated.
        Alpn(&'x [&'x str]),
        /// Nested PAIR records, name → value.
        Pairs(&'x [(&'x str, &'x [u8])]),
        /// Nested REC_PRED*, then the mutations in order (REC_PUT / REC_DEL).
        Commit(&'x Commit<'x>),
        /// Nested DM_ADD*, DM_REMOVE*, DM_REPLACE* member ids.
        Members {
            add: &'x [&'x str],
            remove: &'x [&'x str],
            replace: &'x [&'x str],
        },
    }
    const EMPTY: Arg<'static> = Arg::Bytes(&[]);
    const ZEROS: [u8; 8] = [0; 8];

    /// Zero padding after `len` body bytes.
    const fn pad(len: usize) -> usize {
        (8 - len % 8) % 8
    }
    /// The bytes one record with a `len`-byte body takes.
    const fn record_size(len: usize) -> usize {
        size_of::<RecHead>() + len + pad(len)
    }

    impl Arg<'_> {
        fn checked_len(self) -> Result<usize, Full> {
            if let Self::Destination(dest) = self {
                return dest.checked_len().ok_or(Full);
            }
            Ok(self.len())
        }

        fn len(self) -> usize {
            match self {
                Arg::Destination(_) => unreachable!("destination length must be checked"),
                Arg::Bytes(bytes) => bytes.len(),
                Arg::Alpn(ids) => {
                    ids.iter().map(|id| id.len()).sum::<usize>() + ids.len().saturating_sub(1)
                }
                Arg::Pairs(pairs) => pairs
                    .iter()
                    .map(|(name, value)| {
                        record_size(size_of::<PairRec>() + name.len() + value.len())
                    })
                    .sum(),
                Arg::Commit(c) => {
                    let preds: usize = c
                        .preds
                        .iter()
                        .map(|pred| {
                            let (_, key, value) = pred_parts(*pred);
                            record_size(size_of::<RecPredRec>() + key.len() + value.len())
                        })
                        .sum();
                    let muts: usize = c
                        .muts
                        .iter()
                        .map(|m| match *m {
                            Mut::Put { key, value, .. } => {
                                record_size(size_of::<RecPutRec>() + key.len() + value.len())
                            }
                            Mut::Del { key } => record_size(size_of::<RecDelRec>() + key.len()),
                        })
                        .sum();
                    preds + muts
                }
                Arg::Members {
                    add,
                    remove,
                    replace,
                } => [add, remove, replace]
                    .iter()
                    .flat_map(|ids| ids.iter())
                    .map(|id| record_size(id.len()))
                    .sum(),
            }
        }

        /// Appends the argument; the caller made room for `len()` bytes.
        fn write(self, w: &mut Reply) {
            match self {
                Arg::Destination(dest) => {
                    for part in dest.parts() {
                        w.append(part);
                    }
                }
                Arg::Bytes(bytes) => w.append(bytes),
                Arg::Alpn(ids) => {
                    for (i, id) in ids.iter().enumerate() {
                        if i > 0 {
                            w.append(b",");
                        }
                        w.append(id.as_bytes());
                    }
                }
                Arg::Pairs(pairs) => {
                    for &(name, value) in pairs {
                        let head = PairRec {
                            name_len: name.len() as u32,
                            _r: 0,
                        };
                        nested(w, tag::PAIR, &[head.as_bytes(), name.as_bytes(), value]);
                    }
                }
                Arg::Commit(c) => {
                    for pred in c.preds {
                        let (flags, key, value) = pred_parts(*pred);
                        let head = RecPredRec {
                            flags,
                            key_len: key.len() as u32,
                        };
                        nested(w, tag::REC_PRED, &[head.as_bytes(), key, value]);
                    }
                    for m in c.muts {
                        match *m {
                            Mut::Put { key, value, ttl_s } => {
                                let head = RecPutRec {
                                    flags: 0,
                                    key_len: key.len() as u32,
                                    ttl_s,
                                };
                                nested(w, tag::REC_PUT, &[head.as_bytes(), key, value]);
                            }
                            Mut::Del { key } => {
                                let head = RecDelRec { flags: 0, _r: 0 };
                                nested(w, tag::REC_DEL, &[head.as_bytes(), key]);
                            }
                        }
                    }
                }
                Arg::Members {
                    add,
                    remove,
                    replace,
                } => {
                    for (member_tag, ids) in [
                        (dir::DM_ADD, add),
                        (dir::DM_REMOVE, remove),
                        (dir::DM_REPLACE, replace),
                    ] {
                        for id in ids {
                            nested(w, member_tag, &[id.as_bytes()]);
                        }
                    }
                }
            }
        }
    }

    fn pred_parts<'x>(pred: Pred<'x>) -> (u32, &'x [u8], &'x [u8]) {
        match pred {
            Pred::Absent { key } => (commit::PRED_ABSENT, key, &[]),
            Pred::Present { key } => (commit::PRED_PRESENT, key, &[]),
            Pred::Equals { key, value } => (commit::PRED_EQUALS, key, value),
        }
    }

    /// One nested record from `parts`, inside room already made.
    fn nested(w: &mut Reply, record_tag: u16, parts: &[&[u8]]) {
        let len: usize = parts.iter().map(|part| part.len()).sum();
        let head = RecHead {
            tag: record_tag,
            _r: 0,
            len: len as u32,
        };
        w.append(head.as_bytes());
        for part in parts {
            w.append(part);
        }
        w.append(&ZEROS[..pad(len)]);
    }

    /// One NEED record: NeedRec with its four lengths, then the arguments back to back. Full = over the
    /// mail's cap or a length past u32; nothing is written then.
    fn put_need(w: &mut Reply, mut rec: NeedRec, args: [Arg<'_>; 4]) -> Result<(), Full> {
        let mut body = size_of::<NeedRec>();
        for (len, arg) in rec.lens.iter_mut().zip(args) {
            let n = arg.checked_len()?;
            *len = u32::try_from(n).map_err(|_| Full)?;
            body = body.checked_add(n).ok_or(Full)?;
        }
        let head = RecHead {
            tag: tag::NEED,
            _r: 0,
            len: u32::try_from(body).map_err(|_| Full)?,
        };
        let size = size_of::<RecHead>()
            .checked_add(body)
            .and_then(|n| n.checked_add(pad(body)))
            .ok_or(Full)?;
        w.room(size)?;
        w.append(head.as_bytes());
        w.append(rec.as_bytes());
        for arg in args {
            arg.write(w);
        }
        w.append(&ZEROS[..pad(body)]);
        Ok(())
    }

    /// A request on the wire, or its local answer.
    enum Wire<'x> {
        Need(NeedRec, [Arg<'x>; 4]),
        Local(NeedErr),
    }

    const fn need(op: u32, flags: u32, a: u64, b: u64, secret: u32, trust: u32) -> NeedRec {
        NeedRec {
            op,
            flags,
            a,
            b,
            secret,
            trust,
            lens: [0; 4],
        }
    }

    /// The stated egress class in NeedRec.flags bits 16..=19; a class past 15 is written as 15, which core
    /// answers INVALID like every class past 4.
    fn egress_bits(egress: u32) -> u32 {
        (egress.min(0xF) << need_flag::EGRESS_SHIFT) & need_flag::EGRESS_MASK
    }

    /// A `Tls` as NeedRec fields: mode, SNI, ALPN ids, trust handle, client-cert handle.
    struct TlsParts<'x> {
        mode: u32,
        sni: &'x str,
        alpn: &'x [&'x str],
        trust: u32,
        cert: u32,
    }
    fn tls_parts(tls: Tls<'_>) -> TlsParts<'_> {
        match tls {
            Tls::None => TlsParts {
                mode: need_flag::TLS_NONE,
                sni: "",
                alpn: &[],
                trust: 0,
                cert: 0,
            },
            Tls::Required { sni, alpn, trust } => TlsParts {
                mode: need_flag::TLS_REQUIRED,
                sni,
                alpn,
                trust: trust.0,
                cert: 0,
            },
            Tls::Mutual {
                sni,
                alpn,
                trust,
                cert,
            } => TlsParts {
                mode: need_flag::TLS_MUTUAL,
                sni,
                alpn,
                trust: trust.0,
                cert: cert.0,
            },
            Tls::Inband {
                sni,
                alpn,
                trust,
                cert,
            } => TlsParts {
                mode: need_flag::TLS_INBAND,
                sni,
                alpn,
                trust: trust.0,
                cert: cert.map_or(0, |cert| cert.0),
            },
        }
    }

    /// The NEED for `req` (§6.1 table), or its local answer.
    fn wire<'x>(req: &'x Req<'_>, serial: u64) -> Wire<'x> {
        if req.chain().is_some_and(|chain| chain != serial) {
            return Wire::Local(NeedErr::Invalid);
        }
        match req {
            Req::Open { dest, tls, egress } => {
                let t = tls_parts(*tls);
                Wire::Need(
                    need(
                        op::OPEN,
                        t.mode | egress_bits(*egress),
                        0,
                        0,
                        t.cert,
                        t.trust,
                    ),
                    [
                        Arg::Destination(*dest),
                        Arg::Bytes(t.sni.as_bytes()),
                        Arg::Alpn(t.alpn),
                        EMPTY,
                    ],
                )
            }
            Req::StartTls { conn, tls, .. } => {
                let mode = match tls {
                    Tls::None => return Wire::Local(NeedErr::Invalid),
                    Tls::Required { .. } | Tls::Inband { cert: None, .. } => {
                        need_flag::TLS_REQUIRED
                    }
                    Tls::Mutual { .. } | Tls::Inband { cert: Some(_), .. } => need_flag::TLS_MUTUAL,
                };
                let t = tls_parts(*tls);
                Wire::Need(
                    need(op::STARTTLS, mode, *conn, 0, t.cert, t.trust),
                    [
                        Arg::Bytes(t.sni.as_bytes()),
                        Arg::Alpn(t.alpn),
                        EMPTY,
                        EMPTY,
                    ],
                )
            }
            Req::Write { conn, bytes, .. } => Wire::Need(
                need(op::WRITE, 0, *conn, 0, 0, 0),
                [Arg::Bytes(bytes), EMPTY, EMPTY, EMPTY],
            ),
            Req::Read { conn, max, .. } | Req::ReadInto { conn, max, .. } => {
                Wire::Need(need(op::READ, 0, *conn, u64::from(*max), 0, 0), [EMPTY; 4])
            }
            Req::Close { conn, reusable, .. } => {
                let flags = if *reusable { need_flag::REUSABLE } else { 0 };
                Wire::Need(need(op::CLOSE, flags, *conn, 0, 0, 0), [EMPTY; 4])
            }
            Req::Fetch(fetch) => {
                let mode = if fetch.cert.is_some() {
                    need_flag::TLS_MUTUAL
                } else {
                    need_flag::TLS_NONE
                };
                Wire::Need(
                    need(
                        op::FETCH,
                        mode | egress_bits(fetch.egress),
                        0,
                        fetch.max_body,
                        fetch.cert.map_or(0, |cert| cert.0),
                        fetch.trust.0,
                    ),
                    [
                        Arg::Bytes(fetch.method.as_bytes()),
                        Arg::Bytes(fetch.url.as_bytes()),
                        Arg::Pairs(fetch.headers),
                        Arg::Bytes(fetch.body),
                    ],
                )
            }
            Req::Secret(handle) => Wire::Need(need(op::SECRET, 0, 0, 0, handle.0, 0), [EMPTY; 4]),
            Req::Record(record) => record_wire(*record),
            Req::Directory(op) => directory_wire(*op),
            Req::Batch { .. } => Wire::Local(NeedErr::Invalid),
        }
    }

    fn record_wire(record: Record<'_>) -> Wire<'_> {
        let rec = |flags: u32, a: u64, b: u64| need(op::RECORD, flags, a, b, 0, 0);
        match record {
            Record::Get { key } => Wire::Need(
                rec(need_flag::REC_GET, 0, 0),
                [Arg::Bytes(key), EMPTY, EMPTY, EMPTY],
            ),
            Record::Put { key, value, ttl_s } => Wire::Need(
                rec(need_flag::REC_PUT, ttl_s, 0),
                [Arg::Bytes(key), Arg::Bytes(value), EMPTY, EMPTY],
            ),
            Record::Claim { key, value, ttl_s } => Wire::Need(
                rec(need_flag::REC_CLAIM, ttl_s, 0),
                [Arg::Bytes(key), Arg::Bytes(value), EMPTY, EMPTY],
            ),
            Record::Del { key } => Wire::Need(
                rec(need_flag::REC_DEL, 0, 0),
                [Arg::Bytes(key), EMPTY, EMPTY, EMPTY],
            ),
            Record::List { prefix, limit } => Wire::Need(
                rec(need_flag::REC_LIST, 0, u64::from(limit)),
                [Arg::Bytes(prefix), EMPTY, EMPTY, EMPTY],
            ),
            Record::Commit(c) => Wire::Need(
                rec(need_flag::REC_COMMIT, 0, 0),
                [Arg::Commit(c), EMPTY, EMPTY, EMPTY],
            ),
        }
    }

    fn directory_wire(op: Dir<'_>) -> Wire<'_> {
        let rec = |code: u32, kind: u32, extra: u32, a: u64| {
            need(
                super::op::DIRECTORY,
                code | (kind << dir::KIND_SHIFT) | extra,
                a,
                0,
                0,
                0,
            )
        };
        match op {
            Dir::Get { kind, id } => Wire::Need(
                rec(dir::GET, kind, 0, 0),
                [Arg::Bytes(id.as_bytes()), EMPTY, EMPTY, EMPTY],
            ),
            Dir::Lookup { kind, index, value } => Wire::Need(
                rec(dir::LOOKUP, kind, 0, 0),
                [
                    Arg::Bytes(index.as_bytes()),
                    Arg::Bytes(value),
                    EMPTY,
                    EMPTY,
                ],
            ),
            Dir::Scan {
                kind,
                scope,
                after,
                limit,
            } => Wire::Need(
                rec(dir::SCAN, kind, 0, u64::from(limit)),
                [
                    Arg::Bytes(scope.as_bytes()),
                    Arg::Bytes(after.as_bytes()),
                    EMPTY,
                    EMPTY,
                ],
            ),
            Dir::Count { kind, scope } => Wire::Need(
                rec(dir::COUNT, kind, 0, 0),
                [Arg::Bytes(scope.as_bytes()), EMPTY, EMPTY, EMPTY],
            ),
            Dir::Create {
                kind,
                state,
                pull,
                document,
                indexes,
            } => {
                let pulled = if pull { dir::PULL } else { 0 };
                Wire::Need(
                    rec(dir::CREATE, kind, (state << dir::STATE_SHIFT) | pulled, 0),
                    [EMPTY, Arg::Bytes(document), Arg::Pairs(indexes), EMPTY],
                )
            }
            Dir::Apply {
                kind,
                id,
                expected_version,
                apply,
                state,
                document,
                indexes,
                add,
                remove,
                replace,
            } => Wire::Need(
                rec(
                    dir::APPLY,
                    kind,
                    (apply << dir::APPLY_SHIFT) | (state << dir::STATE_SHIFT),
                    expected_version,
                ),
                [
                    Arg::Bytes(id.as_bytes()),
                    Arg::Bytes(document),
                    Arg::Pairs(indexes),
                    Arg::Members {
                        add,
                        remove,
                        replace,
                    },
                ],
            ),
            Dir::Delete {
                kind,
                id,
                expected_version,
            } => Wire::Need(
                rec(dir::DELETE, kind, 0, expected_version),
                [Arg::Bytes(id.as_bytes()), EMPTY, EMPTY, EMPTY],
            ),
        }
    }

    // ---- reading NEED_RES records ----

    /// This step's results from one future's first record on, and the chain serial its conns carry.
    struct Results<'b> {
        recs: Records<'b>,
        serial: u64,
    }

    /// One NEED_RES: result a and b, data0 and data1.
    struct Res<'b> {
        a: u64,
        b: u64,
        data0: &'b [u8],
        data1: &'b [u8],
    }

    impl<'b> Results<'b> {
        /// The results from NEED_RES `index` on.
        fn at(bytes: &'b [u8], index: u32, serial: u64) -> Self {
            let mut results = Results {
                recs: Records::new(bytes),
                serial,
            };
            for _ in 0..index {
                results.raw();
            }
            results
        }
        /// The next NEED_RES, whatever its status; anything else is a host bug (FAULT BadRecords).
        fn raw(&mut self) -> (u32, u32, Res<'b>) {
            let Some(Ok(rec)) = self.recs.next_rec() else {
                bad()
            };
            if rec.tag != tag::NEED_RES {
                bad()
            }
            let Ok((head, tail)) = rec.pod_tail::<NeedResRec>() else {
                bad()
            };
            let Ok(len0) = usize::try_from(head.lens[0]) else {
                bad()
            };
            let Some((data0, data1)) = tail.split_at_checked(len0) else {
                bad()
            };
            if head._r != 0 || usize::try_from(head.lens[1]).ok() != Some(data1.len()) {
                bad()
            }
            let res = Res {
                a: head.a,
                b: head.b,
                data0,
                data1,
            };
            (head.op, head.status, res)
        }
        /// The next NEED_RES, which must answer `op`: its data on OK, else the step's error.
        fn next(&mut self, expect: u32) -> Result<Res<'b>, NeedErr> {
            let (got, status, res) = self.raw();
            if got != expect {
                bad()
            }
            match status {
                need_status::OK => Ok(res),
                need_status::DENIED => Err(NeedErr::Denied),
                need_status::UNAVAILABLE => Err(NeedErr::Unavailable),
                need_status::TIMEOUT => Err(NeedErr::Timeout),
                need_status::ABSENT => Err(NeedErr::Absent),
                need_status::TAKEN => Err(NeedErr::Taken),
                need_status::LIMIT => Err(NeedErr::Limit),
                need_status::TLS => Err(NeedErr::Tls),
                need_status::CLOSED => Err(NeedErr::Closed),
                need_status::SKIPPED => Err(NeedErr::Skipped),
                need_status::INVALID => Err(NeedErr::Invalid),
                _ => bad(),
            }
        }
    }

    fn text(bytes: &[u8]) -> String {
        match core::str::from_utf8(bytes) {
            Ok(text) => text.to_owned(),
            Err(_) => bad(),
        }
    }

    /// A PAIR record's name and value, bytes as written.
    fn pair_bytes<'b>(rec: &Rec<'b>) -> (&'b [u8], &'b [u8]) {
        if rec.tag != tag::PAIR {
            bad()
        }
        let Ok((head, tail)) = rec.pod_tail::<PairRec>() else {
            bad()
        };
        let Ok(name_len) = usize::try_from(head.name_len) else {
            bad()
        };
        match tail.split_at_checked(name_len) {
            Some(split) if head._r == 0 => split,
            _ => bad(),
        }
    }

    /// Nested PAIR records as (name, value).
    fn pairs(bytes: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
        Records::new(bytes).map(|rec| match rec {
            Ok(rec) => pair_bytes(&rec),
            Err(_) => bad(),
        })
    }

    /// Nested PAIR records with a UTF-8 name.
    fn text_pairs(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        pairs(bytes)
            .map(|(name, value)| (text(name), value.to_vec()))
            .collect()
    }

    fn unit(req: &mut Req<'_>, results: &mut Results<'_>) -> Result<(), NeedErr> {
        results.next(req.op()).map(drop)
    }

    fn opened(req: &mut Req<'_>, results: &mut Results<'_>) -> Result<Opened, NeedErr> {
        let res = results.next(req.op())?;
        let Ok(pooled) = <[u8; open_flag::POOLED_ID_LEN as usize]>::try_from(res.data1) else {
            bad()
        };
        let alpn = (!res.data0.is_empty()).then(|| text(res.data0));
        Ok(Opened {
            conn: Conn {
                id: res.a,
                chain: results.serial,
            },
            reused: res.b & open_flag::REUSED != 0,
            tls_resumed: res.b & open_flag::TLS_RESUMED != 0,
            tls_done: res.b & open_flag::TLS_DONE != 0,
            pooled: u64::from_le_bytes(pooled),
            alpn,
        })
    }

    fn read_bytes(req: &mut Req<'_>, results: &mut Results<'_>) -> Result<SecureVec, NeedErr> {
        results.next(req.op()).map(|res| SecureVec::from(res.data0))
    }

    fn read_appended(req: &mut Req<'_>, results: &mut Results<'_>) -> Result<bool, NeedErr> {
        let res = results.next(op::READ)?;
        let Req::ReadInto { buf, .. } = req else {
            bad()
        };
        buf.extend_from_slice(res.data0);
        Ok(res.b == 1)
    }

    fn fetched_answer(results: &mut Results<'_>) -> Result<Fetched, NeedErr> {
        let res = results.next(op::FETCH)?;
        let Ok(status) = u16::try_from(res.a) else {
            bad()
        };
        Ok(Fetched {
            status,
            headers: pairs(res.data1)
                .map(|(name, value)| (text(name), SecureVec::from(value)))
                .collect(),
            body: SecureVec::from(res.data0),
        })
    }

    fn fetched(req: &mut Req<'_>, results: &mut Results<'_>) -> Result<Fetched, NeedErr> {
        let _ = req;
        fetched_answer(results)
    }

    fn secret_value(req: &mut Req<'_>, results: &mut Results<'_>) -> Result<SecureVec, NeedErr> {
        results.next(req.op()).map(|res| SecureVec::from(res.data0))
    }

    fn record_out(record: Record<'_>, results: &mut Results<'_>) -> Result<RecordOut, NeedErr> {
        let res = results.next(op::RECORD)?;
        Ok(match record {
            Record::Get { .. } => RecordOut::Value((res.a == 1).then(|| res.data0.to_vec())),
            Record::Put { .. } | Record::Del { .. } => RecordOut::Done,
            Record::Claim { .. } => RecordOut::Won(res.a == 1),
            Record::List { .. } => RecordOut::List(
                pairs(res.data0)
                    .map(|(key, value)| (key.to_vec(), value.to_vec()))
                    .collect(),
            ),
            Record::Commit(_) => {
                if res.a == u64::from(commit::APPLIED) {
                    RecordOut::Committed(Ok(()))
                } else if res.a == u64::from(commit::CONFLICT) {
                    let Ok(failed) = u32::try_from(res.b) else {
                        bad()
                    };
                    RecordOut::Committed(Err(failed))
                } else {
                    bad()
                }
            }
        })
    }

    fn record_answer(req: &mut Req<'_>, results: &mut Results<'_>) -> Result<RecordOut, NeedErr> {
        let Req::Record(record) = req else { bad() };
        record_out(*record, results)
    }

    fn directory_answer(req: &mut Req<'_>, results: &mut Results<'_>) -> Result<DirOut, NeedErr> {
        let Req::Directory(op) = req else { bad() };
        let op = *op;
        let res = results.next(super::op::DIRECTORY)?;
        let facts = if res.data1.is_empty() {
            DirFacts {
                state: 0,
                more: 0,
                active: 0,
            }
        } else {
            match DirFacts::read_from_bytes(res.data1) {
                Ok(facts) => facts,
                Err(_) => bad(),
            }
        };
        let mut out = DirOut {
            code: (res.a & 0xFFFF_FFFF) as u32,
            index: (res.a >> 32) as u32,
            version: 0,
            count: 0,
            facts,
            id: String::new(),
            document: Vec::new(),
            indexes: Vec::new(),
            rows: Vec::new(),
        };
        if out.code != dir::OK {
            return Ok(out);
        }
        match op {
            Dir::Get { .. } => {
                out.version = res.b;
                for rec in Records::new(res.data0) {
                    let Ok(rec) = rec else { bad() };
                    match rec.tag {
                        dir::ID => out.id = text(rec.body),
                        dir::DOC => out.document = rec.body.to_vec(),
                        _ => {
                            let (name, value) = pair_bytes(&rec);
                            out.indexes.push((text(name), value.to_vec()));
                        }
                    }
                }
            }
            Dir::Lookup { .. } => out.id = text(res.data0),
            Dir::Create { .. } => {
                out.id = text(res.data0);
                out.version = res.b;
            }
            Dir::Apply { .. } => out.version = res.b,
            Dir::Scan { .. } => {
                out.count = res.b;
                out.rows = text_pairs(res.data0);
            }
            Dir::Count { .. } => out.count = res.b,
            Dir::Delete { .. } => {}
        }
        Ok(out)
    }

    fn batch_item(req: &mut Req<'_>, results: &mut Results<'_>) -> Result<Done, NeedErr> {
        match req {
            Req::Write { .. } => results.next(op::WRITE).map(|_| Done::Unit),
            Req::Read { .. } => results
                .next(op::READ)
                .map(|res| Done::Read(SecureVec::from(res.data0))),
            Req::Fetch(_) => fetched_answer(results).map(Done::Fetched),
            Req::Secret(_) => results
                .next(op::SECRET)
                .map(|res| Done::Secret(SecureVec::from(res.data0))),
            Req::Record(record) => record_out(*record, results).map(Done::Record),
            _ => bad(),
        }
    }

    fn batch_answer(
        req: &mut Req<'_>,
        results: &mut Results<'_>,
    ) -> Result<Vec<Result<Done, NeedErr>>, NeedErr> {
        let Req::Batch { items, sent } = req else {
            bad()
        };
        let sent = *sent;
        let mut failed = false;
        let mut answers = Vec::with_capacity(items.len());
        for (i, item) in items.iter_mut().enumerate() {
            let answer = if i < sent {
                batch_item(item, results)
            } else if i == sent && !failed {
                Err(NeedErr::Invalid)
            } else {
                Err(NeedErr::Skipped)
            };
            failed |= answer.is_err();
            answers.push(answer);
        }
        Ok(answers)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::records::Writer;

        fn needs(bytes: &[u8]) -> Vec<(NeedRec, Vec<Vec<u8>>)> {
            Records::new(bytes)
                .map(|rec| {
                    let Ok(rec) = rec else { panic!("framing") };
                    assert_eq!(rec.tag, tag::NEED);
                    let Ok((head, mut tail)) = rec.pod_tail::<NeedRec>() else {
                        panic!("NeedRec")
                    };
                    let mut args = Vec::new();
                    for len in head.lens {
                        let (arg, rest) = tail.split_at(len as usize);
                        args.push(arg.to_vec());
                        tail = rest;
                    }
                    assert!(tail.is_empty(), "the lengths cover the body");
                    (head, args)
                })
                .collect()
        }

        fn written(req: &Req<'_>) -> (NeedRec, Vec<Vec<u8>>) {
            let Wire::Need(rec, args) = wire(req, 9) else {
                panic!("local")
            };
            let mut w = Reply::new();
            assert!(put_need(&mut w, rec, args).is_ok());
            let mut all = needs(w.as_bytes());
            assert_eq!(all.len(), 1);
            all.remove(0)
        }

        #[test]
        fn open_parts_and_single_destination_have_identical_runtime_encoding() {
            use super::super::Destination;
            for text in [
                "",
                "db.test:0",
                "[::1]:65535",
                "unix:/path",
                &"a".repeat(2049),
            ] {
                let (first, rest) = text.split_at(text.len() / 2);
                let parts = [first, "", rest];
                let one = written(&Req::Open {
                    dest: Destination::One(text),
                    tls: Tls::None,
                    egress: 2,
                });
                let many = written(&Req::Open {
                    dest: Destination::Parts(&parts),
                    tls: Tls::None,
                    egress: 2,
                });
                assert_eq!(one.0.as_bytes(), many.0.as_bytes());
                assert_eq!(one.1, many.1);
            }
            let alpn = ["h2", "http/1.1"];
            let parts = ["db.", "test", ":443"];
            for tls in [
                Tls::None,
                Tls::Required {
                    sni: "db.test",
                    alpn: &alpn,
                    trust: TrustHandle(3),
                },
                Tls::Mutual {
                    sni: "db.test",
                    alpn: &alpn,
                    trust: TrustHandle(3),
                    cert: SecretHandle(4),
                },
                Tls::Inband {
                    sni: "db.test",
                    alpn: &alpn,
                    trust: TrustHandle(3),
                    cert: Some(SecretHandle(4)),
                },
            ] {
                let one = written(&Req::Open {
                    dest: Destination::One("db.test:443"),
                    tls,
                    egress: 2,
                });
                let many = written(&Req::Open {
                    dest: Destination::Parts(&parts),
                    tls,
                    egress: 2,
                });
                assert_eq!(one.0.as_bytes(), many.0.as_bytes());
                assert_eq!(one.1, many.1);
            }
        }

        #[test]
        fn a_parts_need_over_the_output_limit_leaves_existing_records_unchanged() {
            let text = "x".repeat(16 * 1024 * 1024);
            let parts = [text.as_str(), ":80"];
            let request = Req::Open {
                dest: super::super::Destination::Parts(&parts),
                tls: Tls::None,
                egress: 2,
            };
            let Wire::Need(rec, args) = wire(&request, 9) else {
                panic!("wire")
            };
            let mut out = Reply::new();
            out.put_text(tag::TEXT, "retained").unwrap();
            let before = out.as_bytes().to_vec();
            assert!(put_need(&mut out, rec, args).is_err());
            assert_eq!(out.as_bytes(), before);
        }

        #[test]
        fn failed_parts_sends_preserve_prior_mail_and_count_for_single_and_batch() {
            let text = "x".repeat(16 * 1024 * 1024);
            let parts = [text.as_str(), ":80"];
            for batch in [false, true] {
                let mut mail = Mail {
                    key: bridge::ChainKey {
                        thread: 1,
                        serial: 9,
                    },
                    step: 0,
                    results: None,
                    needs: Reply::new(),
                    count: 3,
                };
                mail.needs.put_text(tag::TEXT, "retained").unwrap();
                let before = mail.needs.as_bytes().to_vec();
                let large = Req::Open {
                    dest: super::super::Destination::Parts(&parts),
                    tls: Tls::None,
                    egress: 2,
                };
                let mut request = if batch {
                    Req::Batch {
                        items: vec![Req::Secret(SecretHandle(1)), large],
                        sent: 0,
                    }
                } else {
                    large
                };
                assert!(matches!(
                    send(&mut request, &mut mail),
                    Wrote::Local(NeedErr::Limit)
                ));
                assert_eq!(mail.count, 3);
                assert_eq!(mail.needs.as_bytes(), before);
            }
        }

        /// The §6.1 table, request side: op, flags, a/b, handles and every argument as core decodes them.
        #[test]
        fn requests_go_on_the_wire_as_the_table_says() {
            let alpn = ["h2", "http/1.1"];
            let tls = Tls::Mutual {
                sni: "db.test",
                alpn: &alpn,
                trust: TrustHandle(3),
                cert: SecretHandle(4),
            };
            let (rec, args) = written(&Req::Open {
                dest: super::super::Destination::One("db.test:5432"),
                tls,
                egress: super::super::egress::OPERATOR_INFRASTRUCTURE,
            });
            assert_eq!((rec.op, rec.secret, rec.trust), (op::OPEN, 4, 3));
            assert_eq!(rec.flags, need_flag::TLS_MUTUAL | (2 << 16));
            assert_eq!(args[0], b"db.test:5432");
            assert_eq!(args[1], b"db.test");
            assert_eq!(args[2], b"h2,http/1.1");

            let (rec, _) = written(&Req::Open {
                dest: super::super::Destination::One("x:1"),
                tls: Tls::None,
                egress: 99,
            });
            assert_eq!(rec.flags, 0xF << 16, "out of range stays out of range");

            let headers: [(&str, &[u8]); 2] = [("accept", b"*/*"), ("x-k", b"v")];
            let fetch = Fetch {
                method: "POST",
                url: "https://idp.test/token",
                headers: &headers,
                body: b"grant",
                max_body: 4096,
                trust: TrustHandle::NONE,
                cert: None,
                egress: super::super::egress::OPEN_WEB,
            };
            let (rec, args) = written(&Req::Fetch(&fetch));
            assert_eq!((rec.op, rec.b, rec.flags), (op::FETCH, 4096, 3 << 16));
            let pairs: Vec<_> = pairs(&args[2])
                .map(|(n, v)| (n.to_vec(), v.to_vec()))
                .collect();
            assert_eq!(
                pairs,
                [
                    (b"accept".to_vec(), b"*/*".to_vec()),
                    (b"x-k".to_vec(), b"v".to_vec())
                ]
            );
            assert_eq!(args[3], b"grant");

            let preds = [Pred::Equals {
                key: b"k",
                value: b"v1",
            }];
            let muts = [
                Mut::Put {
                    key: b"k",
                    value: b"v2",
                    ttl_s: 60,
                },
                Mut::Del { key: b"old" },
            ];
            let c = Commit {
                preds: &preds,
                muts: &muts,
            };
            let (rec, args) = written(&Req::Record(Record::Commit(&c)));
            assert_eq!((rec.op, rec.flags), (op::RECORD, need_flag::REC_COMMIT));
            let tags: Vec<u16> = Records::new(&args[0])
                .map(|r| r.map(|r| r.tag).unwrap_or(0))
                .collect();
            assert_eq!(tags, [tag::REC_PRED, tag::REC_PUT, tag::REC_DEL]);

            let (rec, args) = written(&Req::Directory(Dir::Apply {
                kind: dir::GROUP,
                id: "g1",
                expected_version: 5,
                apply: dir::APPLY_REPLACE_MEMBERS,
                state: 0,
                document: b"",
                indexes: &[],
                add: &["a"],
                remove: &["b", "c"],
                replace: &[],
            }));
            assert_eq!(rec.op, op::DIRECTORY);
            assert_eq!(
                rec.flags,
                dir::APPLY | (dir::GROUP << dir::KIND_SHIFT) | (8 << dir::APPLY_SHIFT)
            );
            assert_eq!(rec.a, 5);
            let members: Vec<u16> = Records::new(&args[3])
                .map(|r| r.map(|r| r.tag).unwrap_or(0))
                .collect();
            assert_eq!(members, [dir::DM_ADD, dir::DM_REMOVE, dir::DM_REMOVE]);

            let (rec, _) = written(&Req::Close {
                conn: 7,
                chain: 9,
                reusable: true,
            });
            assert_eq!(
                (rec.op, rec.a, rec.flags),
                (op::CLOSE, 7, need_flag::REUSABLE)
            );
        }

        #[test]
        fn a_conn_of_another_chain_and_a_plain_starttls_never_go_out() {
            let foreign = Req::Write {
                conn: 1,
                chain: 8,
                bytes: b"x",
            };
            assert!(matches!(wire(&foreign, 9), Wire::Local(NeedErr::Invalid)));
            let plain = Req::StartTls {
                conn: 1,
                chain: 9,
                tls: Tls::None,
            };
            assert!(matches!(wire(&plain, 9), Wire::Local(NeedErr::Invalid)));
        }

        fn result(w: &mut Reply, op: u32, status: u32, a: u64, b: u64, d0: &[u8], d1: &[u8]) {
            let head = NeedResRec {
                op,
                status,
                a,
                b,
                lens: [d0.len() as u32, d1.len() as u32],
                _r: 0,
            };
            let mut tail = d0.to_vec();
            tail.extend_from_slice(d1);
            assert!(w.put_pod_tail(tag::NEED_RES, &head, &tail).is_ok());
        }

        /// The §6.1 table, answer side, and a batch's per-item answers.
        #[test]
        fn answers_decode_as_the_table_says() {
            let mut w = Reply::new();
            result(
                &mut w,
                op::OPEN,
                0,
                11,
                open_flag::REUSED | open_flag::TLS_DONE,
                b"h2",
                &42u64.to_le_bytes(),
            );
            result(&mut w, op::SECRET, need_status::ABSENT, 0, 0, b"", b"");
            result(&mut w, op::RECORD, 0, 1, 0, b"value", b"");
            let bytes = w.as_bytes();

            let mut req = Req::Open {
                dest: super::super::Destination::One("x:1"),
                tls: Tls::None,
                egress: 0,
            };
            let Ok(o) = opened(&mut req, &mut Results::at(bytes, 0, 9)) else {
                panic!("opened")
            };
            assert_eq!((o.conn.id, o.conn.chain, o.pooled), (11, 9, 42));
            assert!(o.reused && o.tls_done && !o.tls_resumed);
            assert_eq!(o.alpn.as_deref(), Some("h2"));

            let mut req = Req::Secret(SecretHandle(1));
            assert!(matches!(
                secret_value(&mut req, &mut Results::at(bytes, 1, 9)),
                Err(NeedErr::Absent)
            ));
            let mut req = Req::Record(Record::Get { key: b"k" });
            let answer = record_answer(&mut req, &mut Results::at(bytes, 2, 9));
            assert!(matches!(answer, Ok(RecordOut::Value(Some(ref v))) if v == b"value"));

            let conn = Conn { id: 3, chain: 9 };
            let foreign = Conn { id: 4, chain: 8 };
            let mut batch = Batch::new();
            batch
                .write(&conn, b"a")
                .write(&foreign, b"b")
                .secret(SecretHandle(2));
            let mut req = Req::Batch {
                items: core::mem::take(&mut batch.items),
                sent: 1,
            };
            let mut w = Reply::new();
            result(&mut w, op::WRITE, 0, 1, 0, b"", b"");
            let Ok(answers) = batch_answer(&mut req, &mut Results::at(w.as_bytes(), 0, 9)) else {
                panic!("batch")
            };
            assert!(matches!(answers[0], Ok(Done::Unit)));
            assert!(matches!(answers[1], Err(NeedErr::Invalid)));
            assert!(matches!(answers[2], Err(NeedErr::Skipped)));
        }

        #[test]
        fn read_into_grows_by_copy_and_reports_eof() {
            let mut buf = SecureVec::with_capacity(2).expect("allocation");
            buf.extend_from_slice(b"ab");
            buf.extend_from_slice(b"cdef");
            assert_eq!(buf.as_slice(), b"abcdef");
            let mut w = Reply::new();
            result(&mut w, op::READ, 0, 1, 1, b"g", b"");
            let mut req = Req::ReadInto {
                conn: 1,
                chain: 9,
                max: 10,
                buf: &mut buf,
            };
            assert_eq!(
                read_appended(&mut req, &mut Results::at(w.as_bytes(), 0, 9)),
                Ok(true)
            );
            assert_eq!(buf.as_slice(), b"abcdefg");
        }

        #[test]
        fn a_malformed_answer_panics_as_bad_records() {
            let mut w = Reply::new();
            result(&mut w, op::READ, 0, 0, 0, b"", b"");
            let bytes = w.as_bytes().to_vec();
            let wrong_op = std::panic::catch_unwind(move || {
                let mut req = Req::Secret(SecretHandle(1));
                let _ = secret_value(&mut req, &mut Results::at(&bytes, 0, 9));
            });
            assert!(wrong_op.is_err());
            let mut w = Reply::new();
            result(&mut w, op::OPEN, 0, 1, 0, b"", b"short");
            let bytes = w.as_bytes().to_vec();
            let short_pooled = std::panic::catch_unwind(move || {
                let mut req = Req::Open {
                    dest: super::super::Destination::One("x:1"),
                    tls: Tls::None,
                    egress: 0,
                };
                let _ = opened(&mut req, &mut Results::at(&bytes, 0, 9));
            });
            assert!(short_pooled.is_err());
        }

        /// No chain is being polled: a Need future is FAULT NeedOutsideAsync, and it wrote nothing anywhere.
        #[test]
        fn a_need_future_outside_a_chain_panics() {
            let polled = std::panic::catch_unwind(|| {
                let mut fut = core::pin::pin!(secret(SecretHandle(1)));
                let mut cx = Context::from_waker(core::task::Waker::noop());
                let _ = core::future::Future::poll(fut.as_mut(), &mut cx);
            });
            assert!(polled.is_err());
        }
    }
}

#[cfg(test)]
mod destination_tests {
    use super::{Destination, sum_lengths};

    #[test]
    fn destination_length_checks_overflow_without_fake_slices() {
        assert_eq!(sum_lengths([usize::MAX, 1].into_iter()), None);
        assert_eq!(
            sum_lengths([usize::MAX - 1, 1].into_iter()),
            Some(usize::MAX)
        );
        assert_eq!(Destination::Parts(&["a", "", "bc"]).checked_len(), Some(3));
    }
}
