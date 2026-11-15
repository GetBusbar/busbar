// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Need steps: the wire, chain-scoped argument handles and the plugin-side Need API (IF §6.1, §6.2, §6.3). W0-ABI stub: frozen signatures, `todo!()` bodies; A3 fills it.

use core::cell::Cell;
use core::marker::PhantomData;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

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

/// An async argument. Valid only while its own chain is being polled on this thread.
/// No Deref, AsRef, Borrow, Index, as_ptr, guard type or IntoIterator. `!Sync`, `Send`.
/// The check value is `ChainId`, which is **never reused while the image is mapped** and, round 7, **does not
/// depend on the slot table at all** (so the §6.5 free-list sharding branch keeps it unchanged): `inst` is a 64-bit
/// serial from a per-image `static NEXT_INST: AtomicU64` taken once per `Inst` (cold, in `open`; the global open
/// slab is serial 0, real instances start at 1); `thread` is the starting thread's ordinal, taken once per thread
/// from a per-image `static NEXT_THREAD: AtomicU32` on its first chain start (one RMW per thread lifetime; 0 is
/// never issued; at 2^32 − 1 the image FAULTs `Exhausted` on further chain starts, unreachable in practice);
/// `serial` is that thread's own chain counter, a `const`-initialised `Cell<u64>` thread-local (no destructor,
/// I13) bumped by a plain store on every chain start (no RMW). (thread, serial) is unique for every chain the
/// image ever starts and cannot wrap (2^64 per thread), so a handle stashed anywhere (a
/// `static Mutex<Option<ChainBytes>>`, `Box::leak`) fails the check in every later chain, including chains of a
/// reopened instance at the same address and chains in the same slot after any number of reuses, whatever the
/// slot table's own generation does. A stash cannot outlive the image either: its static lives in the image (I13).
pub struct ChainBytes {
    ptr: *const u8,
    len: usize,
    id: ChainId,
    _ns: PhantomData<Cell<()>>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChainId {
    inst: u64,
    thread: u32,
    serial: u64,
}
impl ChainBytes {
    /// Checks CURRENT.id == self.id (one TLS load, three compares), then calls f.
    /// Any other thread or chain: panic -> FAULT StaleHandle.
    pub fn with<R>(&self, f: impl for<'a> FnOnce(&'a [u8]) -> R) -> R {
        let _ = (
            self.ptr,
            self.len,
            self.id.inst,
            self.id.thread,
            self.id.serial,
            f,
        );
        todo!()
    }
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
    /// Checked copy: the way to keep bytes across an .await or past the chain.
    pub fn to_vec(&self) -> Vec<u8> {
        todo!()
    }
}
// W0-ABI: `unsafe impl Send for ChainBytes {}` is in the IF (W1-A3 adds it with its escape); until then the raw
// `ptr` field leaves the stub `!Send` as well as `!Sync`.

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
    use core::marker::PhantomData;

    use super::{DirFacts, SecretHandle, TrustHandle};

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
        pub headers: Vec<(String, Vec<u8>)>,
        pub body: Vec<u8>,
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
        // W0-ABI: args borrowed for 'a; Option<(ChainId, u32 step, u32 index)>; state (W1-A3).
        _stub: PhantomData<(&'a (), fn() -> T)>,
    }
    impl<T> core::future::Future for NeedFut<'_, T> {
        type Output = Result<T, NeedErr>;
        fn poll(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<Self::Output> {
            let _ = (self, cx);
            todo!()
        }
    }

    /// `egress` = the stated class (`egress::*`; round 7): OPERATOR_INFRASTRUCTURE for a database, directory or
    /// secret service, LOOPBACK_ALLOWED for a local collector, and so on. Out of range => INVALID. Round 24:
    /// `dest` = `host:port`, or `unix:/abs/path` with `Tls::None` and OPERATOR_INFRASTRUCTURE (§12.1).
    pub fn open<'a>(dest: &'a str, tls: Tls<'a>, egress: u32) -> NeedFut<'a, Opened> {
        let _ = (dest, tls, egress);
        todo!()
    }
    pub fn starttls<'a>(c: &'a Conn, tls: Tls<'a>) -> NeedFut<'a, ()> {
        let _ = (c, tls);
        todo!()
    }
    pub fn write<'a>(c: &'a Conn, bytes: &'a [u8]) -> NeedFut<'a, ()> {
        let _ = (c, bytes);
        todo!()
    }
    /// Ok(empty) = EOF.
    pub fn read(c: &Conn, max: u32) -> NeedFut<'_, Vec<u8>> {
        let _ = (c.id, c.chain, max);
        todo!()
    }
    /// Appends to `buf` (reuse it across reads: no allocation once it has capacity). Ok(true) = EOF.
    /// When `buf` lacks capacity, abi grows it by allocate, copy, zero the old block, free (I11), never `reserve`.
    pub fn read_into<'a>(c: &'a Conn, max: u32, buf: &'a mut Vec<u8>) -> NeedFut<'a, bool> {
        let _ = (c, max, buf);
        todo!()
    }
    pub fn close(c: Conn, reusable: bool) -> NeedFut<'static, ()> {
        let _ = (c, reusable);
        todo!()
    }
    pub fn fetch<'a>(req: &'a Fetch<'a>) -> NeedFut<'a, Fetched> {
        let _ = req;
        todo!()
    }
    // W0-ABI: `pub fn secret(handle: SecretHandle) -> NeedFut<'static, zeroize::Zeroizing<Vec<u8>>>;` is in the IF;
    // zeroize is not a W0-ABI dependency (CONVENTIONS rule 10), so it lands with W1-A3.
    pub fn record(op: Record<'_>) -> NeedFut<'_, RecordOut> {
        let _ = op;
        todo!()
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
        let _ = op;
        todo!()
    }

    /// Pipelining: several Needs in one step (one resume). Results come back in push order.
    // W0-ABI: `Default` is derived only so clippy's `new_without_default` stays quiet on the stub.
    #[derive(Default)]
    pub struct Batch<'a> {
        // W0-ABI: private state (W1-A3).
        _stub: PhantomData<&'a ()>,
    }
    pub enum Done {
        Opened(Opened),
        Unit,
        Read(Vec<u8>),
        Fetched(Fetched),
        // W0-ABI: `Secret(zeroize::Zeroizing<Vec<u8>>)` is in the IF here; it lands with W1-A3 (no zeroize in W0).
        Record(RecordOut),
    }
    impl<'a> Batch<'a> {
        pub fn new() -> Self {
            todo!()
        }
        pub fn write(&mut self, c: &'a Conn, bytes: &'a [u8]) -> &mut Self {
            let _ = (c, bytes);
            todo!()
        }
        pub fn read(&mut self, c: &'a Conn, max: u32) -> &mut Self {
            let _ = (c, max);
            todo!()
        }
        pub fn fetch(&mut self, req: &'a Fetch<'a>) -> &mut Self {
            let _ = req;
            todo!()
        }
        pub fn secret(&mut self, handle: SecretHandle) -> &mut Self {
            let _ = handle;
            todo!()
        }
        pub fn record(&mut self, op: Record<'a>) -> &mut Self {
            let _ = op;
            todo!()
        }
        pub fn run(self) -> NeedFut<'a, Vec<Result<Done, NeedErr>>> {
            todo!()
        }
    }
}
