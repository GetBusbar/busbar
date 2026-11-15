// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store kind: the `Store` trait and the `store` module (IF §8.1, §10.4). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-A5 fills it.

crate::kind::kind_stub! {
    /// A store is a database driver. It runs the backend protocol and reports facts. Core owns candidates,
    /// retries, readback and the R0 import of its own records (MIGRATE-ON-BOOT r6 §6). Round 30: the commit is
    /// STORE-TRANSACTIONS §2.5 M1 with G1 and G2 (§2.4 N1-N13), which origin/dev f6e2cf05d7 already carries
    /// (contract abi/store/v4.rs:443-458, persistence.rs `Decision` with Fenced/Stale, `commit(candidate, key:
    /// CommitKey)` :625; §16.146). The store converts its own physical format in `open` (§7.2, round 31), with its own driver.
    pub trait Store: Send + Sync + 'static {
        /// Coherent multi-address read at one serialization point. Answer: READ_DONE, then one VALUE per ADDRESS
        /// in order (none if READ_TIME_GUARD_FAILED).
        fn read(
            &self,
            h: &'static crate::host::Host,
            req: crate::need::ChainBytes,
        ) -> impl core::future::Future<Output = Result<crate::records::Reply, crate::fail::Fail>> + Send;
        /// One ordered namespace page. Answer: SCAN_DONE, ROW* (≤ max_rows, ≤ max_bytes), NEXT if SCAN_CONTINUE.
        fn scan(
            &self,
            h: &'static crate::host::Host,
            req: crate::need::ChainBytes,
        ) -> impl core::future::Future<Output = Result<crate::records::Reply, crate::fail::Fail>> + Send;
        /// One atomic native transaction: STORE-TRANSACTIONS §2.5 M1 (slot record, FENCEs, guard, predicates,
        /// mutations). Answer: COMMITTED (code COMMIT_APPLIED..=COMMIT_STALE), with no RESULT (N5). Evaluated
        /// verdicts are answers (OK + COMMITTED). FAILED means unevaluated or unknown; core resolves it by readback.
        /// G1: a DeleteRange on SLOT_NS deletes the writer's slot records. G2: the SDK decode FAULTs any other
        /// SLOT_NS mutation, any GENERATION_NS mutation, and any condition on GENERATION_NS whose key is not 16 bytes.
        fn commit(
            &self,
            h: &'static crate::host::Host,
            cand: crate::need::ChainBytes,
        ) -> impl core::future::Future<Output = Result<crate::records::Reply, crate::fail::Fail>> + Send;
        /// Authoritative UTC for `dataset` (16 bytes). Answer: CLOCK.
        fn clock(
            &self,
            h: &'static crate::host::Host,
            dataset: crate::need::ChainBytes,
        ) -> impl core::future::Future<Output = Result<crate::records::Reply, crate::fail::Fail>> + Send;
        /// Cold, pure: the facts of the backend this instance opened. Called by the store adapter exactly once,
        /// right after `open` returns INSTANCE and before any other method; the answer is cached for the
        /// instance's life (`PersistenceBackend::info`). Answer: exactly one INFO. An instance whose facts
        /// change (a different dataset after failover) is a new instance: core reopens it.
        fn info(
            &self,
            h: &crate::host::Host,
            out: &mut crate::records::Out<'_>,
        ) -> Result<(), crate::fail::Fail>;
    }
}

pub mod store {
    //! The store kind's records, constants and method bits (IF §8.1), and its host-side `Proxy` (§10.4).

    /// UTC interval; flags TIME_NOT_BEFORE | TIME_BEFORE; zero = unguarded.
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct TimeGuard {
        pub flags: u32,
        pub _r: u32,
        pub not_before: u64,
        pub before: u64,
    }
    /// Exact replay identity (unchanged from v4.rs AttemptId).
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct AttemptId {
        pub dataset: [u8; 16],
        pub writer: [u8; 16],
        pub operation: [u8; 16],
        pub writer_epoch: u64,
        pub execution_epoch: u64,
    }
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct ReadHead {
        pub dataset: [u8; 16],
        pub guard: TimeGuard,
    }
    /// Tail = key bytes.
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct AddressRec {
        pub namespace: [u8; 16],
    }
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct ScanHead {
        pub dataset: [u8; 16],
        pub namespace: [u8; 16],
        pub flags: u32,
        pub max_rows: u32,
        pub generation: u64,
        pub max_bytes: u64,
    }
    /// Round 30 (N1): slot < MAX_SLOTS with seq ≥ 1, or SLOT_SELF_FENCED with seq 0; anything else Refused.
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct CandHead {
        pub id: AttemptId,
        pub codec: u32,
        pub slot: u32,
        pub seq: u64,
        pub guard: TimeGuard,
    }
    /// Tail = key (key_len) then expected bytes.
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct PredicateRec {
        pub namespace: [u8; 16],
        pub tag: u32,
        pub key_len: u32,
    }
    /// Tail = key (key_len) then value bytes.
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct MutationRec {
        pub namespace: [u8; 16],
        pub tag: u32,
        pub key_len: u32,
        pub exact_length: u64,
    }
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct ReadDone {
        pub code: u32,
        pub _r: u32,
        pub observed_at: u64,
        pub authority: [u8; 16],
    }
    /// Tail = value bytes; one per requested address, in request order.
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct ValueRec {
        pub found: u32,
        pub _r: u32,
    }
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct ScanDone {
        pub code: u32,
        pub continuation: u32,
        pub generation: u64,
    }
    /// Tail = key (key_len) then value.
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct RowRec {
        pub key_len: u32,
        pub _r: u32,
    }
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct Committed {
        pub code: u32,
        pub _r: u32,
        pub observed_at: u64,
        pub authority: [u8; 16],
    }
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct ClockRec {
        pub observed_at: u64,
        pub authority: [u8; 16],
    }
    /// One R0 cell (MIGRATE-ON-BOOT r6 §4; replaces contract `legacy_row.rs` Cell, byte-identical to
    /// `abi::sdk::store::cells`). kind = CELL_*; INT: tail = i64 LE; REAL: tail = f64 bits LE; TEXT/BLOB:
    /// tail = bytes; NULL: no tail. An R0 value is CELL records in the fixed column order of its table.
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct CellRec {
        pub kind: u32,
        pub _r: u32,
    }
    /// The opened backend's facts (busbar-contract persistence.rs BackendInfo, field for field):
    /// dataset = persistent identity of the selected dataset; atomic_domain = the one native atomicity
    /// domain covering every namespace of it; clock_authority = the authority every time-bearing op
    /// reports (READ_DONE/COMMITTED/CLOCK `authority` must equal it); physical_version = the store's own
    /// physical format after `migrate`; durability = DUR_*. 56 bytes, no padding.
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct InfoRec {
        pub dataset: [u8; 16],
        pub atomic_domain: [u8; 16],
        pub clock_authority: [u8; 16],
        pub physical_version: u32,
        pub durability: u32,
    }

    // W1-A5: `kind!` (W1-A4) emits these `Pod` impls for every `pods {}` struct; the stub swap deletes them.
    impl crate::records::Pod for TimeGuard {}
    impl crate::records::Pod for AttemptId {}
    impl crate::records::Pod for ReadHead {}
    impl crate::records::Pod for AddressRec {}
    impl crate::records::Pod for ScanHead {}
    impl crate::records::Pod for CandHead {}
    impl crate::records::Pod for PredicateRec {}
    impl crate::records::Pod for MutationRec {}
    impl crate::records::Pod for ReadDone {}
    impl crate::records::Pod for ValueRec {}
    impl crate::records::Pod for ScanDone {}
    impl crate::records::Pod for RowRec {}
    impl crate::records::Pod for Committed {}
    impl crate::records::Pod for ClockRec {}
    impl crate::records::Pod for CellRec {}
    impl crate::records::Pod for InfoRec {}

    pub mod tag {
        /// read request: one READ_HEAD then ADDRESS*.
        pub const READ_HEAD: u16 = 0x0100;
        pub const ADDRESS: u16 = 0x0101;
        /// scan request: SCAN_HEAD, SCAN_PREFIX, SCAN_AFTER (only with SCAN_AFTER flag).
        pub const SCAN_HEAD: u16 = 0x0102;
        pub const SCAN_PREFIX: u16 = 0x0103;
        pub const SCAN_AFTER: u16 = 0x0104;
        /// commit candidate: CAND_HEAD, FENCE*, PREDICATE*, MUTATION*, RESULT. FENCE is a PredicateRec body (N9).
        pub const CAND_HEAD: u16 = 0x0105;
        pub const PREDICATE: u16 = 0x0106;
        pub const MUTATION: u16 = 0x0107;
        pub const RESULT: u16 = 0x0108;
        pub const FENCE: u16 = 0x0109;
        /// answers.
        pub const READ_DONE: u16 = 0x0110;
        pub const VALUE: u16 = 0x0111;
        pub const SCAN_DONE: u16 = 0x0112;
        pub const ROW: u16 = 0x0113;
        pub const NEXT: u16 = 0x0114;
        pub const COMMITTED: u16 = 0x0115;
        pub const CLOCK: u16 = 0x0116;
        /// `info` answer: exactly one INFO (InfoRec).
        pub const INFO: u16 = 0x0117;
        /// R0 cell (CellRec + tail), written by the store's own `migrate` into IMPORT_NS values and read by
        /// core's R0 step through the ordinary `scan`. 0x0120..=0x0122 and 0x0124..=0x0127 are retired
        /// (round 4's `native` vocabulary, deleted in round 5).
        pub const CELL: u16 = 0x0123;
    }

    pub const REQUIRED: u64 = 0b11111;
    /// Round 11, describe fact bit (D_FACTS): this store does blocking local-file I/O (fsync, file locks,
    /// SQLite `busy_timeout` sleeps) inside its polls and never NEEDs. Core makes every entry of such an
    /// instance on its store lane (a blocking-pool thread, never a tokio worker) under the store-lane
    /// ceilings (§10.6, §11.3), and refuses any NEED from it (FAULT NeedNotAllowed, §6.1).
    pub const F_BLOCKING_FILE: u64 = 0b1;
    /// Round 12, describe fact bit (D_FACTS; MIGRATE-ON-BOOT r15 item (f)): what this store holds is lost
    /// when the process ends (today's `MARK_EPHEMERAL` / linked `ephemeral`). Static: core reads it at
    /// `Registry::add`, before any instance opens, for its kind-generic absent-store rule (§12.10 item 1).
    /// An instance's `info` must answer DUR_EPHEMERAL exactly when this bit is set; a mismatch refuses
    /// the open (`OpenError::Config { code: R_INVALID, text }`, core text "the store's `info` durability
    /// disagrees with its describe facts") before any read or write.
    pub const FB_EPHEMERAL: u64 = 0b10;
    /// InfoRec.durability (persistence.rs Durability): state lost with the process / acknowledged on
    /// authoritative local storage / acknowledged by a durable quorum (async replicas are not a quorum).
    pub const DUR_EPHEMERAL: u32 = 1;
    pub const DUR_LOCAL: u32 = 2;
    pub const DUR_QUORUM: u32 = 3;
    pub const TIME_NOT_BEFORE: u32 = 1;
    pub const TIME_BEFORE: u32 = 2;
    pub const PREDICATE_ABSENT: u32 = 1;
    pub const PREDICATE_EXACT: u32 = 2;
    pub const MUTATION_PUT: u32 = 1;
    pub const MUTATION_DELETE: u32 = 2;
    pub const MUTATION_DELETE_RANGE: u32 = 3;
    pub const READ_VALUES: u32 = 1;
    pub const READ_TIME_GUARD_FAILED: u32 = 2;
    pub const SCAN_FLAG_AFTER: u32 = 1;
    pub const SCAN_FLAG_GENERATION: u32 = 2;
    pub const SCAN_FLAG_ALLOW_CHANGE: u32 = 4;
    pub const SCAN_PAGE: u32 = 1;
    pub const SCAN_STALE: u32 = 2;
    pub const SCAN_EXHAUSTED: u32 = 1;
    pub const SCAN_CONTINUE: u32 = 2;
    pub const COMMIT_APPLIED: u32 = 1;
    pub const COMMIT_CONDITION_CONFLICT: u32 = 2;
    pub const COMMIT_TIME_GUARD_FAILED: u32 = 3;
    /// Round 30 (N2-N4, f6e2cf05d7 v4.rs:443-458 byte for byte): 5 = FENCED: a fence failed; this send applied
    /// nothing. 6 = STALE: the slot already evaluated a later sequence; this send applied nothing and never will.
    pub const COMMIT_OPID_CONFLICT: u32 = 4;
    pub const COMMIT_FENCED: u32 = 5;
    pub const COMMIT_STALE: u32 = 6;
    pub const SLOT_SELF_FENCED: u32 = u32::MAX;
    pub const MAX_SLOTS: u32 = 65_536;
    pub const CODEC_VERSION: u32 = 1;
    pub const CELL_NULL: u32 = 0;
    pub const CELL_INT: u32 = 1;
    pub const CELL_REAL: u32 = 2;
    pub const CELL_TEXT: u32 = 3;
    pub const CELL_BLOB: u32 = 4;
    /// The R0 import namespace (MIGRATE-ON-BOOT r6 §4): written only by this store's own `migrate`, with its
    /// own driver, into a namespace verified empty first; core reserves it in FST admission and drains it.
    /// Key = R0 table tag (u8) ‖ PK cells; value = CELL* in the table's fixed column order.
    pub const IMPORT_NS: [u8; 16] = *b"busbar.import.r0";
    /// Slot records (G1): key writer16 ‖ slot u32 BE; the only mutation is DeleteRange{writer16, 20}, the store's per-writer delete.
    pub const SLOT_NS: [u8; 16] = *b"busbar.slot.v1\0\0";
    /// Generation records (G2: never a mutation; a condition's key is a 16-byte namespace N and locks N).
    pub const GENERATION_NS: [u8; 16] = *b"busbar.scan.v1\0\0";
    /// R0 table tags. SUMMARY (one row): physical from-version; per tag 1-7 `source_rows`, `emitted`,
    /// `consumed` (0; core-maintained); `headless_cells`; source digest. KEY / CREDENTIAL / METERING: the
    /// sqlite v1.0.6 column order of `keys` / `credentials` / `usage_metering`. REVISION: store revision
    /// (i64). DENY: sub, reason, created_at. USAGE: one cell per 1.5.5 bucket key: flags (bit 0 =
    /// R0_HEADLESS), bucket key cells, window_start, requests, billable_requests, then per model: model,
    /// requests, billable_requests, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write.
    /// AUDIT: seq, ts, action, resource, outcome, principal, prev_hash, hash. Counts stay in 1.5.5 whole
    /// units; a u64 above i64::MAX is refused BOUNDS.
    pub const R0_SUMMARY: u8 = 0;
    pub const R0_KEY: u8 = 1;
    pub const R0_CREDENTIAL: u8 = 2;
    pub const R0_REVISION: u8 = 3;
    pub const R0_DENY: u8 = 4;
    pub const R0_USAGE: u8 = 5;
    pub const R0_METERING: u8 = 6;
    pub const R0_AUDIT: u8 = 7;
    pub const R0_HEADLESS: u32 = 1;

    pub const KIND: crate::types::KindCode = crate::types::KindCode::Store;
    pub const ABI: u32 = 3;
    pub const FP: u64 = 0; // W0-ABI stub value; kind! computes it (W1-A4).

    pub const M_READ: u64 = 1 << 0;
    pub const M_SCAN: u64 = 1 << 1;
    pub const M_COMMIT: u64 = 1 << 2;
    pub const M_CLOCK: u64 = 1 << 3;
    pub const M_INFO: u64 = 1 << 4;
    pub const ALL: u64 = M_READ | M_SCAN | M_COMMIT | M_CLOCK | M_INFO;

    // W0-ABI: `Vt` (fields read, scan, commit, clock, info are unsafe extern "C" fn pointers) and the
    // `vt::<T>()` shims are unsafe; they land with W1-A4 (`kind!`) under an escapes.json admission.

    /// `vt` points into the plugin image; it is valid because `inst` holds the image (I13), and it is never
    /// handed out with a lifetime longer than `&self`.
    #[cfg(feature = "host")]
    pub struct Proxy {
        // W0-ABI: fields `inst: Arc<Instance>` and `vt: NonNull<Vt>` land with W1-A4; `vt` needs the unsafe
        // `Vt`, and the `unsafe impl Send/Sync for Proxy` and `pub unsafe fn bind` land with it.
        _stub: core::marker::PhantomData<std::sync::Arc<crate::host_side::driver::Instance>>,
    }

    #[cfg(feature = "host")]
    impl Proxy {
        pub fn instance(&self) -> &std::sync::Arc<crate::host_side::driver::Instance> {
            let _ = &self._stub;
            todo!()
        }

        pub fn read<'a, N: crate::host_side::needs::Needs>(
            &'a self,
            drv: &'a mut crate::host_side::driver::Driver<'a, N>,
            req: crate::host_side::pool::PooledOut,
        ) -> impl core::future::Future<
            Output = Result<crate::host_side::answer::OwnedAnswer, crate::fail::CallError>,
        > + Send
        + 'a {
            let _ = (&self._stub, drv, req);
            async move { todo!() }
        }

        pub fn scan<'a, N: crate::host_side::needs::Needs>(
            &'a self,
            drv: &'a mut crate::host_side::driver::Driver<'a, N>,
            req: crate::host_side::pool::PooledOut,
        ) -> impl core::future::Future<
            Output = Result<crate::host_side::answer::OwnedAnswer, crate::fail::CallError>,
        > + Send
        + 'a {
            let _ = (&self._stub, drv, req);
            async move { todo!() }
        }

        pub fn commit<'a, N: crate::host_side::needs::Needs>(
            &'a self,
            drv: &'a mut crate::host_side::driver::Driver<'a, N>,
            req: crate::host_side::pool::PooledOut,
        ) -> impl core::future::Future<
            Output = Result<crate::host_side::answer::OwnedAnswer, crate::fail::CallError>,
        > + Send
        + 'a {
            let _ = (&self._stub, drv, req);
            async move { todo!() }
        }

        pub fn clock<'a, N: crate::host_side::needs::Needs>(
            &'a self,
            drv: &'a mut crate::host_side::driver::Driver<'a, N>,
            req: crate::host_side::pool::PooledOut,
        ) -> impl core::future::Future<
            Output = Result<crate::host_side::answer::OwnedAnswer, crate::fail::CallError>,
        > + Send
        + 'a {
            let _ = (&self._stub, drv, req);
            async move { todo!() }
        }

        pub fn info<'o>(
            &self,
            buf: &'o mut crate::host_side::pool::PooledOut,
        ) -> Result<crate::host_side::answer::Answer<'o>, crate::fail::CallError> {
            let _ = (&self._stub, buf);
            todo!()
        }
    }
}

/// Plugin-side typed helpers every store shares (STORE-TRANSACTIONS Decision 299 §2.4 "SDK plumbing", r39 "MIN-3
/// home"; W1-A5). They sit outside the `kind!` block, so they are not FP-hashed: `Verdict`, `SlotRow` with its
/// packed codec and replay mapping, `holds`, `prelude_order`, the commit decode with its G2 `match` and the
/// `CommitHead` carrier, and the receipt-era refusal. A store depends on busbar-plugin-abi only, so nothing here
/// names busbar-contract: the replay mapping yields the wire `Committed` record, not a `Decision`.
pub mod plumbing {
    use super::store::{AttemptId, CandHead, Committed, TimeGuard};
    use crate::records::{RecErr, Records};

    /// `physical_version` of a receipt-era dataset; M4 refuses it at `open`.
    pub const RECEIPT_ERA_VERSION: u32 = 1;
    /// The one explanation every store gives for a receipt-era dataset.
    pub const RECEIPT_ERA_REFUSAL: &str =
        "pre-release receipt-era dataset; recreate it or re-run the 1.5.5 migration";

    /// A recorded evaluation, stored as the wire `COMMIT_*` code.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Verdict {
        /// `COMMIT_APPLIED`.
        Applied = 1,
        /// `COMMIT_CONDITION_CONFLICT`.
        Conflict = 2,
        /// `COMMIT_TIME_GUARD_FAILED`.
        TimeGuard = 3,
    }

    /// A stored slot row that cannot be decoded.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Corrupt;

    impl Verdict {
        /// The stored byte.
        pub fn to_u8(self) -> u8 {
            todo!()
        }
        /// The wire `COMMIT_*` code.
        pub fn code(self) -> u32 {
            todo!()
        }
        /// Decode a stored byte; anything else is a corrupt row.
        pub fn from_u8(code: u8) -> Result<Self, Corrupt> {
            let _ = code;
            todo!()
        }
    }

    /// One (writer, slot) row: the last evaluated sequence, its fingerprint, verdict and serialization time.
    /// A missing row is `seq == 0`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SlotRow {
        /// Last evaluated lease sequence.
        pub seq: u64,
        /// Candidate fingerprint of that evaluation.
        pub fp: [u8; 32],
        /// Its verdict.
        pub verdict: Verdict,
        /// Its serialization time, in Unix seconds.
        pub observed: u64,
    }

    /// Length of [`SlotRow::encode_packed`].
    pub const PACKED_LEN: usize = 4 + 8 + 32 + 1 + 8;

    /// What M1 step 2 does with an incoming `(seq, fp)` against the slot's row.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Judgement {
        /// No row, or an earlier sequence: evaluate and write the row.
        Fresh,
        /// Equal sequence and fingerprint: answer the recorded verdict, write nothing.
        Replay,
        /// Equal sequence, different fingerprint: `COMMIT_OPID_CONFLICT`, write nothing.
        OpIdConflict,
        /// The row holds a later sequence: `COMMIT_STALE`, write nothing.
        Stale,
    }

    impl SlotRow {
        /// The recorded answer an equal-sequence replay returns, at its original time.
        pub fn replay(&self, authority: [u8; 16]) -> Committed {
            let _ = authority;
            todo!()
        }
        /// Packed value for key-value stores: `'BVS1' | seq LE8 | fp32 | verdict u8 | observed LE8`.
        pub fn encode_packed(&self) -> [u8; PACKED_LEN] {
            todo!()
        }
        /// Decode [`Self::encode_packed`]; any other length, magic or verdict is `Corrupt`.
        pub fn decode_packed(bytes: &[u8]) -> Result<Self, Corrupt> {
            let _ = bytes;
            todo!()
        }
    }

    /// M1 step 2 over the slot's current row (`None` = no row).
    pub fn judge(row: Option<&SlotRow>, seq: u64, fp: &[u8; 32]) -> Judgement {
        let _ = (row, seq, fp);
        todo!()
    }

    /// One condition against the pre-mutation state: `PREDICATE_ABSENT` needs no live value, `PREDICATE_EXACT`
    /// needs exactly `expected`; any other tag never holds (the decode already FAULTed it).
    pub fn holds(tag: u32, expected: &[u8], current: Option<&[u8]>) -> bool {
        let _ = (tag, expected, current);
        todo!()
    }

    /// How an address takes part in M1 step 0.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Use {
        /// A `read` address: locks its namespace shared.
        Read,
        /// A FENCE or PREDICATE: shared; on `GENERATION_NS` it locks the namespace its 16-byte key names (G2).
        Condition,
        /// A MUTATION: locks its namespace exclusive.
        Mutation,
    }

    /// Step 0's lock set and acquisition order (N12): each namespace once, in byte order, exclusive when any
    /// item mutates it. Input is `(namespace, key, use)`.
    pub fn prelude_order<'a>(
        items: impl IntoIterator<Item = (&'a [u8; 16], &'a [u8], Use)>,
    ) -> Vec<([u8; 16], bool)> {
        let _ = items;
        todo!()
    }

    /// One decoded FENCE or PREDICATE: `expected` is empty for `PREDICATE_ABSENT`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Cond<'a> {
        pub namespace: [u8; 16],
        pub tag: u32,
        pub key: &'a [u8],
        pub expected: &'a [u8],
    }

    /// One decoded MUTATION. `value` is empty for a Delete or DeleteRange (whose `key` is the prefix and
    /// `exact_length` the matched key length).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Mut<'a> {
        pub namespace: [u8; 16],
        pub tag: u32,
        pub key: &'a [u8],
        pub value: &'a [u8],
        pub exact_length: u64,
    }

    /// The commit's dedupe key after N1 validation.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum CommitSlot {
        /// `slot < MAX_SLOTS`, `seq >= 1`.
        Slotted { slot: u32, seq: u64 },
        /// `SLOT_SELF_FENCED` with `seq == 0`.
        SelfFenced,
    }

    /// The carrier for decoded fences (one, in the SDK): the validated head and the FENCE records.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct CommitHead<'a> {
        pub id: AttemptId,
        pub codec: u32,
        pub guard: TimeGuard,
        pub slot: CommitSlot,
        pub fences: Vec<Cond<'a>>,
    }

    /// A decoded commit candidate, borrowed from the request.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Commit<'a> {
        pub head: CommitHead<'a>,
        pub predicates: Vec<Cond<'a>>,
        pub mutations: Vec<Mut<'a>>,
        pub result: &'a [u8],
    }

    /// Why a commit request is not run.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum CommitErr {
        /// A malformed buffer or a G2 violation: the caller FAULTs before the store runs.
        Fault(RecErr),
        /// N1: a slot and sequence that are neither slotted nor self-fenced: REFUSED.
        Refused,
    }

    /// Decode a commit request: `CAND_HEAD, FENCE*, PREDICATE*, MUTATION*, RESULT`, with N1 on the head and
    /// G2 (N13) on every record. `METRIC` records are skipped.
    pub fn decode_commit(req: Records<'_>) -> Result<Commit<'_>, CommitErr> {
        let _ = (req, core::marker::PhantomData::<CandHead>);
        todo!()
    }
}

#[cfg(test)]
#[path = "store_plumbing_tests.rs"]
mod plumbing_tests;
