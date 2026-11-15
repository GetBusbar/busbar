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
