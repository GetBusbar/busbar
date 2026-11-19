// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store kind: the `Store` trait and the `store` module (IF §8, §10.4), one `kind!` block (W1-A4b).

crate::kind! {
    /// A store is a database driver. It runs the backend protocol and reports facts. Core owns candidates,
    /// retries, readback and the R0 import of its own records (MIGRATE-ON-BOOT r6 §6). Round 30: the commit is
    /// STORE-TRANSACTIONS §2.5 M1 with G1 and G2 (§2.4 N1-N13), which origin/dev f6e2cf05d7 already carries
    /// (contract abi/store/v4.rs:443-458, persistence.rs `Decision` with Fenced/Stale, `commit(candidate, key:
    /// CommitKey)` :625; §16.146). The store converts its own physical format in `open` (§7.2, round 31), with its own driver.
    pub trait Store: kind = 1, abi = 4 {
        views {
        }
        pods {
        /// UTC interval; flags TIME_NOT_BEFORE | TIME_BEFORE; zero = unguarded.
        pub struct TimeGuard {
            pub flags: u32,
            pub _r: u32,
            pub not_before: u64,
            pub before: u64,
        }
        /// Exact replay identity (unchanged from v4.rs AttemptId).
        pub struct AttemptId {
            pub dataset: [u8; 16],
            pub writer: [u8; 16],
            pub operation: [u8; 16],
            pub writer_epoch: u64,
            pub execution_epoch: u64,
        }
        pub struct ReadHead {
            pub dataset: [u8; 16],
            pub guard: TimeGuard,
        }
        /// Tail = key bytes.
        pub struct AddressRec {
            pub namespace: [u8; 16],
        }
        pub struct ScanHead {
            pub dataset: [u8; 16],
            pub namespace: [u8; 16],
            pub flags: u32,
            pub max_rows: u32,
            pub generation: u64,
            pub max_bytes: u64,
        }
        /// Round 30 (N1): slot < MAX_SLOTS with seq ≥ 1, or SLOT_SELF_FENCED with seq 0; anything else Refused.
        pub struct CandHead {
            pub id: AttemptId,
            pub codec: u32,
            pub slot: u32,
            pub seq: u64,
            pub guard: TimeGuard,
        }
        /// Tail = key (key_len) then expected bytes.
        pub struct PredicateRec {
            pub namespace: [u8; 16],
            pub tag: u32,
            pub key_len: u32,
        }
        /// Tail = key (key_len) then value bytes.
        pub struct MutationRec {
            pub namespace: [u8; 16],
            pub tag: u32,
            pub key_len: u32,
            pub exact_length: u64,
        }
        pub struct ReadDone {
            pub code: u32,
            pub _r: u32,
            pub observed_at: u64,
            pub authority: [u8; 16],
        }
        /// Tail = value bytes; one per requested address, in request order.
        pub struct ValueRec {
            pub found: u32,
            pub _r: u32,
        }
        pub struct ScanDone {
            pub code: u32,
            pub continuation: u32,
            pub generation: u64,
        }
        /// Tail = key (key_len) then value.
        pub struct RowRec {
            pub key_len: u32,
            pub _r: u32,
        }
        pub struct Committed {
            pub code: u32,
            pub _r: u32,
            pub observed_at: u64,
            pub authority: [u8; 16],
        }
        pub struct ClockRec {
            pub observed_at: u64,
            pub authority: [u8; 16],
        }
        /// One R0 cell (MIGRATE-ON-BOOT r6 §4; replaces contract `legacy_row.rs` Cell, byte-identical to
        /// `abi::sdk::store::cells`). kind = CELL_*; INT: tail = i64 LE; REAL: tail = f64 bits LE; TEXT/BLOB:
        /// tail = bytes; NULL: no tail. An R0 value is CELL records in the fixed column order of its table.
        pub struct CellRec {
            pub kind: u32,
            pub _r: u32,
        }
        /// The opened backend's facts (busbar-contract persistence.rs BackendInfo, field for field):
        /// dataset = persistent identity of the selected dataset; atomic_domain = the one native atomicity
        /// domain covering every namespace of it; clock_authority = the authority every time-bearing op
        /// reports (READ_DONE/COMMITTED/CLOCK `authority` must equal it); physical_version = the store's own
        /// physical format after `migrate`; durability = DUR_*. 56 bytes, no padding.
        pub struct InfoRec {
            pub dataset: [u8; 16],
            pub atomic_domain: [u8; 16],
            pub clock_authority: [u8; 16],
            pub physical_version: u32,
            pub durability: u32,
        }
        }
        tags {
            /// read request: one READ_HEAD then ADDRESS*.
            READ_HEAD = 0x0100;
            ADDRESS = 0x0101;
            /// scan request: SCAN_HEAD, SCAN_PREFIX, SCAN_AFTER (only with SCAN_AFTER flag).
            SCAN_HEAD = 0x0102;
            SCAN_PREFIX = 0x0103;
            SCAN_AFTER = 0x0104;
            /// commit candidate: CAND_HEAD, FENCE*, PREDICATE*, MUTATION*, RESULT. FENCE is a PredicateRec body (N9).
            CAND_HEAD = 0x0105;
            PREDICATE = 0x0106;
            MUTATION = 0x0107;
            RESULT = 0x0108;
            FENCE = 0x0109;
            /// answers.
            READ_DONE = 0x0110;
            VALUE = 0x0111;
            SCAN_DONE = 0x0112;
            ROW = 0x0113;
            NEXT = 0x0114;
            COMMITTED = 0x0115;
            CLOCK = 0x0116;
            /// `info` answer: exactly one INFO (InfoRec).
            INFO = 0x0117;
            /// R0 cell (CellRec + tail), written by the store's own `migrate` into IMPORT_NS values and read by
            /// core's R0 step through the ordinary `scan`. 0x0120..=0x0122 and 0x0124..=0x0127 are retired
            /// (round 4's `native` vocabulary, deleted in round 5).
            CELL = 0x0123;
        }
        consts {
            REQUIRED: u64 = 0b11111;
        /// Round 11, describe fact bit (D_FACTS): this store does blocking local-file I/O (fsync, file locks,
        /// SQLite `busy_timeout` sleeps) inside its polls and never NEEDs. Core makes every entry of such an
        /// instance on its store lane (a blocking-pool thread, never a tokio worker) under the store-lane
        /// ceilings (§10.6, §11.3), and refuses any NEED from it (FAULT NeedNotAllowed, §6.1).
            F_BLOCKING_FILE: u64 = 0b1;
        /// Round 12, describe fact bit (D_FACTS; MIGRATE-ON-BOOT r15 item (f)): what this store holds is lost
        /// when the process ends (today's `MARK_EPHEMERAL` / linked `ephemeral`). Static: core reads it at
        /// `Registry::add`, before any instance opens, for its kind-generic absent-store rule (§12.10 item 1).
        /// An instance's `info` must answer DUR_EPHEMERAL exactly when this bit is set; a mismatch refuses
        /// the open (`OpenError::Config { code: R_INVALID, text }`, core text "the store's `info` durability
        /// disagrees with its describe facts") before any read or write.
            FB_EPHEMERAL: u64 = 0b10;
        /// InfoRec.durability (persistence.rs Durability): state lost with the process / acknowledged on
        /// authoritative local storage / acknowledged by a durable quorum (async replicas are not a quorum).
            DUR_EPHEMERAL: u32 = 1;
            DUR_LOCAL: u32 = 2;
            DUR_QUORUM: u32 = 3;
            TIME_NOT_BEFORE: u32 = 1;
            TIME_BEFORE: u32 = 2;
            PREDICATE_ABSENT: u32 = 1;
            PREDICATE_EXACT: u32 = 2;
            MUTATION_PUT: u32 = 1;
            MUTATION_DELETE: u32 = 2;
            MUTATION_DELETE_RANGE: u32 = 3;
            READ_VALUES: u32 = 1;
            READ_TIME_GUARD_FAILED: u32 = 2;
            SCAN_FLAG_AFTER: u32 = 1;
            SCAN_FLAG_GENERATION: u32 = 2;
            SCAN_FLAG_ALLOW_CHANGE: u32 = 4;
            SCAN_PAGE: u32 = 1;
            SCAN_STALE: u32 = 2;
            SCAN_EXHAUSTED: u32 = 1;
            SCAN_CONTINUE: u32 = 2;
            COMMIT_APPLIED: u32 = 1;
            COMMIT_CONDITION_CONFLICT: u32 = 2;
            COMMIT_TIME_GUARD_FAILED: u32 = 3;
        /// Round 30 (N2-N4, f6e2cf05d7 v4.rs:443-458 byte for byte): 5 = FENCED: a fence failed; this send applied
        /// nothing. 6 = STALE: the slot already evaluated a later sequence; this send applied nothing and never will.
            COMMIT_OPID_CONFLICT: u32 = 4;
            COMMIT_FENCED: u32 = 5;
            COMMIT_STALE: u32 = 6;
            COMMIT_CAPACITY_REFUSED: u32 = 7;
            SLOT_SELF_FENCED: u32 = u32::MAX;
            MAX_SLOTS: u32 = 65_536;
            CODEC_VERSION: u32 = 1;
            CELL_NULL: u32 = 0;
            CELL_INT: u32 = 1;
            CELL_REAL: u32 = 2;
            CELL_TEXT: u32 = 3;
            CELL_BLOB: u32 = 4;
        /// The R0 import namespace (MIGRATE-ON-BOOT r6 §4): written only by this store's own `migrate`, with its
        /// own driver, into a namespace verified empty first; core reserves it in FST admission and drains it.
        /// Key = R0 table tag (u8) ‖ PK cells; value = CELL* in the table's fixed column order.
            IMPORT_NS: [u8; 16] = *b"busbar.import.r0";
        /// Slot records (G1): key writer16 ‖ slot u32 BE; the only mutation is DeleteRange{writer16, 20}, the store's per-writer delete.
            SLOT_NS: [u8; 16] = *b"busbar.slot.v1\0\0";
        /// Generation records (G2: never a mutation; a condition's key is a 16-byte namespace N and locks N).
            GENERATION_NS: [u8; 16] = *b"busbar.scan.v1\0\0";
        /// R0 table tags. SUMMARY (one row): physical from-version; per tag 1-7 `source_rows`, `emitted`,
        /// `consumed` (0; core-maintained); `headless_cells`; source digest. KEY / CREDENTIAL / METERING: the
        /// sqlite v1.0.6 column order of `keys` / `credentials` / `usage_metering`. REVISION: store revision
        /// (i64). DENY: sub, reason, created_at. USAGE: one cell per 1.5.5 bucket key: flags (bit 0 =
        /// R0_HEADLESS), bucket key cells, window_start, requests, billable_requests, then per model: model,
        /// requests, billable_requests, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write.
        /// AUDIT: seq, ts, action, resource, outcome, principal, prev_hash, hash. Counts stay in 1.5.5 whole
        /// units; a u64 above i64::MAX is refused BOUNDS.
            R0_SUMMARY: u8 = 0;
            R0_KEY: u8 = 1;
            R0_CREDENTIAL: u8 = 2;
            R0_REVISION: u8 = 3;
            R0_DENY: u8 = 4;
            R0_USAGE: u8 = 5;
            R0_METERING: u8 = 6;
            R0_AUDIT: u8 = 7;
            R0_HEADLESS: u32 = 1;
            M_READ: u64 = 1 << 0;
            M_SCAN: u64 = 1 << 1;
            M_COMMIT: u64 = 1 << 2;
            M_CLOCK: u64 = 1 << 3;
            M_INFO: u64 = 1 << 4;
        }
        /// Coherent multi-address read at one serialization point. Answer: READ_DONE, then one VALUE per ADDRESS
        /// in order (none if READ_TIME_GUARD_FAILED).
        async fn read(&self, h: &'static Host, req: ChainBytes) -> Result<Reply, Fail>;
        /// One ordered namespace page. Answer: SCAN_DONE, ROW* (≤ max_rows, ≤ max_bytes), NEXT if SCAN_CONTINUE.
        async fn scan(&self, h: &'static Host, req: ChainBytes) -> Result<Reply, Fail>;
        /// One atomic native transaction: STORE-TRANSACTIONS §2.5 M1 (slot record, FENCEs, guard, predicates,
        /// mutations). Answer: COMMITTED (code COMMIT_APPLIED..=COMMIT_CAPACITY_REFUSED), with no RESULT (N5). Evaluated
        /// verdicts are answers (OK + COMMITTED). FAILED means unevaluated or unknown; core resolves it by readback.
        /// G1: a DeleteRange on SLOT_NS deletes the writer's slot records. G2: the SDK decode FAULTs any other
        /// SLOT_NS mutation, any GENERATION_NS mutation, and any condition on GENERATION_NS whose key is not 16 bytes.
        async fn commit(&self, h: &'static Host, cand: ChainBytes) -> Result<Reply, Fail>;
        /// Authoritative UTC for `dataset` (16 bytes). Answer: CLOCK.
        async fn clock(&self, h: &'static Host, dataset: ChainBytes) -> Result<Reply, Fail>;
        /// Cold, pure: the facts of the backend this instance opened. Called by the store adapter exactly once,
        /// right after `open` returns INSTANCE and before any other method; the answer is cached for the
        /// instance's life (`PersistenceBackend::info`). Answer: exactly one INFO. An instance whose facts
        /// change (a different dataset after failover) is a new instance: core reopens it.
        /// E.9: keep, implemented by every store image (the method has no default body, so each of
        /// store-memory, -sqlite, -postgres, -mysql and -valkey states it). The candidate head (CAND_HEAD,
        /// `CandHead`) is kept too: it is the first record of every `commit` request, written and read
        /// through this module's helpers, which is why a word search of the images does not find it.
        sync fn info(&self, h: &Host, out: &mut Out<'_>) -> Result<(), Fail>;

        extras {
            /// The host side of the store kind: a typed face over busbar-ffi's `Instance` (IF §10.4).
            /// `live` points into the plugin image and is valid because `inst` holds the image (I13).
            #[cfg(feature = "host")]
            pub struct Proxy {
                /// Declared first so it drops first: `inst`'s `Drop` then holds the last `Arc` of the live instance
                /// and runs `close` under the entry guard as this instance's slot (C-CLOSE-LOG, 632805ee11).
                live: std::sync::Arc<busbar_ffi::host::Instance<Marker>>,
                inst: std::sync::Arc<crate::host_side::driver::Instance>,
            }

            #[cfg(feature = "host")]
            impl Proxy {
                /// Bind. Done by the loader only, after admit; None when `inst` is not a store instance.
                pub fn bind(inst: std::sync::Arc<crate::host_side::driver::Instance>) -> Option<Self> {
                    let live = inst.live::<Marker>()?;
                    Some(Proxy { inst, live })
                }

                pub fn instance(&self) -> &std::sync::Arc<crate::host_side::driver::Instance> {
                    &self.inst
                }

                pub fn read<'a, N: crate::host_side::needs::Needs>(
                    &'a self,
                    drv: &'a mut crate::host_side::driver::Driver<'a, N>,
                    req: crate::host_side::pool::PooledOut,
                ) -> impl core::future::Future<
                    Output = Result<crate::host_side::answer::OwnedAnswer, crate::fail::CallError>,
                > + Send
                + 'a {
                    use crate::host_side::proxy;
                    proxy::chain::<Marker, _, _>(&self.inst, drv, proxy::entry(M_READ), req, |req, lease| {
                        let _ = req;
                        let (bufs, at) = proxy::staged(req);
                        self.live
                            .start(slot::read, bufs, |b, cross| pack::read(crate::host_side::proxy::now(), b.get(at), cross), lease)
                            .into()
                    })
                }

                pub fn scan<'a, N: crate::host_side::needs::Needs>(
                    &'a self,
                    drv: &'a mut crate::host_side::driver::Driver<'a, N>,
                    req: crate::host_side::pool::PooledOut,
                ) -> impl core::future::Future<
                    Output = Result<crate::host_side::answer::OwnedAnswer, crate::fail::CallError>,
                > + Send
                + 'a {
                    use crate::host_side::proxy;
                    proxy::chain::<Marker, _, _>(&self.inst, drv, proxy::entry(M_SCAN), req, |req, lease| {
                        let _ = req;
                        let (bufs, at) = proxy::staged(req);
                        self.live
                            .start(slot::scan, bufs, |b, cross| pack::scan(crate::host_side::proxy::now(), b.get(at), cross), lease)
                            .into()
                    })
                }

                pub fn commit<'a, N: crate::host_side::needs::Needs>(
                    &'a self,
                    drv: &'a mut crate::host_side::driver::Driver<'a, N>,
                    req: crate::host_side::pool::PooledOut,
                ) -> impl core::future::Future<
                    Output = Result<crate::host_side::answer::OwnedAnswer, crate::fail::CallError>,
                > + Send
                + 'a {
                    use crate::host_side::proxy;
                    proxy::chain::<Marker, _, _>(&self.inst, drv, proxy::entry(M_COMMIT), req, |req, lease| {
                        let _ = req;
                        let (bufs, at) = proxy::staged(req);
                        self.live
                            .start(slot::commit, bufs, |b, cross| pack::commit(crate::host_side::proxy::now(), b.get(at), cross), lease)
                            .into()
                    })
                }

                pub fn clock<'a, N: crate::host_side::needs::Needs>(
                    &'a self,
                    drv: &'a mut crate::host_side::driver::Driver<'a, N>,
                    req: crate::host_side::pool::PooledOut,
                ) -> impl core::future::Future<
                    Output = Result<crate::host_side::answer::OwnedAnswer, crate::fail::CallError>,
                > + Send
                + 'a {
                    use crate::host_side::proxy;
                    proxy::chain::<Marker, _, _>(&self.inst, drv, proxy::entry(M_CLOCK), req, |req, lease| {
                        let _ = req;
                        let (bufs, at) = proxy::staged(req);
                        self.live
                            .start(slot::clock, bufs, |b, cross| pack::clock(crate::host_side::proxy::now(), b.get(at), cross), lease)
                            .into()
                    })
                }

                pub fn info<'o>(
                    &self,
                    buf: &'o mut crate::host_side::pool::PooledOut,
                ) -> Result<crate::host_side::answer::Answer<'o>, crate::fail::CallError> {
                    crate::host_side::proxy::sync(&self.inst, crate::host_side::proxy::entry(M_INFO), buf, |lease| {
                        pack::info(crate::host_side::proxy::now(), |call| self.live.call(slot::info, call, lease))
                    })
                }

            }
        }
    }
}

/// Plugin-side typed helpers every store shares (STORE-TRANSACTIONS Decision 299 §2.4 "SDK plumbing", r39 "MIN-3
/// home"; W1-A5). They sit outside the `kind!` block, so they are not FP-hashed: `Verdict`, `SlotRow` with its
/// packed codec and replay mapping, `holds`, `prelude_order`, the commit decode with its G2 `match` and the
/// `CommitHead` carrier, and the receipt-era refusal. A store depends on busbar-plugin-abi only, so nothing here
/// names busbar-contract: the replay mapping yields the wire `Committed` record, not a `Decision`.
pub mod plumbing {
    /// Whether exact native-encoded parts exceed an admitted deterministic bound.
    /// No default limit or allocation policy is inferred. Overflow exceeds every
    /// representable bound; allocation/driver errors are not inputs to this check.
    pub fn capacity_exceeded(parts: impl IntoIterator<Item = usize>, limit: usize) -> bool {
        parts
            .into_iter()
            .try_fold(0usize, |sum, part| sum.checked_add(part))
            .is_none_or(|sum| sum > limit)
    }

    use super::store::{
        self as wire, AttemptId, CandHead, Committed, MutationRec, PredicateRec, TimeGuard,
    };
    use crate::records::{Rec, RecErr, Records, tag};
    use crate::secure::{Overflow, SecureVec};
    use std::convert::Infallible;
    use zeroize::Zeroize;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum AllocationSite {
        Metadata,
        Row,
    }

    #[cfg(test)]
    std::thread_local! {
        static REFUSE_ALLOCATION: std::cell::Cell<Option<(AllocationSite, usize)>> = const { std::cell::Cell::new(None) };
    }

    #[cfg(test)]
    pub(super) fn with_allocation_failure<R>(
        site: AllocationSite,
        after: usize,
        run: impl FnOnce() -> R,
    ) -> R {
        struct Restore(Option<(AllocationSite, usize)>);
        impl Drop for Restore {
            fn drop(&mut self) {
                REFUSE_ALLOCATION.set(self.0);
            }
        }
        let _restore = Restore(REFUSE_ALLOCATION.replace(Some((site, after))));
        run()
    }

    #[cfg(test)]
    fn allocation_refused(site: AllocationSite) -> bool {
        REFUSE_ALLOCATION.with(|state| match state.get() {
            Some((wanted, left)) if wanted == site => {
                if left == 0 {
                    true
                } else {
                    state.set(Some((wanted, left - 1)));
                    false
                }
            }
            _ => false,
        })
    }

    #[cfg(not(test))]
    const fn allocation_refused(_: AllocationSite) -> bool {
        false
    }

    trait Reservation {
        type Error;
        fn reserve<T>(values: &mut Vec<T>) -> Result<(), Self::Error>;
    }

    struct Legacy;
    impl Reservation for Legacy {
        type Error = Infallible;
        fn reserve<T>(values: &mut Vec<T>) -> Result<(), Self::Error> {
            values.reserve(1);
            Ok(())
        }
    }

    struct Fallible;
    impl Reservation for Fallible {
        type Error = Overflow;
        fn reserve<T>(values: &mut Vec<T>) -> Result<(), Self::Error> {
            if values.len() == values.capacity() {
                if allocation_refused(AllocationSite::Metadata) {
                    return Err(Overflow);
                }
                values.try_reserve(1).map_err(|_| Overflow)?;
            }
            Ok(())
        }
    }

    /// Why assembling one scan row failed. No incomplete row is emitted.
    #[derive(Clone, Copy, Debug)]
    pub enum RowErr {
        Size,
        Allocation,
        Full(crate::records::Full),
    }

    pub(super) fn row_shape(key: usize, value: usize) -> Result<(u32, usize), RowErr> {
        let key_len = u32::try_from(key).map_err(|_| RowErr::Size)?;
        let total = key.checked_add(value).ok_or(RowErr::Size)?;
        Ok((key_len, total))
    }

    /// Emit an admitted row using operation-owned scratch. Dirty input and every exit are volatile-wiped.
    pub fn write_row(
        out: &mut impl crate::records::Writer,
        scratch: &mut SecureVec,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), RowErr> {
        struct RowScratch<'a>(&'a mut SecureVec);
        impl Drop for RowScratch<'_> {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }
        let scratch = RowScratch(scratch);
        scratch.0.zeroize();
        let (key_len, total) = row_shape(key.len(), value.len())?;
        if scratch.0.capacity() < total {
            if allocation_refused(AllocationSite::Row) {
                return Err(RowErr::Allocation);
            }
            *scratch.0 = SecureVec::with_capacity(total).map_err(|_| RowErr::Allocation)?;
        }
        scratch.0.extend(key).map_err(|_| RowErr::Allocation)?;
        scratch.0.extend(value).map_err(|_| RowErr::Allocation)?;
        out.put_pod_tail(
            wire::tag::ROW,
            &wire::RowRec { key_len, _r: 0 },
            scratch.0.as_slice(),
        )
        .map_err(RowErr::Full)
    }

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
            self as u8
        }
        /// The wire `COMMIT_*` code.
        pub fn code(self) -> u32 {
            u32::from(self as u8)
        }
        /// Decode a stored byte; anything else is a corrupt row.
        pub fn from_u8(code: u8) -> Result<Self, Corrupt> {
            match code {
                1 => Ok(Self::Applied),
                2 => Ok(Self::Conflict),
                3 => Ok(Self::TimeGuard),
                _ => Err(Corrupt),
            }
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

    const PACKED_MAGIC: &[u8; 4] = b"BVS1";
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
            Committed {
                code: self.verdict.code(),
                _r: 0,
                observed_at: self.observed,
                authority,
            }
        }

        /// Packed value for key-value stores: `'BVS1' | seq LE8 | fp32 | verdict u8 | observed LE8`.
        pub fn encode_packed(&self) -> [u8; PACKED_LEN] {
            let mut out = [0; PACKED_LEN];
            out[..4].copy_from_slice(PACKED_MAGIC);
            out[4..12].copy_from_slice(&self.seq.to_le_bytes());
            out[12..44].copy_from_slice(&self.fp);
            out[44] = self.verdict.to_u8();
            out[45..].copy_from_slice(&self.observed.to_le_bytes());
            out
        }

        /// Decode [`Self::encode_packed`]; any other length, magic or verdict is `Corrupt`.
        pub fn decode_packed(bytes: &[u8]) -> Result<Self, Corrupt> {
            let bytes: &[u8; PACKED_LEN] = bytes.try_into().map_err(|_| Corrupt)?;
            if &bytes[..4] != PACKED_MAGIC {
                return Err(Corrupt);
            }
            let word = |at: usize| {
                let mut w = [0; 8];
                w.copy_from_slice(&bytes[at..at + 8]);
                u64::from_le_bytes(w)
            };
            let mut fp = [0; 32];
            fp.copy_from_slice(&bytes[12..44]);
            Ok(Self {
                seq: word(4),
                fp,
                verdict: Verdict::from_u8(bytes[44])?,
                observed: word(45),
            })
        }
    }

    /// M1 step 2 over the slot's current row (`None` = no row).
    pub fn judge(row: Option<&SlotRow>, seq: u64, fp: &[u8; 32]) -> Judgement {
        match row {
            Some(row) if row.seq > seq => Judgement::Stale,
            Some(row) if row.seq == seq && row.fp == *fp => Judgement::Replay,
            Some(row) if row.seq == seq => Judgement::OpIdConflict,
            _ => Judgement::Fresh,
        }
    }

    /// One condition against the pre-mutation state: `PREDICATE_ABSENT` needs no live value, `PREDICATE_EXACT`
    /// needs exactly `expected`; any other tag never holds (the decode already FAULTed it).
    pub fn holds(tag: u32, expected: &[u8], current: Option<&[u8]>) -> bool {
        match tag {
            wire::PREDICATE_ABSENT => current.is_none(),
            wire::PREDICATE_EXACT => current == Some(expected),
            _ => false,
        }
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
        match ordered::<Legacy>(items) {
            Ok(plan) => plan,
            Err(never) => match never {},
        }
    }

    /// Fallible version of [`prelude_order`], with identical namespace merging and byte order.
    pub fn try_prelude_order<'a>(
        items: impl IntoIterator<Item = (&'a [u8; 16], &'a [u8], Use)>,
    ) -> Result<Vec<([u8; 16], bool)>, Overflow> {
        ordered::<Fallible>(items)
    }

    fn ordered<'a, R: Reservation>(
        items: impl IntoIterator<Item = (&'a [u8; 16], &'a [u8], Use)>,
    ) -> Result<Vec<([u8; 16], bool)>, R::Error> {
        let mut out: Vec<([u8; 16], bool)> = Vec::new();
        for (namespace, key, how) in items {
            let target = match how {
                Use::Condition if *namespace == wire::GENERATION_NS => {
                    <[u8; 16]>::try_from(key).unwrap_or(*namespace)
                }
                _ => *namespace,
            };
            let exclusive = how == Use::Mutation;
            match out.binary_search_by(|(held, _)| held.cmp(&target)) {
                Ok(at) => {
                    if let Some(held) = out.get_mut(at) {
                        held.1 |= exclusive;
                    }
                }
                Err(at) => {
                    R::reserve(&mut out)?;
                    out.insert(at, (target, exclusive));
                }
            }
        }
        Ok(out)
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
    #[derive(Clone)]
    pub struct CommitHead<'a> {
        pub id: AttemptId,
        pub codec: u32,
        pub guard: TimeGuard,
        pub slot: CommitSlot,
        pub fences: Vec<Cond<'a>>,
    }

    /// A decoded commit candidate, borrowed from the request.
    #[derive(Clone)]
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

    /// A malformed/refused candidate, or inability to allocate its metadata before backend work.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PrepareErr {
        Commit(CommitErr),
        Allocation,
    }

    enum DecodeErr<E> {
        Commit(CommitErr),
        Allocation(E),
    }

    impl<E> From<CommitErr> for DecodeErr<E> {
        fn from(error: CommitErr) -> Self {
            Self::Commit(error)
        }
    }

    const SIZE: CommitErr = CommitErr::Fault(RecErr::Size);

    /// The next record, skipping the generic `METRIC` records any answer or request may carry.
    fn next<'a>(recs: &mut Records<'a>) -> Result<Option<Rec<'a>>, CommitErr> {
        loop {
            match recs.next_rec() {
                None => return Ok(None),
                Some(Err(e)) => return Err(CommitErr::Fault(e)),
                Some(Ok(rec)) if rec.tag == tag::METRIC => {}
                Some(Ok(rec)) => return Ok(Some(rec)),
            }
        }
    }

    /// FENCE or PREDICATE: a `PredicateRec`, its key, then (EXACT only) the expected bytes. G2: a condition on
    /// `GENERATION_NS` names a namespace, so its key is exactly 16 bytes.
    fn cond<'a>(rec: &Rec<'a>) -> Result<Cond<'a>, CommitErr> {
        let (head, tail) = rec.pod_tail::<PredicateRec>().map_err(CommitErr::Fault)?;
        let key_len = usize::try_from(head.key_len).map_err(|_| SIZE)?;
        let (key, expected) = tail.split_at_checked(key_len).ok_or(SIZE)?;
        match head.tag {
            wire::PREDICATE_ABSENT if expected.is_empty() => {}
            wire::PREDICATE_EXACT => {}
            _ => return Err(SIZE),
        }
        if head.namespace == wire::GENERATION_NS && key.len() != 16 {
            return Err(SIZE);
        }
        Ok(Cond {
            namespace: head.namespace,
            tag: head.tag,
            key,
            expected,
        })
    }

    /// MUTATION: a `MutationRec`, its key, then (PUT only) the value. G2: a `SLOT_NS` mutation is only
    /// `DeleteRange{16-byte prefix, exact length 20}`, and `GENERATION_NS` is never mutated.
    fn mutation<'a>(rec: &Rec<'a>) -> Result<Mut<'a>, CommitErr> {
        let (head, tail) = rec.pod_tail::<MutationRec>().map_err(CommitErr::Fault)?;
        let key_len = usize::try_from(head.key_len).map_err(|_| SIZE)?;
        let (key, value) = tail.split_at_checked(key_len).ok_or(SIZE)?;
        let shaped = match head.tag {
            wire::MUTATION_PUT => head.exact_length == 0,
            wire::MUTATION_DELETE => head.exact_length == 0 && value.is_empty(),
            wire::MUTATION_DELETE_RANGE => value.is_empty(),
            _ => false,
        };
        let allowed = if head.namespace == wire::SLOT_NS {
            head.tag == wire::MUTATION_DELETE_RANGE && key.len() == 16 && head.exact_length == 20
        } else {
            head.namespace != wire::GENERATION_NS
        };
        if !shaped || !allowed {
            return Err(SIZE);
        }
        Ok(Mut {
            namespace: head.namespace,
            tag: head.tag,
            key,
            value,
            exact_length: head.exact_length,
        })
    }

    /// Decode a commit request: `CAND_HEAD, FENCE*, PREDICATE*, MUTATION*, RESULT`, with N1 on the head and
    /// G2 (N13) on every record. `METRIC` records are skipped.
    pub fn decode_commit(req: Records<'_>) -> Result<Commit<'_>, CommitErr> {
        match decode::<Legacy>(req) {
            Ok(commit) => Ok(commit),
            Err(DecodeErr::Commit(error)) => Err(error),
            Err(DecodeErr::Allocation(never)) => match never {},
        }
    }

    /// Decode exactly as [`decode_commit`], returning allocation refusal before any backend operation.
    pub fn try_decode_commit(req: Records<'_>) -> Result<Commit<'_>, PrepareErr> {
        decode::<Fallible>(req).map_err(|error| match error {
            DecodeErr::Commit(error) => PrepareErr::Commit(error),
            DecodeErr::Allocation(_) => PrepareErr::Allocation,
        })
    }

    fn decode<R: Reservation>(mut req: Records<'_>) -> Result<Commit<'_>, DecodeErr<R::Error>> {
        let first = next(&mut req)?.ok_or(CommitErr::Fault(RecErr::Truncated))?;
        if first.tag != wire::tag::CAND_HEAD {
            return Err(CommitErr::Fault(RecErr::Unknown(first.tag)).into());
        }
        let cand = first.pod::<CandHead>().map_err(CommitErr::Fault)?;
        let slot = if cand.slot < wire::MAX_SLOTS && cand.seq >= 1 {
            CommitSlot::Slotted {
                slot: cand.slot,
                seq: cand.seq,
            }
        } else if cand.slot == wire::SLOT_SELF_FENCED && cand.seq == 0 {
            CommitSlot::SelfFenced
        } else {
            return Err(CommitErr::Refused.into());
        };
        let (mut fences, mut predicates, mut mutations) = (Vec::new(), Vec::new(), Vec::new());
        let mut stage = 0u8;
        let result = loop {
            let rec = next(&mut req)?.ok_or(CommitErr::Fault(RecErr::Truncated))?;
            match rec.tag {
                wire::tag::FENCE if stage == 0 => {
                    let item = cond(&rec)?;
                    R::reserve(&mut fences).map_err(DecodeErr::Allocation)?;
                    fences.push(item);
                }
                wire::tag::PREDICATE if stage <= 1 => {
                    stage = 1;
                    let item = cond(&rec)?;
                    R::reserve(&mut predicates).map_err(DecodeErr::Allocation)?;
                    predicates.push(item);
                }
                wire::tag::MUTATION if stage <= 2 => {
                    stage = 2;
                    let item = mutation(&rec)?;
                    R::reserve(&mut mutations).map_err(DecodeErr::Allocation)?;
                    mutations.push(item);
                }
                wire::tag::RESULT => break rec.body,
                other => return Err(CommitErr::Fault(RecErr::Unknown(other)).into()),
            }
        };
        if let Some(extra) = next(&mut req)? {
            return Err(CommitErr::Fault(RecErr::Unknown(extra.tag)).into());
        }
        Ok(Commit {
            head: CommitHead {
                id: cand.id,
                codec: cand.codec,
                guard: cand.guard,
                slot,
                fences,
            },
            predicates,
            mutations,
            result,
        })
    }
}

#[cfg(test)]
#[path = "store_plumbing_tests.rs"]
mod plumbing_tests;
