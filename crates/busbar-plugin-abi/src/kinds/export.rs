// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The export kind as frozen at round 33: the `Export` trait and the `export` module (IF §8.5, §49, §10.4). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-A9 fills it.

crate::kind::kind_stub! {
    /// An exporter ships what core hands it. Core owns batching, retries, backoff, drop policy and which streams go where.
    /// Round 33: core also mints every delivery's identity and decides custody; the plugin reports the level it reached.
    pub trait Export: Send + Sync + 'static {
        /// Push one batch of `stream` (a STREAM_* id; round 28: always one this instance declared in D_STREAMS, core's
        /// routing never sends another). Round 29: on STREAM_TRACES, each line of a batch for an instance whose image
        /// declared FB_SPAN_RECORDS carries the reserved member `span` (the full span record: events, status,
        /// exception data, ns timestamps; dev kernel export/traces.rs SPAN_MEMBER) beside the `fields:` projection;
        /// a sink without the bit never gets `span`, and core records tracing events at all only while at least one
        /// running sink declared it. Answer: ACK{accepted} (a prefix; core retries or drops the rest per policy). A file
        /// sink answers APPEND{dest} (empty tail = this batch verbatim) then ACK{accepted}; core does the append,
        /// rotation and retention (§12.21) and owns the open/append/rotate failure audit codes. A file sink never
        /// opens a path (I1).
        /// Round 33. `delivery` is core-minted, never 0 and never time-derived: it names this line set, so
        /// `(delivery, i)` is a stable per-line key (an idempotency key, a document id). A resend of the same lines
        /// keeps `delivery`, with `attempt` + 1; after ACK{accepted} the prefix keeps `delivery` and the rest is a new
        /// line set with a fresh `delivery` and `attempt` = this one's + 1. `attempt` is 1 on first send; > 1 = the
        /// sink may hold these lines already. Answer: ACK CUSTODY? or APPEND ACK. Core decides custody: required is
        /// CUSTODY_ACCEPTED on every stream but STREAM_CONTENT (whose level is the sink's configured one, 1.6.x);
        /// at or above required `recheck_s` is ignored; a file sink's custody is always ACCEPTED (the disk lane does
        /// not sync). On STREAM_CONTENT, and on every `confirm`, core keeps only a Fail's code and facts and records
        /// its own fixed text, never the plugin's (content never enters engine records). Round 34: an ERROR number
        /// on those answers is accepted and dropped (no `plugin_diag`), never FAULT.
        fn deliver(
            &self,
            h: &'static crate::host::Host,
            stream: u32,
            delivery: u64,
            attempt: u32,
            batch: crate::need::ChainBytes,
        ) -> impl core::future::Future<Output = Result<crate::records::Reply, crate::fail::Fail>> + Send {
            let _ = (h, stream, delivery, attempt, batch);
            async move { todo!() }
        }
        /// Pull exporters: render the snapshot of one declared `scope` (D_SCOPE) that core serves at that scope's
        /// path (core owns the listener, the route and its auth). Answer: CONTENT_TYPE, BODY.
        fn render(
            &self,
            h: &crate::host::Host,
            scope: u32,
            snapshot: crate::types::Bytes<'_>,
            out: &mut crate::records::Out<'_>,
        ) -> Result<(), crate::fail::Fail> {
            let _ = (h, scope, snapshot, out);
            todo!()
        }
        /// Round 33. Bytes-free re-check of an earlier delivery whose answer said `recheck_s > 0`: the plugin finds
        /// `delivery` in its own pending map (at most `pending_capacity` entries) and asks its sink (a Need). It never
        /// resends (I3). Answer: exactly one CUSTODY. CUSTODY_NONE = no record: core resends that prefix with
        /// `deliver`, same `delivery`, `attempt` + 1. Declared after `render`: M_CONFIRM = 1 << 2, no bit moves.
        fn confirm(
            &self,
            h: &'static crate::host::Host,
            delivery: u64,
        ) -> impl core::future::Future<Output = Result<crate::records::Reply, crate::fail::Fail>> + Send {
            let _ = (h, delivery);
            async move { todo!() }
        }
    }
}

pub mod export {
    //! The export kind's records, constants and method bits (IF §8.5, round 33), and its host-side `Proxy`
    //! (§10.4).

    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct Ack {
        pub accepted: u64,
    }
    /// Tail = nested: M_NAME text, M_HELP text, M_SAMPLE*.
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct FamilyRec {
        pub kind: u32,
        pub _r: u32,
    }
    /// Tail = nested M_LABEL* (pair shape). role = SAMPLE_*; bound = the bucket `le` (SAMPLE_BUCKET) or the
    /// quantile `q` (SAMPLE_QUANTILE), NaN otherwise.
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct SampleRec {
        pub value: f64,
        pub bound: f64,
        pub ts_ms: u64,
        pub role: u32,
        pub _r: u32,
    }
    /// Describe: one pull scope core serves. Tail = the path core mounts it at (`/metrics`, `/metrics/hooks`).
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct ScopeRec {
        pub scope: u32,
        pub _r: u32,
    }
    /// Describe: what this exporter needs core's metric recorder to keep for it (clamped by core).
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct RecorderRec {
        pub retention_s: u64,
        pub key_gauge_limit: u64,
    }
    /// Round 7. `deliver` answer: "append to my bound destination `dest`" (a `{"$dest": n}` handle from
    /// the instance's own config, §12.7). Tail = the bytes to append; an **empty tail = the delivered
    /// batch exactly as core handed it** (no copy through the plugin). Core appends on its host disk lane
    /// to the operator's path, rotating by `rotate_mb` and pruning to `keep` by core policy (§12.21);
    /// the plugin never sees the path, a file handle or the outcome. At most one APPEND per answer.
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct AppendRec {
        pub dest: u32,
        pub _r: u32,
    }
    /// Round 33. The custody a sink reached, `level` = CUSTODY_*. In a `deliver` answer it covers
    /// `lines[0..accepted]`, the prefix the ACK covers; `recheck_s > 0` = "ask me again with `confirm` in about
    /// that many seconds" (only from an image that declared M_CONFIRM). In a `confirm` answer it covers that
    /// delivery's prefix. In an `open` answer (written by `Open::settled`, §7.2) it is the instance's ceiling:
    /// the highest level its settings can reach, `recheck_s` 0.
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct CustodyRec {
        pub level: u32,
        pub recheck_s: u32,
    }
    /// Round 33. Describe: how many deliveries this instance holds pending custody at most (≥ 1; core clamps).
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct DeliveryRec {
        pub pending_capacity: u64,
    }

    impl crate::records::Pod for Ack {}
    impl crate::records::Pod for FamilyRec {}
    impl crate::records::Pod for SampleRec {}
    impl crate::records::Pod for ScopeRec {}
    impl crate::records::Pod for RecorderRec {}
    impl crate::records::Pod for AppendRec {}
    impl crate::records::Pod for CustodyRec {}
    impl crate::records::Pod for DeliveryRec {}

    pub mod tag {
        pub const ACK: u16 = 0x0100;
        pub const CONTENT_TYPE: u16 = 0x0101;
        pub const BODY: u16 = 0x0102;
        /// Round 7: deliver answer, file sink (AppendRec + tail). Followed by ACK.
        pub const APPEND: u16 = 0x0103;
        /// Round 33: CustodyRec. Optional after ACK in a `deliver` answer (never after APPEND); exactly one in a
        /// `confirm` answer; optional and last in an export `open` answer. Absent from a `deliver` answer = ACCEPTED.
        pub const CUSTODY: u16 = 0x0104;
        /// metric snapshot (core-built): FAMILY*.
        pub const M_FAMILY: u16 = 0x0110;
        pub const M_NAME: u16 = 0x0111;
        pub const M_HELP: u16 = 0x0112;
        pub const M_SAMPLE: u16 = 0x0113;
        pub const M_LABEL: u16 = 0x0114;
        /// describe: D_STREAMS, D_SCOPE* (ScopeRec + path), D_RECORDER? (RecorderRec). Round 28: D_STREAMS has no
        /// pod; its body is the declared streams as one `u8` STREAM_* id per byte, 1..=STREAM_COUNT bytes, strictly
        /// ascending (the `ExportStream::ALL` order), the same ids dev's `Tail.streams[]` carried; any other body is
        /// DescribeInvalid. At most one D_STREAMS; absent = none. Round 33: D_DELIVERY? (DeliveryRec), declared
        /// exactly when M_CONFIRM is, with STREAM_CONTENT in D_STREAMS and no D_DEST_PATH; else DescribeInvalid.
        pub const D_STREAMS: u16 = 0x0180;
        pub const D_SCOPE: u16 = 0x0181;
        pub const D_RECORDER: u16 = 0x0182;
        pub const D_DELIVERY: u16 = 0x0183;
    }

    pub const REQUIRED: u64 = 0;
    /// Round 28: streams = core's `ExportStream`, same names, same numbers: each id is the stream's position in
    /// `ExportStream::ALL` (ascending sensitivity); round 29: the enum's one home is
    /// `busbar_contract::export_stream::ExportStream` (moved out of the old abi tree by D1a, §8.5). METRICS is a
    /// snapshot; every other stream's batch is JSONL (Q7; TRACES = spans) with core's `fields:` projection
    /// already applied. EVENTS is the hash-chained engine lifecycle and audit chain; IDENTITY is the
    /// pseudonymization switch (a sink without it gets the same records with no subject). Round 33: PROMPTS
    /// and COMPLETIONS are reserved and never produced; CONTENT is the one content stream (core-built content
    /// events, 1.6.x). A subscription to a stream with no producer is refused at config load (dev's HAS NO
    /// PRODUCER rule), CONTENT included in 1.6.0. There is no AUDIT, SEALS or USAGE stream (audit = EVENTS,
    /// spend = COSTS).
    pub const STREAM_METRICS: u32 = 0;
    pub const STREAM_LOGS: u32 = 1;
    pub const STREAM_TRACES: u32 = 2;
    pub const STREAM_COSTS: u32 = 3;
    pub const STREAM_DECISIONS: u32 = 4;
    pub const STREAM_EVENTS: u32 = 5;
    pub const STREAM_IDENTITY: u32 = 6;
    pub const STREAM_PROMPTS: u32 = 7;
    pub const STREAM_COMPLETIONS: u32 = 8;
    pub const STREAM_CONTENT: u32 = 9;
    pub const STREAM_COUNT: u32 = 10;
    /// Round 33, custody levels, ascending (core compares a reported level with the required one; each plugin
    /// documents which levels it can honestly claim).
    pub const CUSTODY_NONE: u32 = 0; // `confirm` only: "I hold no record of this delivery, or its ack was lost"
    pub const CUSTODY_ACCEPTED: u32 = 1; // the sink acknowledged receipt
    pub const CUSTODY_DURABLE: u32 = 2; // durably stored or replicated
    pub const CUSTODY_INDEXED: u32 = 3; // durable and confirmed queryable
    pub const FAMILY_COUNTER: u32 = 1;
    pub const FAMILY_GAUGE: u32 = 2;
    pub const FAMILY_HISTOGRAM: u32 = 3;
    pub const FAMILY_SUMMARY: u32 = 4;
    pub const SAMPLE_VALUE: u32 = 0;
    pub const SAMPLE_BUCKET: u32 = 1;
    pub const SAMPLE_QUANTILE: u32 = 2;
    pub const SAMPLE_SUM: u32 = 3;
    pub const SAMPLE_COUNT: u32 = 4;
    /// pull scopes: the general registry, and the per-hook families (today's /metrics/hooks).
    pub const SCOPE_METRICS: u32 = 1;
    pub const SCOPE_HOOKS: u32 = 2;
    /// Round 29, describe fact bit (dev's EXT_SPAN_RECORDS): this sink wants full span records on TRACES.
    /// Requires STREAM_TRACES in D_STREAMS (DescribeInvalid otherwise). Intent only; core decides (below).
    pub const FB_SPAN_RECORDS: u64 = 1;

    pub const KIND: crate::types::KindCode = crate::types::KindCode::Export;
    pub const ABI: u32 = 3;
    pub const FP: u64 = 0; // W0-ABI stub value; kind! computes it (W1-A4).

    pub const M_DELIVER: u64 = 1 << 0;
    pub const M_RENDER: u64 = 1 << 1;
    pub const M_CONFIRM: u64 = 1 << 2;
    pub const ALL: u64 = M_DELIVER | M_RENDER | M_CONFIRM;

    // W0-ABI: `Vt` (fields deliver, render, confirm are unsafe extern "C" fn pointers) and the `vt::<T>()`
    // shims are unsafe; they land with W1-A4 (`kind!`) under an escapes.json admission.

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

        pub fn deliver<'a, N: crate::host_side::needs::Needs>(
            &'a self,
            drv: &'a mut crate::host_side::driver::Driver<'a, N>,
            req: crate::host_side::pool::PooledOut,
            stream: u32,
            delivery: u64,
            attempt: u32,
        ) -> impl core::future::Future<
            Output = Result<crate::host_side::answer::OwnedAnswer, crate::fail::CallError>,
        > + Send
               + 'a {
            let _ = (&self._stub, drv, req, stream, delivery, attempt);
            async move { todo!() }
        }

        pub fn render<'o>(
            &self,
            buf: &'o mut crate::host_side::pool::PooledOut,
            scope: u32,
            snapshot: &[u8],
        ) -> Result<crate::host_side::answer::Answer<'o>, crate::fail::CallError> {
            let _ = (&self._stub, buf, scope, snapshot);
            todo!()
        }

        pub fn confirm<'a, N: crate::host_side::needs::Needs>(
            &'a self,
            drv: &'a mut crate::host_side::driver::Driver<'a, N>,
            req: crate::host_side::pool::PooledOut,
            delivery: u64,
        ) -> impl core::future::Future<
            Output = Result<crate::host_side::answer::OwnedAnswer, crate::fail::CallError>,
        > + Send
               + 'a {
            let _ = (&self._stub, drv, req, delivery);
            async move { todo!() }
        }
    }
}
