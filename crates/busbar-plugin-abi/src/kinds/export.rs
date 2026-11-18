// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The export kind: the `Export` trait and the `export` module (IF §8, §10.4), one `kind!` block (W1-A4b).

crate::kind! {
    /// An exporter ships what core hands it. Core owns batching, retries, backoff, drop policy and which streams go where.
    /// Round 33: core also mints every delivery's identity and decides custody; the plugin reports the level it reached.
    pub trait Export: kind = 5, abi = 3 {
        views {
        }
        pods {
        pub struct Ack {
            pub accepted: u64,
        }
        /// Tail = nested: M_NAME text, M_HELP text, M_SAMPLE*.
        pub struct FamilyRec {
            pub kind: u32,
            pub _r: u32,
        }
        /// Tail = nested M_LABEL* (pair shape). role = SAMPLE_*; bound = the bucket `le` (SAMPLE_BUCKET) or the
        /// quantile `q` (SAMPLE_QUANTILE), NaN otherwise.
        pub struct SampleRec {
            pub value: f64,
            pub bound: f64,
            pub ts_ms: u64,
            pub role: u32,
            pub _r: u32,
        }
        /// Describe: one pull scope core serves. Tail = the path core mounts it at (`/metrics`, `/metrics/hooks`).
        pub struct ScopeRec {
            pub scope: u32,
            pub _r: u32,
        }
        /// Describe: what this exporter needs core's metric recorder to keep for it (clamped by core).
        pub struct RecorderRec {
            pub retention_s: u64,
            pub key_gauge_limit: u64,
        }
        /// Round 7. `deliver` answer: "append to my bound destination `dest`" (a `{"$dest": n}` handle from
        /// the instance's own config, §12.7). Tail = the bytes to append; an **empty tail = the delivered
        /// batch exactly as core handed it** (no copy through the plugin). Core appends on its host disk lane
        /// to the operator's path, rotating by `rotate_mb` and pruning to `keep` by core policy (§12.21);
        /// the plugin never sees the path, a file handle or the outcome. At most one APPEND per answer.
        pub struct AppendRec {
            pub dest: u32,
            pub _r: u32,
        }
        /// Round 33. The custody a sink reached, `level` = CUSTODY_*. In a `deliver` answer it covers
        /// `lines[0..accepted]`, the prefix the ACK covers; `recheck_s > 0` = "ask me again with `confirm` in about
        /// that many seconds" (only from an image that declared M_CONFIRM). In a `confirm` answer it covers that
        /// delivery's prefix. In an `open` answer (written by `Open::settled`, §7.2) it is the instance's ceiling:
        /// the highest level its settings can reach, `recheck_s` 0.
        pub struct CustodyRec {
            pub level: u32,
            pub recheck_s: u32,
        }
        /// Round 33. Describe: how many deliveries this instance holds pending custody at most, 1 to PENDING_CAPACITY_MAX
        /// (4096); core refuses a value above it at admit and never clamps.
        pub struct DeliveryRec {
            pub pending_capacity: u64,
        }
        }
        tags {
            ACK = 0x0100;
            CONTENT_TYPE = 0x0101;
            BODY = 0x0102;
            /// Round 7: deliver answer, file sink (AppendRec + tail). Followed by ACK.
            APPEND = 0x0103;
            /// Round 33: CustodyRec. Optional after ACK in a `deliver` answer (never after APPEND); exactly one in a
            /// `confirm` answer; optional and last in an export `open` answer. Absent from a `deliver` answer = ACCEPTED.
            CUSTODY = 0x0104;
            /// metric snapshot (core-built): FAMILY*.
            M_FAMILY = 0x0110;
            M_NAME = 0x0111;
            M_HELP = 0x0112;
            M_SAMPLE = 0x0113;
            M_LABEL = 0x0114;
            /// describe: D_STREAMS, D_SCOPE* (ScopeRec + path), D_RECORDER? (RecorderRec). Round 28: D_STREAMS has no
            /// pod; its body is the declared streams as one `u8` STREAM_* id per byte, 1..=STREAM_COUNT bytes, strictly
            /// ascending (the `ExportStream::ALL` order), the same ids dev's `Tail.streams[]` carried; any other body is
            /// DescribeInvalid. At most one D_STREAMS; absent = none. Round 33: D_DELIVERY? (DeliveryRec), declared
            /// exactly when M_CONFIRM is, with STREAM_CONTENT in D_STREAMS and no D_DEST_PATH; else DescribeInvalid.
            D_STREAMS = 0x0180;
            D_SCOPE = 0x0181;
            D_RECORDER = 0x0182;
            D_DELIVERY = 0x0183;
        }
        consts {
            REQUIRED: u64 = 0;
        /// Round 28: streams = core's `ExportStream`, same names, same numbers: each id is the stream's position in
        /// `ExportStream::ALL` (ascending sensitivity); round 29: the enum's one home is
        /// `busbar_contract::export_stream::ExportStream` (moved out of the old abi tree by D1a, §8.5). METRICS is a
        /// snapshot; every other stream's batch is JSONL (Q7; TRACES = spans) with core's `fields:` projection
        /// already applied. EVENTS is the hash-chained engine lifecycle and audit chain; IDENTITY is the
        /// pseudonymization switch (a sink without it gets the same records with no subject). Round 33: PROMPTS
        /// and COMPLETIONS are reserved and never produced; CONTENT is the one content stream (core-built content
        /// events; content lines are `busbar.content.v2`). A subscription to a stream with no producer is refused at config load (dev's HAS NO
        /// PRODUCER rule), CONTENT included in 1.6.0. There is no AUDIT, SEALS or USAGE stream (audit = EVENTS,
        /// spend = COSTS).
            STREAM_METRICS: u32 = 0;
            STREAM_LOGS: u32 = 1;
            STREAM_TRACES: u32 = 2;
            STREAM_COSTS: u32 = 3;
            STREAM_DECISIONS: u32 = 4;
            STREAM_EVENTS: u32 = 5;
            STREAM_IDENTITY: u32 = 6;
            STREAM_PROMPTS: u32 = 7;
            STREAM_COMPLETIONS: u32 = 8;
            STREAM_CONTENT: u32 = 9;
            STREAM_COUNT: u32 = 10;
        /// Round 33, custody levels, ascending (core compares a reported level with the required one; each plugin
        /// documents which levels it can honestly claim).
            CUSTODY_NONE: u32 = 0;
            CUSTODY_ACCEPTED: u32 = 1;
            CUSTODY_DURABLE: u32 = 2;
            CUSTODY_INDEXED: u32 = 3;
            FAMILY_COUNTER: u32 = 1;
            FAMILY_GAUGE: u32 = 2;
            FAMILY_HISTOGRAM: u32 = 3;
            FAMILY_SUMMARY: u32 = 4;
            SAMPLE_VALUE: u32 = 0;
            SAMPLE_BUCKET: u32 = 1;
            SAMPLE_QUANTILE: u32 = 2;
            SAMPLE_SUM: u32 = 3;
            SAMPLE_COUNT: u32 = 4;
        /// pull scopes: the general registry, and the per-hook families (today's /metrics/hooks).
            SCOPE_METRICS: u32 = 1;
            SCOPE_HOOKS: u32 = 2;
        /// Round 29, describe fact bit (dev's EXT_SPAN_RECORDS): this sink wants full span records on TRACES.
        /// Requires STREAM_TRACES in D_STREAMS (DescribeInvalid otherwise). Intent only; core decides (below).
            FB_SPAN_RECORDS: u64 = 1;
            M_DELIVER: u64 = 1 << 0;
            M_RENDER: u64 = 1 << 1;
            M_CONFIRM: u64 = 1 << 2;
        }
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
        async fn deliver(&self, h: &'static Host, stream: u32, delivery: u64, attempt: u32, batch: ChainBytes) -> Result<Reply, Fail> { let _ = (h, stream, delivery, attempt, batch); Err(crate::fail::Fail::unsupported()) }
        /// Pull exporters: render the snapshot of one declared `scope` (D_SCOPE) that core serves at that scope's
        /// path (core owns the listener, the route and its auth). Answer: CONTENT_TYPE, BODY.
        sync fn render(&self, h: &Host, scope: u32, snapshot: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail> { let _ = (h, scope, snapshot, out); Err(crate::fail::Fail::unsupported()) }
        /// Round 33. Bytes-free re-check of an earlier delivery whose answer said `recheck_s > 0`: the plugin finds
        /// `delivery` in its own pending map (at most `pending_capacity` entries) and asks its sink (a Need). It never
        /// resends (I3). Answer: exactly one CUSTODY. CUSTODY_NONE = no record: core resends that prefix with
        /// `deliver`, same `delivery`, `attempt` + 1. Declared after `render`: M_CONFIRM = 1 << 2, no bit moves.
        async fn confirm(&self, h: &'static Host, delivery: u64) -> Result<Reply, Fail> { let _ = (h, delivery); Err(crate::fail::Fail::unsupported()) }

        extras {
            /// The host side of the export kind: a typed face over busbar-ffi's `Instance` (IF §10.4).
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
                /// Bind. Done by the loader only, after admit; None when `inst` is not an export instance.
                pub fn bind(inst: std::sync::Arc<crate::host_side::driver::Instance>) -> Option<Self> {
                    let live = inst.live::<Marker>()?;
                    Some(Proxy { inst, live })
                }

                pub fn instance(&self) -> &std::sync::Arc<crate::host_side::driver::Instance> {
                    &self.inst
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
                    use crate::host_side::proxy;
                    use crate::plugin::__rt::Arg;
                    proxy::chain::<Marker, _, _>(&self.inst, drv, proxy::entry(M_DELIVER), req, move |req, lease| {
                        let _ = req;
                        let (bufs, at) = proxy::staged(req);
                        self.live
                            .start4(
                                |vt| &vt.deliver,
                                bufs,
                                |b| (Arg::u32(stream), Arg::u64(delivery), Arg::u32(attempt), Arg::bytes(b.get(at))),
                                lease,
                            )
                            .into()
                    })
                }

                pub fn render<'o>(
                    &self,
                    buf: &'o mut crate::host_side::pool::PooledOut,
                    scope: u32,
                    snapshot: &[u8],
                ) -> Result<crate::host_side::answer::Answer<'o>, crate::fail::CallError> {
                    use crate::plugin::__rt::Arg;
                    use crate::types::Bytes;
                    crate::host_side::proxy::sync(&self.inst, crate::host_side::proxy::entry(M_RENDER), buf, |lease| {
                        self.live.call2(|vt| &vt.render, Arg::u32(scope), Arg::bytes(Bytes::new(snapshot)), lease)
                    })
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
                    use crate::host_side::proxy;
                    use crate::plugin::__rt::Arg;
                    proxy::chain::<Marker, _, _>(&self.inst, drv, proxy::entry(M_CONFIRM), req, move |req, lease| {
                        let _ = req;
                        self.live
                            .start1(
                                |vt| &vt.confirm,
                                busbar_ffi::host::ChainBufs::new(),
                                |_| Arg::u64(delivery),
                                lease,
                            )
                            .into()
                    })
                }

            }
        }
    }
}
