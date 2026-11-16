// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hook kind: the `Hook` trait and the `hook` module (IF §8, §10.4), one `kind!` block (W1-A4b).

crate::kind! {
    /// A hook gives an opinion at a decision point. Core owns the decision and applies, clamps or ignores it.
    pub trait Hook: kind = 4, abi = 2 {
        views {
        }
        pods {
        /// One routing candidate as core sees it. Tail = nested: C_MODEL text, C_PROVIDER text (a config name,
        /// never a plugin), C_TIER text? (the member's configured tier, verbatim), C_TAG* text, C_COST_TERM*
        /// (CostTermRec + class text). weight = the operator's configured weight; available_concurrency = free
        /// concurrency permits now (today's DecodedCandidate fields, busbar-contract abi/sdk/hook.rs:161-179).
        /// flags = C_HAS_* presence bits: a numeric field whose bit is clear has **no sample** (it is 0 and must
        /// not be read as a value; `fastest` demotes such a member, it does not rank it first). Round 6.
        pub struct CandidateRec {
            pub index: u32,
            pub flags: u32,
            pub context_max: u64,
            pub cost_per_mtok_micros: u64,
            pub latency_ms: u64,
            pub budget_remaining_micros: i64,
            pub error_rate_ppm: u32,
            pub breaker: u32,
            pub rate_headroom_ppm: u32,
            pub _r: u32,
            pub weight: u32,
            pub available_concurrency: u32,
        }
        /// One budget bucket that applies to this request (today's projection `context.budget[]`). Tail = nested
        /// B_ID text, B_PERIOD text, B_GROUP text?, B_POOL text?. flags = B_HAS_SPEND? (spend_micros_at_current_rate
        /// present). window_start_s = UTC seconds.
        pub struct BudgetRec {
            pub remaining_micros: i64,
            pub spend_micros_at_current_rate: i64,
            pub window_start_s: u64,
            pub flags: u32,
            pub _r: u32,
        }
        /// One term of the candidate's cost recipe (today's busbar_contract::signal::route_cost Term), built by
        /// core: price_per_unit from the operator's rate card for this member and class (NaN with
        /// COST_UNPRICED when the card has no price), expected_units from the plane's EXPECT for this
        /// request or its D_USAGE_CLASS default (§8.6). Tail = class text. A hook multiplies; core prices.
        pub struct CostTermRec {
            pub price_per_unit: f64,
            pub expected_units: f64,
            pub flags: u32,
            pub _r: u32,
        }
        pub struct Verdict {
            pub verb: u32,
            pub reject_status: u32,
        }
        pub struct Points {
            pub mask: u32,
            pub _r: u32,
        }
        }
        tags {
            /// view (core-built): FACT/FACT_TEXT signals (generic PJ_* request projection copied from the plane,
            /// plus the S_* keys below), CANDIDATE*, generic CONVERSATION (only if FB_WANTS_PROMPT),
            /// BODY (raw client body, only if FB_WANTS_BODY), generic ID_* (only if FB_WANTS_IDENTITY).
            CANDIDATE = 0x0100;
            C_MODEL = 0x0101;
            C_PROVIDER = 0x0102;
            C_TAG = 0x0103;
            C_COST_TERM = 0x0104;
            BODY = 0x0105;
            /// round 6: the candidate's tier text (nested in CANDIDATE); BUDGET* (BudgetRec + nested B_*), one per
            /// bucket, after the candidates.
            C_TIER = 0x0106;
            BUDGET = 0x0107;
            B_ID = 0x0108;
            B_PERIOD = 0x0109;
            B_GROUP = 0x010A;
            B_POOL = 0x010B;
            /// answer: VERDICT, then ORDER (u32 LE indices) | RESTRICT* (text) | MESSAGE (text) | REWRITE.
            /// REWRITE body = the generic CONVERSATION JSON shape (dialect-neutral; never the caller's dialect).
            /// Core hands it to the plane's `rewrite` (§8.6), which re-encodes it in the client's dialect.
            VERDICT = 0x0110;
            ORDER = 0x0111;
            RESTRICT = 0x0112;
            MESSAGE = 0x0113;
            REWRITE = 0x0114;
            /// describe: the points this hook serves.
            D_POINTS = 0x0180;
            /// Round 12, describe: one routing-strategy word this hook answers at POINT_ROUTE (text,
            /// `[a-z][a-z0-9_-]{0,31}`; at most 8; requires POINT_ROUTE in D_POINTS, else DescribeInvalid).
            /// Replaces today's MARK_WORD_HOOK marks. A pool that names the word as its ranking strategy is
            /// served by this hook, and the view carries the word as FACT_TEXT(S_ROUTING_POLICY) (§12.25).
            D_WORD = 0x0181;
        }
        consts {
            REQUIRED: u64 = 0;
            POINT_ROUTE: u32 = 1;
            POINT_REWRITE: u32 = 2;
            POINT_NOTIFY: u32 = 3;
            VERB_ABSTAIN: u32 = 0;
            VERB_PREFER: u32 = 1;
            VERB_PRIORITIZE: u32 = 2;
            VERB_RESTRICT: u32 = 3;
            VERB_REJECT: u32 = 4;
            VERB_REWRITE: u32 = 5;
        /// Hook-only signal keys (FACT / FACT_TEXT). The request-shape signals of round 1 (requested model,
        /// total chars, message, tool and system counts, stream, max tokens) are the generic PJ_* keys now;
        /// 0x100..=0x106 are retired.
            S_BUDGET_REMAINING_MICROS: u32 = 0x107;
            S_USER_SUBJECT: u32 = 0x108;
            S_ATTEMPT: u32 = 0x109;
            S_PREVIOUS_FAILURE: u32 = 0x10A;
            S_RESPONSE_TOKENS_OUT: u32 = 0x10B;
        /// S_ROUTING_POLICY (FACT_TEXT, round 12): the strategy word the pool named, when core resolved the
        /// pool's strategy to this instance by D_WORD (§12.25); absent otherwise.
            S_OUTCOME: u32 = 0x10C;
            S_STATUS: u32 = 0x10D;
            S_ROUTING_POLICY: u32 = 0x10E;
        /// round 6 (FACT_TEXT): the request's pool (operator name), its ingress protocol (the plane dialect
        /// text, e.g. "openai-chat"), and the calling API key's id and name (operator vocabulary; absent for
        /// unkeyed callers). S_REMAINING_CANDIDATES (FACT): candidates left after this attempt.
            S_POOL: u32 = 0x10F;
            S_INGRESS_PROTOCOL: u32 = 0x110;
            S_KEY_ID: u32 = 0x111;
            S_KEY_NAME: u32 = 0x112;
            S_REMAINING_CANDIDATES: u32 = 0x113;
        /// Round 17 (today's StageView `at` and `model`, contract abi/hook/mod.rs:700-719). S_STAGE (FACT): which
        /// operator stage fired the POINT_NOTIFY tap, one of STAGE_*; **present exactly on a stage tap** (today's
        /// candidate/routing/response taps) and absent on a request-stage call, so its presence is today's
        /// "this view has a `stage` object". S_STAGE_MODEL (FACT_TEXT): the attempt's model (today's
        /// `stage.model`, STAGE_HAS_MODEL), not PJ_MODEL (the model the client asked for); absent when today's
        /// presence bit is clear.
            S_STAGE: u32 = 0x114;
            S_STAGE_MODEL: u32 = 0x115;
            STAGE_CANDIDATE: u64 = 1;
            STAGE_ROUTING: u64 = 2;
            STAGE_RESPONSE: u64 = 3;
        /// CandidateRec.flags presence bits (today's CANDIDATE_HAS_* in busbar-contract abi/hook/mod.rs:446-450,
        /// plus the three optional fields the projection already omits when unknown).
            C_HAS_LATENCY: u32 = 1;
            C_HAS_BUDGET: u32 = 2;
            C_HAS_RATE_HEADROOM: u32 = 4;
            C_HAS_CONTEXT_MAX: u32 = 8;
            C_HAS_COST: u32 = 16;
            C_HAS_ERROR_RATE: u32 = 32;
        /// BudgetRec.flags.
            B_HAS_SPEND: u32 = 1;
            FB_WANTS_PROMPT: u64 = 1;
            FB_WANTS_BODY: u64 = 2;
            FB_WANTS_IDENTITY: u64 = 4;
        /// CostTermRec.flags.
            COST_UNPRICED: u32 = 1;
            M_ON: u64 = 1 << 0;
            M_ON_IO: u64 = 1 << 1;
        }
        /// In-process opinion. Answer: VERDICT + its data, plus METRIC* (generic, any point). At POINT_NOTIFY
        /// only METRIC is read. Core clamps reject_status to 400..=499 (else 403), drops out-of-range ORDER
        /// indices, and treats MESSAGE as operator text: audited, and shown to the client only as §12.15 says.
        sync fn on(&self, h: &Host, point: u32, view: Bytes<'_>, out: &mut Out<'_>) -> Result<(), Fail> { let _ = (h, point, view, out); Err(crate::fail::Fail::unsupported()) }
        /// The same, when the opinion needs I/O (hook-webrequest). Off the hot path. Declare exactly one of on / on_io.
        async fn on_io(&self, h: &'static Host, point: u32, view: ChainBytes) -> Result<Reply, Fail> { let _ = (h, point, view); Err(crate::fail::Fail::unsupported()) }

        extras {
            /// The host side of the hook kind: a typed face over busbar-ffi's `Instance` (IF §10.4).
            /// `live` points into the plugin image and is valid because `inst` holds the image (I13).
            #[cfg(feature = "host")]
            pub struct Proxy {
                inst: std::sync::Arc<crate::host_side::driver::Instance>,
                live: std::sync::Arc<busbar_ffi::host::Instance<Marker>>,
            }

            #[cfg(feature = "host")]
            impl Proxy {
                /// Bind. Done by the loader only, after admit; None when `inst` is not a hook instance.
                pub fn bind(inst: std::sync::Arc<crate::host_side::driver::Instance>) -> Option<Self> {
                    let live = inst.live::<Marker>()?;
                    Some(Proxy { inst, live })
                }

                pub fn instance(&self) -> &std::sync::Arc<crate::host_side::driver::Instance> {
                    &self.inst
                }

                /// `on`: the thread's sync buffer or the caller's, inside the watchdog word; never allocates.
                pub fn on<'o>(
                    &self,
                    buf: &'o mut crate::host_side::pool::PooledOut,
                    point: u32,
                    view: &[u8],
                ) -> Result<crate::host_side::answer::Answer<'o>, crate::fail::CallError> {
                    use crate::plugin::__rt::Arg;
                    use crate::types::Bytes;
                    crate::host_side::proxy::sync(&self.inst, crate::host_side::proxy::entry(M_ON), buf, |lease| {
                        self.live.call2(
                            |vt| &vt.on,
                            Arg::u32(point),
                            Arg::bytes(Bytes::new(view)),
                            lease,
                        )
                    })
                }

                pub fn on_io<'a, N: crate::host_side::needs::Needs>(
                    &'a self,
                    drv: &'a mut crate::host_side::driver::Driver<'a, N>,
                    req: crate::host_side::pool::PooledOut,
                    point: u32,
                ) -> impl core::future::Future<
                    Output = Result<crate::host_side::answer::OwnedAnswer, crate::fail::CallError>,
                > + Send
                + 'a {
                    use crate::host_side::proxy;
                    proxy::chain::<Marker, _, _>(&self.inst, drv, proxy::entry(M_ON_IO), req, |req, lease| {
                        let (bufs, at) = proxy::staged(req);
                        self.live
                            .start2(
                                |vt| &vt.on_io,
                                bufs,
                                |b| {
                                    (
                                        crate::plugin::__rt::Arg::u32(point),
                                        crate::plugin::__rt::Arg::bytes(b.get(at)),
                                    )
                                },
                                lease,
                            )
                            .into()
                    })
                }
            }
        }
    }
}
