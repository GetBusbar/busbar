// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hook kind: the `Hook` trait and the `hook` module (IF §8.4, §10.4). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-A8 fills it.

crate::kind::kind_stub! {
    /// A hook gives an opinion at a decision point. Core owns the decision and applies, clamps or ignores it.
    pub trait Hook: Send + Sync + 'static {
        /// In-process opinion. Answer: VERDICT + its data, plus METRIC* (generic, any point). At POINT_NOTIFY
        /// only METRIC is read. Core clamps reject_status to 400..=499 (else 403), drops out-of-range ORDER
        /// indices, and treats MESSAGE as operator text: audited, and shown to the client only as §12.15 says.
        fn on(
            &self,
            h: &crate::host::Host,
            point: u32,
            view: crate::types::Bytes<'_>,
            out: &mut crate::records::Out<'_>,
        ) -> Result<(), crate::fail::Fail> {
            let _ = (h, point, view, out);
            todo!()
        }
        /// The same, when the opinion needs I/O (hook-webrequest). Off the hot path. Declare exactly one of on / on_io.
        fn on_io(
            &self,
            h: &'static crate::host::Host,
            point: u32,
            view: crate::need::ChainBytes,
        ) -> impl core::future::Future<Output = Result<crate::records::Reply, crate::fail::Fail>> + Send {
            let _ = (h, point, view);
            async move { todo!() }
        }
    }
}

pub mod hook {
    //! The hook kind's records, constants and method bits (IF §8.4), and its host-side `Proxy` (§10.4).

    /// One routing candidate as core sees it. Tail = nested: C_MODEL text, C_PROVIDER text (a config name,
    /// never a plugin), C_TIER text? (the member's configured tier, verbatim), C_TAG* text, C_COST_TERM*
    /// (CostTermRec + class text). weight = the operator's configured weight; available_concurrency = free
    /// concurrency permits now (today's DecodedCandidate fields, busbar-contract abi/sdk/hook.rs:161-179).
    /// flags = C_HAS_* presence bits: a numeric field whose bit is clear has **no sample** (it is 0 and must
    /// not be read as a value; `fastest` demotes such a member, it does not rank it first). Round 6.
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
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
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
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
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct CostTermRec {
        pub price_per_unit: f64,
        pub expected_units: f64,
        pub flags: u32,
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
    pub struct Verdict {
        pub verb: u32,
        pub reject_status: u32,
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
    pub struct Points {
        pub mask: u32,
        pub _r: u32,
    }

    impl crate::records::Pod for CandidateRec {}
    impl crate::records::Pod for BudgetRec {}
    impl crate::records::Pod for CostTermRec {}
    impl crate::records::Pod for Verdict {}
    impl crate::records::Pod for Points {}

    pub mod tag {
        /// view (core-built): FACT/FACT_TEXT signals (generic PJ_* request projection copied from the plane,
        /// plus the S_* keys below), CANDIDATE*, generic CONVERSATION (only if FB_WANTS_PROMPT),
        /// BODY (raw client body, only if FB_WANTS_BODY), generic ID_* (only if FB_WANTS_IDENTITY).
        pub const CANDIDATE: u16 = 0x0100;
        pub const C_MODEL: u16 = 0x0101;
        pub const C_PROVIDER: u16 = 0x0102;
        pub const C_TAG: u16 = 0x0103;
        pub const C_COST_TERM: u16 = 0x0104;
        pub const BODY: u16 = 0x0105;
        /// round 6: the candidate's tier text (nested in CANDIDATE); BUDGET* (BudgetRec + nested B_*), one per
        /// bucket, after the candidates.
        pub const C_TIER: u16 = 0x0106;
        pub const BUDGET: u16 = 0x0107;
        pub const B_ID: u16 = 0x0108;
        pub const B_PERIOD: u16 = 0x0109;
        pub const B_GROUP: u16 = 0x010A;
        pub const B_POOL: u16 = 0x010B;
        /// answer: VERDICT, then ORDER (u32 LE indices) | RESTRICT* (text) | MESSAGE (text) | REWRITE.
        /// REWRITE body = the generic CONVERSATION JSON shape (dialect-neutral; never the caller's dialect).
        /// Core hands it to the plane's `rewrite` (§8.6), which re-encodes it in the client's dialect.
        pub const VERDICT: u16 = 0x0110;
        pub const ORDER: u16 = 0x0111;
        pub const RESTRICT: u16 = 0x0112;
        pub const MESSAGE: u16 = 0x0113;
        pub const REWRITE: u16 = 0x0114;
        /// describe: the points this hook serves.
        pub const D_POINTS: u16 = 0x0180;
        /// Round 12, describe: one routing-strategy word this hook answers at POINT_ROUTE (text,
        /// `[a-z][a-z0-9_-]{0,31}`; at most 8; requires POINT_ROUTE in D_POINTS, else DescribeInvalid).
        /// Replaces today's MARK_WORD_HOOK marks. A pool that names the word as its ranking strategy is
        /// served by this hook, and the view carries the word as FACT_TEXT(S_ROUTING_POLICY) (§12.25).
        pub const D_WORD: u16 = 0x0181;
    }

    pub const REQUIRED: u64 = 0;
    pub const POINT_ROUTE: u32 = 1;
    pub const POINT_REWRITE: u32 = 2;
    pub const POINT_NOTIFY: u32 = 3;
    pub const VERB_ABSTAIN: u32 = 0;
    pub const VERB_PREFER: u32 = 1;
    pub const VERB_PRIORITIZE: u32 = 2;
    pub const VERB_RESTRICT: u32 = 3;
    pub const VERB_REJECT: u32 = 4;
    pub const VERB_REWRITE: u32 = 5;
    /// Hook-only signal keys (FACT / FACT_TEXT). The request-shape signals of round 1 (requested model,
    /// total chars, message, tool and system counts, stream, max tokens) are the generic PJ_* keys now;
    /// 0x100..=0x106 are retired.
    pub const S_BUDGET_REMAINING_MICROS: u32 = 0x107;
    pub const S_USER_SUBJECT: u32 = 0x108;
    pub const S_ATTEMPT: u32 = 0x109;
    pub const S_PREVIOUS_FAILURE: u32 = 0x10A;
    pub const S_RESPONSE_TOKENS_OUT: u32 = 0x10B;
    /// S_ROUTING_POLICY (FACT_TEXT, round 12): the strategy word the pool named, when core resolved the
    /// pool's strategy to this instance by D_WORD (§12.25); absent otherwise.
    pub const S_OUTCOME: u32 = 0x10C;
    pub const S_STATUS: u32 = 0x10D;
    pub const S_ROUTING_POLICY: u32 = 0x10E;
    /// round 6 (FACT_TEXT): the request's pool (operator name), its ingress protocol (the plane dialect
    /// text, e.g. "openai-chat"), and the calling API key's id and name (operator vocabulary; absent for
    /// unkeyed callers). S_REMAINING_CANDIDATES (FACT): candidates left after this attempt.
    pub const S_POOL: u32 = 0x10F;
    pub const S_INGRESS_PROTOCOL: u32 = 0x110;
    pub const S_KEY_ID: u32 = 0x111;
    pub const S_KEY_NAME: u32 = 0x112;
    pub const S_REMAINING_CANDIDATES: u32 = 0x113;
    /// Round 17 (today's StageView `at` and `model`, contract abi/hook/mod.rs:700-719). S_STAGE (FACT): which
    /// operator stage fired the POINT_NOTIFY tap, one of STAGE_*; **present exactly on a stage tap** (today's
    /// candidate/routing/response taps) and absent on a request-stage call, so its presence is today's
    /// "this view has a `stage` object". S_STAGE_MODEL (FACT_TEXT): the attempt's model (today's
    /// `stage.model`, STAGE_HAS_MODEL), not PJ_MODEL (the model the client asked for); absent when today's
    /// presence bit is clear.
    pub const S_STAGE: u32 = 0x114;
    pub const S_STAGE_MODEL: u32 = 0x115;
    pub const STAGE_CANDIDATE: u64 = 1;
    pub const STAGE_ROUTING: u64 = 2;
    pub const STAGE_RESPONSE: u64 = 3;
    /// CandidateRec.flags presence bits (today's CANDIDATE_HAS_* in busbar-contract abi/hook/mod.rs:446-450,
    /// plus the three optional fields the projection already omits when unknown).
    pub const C_HAS_LATENCY: u32 = 1;
    pub const C_HAS_BUDGET: u32 = 2;
    pub const C_HAS_RATE_HEADROOM: u32 = 4;
    pub const C_HAS_CONTEXT_MAX: u32 = 8;
    pub const C_HAS_COST: u32 = 16;
    pub const C_HAS_ERROR_RATE: u32 = 32;
    /// BudgetRec.flags.
    pub const B_HAS_SPEND: u32 = 1;
    pub const FB_WANTS_PROMPT: u64 = 1;
    pub const FB_WANTS_BODY: u64 = 2;
    pub const FB_WANTS_IDENTITY: u64 = 4;
    /// CostTermRec.flags.
    pub const COST_UNPRICED: u32 = 1;

    pub const KIND: crate::types::KindCode = crate::types::KindCode::Hook;
    pub const ABI: u32 = 2;
    pub const FP: u64 = 0; // W0-ABI stub value; kind! computes it (W1-A4).

    pub const M_ON: u64 = 1 << 0;
    pub const M_ON_IO: u64 = 1 << 1;
    pub const ALL: u64 = M_ON | M_ON_IO;

    // W0-ABI: `Vt` (fields on, on_io are unsafe extern "C" fn pointers) and the `vt::<T>()` shims are unsafe;
    // they land with W1-A4 (`kind!`) under an escapes.json admission.

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

        pub fn on<'o>(
            &self,
            buf: &'o mut crate::host_side::pool::PooledOut,
            point: u32,
            view: &[u8],
        ) -> Result<crate::host_side::answer::Answer<'o>, crate::fail::CallError> {
            let _ = (&self._stub, buf, point, view);
            todo!()
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
            let _ = (&self._stub, drv, req, point);
            async move { todo!() }
        }
    }
}
