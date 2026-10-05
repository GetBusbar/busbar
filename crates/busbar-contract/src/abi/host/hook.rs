// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK KIND'S VIEWS, HOST SIDE: the fixed `in`s of `decide`/`transform`/`notify`
//! (`abi::hook`) built from the kernel's own projections ([`RoutingRequest`], [`Candidate`],
//! [`RoutingContext`]), and the host buffers a `decide`/`transform` answer is written into.
//!
//! A view owns the SMALL things its pointers name — the projection's strings and lists, and the
//! frame's result buffers — so the dispatcher can hold them past a caller that stopped waiting
//! (`plugin-loader`'s `Dispatcher::submit_lent`, ARCHITECT ruling 2026-09-29). The request BODY is
//! never copied into a view: `PromptView::body` names bytes LENT by the request-serving code, which
//! hands their owner to `submit_lent` beside the frame (the hooks law: body zero-copy). A frame is
//! immutable once built except for the host buffers the plugin writes; the one short-buffer
//! re-call gets a fresh frame over the same view ([`DecideFrame::regrown_decide`]).
//!
//! An absent string is a NULL [`AbiStr`]; a present one — even an empty one — is non-NULL.

use std::sync::Arc;

use crate::abi::hook::{
    BudgetBucketState, CandidateDynamic, CandidateStatic, DecideIn, DecideOut, MessageView,
    NotifyIn, PromptView, RequestView, SignalEntry, SignalValue, StageView, TransformOut, UserView,
    BUDGET_HAS_REMAINING_MICROS, CANDIDATE_HAS_BUDGET_REMAINING, CANDIDATE_HAS_CONTEXT_MAX,
    CANDIDATE_HAS_COST_PER_MTOK, CANDIDATE_HAS_LATENCY_MS, CANDIDATE_HAS_RATE_HEADROOM,
    CANDIDATE_HAS_TIER, REQUEST_HAS_MAX_TOKENS, REQUEST_HAS_TOOLS, REQUEST_STREAM, SIGNAL_TAG_BOOL,
    SIGNAL_TAG_F64, SIGNAL_TAG_I64, SIGNAL_TAG_STR, SIGNAL_TAG_U64, STAGE_AT_CANDIDATE,
    STAGE_AT_RESPONSE, STAGE_AT_ROUTING, STAGE_HAS_ATTEMPT_NUMBER, STAGE_HAS_MODEL,
    STAGE_HAS_OUTCOME, STAGE_HAS_PREVIOUS_FAILURE, STAGE_HAS_PROJECTION,
    STAGE_HAS_REMAINING_CANDIDATES, STAGE_HAS_STATUS, VIEW_HAS_BUDGET_REMAINING, VIEW_HAS_PROMPT,
    VIEW_HAS_USER,
};
use crate::abi::mechanism::call::{AbiStr, Blob, InHead, Outcome, BLOB_ABSENT, BLOB_OCTETS};
use crate::hook_wire::HookStageProjection;
use crate::hooks::{Candidate, RoutingContext, RoutingRequest};
use crate::signal::{SignalBag, SignalValue as Value};

/// The NULL string: absent.
const NULL: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// An absent blob.
const NO_BLOB: Blob = Blob {
    ptr: std::ptr::null(),
    len: 0,
    fmt: BLOB_ABSENT,
    flags: 0,
};

/// The owned storage a view's pointers name. Every element is pushed BEFORE a pointer to it is
/// taken, and nothing is pushed after, so every heap buffer below is stable for the view's life.
#[derive(Default)]
struct Store {
    strs: Vec<Box<str>>,
    lists: Vec<Box<[AbiStr]>>,
    signals: Vec<Box<[SignalEntry]>>,
    messages: Vec<Box<[MessageView]>>,
    octets: Vec<Box<[u8]>>,
}

impl Store {
    /// A present string (non-NULL even when empty: a `Box<str>`'s pointer is never NULL).
    fn s(&mut self, v: &str) -> AbiStr {
        let b: Box<str> = v.into();
        let out = AbiStr {
            ptr: b.as_ptr(),
            len: b.len(),
        };
        self.strs.push(b);
        out
    }

    fn opt(&mut self, v: Option<&str>) -> AbiStr {
        v.map_or(NULL, |v| self.s(v))
    }

    /// Present octets ([`BLOB_OCTETS`]), copied into the view; `None` = an absent blob.
    fn octets(&mut self, v: Option<&[u8]>) -> Blob {
        let Some(v) = v else {
            return NO_BLOB;
        };
        let b: Box<[u8]> = v.into();
        let out = Blob {
            ptr: b.as_ptr(),
            len: b.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        self.octets.push(b);
        out
    }

    fn list(&mut self, v: &[String]) -> (*const AbiStr, usize) {
        if v.is_empty() {
            return (std::ptr::null(), 0);
        }
        let items: Box<[AbiStr]> = v.iter().map(|t| self.s(t)).collect();
        let out = (items.as_ptr(), items.len());
        self.lists.push(items);
        out
    }

    fn bag(&mut self, bag: &SignalBag) -> (*const SignalEntry, usize) {
        if bag.is_empty() {
            return (std::ptr::null(), 0);
        }
        let items: Box<[SignalEntry]> = bag
            .iter()
            .map(|(sig, v)| {
                let (tag, value) = match v {
                    Value::U64(n) => (SIGNAL_TAG_U64, SignalValue { u64_: *n }),
                    Value::I64(n) => (SIGNAL_TAG_I64, SignalValue { i64_: *n }),
                    Value::F64(n) => (SIGNAL_TAG_F64, SignalValue { f64_: *n }),
                    Value::Bool(b) => (
                        SIGNAL_TAG_BOOL,
                        SignalValue {
                            boolean: u8::from(*b),
                        },
                    ),
                    Value::Str(t) => (SIGNAL_TAG_STR, SignalValue { str_: self.s(t) }),
                };
                SignalEntry {
                    id: sig.bit(),
                    tag,
                    value,
                }
            })
            .collect();
        let out = (items.as_ptr(), items.len());
        self.signals.push(items);
        out
    }

    /// The prompt view of `req`, or `None` when the request carries none (no `prompt` grant).
    fn prompt(&mut self, req: &RoutingRequest<'_>) -> Option<PromptView> {
        let p = req.prompt.as_ref()?;
        let items: Box<[MessageView]> = p
            .messages
            .iter()
            .map(|(role, text)| MessageView {
                role: self.s(role),
                text: self.s(text),
            })
            .collect();
        let view = PromptView {
            system: self.opt(p.system.as_deref()),
            message_count: items.len() as u64,
            body: NO_BLOB,
            messages: if items.is_empty() {
                std::ptr::null()
            } else {
                items.as_ptr()
            },
            messages_len: items.len(),
        };
        self.messages.push(items);
        Some(view)
    }
}

fn empty_prompt() -> PromptView {
    PromptView {
        system: NULL,
        message_count: 0,
        body: NO_BLOB,
        messages: std::ptr::null(),
        messages_len: 0,
    }
}

fn request_view(store: &mut Store, req: &RoutingRequest<'_>) -> RequestView {
    let (signals, signals_len) = store.bag(&req.signals);
    let mut flags = 0;
    if req.max_tokens.is_some() {
        flags |= REQUEST_HAS_MAX_TOKENS;
    }
    if req.has_tools {
        flags |= REQUEST_HAS_TOOLS;
    }
    if req.stream {
        flags |= REQUEST_STREAM;
    }
    RequestView {
        request_id: req.request_id,
        pool: store.s(req.pool),
        ingress_dialect: store.s(req.ingress_protocol),
        message_count: req.message_count as u64,
        total_chars: req.total_chars as u64,
        max_tokens: req.max_tokens.unwrap_or(0),
        flags,
        signals,
        signals_len,
        session: store.octets(req.session),
    }
}

/// THE `decide`/`transform` VIEW: everything the two ops' shared [`DecideIn`] points at, built once
/// per call from the kernel's projections. Immutable; shared by the call's frames.
pub struct DecideView {
    base: DecideIn,
    _store: Store,
    _statics: Box<[CandidateStatic]>,
    _dynamics: Box<[CandidateDynamic]>,
    _budget: Box<[BudgetBucketState]>,
    /// The candidates' `idx`es, in order (what an `order` answer may name).
    idx: Box<[usize]>,
}

// SAFETY: every pointer in `base` names storage this view owns and never mutates; it moves between
// threads as a whole and is only read.
unsafe impl Send for DecideView {}
// SAFETY: as above; shared reads only.
unsafe impl Sync for DecideView {}

impl DecideView {
    /// The view of one request: `prompt`/`user` are populated exactly when the kernel's projection
    /// carries them (the grants already applied), `budget_remaining` when the pool is capped.
    #[must_use]
    pub fn build(
        req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        ctx: &RoutingContext<'_>,
    ) -> Arc<Self> {
        let mut store = Store::default();
        let request = request_view(&mut store, req);
        let mut present = 0;
        let prompt = match store.prompt(req) {
            Some(p) => {
                present |= VIEW_HAS_PROMPT;
                p
            }
            None => empty_prompt(),
        };
        let user = match &req.identity {
            Some(i) => {
                present |= VIEW_HAS_USER;
                UserView {
                    key_id: store.opt(i.key_id.as_deref()),
                    key_name: store.opt(i.key_name.as_deref()),
                    user: store.opt(i.user.as_deref()),
                }
            }
            None => UserView {
                key_id: NULL,
                key_name: NULL,
                user: NULL,
            },
        };
        if ctx.budget_remaining.is_some() {
            present |= VIEW_HAS_BUDGET_REMAINING;
        }
        let statics: Box<[CandidateStatic]> = candidates
            .iter()
            .map(|c| {
                let (tags, tags_len) = store.list(c.tags);
                let mut p = 0;
                if c.context_max.is_some() {
                    p |= CANDIDATE_HAS_CONTEXT_MAX;
                }
                if c.tier.is_some() {
                    p |= CANDIDATE_HAS_TIER;
                }
                if c.cost_per_mtok.is_some() {
                    p |= CANDIDATE_HAS_COST_PER_MTOK;
                }
                CandidateStatic {
                    idx: u32::try_from(c.idx).unwrap_or(u32::MAX),
                    _reserved: 0,
                    model: store.s(c.model),
                    provider: store.s(c.provider),
                    weight: c.weight,
                    _reserved3: 0,
                    context_max: c.context_max.unwrap_or(0) as u64,
                    tier: store.opt(c.tier),
                    cost_per_mtok: c.cost_per_mtok.unwrap_or(0.0),
                    tags,
                    tags_len,
                    present: p,
                    _reserved2: 0,
                }
            })
            .collect();
        let dynamics: Box<[CandidateDynamic]> = candidates
            .iter()
            .map(|c| {
                let (signals, signals_len) = store.bag(&c.signals);
                let mut p = 0;
                if c.latency_ms.is_some() {
                    p |= CANDIDATE_HAS_LATENCY_MS;
                }
                if c.budget_remaining.is_some() {
                    p |= CANDIDATE_HAS_BUDGET_REMAINING;
                }
                if c.rate_headroom.is_some() {
                    p |= CANDIDATE_HAS_RATE_HEADROOM;
                }
                CandidateDynamic {
                    latency_ms: c.latency_ms.unwrap_or(0.0),
                    available_concurrency: c.available_concurrency as u64,
                    budget_remaining: c.budget_remaining.unwrap_or(0),
                    rate_headroom: c.rate_headroom.unwrap_or(0.0),
                    signals,
                    signals_len,
                    present: p,
                    _reserved: 0,
                }
            })
            .collect();
        let budget: Box<[BudgetBucketState]> = ctx
            .budget
            .iter()
            .map(|b| BudgetBucketState {
                bucket_id: store.s(&b.bucket_id),
                budget_group: store.opt(b.budget_group.as_deref()),
                pool: store.opt(b.pool.as_deref()),
                spend_micros_at_current_rate: b.spend_micros_at_current_rate,
                remaining_micros: b.remaining_micros.unwrap_or(0),
                window_start: b.window_start,
                budget_period: store.s(&b.budget_period),
                present: if b.remaining_micros.is_some() {
                    BUDGET_HAS_REMAINING_MICROS
                } else {
                    0
                },
                _reserved: 0,
            })
            .collect();
        let ptr_or_null = |len: usize, p: *const u8| if len == 0 { std::ptr::null() } else { p };
        let base = DecideIn {
            head: blank_head(),
            request,
            candidates: ptr_or_null(statics.len(), statics.as_ptr().cast()).cast(),
            candidate_dynamics: ptr_or_null(dynamics.len(), dynamics.as_ptr().cast()).cast(),
            candidates_len: statics.len(),
            prompt,
            user,
            budget_remaining: ctx.budget_remaining.unwrap_or(0),
            budget: ptr_or_null(budget.len(), budget.as_ptr().cast()).cast(),
            budget_len: budget.len(),
            present,
            _reserved: 0,
            order_buf: std::ptr::null_mut(),
            order_cap: 0,
            reject_message_buf: std::ptr::null_mut(),
            reject_message_cap: 0,
            restrict_tags_buf: std::ptr::null_mut(),
            restrict_tags_cap: 0,
            rewrite_buf: std::ptr::null_mut(),
            rewrite_cap: 0,
        };
        Arc::new(Self {
            base,
            idx: candidates.iter().map(|c| c.idx).collect(),
            _store: store,
            _statics: statics,
            _dynamics: dynamics,
            _budget: budget,
        })
    }

    /// The candidates' `idx`es, in order.
    #[must_use]
    pub fn candidate_idx(&self) -> &[usize] {
        &self.idx
    }
}

/// A blank head; the dispatcher fills it before each crossing.
fn blank_head() -> InHead {
    // SAFETY: `InHead` is plain integers, raw pointers and plain structs of those.
    let mut h: InHead = unsafe { std::mem::zeroed() };
    h.size = std::mem::size_of::<InHead>() as u32;
    h
}

/// One host buffer a plugin writes into: zero-filled, owned, freed on drop. Held by raw pointer so
/// the plugin's writes never alias a Rust reference.
struct HostBuf<T: Copy + Default> {
    ptr: *mut T,
    cap: usize,
}

impl<T: Copy + Default> HostBuf<T> {
    fn new(cap: usize) -> Self {
        let boxed: Box<[T]> = vec![T::default(); cap].into_boxed_slice();
        let cap = boxed.len();
        Self {
            ptr: Box::into_raw(boxed).cast::<T>(),
            cap,
        }
    }

    /// The first `n` elements (clamped to the capacity). Read only after the op answered.
    fn read(&self, n: usize) -> &[T] {
        if self.cap == 0 {
            return &[];
        }
        // SAFETY: `ptr` holds `cap` initialized elements (zero-filled at birth); the plugin wrote
        // through it only during a crossing that has returned.
        unsafe { std::slice::from_raw_parts(self.ptr, n.min(self.cap)) }
    }
}

impl<T: Copy + Default> Drop for HostBuf<T> {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`cap` came from `Box::into_raw` of a `Box<[T]>` of exactly `cap` elements.
        unsafe {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                self.ptr, self.cap,
            )))
        };
    }
}

/// The capacities one `decide`/`transform` call hands the plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// `order_buf`, in `u32` slots.
    pub order: usize,
    /// `reject_message_buf`, in bytes.
    pub reject_message: usize,
    /// `restrict_tags_buf`, in bytes.
    pub restrict_tags: usize,
    /// `rewrite_buf`, in bytes.
    pub rewrite: usize,
}

impl Caps {
    /// The first call's capacities: an order as long as the candidate list, room for a reject
    /// message past the 300-character cap in any UTF-8, and generous tag and rewrite buffers. A
    /// longer answer takes the one short-buffer re-call.
    #[must_use]
    pub fn initial(view: &DecideView) -> Self {
        Self {
            order: view.idx.len().max(1),
            reject_message: 2048,
            restrict_tags: 4096,
            rewrite: 64 * 1024,
        }
    }

    /// The re-call's capacities after a SHORT `decide` answer: each dimension grown to what it
    /// said it needs.
    #[must_use]
    pub fn after_decide(self, out: &DecideOut) -> Self {
        Self {
            order: self.order.max(out.order_needed),
            reject_message: self.reject_message.max(out.reject_message_needed),
            restrict_tags: self.restrict_tags.max(out.restrict_tags_needed),
            rewrite: self.rewrite,
        }
    }

    /// The re-call's capacities after a SHORT `transform` answer.
    #[must_use]
    pub fn after_transform(self, out: &TransformOut) -> Self {
        Self {
            reject_message: self.reject_message.max(out.reject_message_needed),
            rewrite: self.rewrite.max(out.rewrite_needed),
            ..self
        }
    }
}

/// ONE `decide`/`transform` CALL'S FRAME: the view's [`DecideIn`] pointed at this frame's own host
/// buffers. Lent to the dispatcher for the life of the op; read after it answered.
pub struct DecideFrame {
    view: Arc<DecideView>,
    caps: Caps,
    order: HostBuf<u32>,
    reject_message: HostBuf<u8>,
    restrict_tags: HostBuf<u8>,
    rewrite: HostBuf<u8>,
}

impl std::fmt::Debug for DecideFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecideFrame")
            .field("caps", &self.caps)
            .finish_non_exhaustive()
    }
}

// SAFETY: the host buffers are written only by the plugin during a crossing (the frame is lent to
// the dispatcher then) and read only after the op answered; the view is `Sync`.
unsafe impl Send for DecideFrame {}
// SAFETY: as above.
unsafe impl Sync for DecideFrame {}

impl DecideFrame {
    /// A frame over `view` with `caps`.
    #[must_use]
    pub fn new(view: Arc<DecideView>, caps: Caps) -> Arc<Self> {
        Arc::new(Self {
            view,
            caps,
            order: HostBuf::new(caps.order),
            reject_message: HostBuf::new(caps.reject_message),
            restrict_tags: HostBuf::new(caps.restrict_tags),
            rewrite: HostBuf::new(caps.rewrite),
        })
    }

    /// The first frame of a call.
    #[must_use]
    pub fn first(view: Arc<DecideView>) -> Arc<Self> {
        let caps = Caps::initial(&view);
        Self::new(view, caps)
    }

    /// The frame for the one short-buffer re-call of `decide`: the same view, grown buffers.
    #[must_use]
    pub fn regrown_decide(&self, out: &DecideOut) -> Arc<Self> {
        Self::new(self.view.clone(), self.caps.after_decide(out))
    }

    /// The frame for the one short-buffer re-call of `transform`.
    #[must_use]
    pub fn regrown_transform(&self, out: &TransformOut) -> Arc<Self> {
        Self::new(self.view.clone(), self.caps.after_transform(out))
    }

    /// The `in` the call crosses with (its head blank; the dispatcher fills it).
    #[must_use]
    pub fn input(&self) -> DecideIn {
        DecideIn {
            order_buf: self.order.ptr,
            order_cap: self.order.cap,
            reject_message_buf: self.reject_message.ptr,
            reject_message_cap: self.reject_message.cap,
            restrict_tags_buf: self.restrict_tags.ptr,
            restrict_tags_cap: self.restrict_tags.cap,
            rewrite_buf: self.rewrite.ptr,
            rewrite_cap: self.rewrite.cap,
            ..self.view.base
        }
    }

    /// The view.
    #[must_use]
    pub fn view(&self) -> &DecideView {
        &self.view
    }

    /// The candidate order a `decide` answer wrote (`order_written` entries, as `idx`es).
    #[must_use]
    pub fn order(&self, written: usize) -> Vec<usize> {
        self.order
            .read(written)
            .iter()
            .map(|&i| i as usize)
            .collect()
    }

    /// The reject-message bytes an answer wrote (`reject_message_written`), lossily UTF-8.
    #[must_use]
    pub fn reject_message(&self, written: usize) -> String {
        String::from_utf8_lossy(self.reject_message.read(written)).into_owned()
    }

    /// The restrict tags a `decide` answer wrote: NUL-separated, each lossily UTF-8.
    #[must_use]
    pub fn restrict_tags(&self, written: usize) -> Vec<String> {
        let bytes = self.restrict_tags.read(written);
        if bytes.is_empty() {
            return Vec::new();
        }
        bytes
            .split(|b| *b == 0)
            .map(|t| String::from_utf8_lossy(t).into_owned())
            .collect()
    }

    /// The rewrite bytes a `transform` answer wrote (`rewrite_written`).
    #[must_use]
    pub fn rewrite(&self, written: usize) -> Vec<u8> {
        self.rewrite.read(written).to_vec()
    }

    /// The 1.5.5 `decide`/`transform` JSON (`op`: [`crate::hook_wire::OP_DECIDE`] or
    /// [`crate::hook_wire::OP_TRANSFORM`]) a hook written against the JSON contract is handed for
    /// this frame's view: the SDK's own rebuild ([`crate::abi::sdk::hook::Decoded::projection_json`]),
    /// read here so an in-process hook reads exactly what a plugin reads (as
    /// [`NotifyFrame::projection_json`]).
    #[must_use]
    pub fn projection_json(&self, op: &'static str) -> serde_json::Value {
        let input = self.input();
        // SAFETY: every pointer in `input` names storage this frame owns (its view's store and its
        // host buffers), live while `self` is borrowed.
        let lent = unsafe { crate::abi::sdk::Lent::new(&input) };
        crate::abi::sdk::hook::Decoded::of(lent).projection_json(op)
    }

    /// ANSWER `decide` IN PROCESS: `v` lowered into this frame's own host buffers exactly as the
    /// SDK's door lowers it ([`crate::abi::sdk::hook::write_verdict`], the one short FAILED
    /// included), and the `out` it answers (its head blank: nothing crossed). For an in-process
    /// [`crate::hook_calls::HookCalls`], the frame's one answerer: nothing reads the answer before
    /// this returns.
    #[must_use]
    pub fn answer_decide(&self, v: &crate::abi::sdk::hook::Verdict) -> (Outcome, DecideOut) {
        let input = self.input();
        // SAFETY: as `projection_json`; the host buffers are writable for their stated capacity
        // and overlap nothing else.
        let lent = unsafe { crate::abi::sdk::Lent::new(&input) };
        // SAFETY: `DecideOut` is plain integers and a head of plain integers, raw pointers and
        // blobs, for which the all-zero pattern is valid (the host's own pre-fill).
        let mut out: DecideOut = unsafe { std::mem::zeroed() };
        let outcome = crate::abi::sdk::hook::write_verdict(v, lent, &mut out);
        (outcome, out)
    }

    /// [`Self::answer_decide`]'s `transform` twin ([`crate::abi::sdk::hook::write_rewrite`]).
    #[must_use]
    pub fn answer_transform(
        &self,
        v: &crate::abi::sdk::hook::RewriteVerdict,
    ) -> (Outcome, TransformOut) {
        let input = self.input();
        // SAFETY: as `answer_decide`.
        let lent = unsafe { crate::abi::sdk::Lent::new(&input) };
        // SAFETY: as `answer_decide`: `TransformOut` is plain integers and a plain head.
        let mut out: TransformOut = unsafe { std::mem::zeroed() };
        let outcome = crate::abi::sdk::hook::write_rewrite(v, lent, &mut out);
        (outcome, out)
    }
}

/// ONE `notify` CALL'S FRAME (WIRE-HOOK Q5): the stage view, the request's declared signals and —
/// only under the tap's `prompt: ro` grant — the prompt view. Owns everything it points at; the host's tap pool holds one per
/// queued notification (H3: a copy of the fixed view, never JSON).
pub struct NotifyFrame {
    input: NotifyIn,
    _store: Store,
}

impl std::fmt::Debug for NotifyFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotifyFrame").finish_non_exhaustive()
    }
}

// SAFETY: as `DecideView`: owned, immutable, read-only storage behind every pointer.
unsafe impl Send for NotifyFrame {}
// SAFETY: as above.
unsafe impl Sync for NotifyFrame {}

impl NotifyFrame {
    /// The tap view of `req` (its shape fields and declared signals) at `stage` (`None` = a
    /// request-stage tap: no stage projection, as 1.5.5's `stage` was absent). The prompt view is
    /// carried only when `prompt_granted` (the tap's `prompt: ro` grant) AND `req` projects one: an
    /// ungranted tap never sees the prompt, whatever the request carries.
    #[must_use]
    pub fn build(
        req: &RoutingRequest<'_>,
        stage: Option<&HookStageProjection<'_>>,
        prompt_granted: bool,
    ) -> Arc<Self> {
        let mut store = Store::default();
        let (signals, signals_len) = store.bag(&req.signals);
        let granted = if prompt_granted {
            store.prompt(req)
        } else {
            None
        };
        let (prompt, present) = match granted {
            Some(p) => (p, VIEW_HAS_PROMPT),
            None => (empty_prompt(), 0),
        };
        let mut flags = 0;
        if req.max_tokens.is_some() {
            flags |= REQUEST_HAS_MAX_TOKENS;
        }
        if req.has_tools {
            flags |= REQUEST_HAS_TOOLS;
        }
        if req.stream {
            flags |= REQUEST_STREAM;
        }
        let mut sv = StageView {
            request_id: req.request_id,
            pool: store.s(req.pool),
            ingress_dialect: store.s(req.ingress_protocol),
            message_count: req.message_count as u64,
            total_chars: req.total_chars as u64,
            remaining_candidates: 0,
            model: NULL,
            previous_failure: NULL,
            outcome: NULL,
            max_tokens: req.max_tokens.unwrap_or(0),
            flags,
            at: 0,
            attempt_number: 0,
            status: 0,
            _reserved: [0; 2],
            stage_present: 0,
            _reserved2: 0,
        };
        if let Some(st) = stage {
            sv.stage_present |= STAGE_HAS_PROJECTION;
            sv.at = match st.at {
                "candidate" => STAGE_AT_CANDIDATE,
                "routing" => STAGE_AT_ROUTING,
                _ => STAGE_AT_RESPONSE,
            };
            if let Some(m) = st.model {
                sv.stage_present |= STAGE_HAS_MODEL;
                sv.model = store.s(m);
            }
            if let Some(n) = st.attempt_number {
                sv.stage_present |= STAGE_HAS_ATTEMPT_NUMBER;
                sv.attempt_number = n;
            }
            if let Some(n) = st.remaining_candidates {
                sv.stage_present |= STAGE_HAS_REMAINING_CANDIDATES;
                sv.remaining_candidates = n as u64;
            }
            if let Some(f) = st.previous_failure {
                sv.stage_present |= STAGE_HAS_PREVIOUS_FAILURE;
                sv.previous_failure = store.s(f);
            }
            if let Some(o) = st.outcome {
                sv.stage_present |= STAGE_HAS_OUTCOME;
                sv.outcome = store.s(o);
            }
            if let Some(s) = st.status {
                sv.stage_present |= STAGE_HAS_STATUS;
                sv.status = s;
            }
        }
        Arc::new(Self {
            input: NotifyIn {
                head: blank_head(),
                stage: sv,
                signals,
                signals_len,
                prompt,
                present,
                _reserved: 0,
            },
            _store: store,
        })
    }

    /// The `in` the call crosses with (its head blank; the dispatcher fills it).
    #[must_use]
    pub fn input(&self) -> NotifyIn {
        self.input
    }

    /// The 1.5.5 `notify` JSON a tap plugin written against the JSON contract is handed for this
    /// view: the SDK's own rebuild ([`crate::abi::sdk::hook::DecodedTap::projection_json`]), read
    /// here so an in-process tap reads exactly what a plugin reads.
    #[must_use]
    pub fn projection_json(&self) -> serde_json::Value {
        // SAFETY: every pointer in `input` names storage this frame owns (`_store`), live while
        // `self` is borrowed.
        let lent = unsafe { crate::abi::sdk::Lent::new(&self.input) };
        crate::abi::sdk::hook::DecodedTap::of(lent).projection_json()
    }
}

#[cfg(test)]
#[path = "../tests/host_hook_tests.rs"]
mod tests;
