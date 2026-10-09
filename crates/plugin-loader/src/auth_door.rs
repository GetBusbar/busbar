// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE OPENED AUTH INSTANCE ON THE ONE DISPATCHER (THE DESIGN: the auth kind, the one dispatcher):
//! [`AuthInstance`] calls a `kind: auth` plugin through its v3 table (`abi::auth`) and nothing else,
//! and implements the contract's [`AuthCalls`], so the kernel's identity chain names neither this
//! crate nor the plugin's.
//!
//! * `verify` ON THE SPOT ([`AuthCalls::verify_now`]): one ticket-less crossing on the caller's
//!   thread, watchdog-bounded. A plugin that must wait answers REFUSED there, and the caller submits.
//! * `verify` SUBMITTED ([`AuthCalls::verify`]): on a request ticket of the dispatcher, awaited
//!   through the reply's waker, so no thread is parked. The memory the `in` lends (the field lines,
//!   the peer facts, the body, the request facts, the identity buffer and the strip array) travels
//!   with the op
//!   ([`Dispatcher::submit_lent`]) and outlives a caller that stops waiting. The instance's
//!   `max_inflight` full is [`Verified::Overloaded`] (R8: the host answers 503).
//! * A SHORT answer is re-called ONCE with the buffers it named; a second is [`Verified::Failed`].
//! * `refresh` ([`AuthCalls::refresh`]) re-opens the settings under a NEW generation: the plugin
//!   drops its inbound cache and reports how many entries under its
//!   [`METRIC_CACHE_FLUSHED`](busbar_contract::abi::auth::METRIC_CACHE_FLUSHED) family, which this
//!   answers.
//!
//! Every answer is a [`VerifyAnswer`]: the verdict (with the identity and its credential, a
//! secret), the decision and the lines to strip (THE DESIGN, "Auth points and guest lists").
//!
//! The credential and every line value are secret: their bytes are zeroed when the op's lent
//! memory is dropped, and nothing here prints them.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use busbar_contract::abi::auth::{
    slot, IdentifyOut, IdentityBuf, IdentityOut, NamedValue, RequestFacts, StripName, VerifyIn,
    DECISION_CONTINUE, FIELDS_HARD_MAX, FIELDS_MAX, IDENTITY_BUF_BYTES, IDENTITY_GROUPS,
    IDENTITY_HAS_TTL, SPAN_ABSENT, STRIP_QUERY, VERDICT_IDENTITY, VERDICT_REJECT,
};
use busbar_contract::abi::mechanism::call::Span;
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, Outcome, BLOB_ABSENT, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as lc, OpenIn, OpenOut, RefreshIn, ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::auth_calls::{
    AuthCalls, Decision, Strip, StripPlace, Verified, VerifiedIdentity, VerifyAnswer,
    VerifyRequest, Verifying,
};

use crate::dispatch::kinds::auth::{Auth, AuthFacts};
use crate::dispatch::{
    in_head, now_ns, out_head, Diagnostic, Dispatcher, Done, Dropped, EnvelopeSink, Frame, Metric,
    Plugin, Reply,
};

/// A submitted `verify`'s deadline: past it the op is cancelled and answers FAILED.
pub const VERIFY_DEADLINE: Duration = Duration::from_secs(10);

/// The most bytes a short answer may ask the identity buffer to grow to.
const IDENTITY_BUF_MAX: u64 = 1024 * 1024;

/// A string the host lends for a call.
fn lend(s: &str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

/// An optional string the host lends; `None` is absent (NULL).
fn lend_opt(s: Option<&str>) -> AbiStr {
    s.map_or(
        AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        lend,
    )
}

/// Bytes the host lends for a call, as a blob of `fmt` with `flags`; empty is absent.
fn blob(b: &[u8], fmt: u32, flags: u32) -> Blob {
    if b.is_empty() && fmt != BLOB_OCTETS {
        return crate::dispatch::NO_BLOB;
    }
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt,
        flags,
    }
}

/// A fresh `verify` `out`: no verdict, no identity, no decision, no strip.
fn identify_out() -> IdentifyOut {
    let absent = Span {
        offset: SPAN_ABSENT,
        len: 0,
    };
    IdentifyOut {
        head: out_head(),
        verdict: 0,
        needed_groups: 0,
        needed_bytes: 0,
        identity: IdentityOut {
            subject: absent,
            key_id: absent,
            key_name: absent,
            user: absent,
            provider: absent,
            name: absent,
            claims: absent,
            claims_fmt: BLOB_ABSENT,
            flags: 0,
            ttl_secs: 0,
            groups_len: 0,
            _reserved: 0,
            replay_key: absent,
            replay_ttl_secs: 0,
            credential: absent,
        },
        decision: 0,
        strip_len: 0,
        needed_strip: 0,
        _reserved: 0,
    }
}

/// A plugin's error text, or the outcome's name.
fn why(outcome: Outcome, error: Option<Vec<u8>>) -> String {
    error.map_or_else(
        || format!("{outcome:?}"),
        |e| String::from_utf8_lossy(&e).into_owned(),
    )
}

/// Overwrite secret bytes before their allocation is freed.
fn zero(bytes: &mut [u8]) {
    bytes.fill(0);
    std::hint::black_box(bytes);
}

/// THE MEMORY ONE `verify` LENDS: the owned request, the line list pointing into it, and the
/// identity buffers and strip array the plugin writes. Built once, then only read (by the plugin through the `in`,
/// and by the host after the op completed), so it is shared behind an `Arc` with the dispatcher.
struct Held {
    credential: Vec<u8>,
    lines: Vec<(String, Vec<u8>)>,
    named: Vec<NamedValue>,
    point: u32,
    conn: u64,
    unit: u64,
    peer: Option<Vec<u8>>,
    body: Option<Vec<u8>>,
    method: String,
    authority: String,
    path: String,
    query: Option<String>,
    timestamp: u64,
    /// The strip names: an allocation of `strip_cap` entries the plugin writes through `in`.
    strip: *mut StripName,
    strip_cap: u32,
    /// The identity bytes: an allocation of `buf_cap` bytes the plugin writes through `in`.
    buf: *mut u8,
    buf_cap: usize,
    /// The group spans: an allocation of `groups_cap` spans the plugin writes through `in`.
    groups: *mut Span,
    groups_cap: u32,
}

// SAFETY: `named` and the three buffers point only into allocations `Held` owns and frees in `Drop`;
// after construction nothing writes through them but the plugin crossing under the dispatcher,
// which never runs concurrently with the host's read (the host reads only after the op completed).
unsafe impl Send for Held {}
// SAFETY: as above.
unsafe impl Sync for Held {}

impl Held {
    fn new(req: &VerifyRequest, buf_cap: usize, groups_cap: u32, strip_cap: u32) -> Arc<Self> {
        let buf = Box::into_raw(vec![0u8; buf_cap].into_boxed_slice()).cast::<u8>();
        let empty = Span {
            offset: SPAN_ABSENT,
            len: 0,
        };
        let groups =
            Box::into_raw(vec![empty; groups_cap as usize].into_boxed_slice()).cast::<Span>();
        let unnamed = StripName {
            name: empty,
            place: 0,
            _reserved: 0,
        };
        let strip =
            Box::into_raw(vec![unnamed; strip_cap as usize].into_boxed_slice()).cast::<StripName>();
        let mut held = Self {
            // The candidate the host extracted, lent as `verify`'s `credential` blob.
            credential: req
                .credential
                .as_ref()
                .map(|c| c.expose_secret().clone())
                .unwrap_or_default(),
            lines: req
                .lines
                .iter()
                .map(|(n, v)| (n.clone(), v.expose_secret().clone()))
                .collect(),
            named: Vec::new(),
            point: req.point.bit(),
            conn: req.conn,
            unit: req.unit,
            peer: req.peer.clone(),
            body: req.body.clone(),
            method: req.method.clone(),
            authority: req.authority.clone(),
            path: req.path.clone(),
            query: req.query.clone(),
            timestamp: req.timestamp,
            strip,
            strip_cap,
            buf,
            buf_cap,
            groups,
            groups_cap,
        };
        held.named = held
            .lines
            .iter()
            .map(|(name, value)| NamedValue {
                name: lend(name),
                value: blob(value, BLOB_OCTETS, BLOB_SECRET),
            })
            .collect();
        Arc::new(held)
    }

    /// The `in` over this memory; `presented` says whether a credential was presented at all.
    fn input(&self, presented: bool) -> VerifyIn {
        VerifyIn {
            head: in_head(),
            credential: if presented {
                blob(&self.credential, BLOB_OCTETS, BLOB_SECRET)
            } else {
                crate::dispatch::NO_BLOB
            },
            lines: if self.named.is_empty() {
                std::ptr::null()
            } else {
                self.named.as_ptr()
            },
            lines_len: self.named.len(),
            request: RequestFacts {
                method: lend(&self.method),
                authority: lend(&self.authority),
                canonical_path: lend(&self.path),
                query: lend_opt(self.query.as_deref()),
                timestamp: self.timestamp,
            },
            out_buf: IdentityBuf {
                buf: self.buf,
                buf_cap: self.buf_cap,
                groups: self.groups,
                groups_cap: self.groups_cap,
                _reserved: 0,
            },
            point: self.point,
            _reserved: 0,
            conn: self.conn,
            unit: self.unit,
            // Present (even when empty) exactly when the request carries one.
            peer: self
                .peer
                .as_deref()
                .map_or(crate::dispatch::NO_BLOB, |p| blob(p, BLOB_OCTETS, 0)),
            body: self
                .body
                .as_deref()
                .map_or(crate::dispatch::NO_BLOB, |b| blob(b, BLOB_OCTETS, 0)),
            strip: self.strip,
            strip_cap: self.strip_cap,
            _reserved2: 0,
        }
    }

    /// The strip names a READY answer reported, as names and places.
    fn strips(&self, out: &IdentifyOut) -> Vec<Strip> {
        let n = out.strip_len.min(self.strip_cap) as usize;
        if n == 0 {
            return Vec::new();
        }
        // SAFETY: `strip` holds `strip_cap` initialized entries; `n` is bounded by it, and the op
        // completed, so the plugin no longer writes the array.
        let names = unsafe { std::slice::from_raw_parts(self.strip, n) };
        names
            .iter()
            .filter_map(|s| {
                let name = self.text(s.name)?;
                Some(Strip {
                    name: name.into(),
                    place: if s.place == STRIP_QUERY {
                        StripPlace::Query
                    } else {
                        StripPlace::Field
                    },
                })
            })
            .collect()
    }

    /// The text at `s` in the identity buffer; `None` when absent.
    fn text(&self, s: Span) -> Option<String> {
        if s.offset == SPAN_ABSENT {
            return None;
        }
        let (off, len) = (s.offset as usize, s.len as usize);
        if off.checked_add(len)? > self.buf_cap {
            return None;
        }
        // SAFETY: the kind's check bounded every reported span by the capacity passed in the `in`
        // (re-checked above), and the op completed, so the plugin no longer writes the buffer.
        let bytes = unsafe { std::slice::from_raw_parts(self.buf.add(off), len) };
        Some(String::from_utf8_lossy(bytes).into_owned())
    }

    /// The identity a READY `VERDICT_IDENTITY` answer reported.
    fn identity(&self, o: &IdentityOut) -> VerifiedIdentity {
        let n = (o.groups_len.min(self.groups_cap)) as usize;
        // SAFETY: `groups` holds `groups_cap` initialized spans; `n` is bounded by it.
        let spans = unsafe { std::slice::from_raw_parts(self.groups, n) };
        VerifiedIdentity {
            subject: self.text(o.subject).unwrap_or_default(),
            key_id: self.text(o.key_id),
            key_name: self.text(o.key_name),
            user: self.text(o.user),
            provider: self.text(o.provider),
            name: self.text(o.name),
            groups: spans.iter().filter_map(|s| self.text(*s)).collect(),
            ttl_secs: (o.flags & IDENTITY_HAS_TTL != 0).then_some(o.ttl_secs),
            replay: self
                .text(o.replay_key)
                .filter(|k| !k.is_empty())
                .map(|key| {
                    Box::new(busbar_contract::auth_calls::Replay {
                        key,
                        ttl_secs: o.replay_ttl_secs,
                    })
                }),
            // `len == 0` is absent.
            credential: if o.credential.len == 0 {
                None
            } else {
                self.text(o.credential).map(Into::into)
            },
        }
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        zero(&mut self.credential);
        for (_, v) in &mut self.lines {
            zero(v);
        }
        // SAFETY: the three allocations were made in `new` from boxed slices of exactly these
        // lengths, and nothing reads them once the last `Arc` is dropped.
        unsafe {
            let buf = std::ptr::slice_from_raw_parts_mut(self.buf, self.buf_cap);
            zero(&mut *buf);
            drop(Box::from_raw(buf));
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                self.groups,
                self.groups_cap as usize,
            )));
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                self.strip,
                self.strip_cap as usize,
            )));
        }
    }
}

/// An answer, read over `held`: the verdict (the kernel's), the decision and the strips (the
/// transport's). The strips are named whatever the verdict; an answer that is not READY is
/// [`Verified::Failed`] with the decision to stop.
fn verdict(outcome: Outcome, out: &IdentifyOut, held: &Held) -> VerifyAnswer {
    if outcome != Outcome::Ready {
        return Verified::Failed.into();
    }
    let verified = match out.verdict {
        VERDICT_IDENTITY => Verified::Identity(held.identity(&out.identity)),
        VERDICT_REJECT => Verified::Reject,
        _ => Verified::Pass,
    };
    VerifyAnswer {
        verified,
        decision: if out.decision == DECISION_CONTINUE {
            Decision::Continue
        } else {
            Decision::Stop
        },
        strips: held.strips(out),
    }
}

/// The bigger buffers a SHORT answer names (bytes, groups, strip names); `None` when it asks past
/// the host's limits.
fn grown(out: &IdentifyOut, held: &Held) -> Option<(usize, u32, u32)> {
    if out.needed_bytes > IDENTITY_BUF_MAX
        || out.needed_groups > busbar_contract::abi::auth::IDENTITY_GROUPS_HARD_MAX
        || out.needed_strip > FIELDS_HARD_MAX
    {
        return None;
    }
    Some((
        (out.needed_bytes as usize).max(held.buf_cap),
        out.needed_groups.max(held.groups_cap),
        out.needed_strip.max(held.strip_cap),
    ))
}

/// THE ENVELOPE of an auth instance: the cache-flush counter is summed for `refresh`; a
/// diagnostic is logged under the instance; every other metric is dropped.
struct FlushSink {
    plugin: String,
    family: Mutex<Option<u32>>,
    flushed: AtomicU64,
}

impl EnvelopeSink for FlushSink {
    fn metric(&self, m: Metric<'_>) {
        let family = *self.family.lock().unwrap_or_else(|e| e.into_inner());
        if family == Some(m.family) && m.value.is_finite() && m.value >= 0.0 {
            self.flushed.fetch_add(m.value as u64, Ordering::AcqRel);
        }
    }

    fn diag(&self, d: Diagnostic<'_>) {
        let text = String::from_utf8_lossy(d.text);
        match d.severity {
            2 => tracing::error!(plugin = %self.plugin, "{text}"),
            1 => tracing::warn!(plugin = %self.plugin, "{text}"),
            _ => tracing::info!(plugin = %self.plugin, "{text}"),
        }
    }

    fn dropped(&self, why: Dropped) {
        tracing::debug!(plugin = %self.plugin, ?why, "an auth envelope entry was dropped");
    }
}

/// The sink an auth instance binds with, before it is opened.
#[derive(Clone)]
pub struct AuthSink(Arc<FlushSink>);

impl AuthSink {
    /// A sink logging under `plugin`.
    #[must_use]
    pub fn new(plugin: &str) -> Self {
        Self(Arc::new(FlushSink {
            plugin: plugin.to_string(),
            family: Mutex::new(None),
            flushed: AtomicU64::new(0),
        }))
    }

    /// The sink as the bind takes it.
    #[must_use]
    pub fn bind(&self) -> Arc<dyn EnvelopeSink> {
        self.0.clone()
    }
}

impl std::fmt::Debug for AuthSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSink").finish_non_exhaustive()
    }
}

/// What a verify's in-flight state shares with the instance.
struct Shared {
    plugin: Plugin<Auth>,
    dispatcher: Arc<Dispatcher>,
    minted: AtomicU64,
}

impl Shared {
    /// A request ticket on a worker picked by the counter.
    fn ticket(&self) -> Option<Ticket> {
        let n = self.minted.fetch_add(1, Ordering::Relaxed);
        let worker = (n % u64::from(self.dispatcher.workers().max(1))) as u32;
        self.dispatcher.mint(worker)
    }

    fn submit(
        &self,
        ticket: Ticket,
        held: &Arc<Held>,
        presented: bool,
    ) -> Reply<VerifyIn, IdentifyOut> {
        let frame = Frame::new(held.input(presented), identify_out());
        let lent: crate::dispatch::Lent = held.clone();
        self.dispatcher.submit_lent(
            &self.plugin,
            ticket,
            slot::VERIFY,
            frame,
            DeadlineClass::Call,
            now_ns() + VERIFY_DEADLINE.as_nanos() as u64,
            lent,
        )
    }
}

/// ONE AUTH INSTANCE, opened, as the kernel's chain calls it.
pub struct AuthInstance {
    shared: Arc<Shared>,
    sink: AuthSink,
    facts: AuthFacts,
    // settings-leak-lint: allow — NON-PROJECTION engine type: the settings bytes this instance was
    // opened over, re-sent on `refresh`. No `Serialize`; the hand-written `Debug` below prints the
    // plugin and the label only (`an_instance_debug_never_shows_its_settings_or_secrets`).
    settings: Vec<u8>,
    secrets: Vec<Vec<u8>>,
    generation: AtomicU64,
    label: String,
    lifecycle: Mutex<()>,
}

impl std::fmt::Debug for AuthInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthInstance")
            .field("plugin", &self.shared.plugin.name())
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

/// THE SERVICE CREDENTIALS OUT OF THE SETTINGS: each key `plugin`'s Statement names as a secret-ref
/// is taken out of the `settings` object (its value already resolved by the kernel, as 1.5.5
/// resolved a provider's secret-refs) and handed to `open` as `secrets`, in the Statement's order —
/// a missing or non-string one as empty bytes, which the plugin refuses. The settings the plugin
/// sees no longer carry them.
pub fn split_secrets(
    plugin: &Plugin<Auth>,
    settings: &serde_json::Value,
) -> (serde_json::Value, Vec<Vec<u8>>) {
    let refs = plugin
        .context::<AuthFacts>()
        .map(|f| f.secret_refs.clone())
        .unwrap_or_default();
    let mut settings = settings.clone();
    let secrets = refs
        .iter()
        .map(|key| {
            let taken = settings.as_object_mut().and_then(|o| o.remove(key));
            match taken {
                Some(serde_json::Value::String(s)) => s.into_bytes(),
                _ => Vec::new(),
            }
        })
        .collect();
    (settings, secrets)
}

/// The secrets list the host lends `open`/`refresh`.
fn secret_blobs(secrets: &[Vec<u8>]) -> Vec<Blob> {
    secrets
        .iter()
        .map(|s| Blob {
            ptr: s.as_ptr(),
            len: s.len(),
            fmt: BLOB_OCTETS,
            flags: BLOB_SECRET,
        })
        .collect()
}

impl AuthInstance {
    /// OPEN `plugin` (bound to `dispatcher` with `sink`) with `settings` (one JSON document) and the
    /// resolved `secrets`, after `validate`, as the host's instance `label`.
    ///
    /// # Errors
    /// The plugin refused its settings, or would not open.
    pub fn open(
        plugin: Plugin<Auth>,
        sink: AuthSink,
        dispatcher: Arc<Dispatcher>,
        label: &str,
        settings: &[u8],
        secrets: Vec<Vec<u8>>,
    ) -> Result<Self, String> {
        let facts = plugin.context::<AuthFacts>().cloned().unwrap_or_default();
        *sink.0.family.lock().unwrap_or_else(|e| e.into_inner()) = facts.cache_family;
        let mut v = Frame::new(
            ValidateIn {
                head: in_head(),
                settings: blob(settings, BLOB_JSON, 0),
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            out_head(),
        );
        let called = plugin.call(lc::VALIDATE, &mut v);
        if called.outcome != Outcome::Ready {
            return Err(why(called.outcome, called.error));
        }
        let blobs = secret_blobs(&secrets);
        let mut f = Frame::new(
            OpenIn {
                head: in_head(),
                host: std::ptr::null(),
                settings: blob(settings, BLOB_JSON, 0),
                secrets: if blobs.is_empty() {
                    std::ptr::null()
                } else {
                    blobs.as_ptr()
                },
                secrets_len: blobs.len(),
                generation: 1,
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            OpenOut {
                head: out_head(),
                instance: std::ptr::null_mut(),
                err_len: 0,
            },
        );
        let called = plugin.call(lc::OPEN, &mut f);
        if called.outcome != Outcome::Ready {
            return Err(why(called.outcome, called.error));
        }
        drop(blobs);
        // READY, as boot runs it for every door instance (`boot::open_ready`): what the instance
        // must do on the network before it serves (an IdP's discovery and key warm-up through its
        // declared needs), awaited on a ticket; a door that states none is not called. A refusal
        // refuses the open in the plugin's words.
        plugin.ready(&dispatcher, crate::dispatch::ready::READY_DEADLINE)?;
        Ok(Self {
            shared: Arc::new(Shared {
                plugin,
                dispatcher,
                minted: AtomicU64::new(0),
            }),
            sink,
            facts,
            settings: settings.to_vec(),
            secrets,
            generation: AtomicU64::new(1),
            label: label.to_string(),
            lifecycle: Mutex::new(()),
        })
    }

    /// The plugin handle.
    pub fn plugin(&self) -> &Plugin<Auth> {
        &self.shared.plugin
    }

    /// The host's instance label.
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl Drop for AuthInstance {
    fn drop(&mut self) {
        for s in &mut self.secrets {
            zero(s);
        }
    }
}

impl AuthCalls for AuthInstance {
    fn name(&self) -> &str {
        self.shared.plugin.name()
    }

    fn facts(&self) -> u32 {
        self.facts.facts
    }

    fn credential_kinds(&self) -> Vec<String> {
        self.facts.credential_kinds.clone()
    }

    fn carriers(&self) -> Vec<String> {
        self.facts.carriers.clone()
    }

    fn verify_now(&self, request: &VerifyRequest) -> Option<VerifyAnswer> {
        let presented = request.credential.is_some();
        let plugin = &self.shared.plugin;
        let held = Held::new(request, IDENTITY_BUF_BYTES, IDENTITY_GROUPS, FIELDS_MAX);
        let mut f = Frame::new(held.input(presented), identify_out());
        let called = plugin.call(slot::VERIFY, &mut f);
        match called.outcome {
            Outcome::Refused => None,
            Outcome::Failed if called.recall.is_some() => {
                let token = called.recall?;
                let Some((cap, groups, strips)) = grown(&f.out, &held) else {
                    return Some(Verified::Failed.into());
                };
                let bigger = Held::new(request, cap, groups, strips);
                let mut g = Frame::new(bigger.input(presented), identify_out());
                let again = plugin.recall(token, slot::VERIFY, &mut g);
                Some(verdict(again.outcome, &g.out, &bigger))
            }
            o => Some(verdict(o, &f.out, &held)),
        }
    }

    fn verify(&self, request: VerifyRequest) -> Box<dyn Verifying> {
        let sh = &self.shared;
        let p = &sh.plugin;
        if p.max_inflight() != 0 && p.inflight() >= p.max_inflight() {
            return Box::new(Settled(Some(Verified::Overloaded.into())));
        }
        let Some(ticket) = sh.ticket() else {
            return Box::new(Settled(Some(Verified::Overloaded.into())));
        };
        let presented = request.credential.is_some();
        let held = Held::new(&request, IDENTITY_BUF_BYTES, IDENTITY_GROUPS, FIELDS_MAX);
        let reply = sh.submit(ticket, &held, presented);
        Box::new(Submitted {
            shared: sh.clone(),
            ticket,
            request,
            presented,
            held,
            reply: Some(reply),
            recalled: false,
            answer: None,
        })
    }

    fn refresh(&self) -> Result<u64, String> {
        let _one = self.lifecycle.lock().unwrap_or_else(|e| e.into_inner());
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.sink.0.flushed.store(0, Ordering::Release);
        let blobs = secret_blobs(&self.secrets);
        let mut f = Frame::new(
            RefreshIn {
                head: in_head(),
                generation,
                settings: blob(&self.settings, BLOB_JSON, 0),
                secrets: if blobs.is_empty() {
                    std::ptr::null()
                } else {
                    blobs.as_ptr()
                },
                secrets_len: blobs.len(),
            },
            out_head(),
        );
        let called = self.shared.plugin.call(lc::REFRESH, &mut f);
        if called.outcome != Outcome::Ready {
            return Err(why(called.outcome, called.error));
        }
        Ok(self.sink.0.flushed.load(Ordering::Acquire))
    }

    fn login_kind(&self) -> Option<busbar_contract::auth::LoginKind> {
        use busbar_contract::abi::auth::{CAP_LOGIN, LOGIN_KIND_CREDENTIAL, LOGIN_KIND_REDIRECT};
        use busbar_contract::auth::LoginKind;
        if self.facts.caps & CAP_LOGIN == 0 {
            return None;
        }
        match self.facts.login_kind {
            LOGIN_KIND_REDIRECT => Some(LoginKind::Redirect),
            LOGIN_KIND_CREDENTIAL => Some(LoginKind::Credential),
            _ => None,
        }
    }

    fn begin_login(
        &self,
        request: busbar_contract::auth::BeginLogin,
    ) -> Box<dyn busbar_contract::auth_calls::LoginCall> {
        login::begin(&self.shared, request)
    }

    fn complete_login(
        &self,
        request: busbar_contract::auth_calls::LoginCallback,
    ) -> Box<dyn busbar_contract::auth_calls::LoginCall> {
        login::complete(&self.shared, request)
    }
}

/// A verify answered before it was submitted (overload).
struct Settled(Option<VerifyAnswer>);

impl Future for Settled {
    type Output = VerifyAnswer;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<VerifyAnswer> {
        Poll::Ready(self.0.take().unwrap_or_else(|| Verified::Failed.into()))
    }
}

impl Verifying for Settled {
    fn settled(&mut self) -> Option<VerifyAnswer> {
        self.0.take()
    }
}

/// A submitted verify: its reply, the one re-call a short answer earns, then its verdict.
struct Submitted {
    shared: Arc<Shared>,
    ticket: Ticket,
    request: VerifyRequest,
    presented: bool,
    held: Arc<Held>,
    reply: Option<Reply<VerifyIn, IdentifyOut>>,
    recalled: bool,
    answer: Option<VerifyAnswer>,
}

impl Submitted {
    /// Take a completed op: its verdict, or `None` after re-submitting a short answer.
    fn complete(&mut self, done: Done<VerifyIn, IdentifyOut>) -> Option<VerifyAnswer> {
        let out = done.frame.as_ref().map(|f| f.out);
        if done.short && !self.recalled {
            self.recalled = true;
            let grow = out.as_ref().and_then(|o| grown(o, &self.held));
            if let Some((cap, groups, strips)) = grow {
                self.held = Held::new(&self.request, cap, groups, strips);
                self.reply = Some(self.shared.submit(self.ticket, &self.held, self.presented));
                return None;
            }
            return Some(Verified::Failed.into());
        }
        Some(match out {
            Some(o) => verdict(done.outcome, &o, &self.held),
            None => Verified::Failed.into(),
        })
    }

    fn step(&mut self, cx: &mut Context<'_>) -> Poll<VerifyAnswer> {
        loop {
            if let Some(v) = &self.answer {
                return Poll::Ready(v.clone());
            }
            let Some(reply) = self.reply.as_mut() else {
                return Poll::Ready(Verified::Failed.into());
            };
            let done = match Pin::new(reply).poll(cx) {
                Poll::Ready(d) => d,
                Poll::Pending => return Poll::Pending,
            };
            self.reply = None;
            if let Some(v) = self.complete(done) {
                self.answer = Some(v);
            }
        }
    }
}

impl Future for Submitted {
    type Output = VerifyAnswer;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<VerifyAnswer> {
        self.step(cx)
    }
}

impl Verifying for Submitted {
    fn settled(&mut self) -> Option<VerifyAnswer> {
        let mut cx = Context::from_waker(Waker::noop());
        match self.step(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }
}

impl Drop for Submitted {
    fn drop(&mut self) {
        // A reply dropped unanswered is a client drop (its op cancelled); the ticket is recycled
        // once its last op ends.
        drop(self.reply.take());
        self.shared.dispatcher.recycle(self.ticket);
    }
}

#[path = "auth_login.rs"]
mod login;

#[cfg(test)]
#[path = "tests/auth_door_tests.rs"]
mod tests;
