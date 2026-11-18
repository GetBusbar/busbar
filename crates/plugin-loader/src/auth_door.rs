// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use busbar_contract::abi::auth::{
    slot, AuthPoint, IdentifyOut, IdentityBuf, IdentityOut, NamedValue, RequestFacts, StripName,
    VerifyIn, DECISION_CONTINUE, FACT_INBOUND_ALL_HEADERS, FIELDS_HARD_MAX, FIELDS_MAX,
    IDENTITY_BUF_BYTES, IDENTITY_GROUPS, IDENTITY_HAS_TTL, SPAN_ABSENT, STRIP_QUERY,
    VERDICT_IDENTITY, VERDICT_REJECT,
};
use busbar_contract::abi::mechanism::call::Span;
use busbar_contract::abi::mechanism::call::{
    Blob, DeadlineClass, Outcome, BLOB_ABSENT, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::lifecycle::{slot as lc, RefreshIn};
use busbar_contract::auth_calls::{
    AuthCalls, Decision, Strip, StripPlace, Verified, VerifiedIdentity, VerifyAnswer,
    VerifyRequest, Verifying,
};
use busbar_contract::secure::{SecureString, SecureVec};

use crate::cold::auth_door as cold;
use crate::dispatch::call::{Answering, Pending, Ticketed};
use crate::dispatch::kinds::auth::{Auth, AuthFacts};
use crate::dispatch::lifecycle::{
    close, lend, lend_opt, open_frame, release, validate_call, why, AnswerLease,
};
use crate::dispatch::{
    in_head, now_ns, out_head, Diagnostic, Dispatcher, Done, Dropped, EnvelopeSink, Frame, InFrame,
    Metric, OutFrame, Plugin,
};

pub const VERIFY_DEADLINE: Duration = Duration::from_secs(10);

const IDENTITY_BUF_MAX: u64 = 1024 * 1024;

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

fn zero(bytes: &mut [u8]) {
    bytes.fill(0);
    std::hint::black_box(bytes);
}

/// What one provider is lent for one verify, built once per provider (SINGLE-PATH SP-AU2): a
/// submitted request is moved in, a borrowed one copied once, and a grown recall lends the same
/// input with larger output buffers.
struct VerifyInput {
    credential: SecureVec,
    lines: Vec<(String, Vec<u8>)>,
    named: Vec<NamedValue>,
    point: u32,
    conn: u64,
    unit: u64,
    peer: Option<SecureVec>,
    body: Option<SecureVec>,
    method: SecureString,
    authority: SecureString,
    path: SecureString,
    query: Option<SecureString>,
    timestamp: u64,
}

// SAFETY: `named` points only into `lines`, which `VerifyInput` owns and never changes after
// construction; nothing writes through it.
unsafe impl Send for VerifyInput {}
// SAFETY: as above.
unsafe impl Sync for VerifyInput {}

impl VerifyInput {
    /// A borrowed request's input, copied once.
    fn copied(
        req: &VerifyRequest,
        seal: Option<&(dyn busbar_contract::plugin::KernelSeal + Send + Sync)>,
        headers: &Headers,
    ) -> Arc<Self> {
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::VerifyCopy);
        Self {
            credential: req
                .credential
                .as_ref()
                .and_then(|c| Some(SecureVec::from(c.expose(seal?).as_slice())))
                .unwrap_or_default(),
            lines: req
                .lines
                .iter()
                .filter(|(name, _)| headers.allows(name))
                .filter_map(|(n, v)| Some((n.clone(), v.expose(seal?).clone())))
                .collect(),
            named: Vec::new(),
            point: req.point.bit(),
            conn: req.conn,
            unit: req.unit,
            peer: req.peer.as_deref().map(SecureVec::from),
            body: req.body.as_deref().map(SecureVec::from),
            method: SecureString::from(req.method.as_str()),
            authority: SecureString::from(req.authority.as_str()),
            path: SecureString::from(req.path.as_str()),
            query: req.query.as_deref().map(SecureString::from),
            timestamp: req.timestamp,
        }
        .named()
    }

    /// A submitted request's input, moved in: no byte is copied.
    fn taken(
        mut req: VerifyRequest,
        seal: Option<&(dyn busbar_contract::plugin::KernelSeal + Send + Sync)>,
        headers: &Headers,
    ) -> Arc<Self> {
        Self {
            credential: req
                .credential
                .take()
                .and_then(|c| Some(SecureVec::from(c.into_exposed(seal?))))
                .unwrap_or_default(),
            lines: std::mem::take(&mut req.lines)
                .into_iter()
                .filter(|(name, _)| headers.allows(name))
                .filter_map(|(n, v)| Some((n, v.into_exposed(seal?))))
                .collect(),
            named: Vec::new(),
            point: req.point.bit(),
            conn: req.conn,
            unit: req.unit,
            peer: req.peer.take().map(SecureVec::from),
            body: req.body.take().map(SecureVec::from),
            method: SecureString::from(std::mem::take(&mut req.method)),
            authority: SecureString::from(std::mem::take(&mut req.authority)),
            path: SecureString::from(std::mem::take(&mut req.path)),
            query: req.query.take().map(SecureString::from),
            timestamp: req.timestamp,
        }
        .named()
    }

    /// No request at all: a login's identity buffers lend no verify input.
    fn empty() -> Arc<Self> {
        Self::taken(VerifyRequest::default(), None, &Headers::None)
    }

    fn named(mut self) -> Arc<Self> {
        self.named = self
            .lines
            .iter()
            .map(|(name, value)| NamedValue {
                name: lend(name),
                value: blob(value, BLOB_OCTETS, BLOB_SECRET),
            })
            .collect();
        Arc::new(self)
    }
}

impl Drop for VerifyInput {
    fn drop(&mut self) {
        zero(&mut self.credential);
        for (_, v) in &mut self.lines {
            zero(v);
        }
    }
}

struct Held {
    input: Arc<VerifyInput>,

    strip: *mut StripName,
    strip_cap: u32,

    buf: *mut u8,
    buf_cap: usize,

    groups: *mut Span,
    groups_cap: u32,

    // The set the pointers above point into, allocated for this verify and released with it. It is never
    // touched again until `Drop` (moving a `Vec` does not move its heap block), so the pointers stay valid.
    store: Buffers,
}

/// An absent span: what every group span of a fresh set holds.
const EMPTY_SPAN: Span = Span {
    offset: SPAN_ABSENT,
    len: 0,
};

/// An unnamed strip name: what every strip slot of a fresh set holds.
const UNNAMED: StripName = StripName {
    name: EMPTY_SPAN,
    place: 0,
    _reserved: 0,
};

/// The identity buffers one verify lends its plugin: the identity text, its group spans and the
/// strip names. Each verify (and a grown recall, and a login's identity) allocates its own set and releases it
/// when the verify ends; a door keeps none (the owner's ruling on allocation, 18 Nov).
#[derive(Default)]
struct Buffers {
    buf: Vec<u8>,
    groups: Vec<Span>,
    strip: Vec<StripName>,
}

impl Buffers {
    /// A fresh set: the text zeroed, every span absent, every strip slot unnamed.
    fn new(buf_cap: usize, groups_cap: u32, strip_cap: u32) -> Self {
        let made = Self {
            buf: vec![0u8; buf_cap],
            groups: vec![EMPTY_SPAN; groups_cap as usize],
            strip: vec![UNNAMED; strip_cap as usize],
        };
        #[cfg(test)]
        LIVE_SET_BYTES.fetch_add(made.bytes(), Ordering::Relaxed);
        made
    }

    /// The bytes this set holds.
    #[cfg(test)]
    fn bytes(&self) -> usize {
        self.buf.capacity()
            + self.groups.capacity() * std::mem::size_of::<Span>()
            + self.strip.capacity() * std::mem::size_of::<StripName>()
    }
}

/// Tests only: the bytes of identity sets alive now (counted where `Buffers::new` makes a set and where a set
/// is freed), so a test can prove a door's verifies release what they allocated (the owner's ruling, 18 Nov).
#[cfg(test)]
pub(crate) static LIVE_SET_BYTES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
impl Drop for Buffers {
    fn drop(&mut self) {
        LIVE_SET_BYTES.fetch_sub(self.bytes(), Ordering::Relaxed);
    }
}

// SAFETY: the three buffers point only into the set `Held` owns until it is dropped (then wiped and freed);
// after construction nothing writes through them but the plugin crossing under the dispatcher,
// which never runs concurrently with the host's read (the host reads only after the op completed).
unsafe impl Send for Held {}
// SAFETY: as above.
unsafe impl Sync for Held {}

fn reveals(req: &VerifyRequest) -> bool {
    req.credential.is_some() || !req.lines.is_empty()
}

enum Headers {
    None,
    All,
    /// The instance's carrier names, shared with its metadata: a verify takes a reference, not a copy.
    Carriers(Arc<[String]>),
}

impl Headers {
    fn allows(&self, name: &str) -> bool {
        match self {
            Self::None => false,
            Self::All => true,
            Self::Carriers(names) => names.iter().any(|n| n.eq_ignore_ascii_case(name)),
        }
    }
}

impl Held {
    /// A verify lent a set of its own, of the given capacities (a grown recall, a login's identity).
    fn new(input: Arc<VerifyInput>, buf_cap: usize, groups_cap: u32, strip_cap: u32) -> Arc<Self> {
        Self::over(
            input,
            Buffers::new(buf_cap, groups_cap, strip_cap),
            (groups_cap, strip_cap),
        )
    }

    /// A verify lent a default-sized set of its own, released when the verify ends.
    fn fresh(input: Arc<VerifyInput>) -> Arc<Self> {
        Self::new(input, IDENTITY_BUF_BYTES, IDENTITY_GROUPS, FIELDS_MAX)
    }

    fn over(
        input: Arc<VerifyInput>,
        mut store: Buffers,
        (groups_cap, strip_cap): (u32, u32),
    ) -> Arc<Self> {
        let buf = store.buf.as_mut_ptr();
        let buf_cap = store.buf.len();
        let groups = store.groups.as_mut_ptr();
        let strip = store.strip.as_mut_ptr();
        Arc::new(Self {
            input,
            strip,
            strip_cap,
            buf,
            buf_cap,
            groups,
            groups_cap,
            store,
        })
    }

    fn input(&self, presented: bool) -> VerifyIn {
        VerifyIn {
            head: in_head(),
            credential: if presented {
                blob(&self.input.credential, BLOB_OCTETS, BLOB_SECRET)
            } else {
                crate::dispatch::NO_BLOB
            },
            lines: if self.input.named.is_empty() {
                std::ptr::null()
            } else {
                self.input.named.as_ptr()
            },
            lines_len: self.input.named.len(),
            request: RequestFacts {
                method: lend(&self.input.method),
                authority: lend(&self.input.authority),
                canonical_path: lend(&self.input.path),
                query: lend_opt(self.input.query.as_deref()),
                timestamp: self.input.timestamp,
            },
            out_buf: IdentityBuf {
                buf: self.buf,
                buf_cap: self.buf_cap,
                groups: self.groups,
                groups_cap: self.groups_cap,
                _reserved: 0,
            },
            point: self.input.point,
            _reserved: 0,
            conn: self.input.conn,
            unit: self.input.unit,

            peer: self
                .input
                .peer
                .as_deref()
                .map_or(crate::dispatch::NO_BLOB, |p| blob(p, BLOB_OCTETS, 0)),
            body: self
                .input
                .body
                .as_deref()
                .map_or(crate::dispatch::NO_BLOB, |b| blob(b, BLOB_OCTETS, 0)),
            strip: self.strip,
            strip_cap: self.strip_cap,
            _reserved2: 0,
        }
    }

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

    fn reject_hint(&self, ext: Blob) -> Option<busbar_contract::auth_calls::RejectHint> {
        busbar_contract::abi::auth::reject_hint_of(self.extensions(ext)?)
    }

    fn extensions(&self, ext: Blob) -> Option<&[u8]> {
        if ext.ptr.is_null() || ext.len == 0 {
            return None;
        }
        let off = (ext.ptr as usize).checked_sub(self.buf as usize)?;
        if off.checked_add(ext.len)? > self.buf_cap {
            return None;
        }
        // SAFETY: `off + len <= buf_cap` (checked above) inside the `buf_cap` bytes `Held` owns,
        // and the op completed, so the plugin no longer writes the buffer.
        Some(unsafe { std::slice::from_raw_parts(self.buf.add(off), ext.len) })
    }

    fn retry_after(&self, ext: Blob) -> Option<u64> {
        if ext.ptr.is_null() || ext.len == 0 {
            return None;
        }
        let off = (ext.ptr as usize).checked_sub(self.buf as usize)?;
        if off.checked_add(ext.len)? > self.buf_cap {
            return None;
        }
        // SAFETY: `off + len <= buf_cap` (checked above) inside the `buf_cap` bytes `Held` owns,
        // and the op completed, so the plugin no longer writes the buffer.
        let bytes = unsafe { std::slice::from_raw_parts(self.buf.add(off), ext.len) };
        busbar_contract::abi::auth::retry_after_of(bytes)
    }

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
        // Nothing reads the buffers once the last `Arc` is dropped (the plugin's crossing is over): the
        // identity text is wiped, and the set is freed with `Held`.
        zero(&mut self.store.buf);
    }
}

fn verdict(
    outcome: Outcome,
    out: &IdentifyOut,
    held: &Held,
    plugin: &Plugin<Auth>,
) -> VerifyAnswer {
    if outcome != Outcome::Ready {
        return Verified::Failed.into();
    }
    let mut reason = None;
    let verified = match out.verdict {
        VERDICT_IDENTITY => Verified::Identity(held.identity(&out.identity)),
        VERDICT_REJECT => {
            reason = declined(plugin, out, 0, "verify rejected the credential");
            Verified::Reject
        }
        _ => Verified::Pass,
    };
    VerifyAnswer {
        reason,
        verified,
        decision: if out.decision == DECISION_CONTINUE {
            Decision::Continue
        } else {
            Decision::Stop
        },
        strips: held.strips(out),
    }
}

pub(crate) fn declined(
    plugin: &Plugin<Auth>,
    out: &IdentifyOut,
    severity: u8,
    what: &str,
) -> Option<String> {
    let text = crate::dispatch::plugin::copy_str(out.head.error)?;
    let reason = crate::dispatch::lifecycle::lossy(text);
    cold::note_declined(plugin, severity, what, &reason);
    Some(reason)
}

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

pub(crate) struct FlushSink {
    pub(crate) plugin: String,
    pub(crate) family: Mutex<Option<u32>>,
    pub(crate) flushed: AtomicU64,
}

impl EnvelopeSink for FlushSink {
    fn metric(&self, m: Metric<'_>) {
        let family = *self.family.lock().unwrap_or_else(|e| e.into_inner());
        if family == Some(m.family) && m.value.is_finite() && m.value >= 0.0 {
            self.flushed.fetch_add(m.value as u64, Ordering::AcqRel);
        }
    }

    fn diag(&self, d: Diagnostic<'_>) {
        // Plugin text is the plain `text` field, never the message (IF §12.16): the formatter
        // escapes it, so plugin-echoed caller input cannot open a new field or line.
        let text = String::from_utf8_lossy(d.text);
        let text = text.as_ref();
        match d.severity {
            2 => tracing::error!(plugin = %self.plugin, text, "auth plugin diagnostic"),
            1 => tracing::warn!(plugin = %self.plugin, text, "auth plugin diagnostic"),
            _ => tracing::info!(plugin = %self.plugin, text, "auth plugin diagnostic"),
        }
    }

    fn dropped(&self, why: Dropped) {
        tracing::debug!(plugin = %self.plugin, ?why, "an auth envelope entry was dropped");
    }
}

/// The sink an auth instance binds with, before it is opened.
#[derive(Clone)]
pub struct AuthSink(pub(crate) Arc<FlushSink>);

impl AuthSink {
    #[must_use]
    pub fn bind(&self) -> Arc<dyn EnvelopeSink> {
        self.0.clone()
    }

    pub fn to_file(
        &self,
        logs: &crate::dispatch::PluginLogConfig,
        label: &str,
    ) -> Result<Arc<dyn EnvelopeSink>, String> {
        let file = logs.sink(
            label,
            busbar_contract::abi::mechanism::KindCode::Auth,
            self.bind(),
        )?;
        Ok(Arc::new(InstanceSink {
            file,
            host: Arc::clone(&self.0),
        }))
    }
}

struct InstanceSink {
    file: crate::dispatch::PluginLogSink,
    host: Arc<FlushSink>,
}

impl EnvelopeSink for InstanceSink {
    fn metric(&self, m: Metric<'_>) {
        self.file.metric(m);
    }

    fn diag(&self, d: Diagnostic<'_>) {
        if d.id != busbar_contract::abi::mechanism::call::DIAG_LOG {
            self.host.diag(d);
        }
        self.file.diag(d);
    }

    fn dropped(&self, why: Dropped) {
        self.file.dropped(why);
    }
}

impl std::fmt::Debug for AuthSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSink").finish_non_exhaustive()
    }
}

struct Shared {
    plugin: Arc<Plugin<Auth>>,
    dispatcher: Arc<Dispatcher>,
    minted: AtomicU64,
}

impl Shared {
    fn call<I: InFrame, O: OutFrame>(&self) -> Option<Ticketed<I, O>> {
        let n = self.minted.fetch_add(1, Ordering::Relaxed);
        let worker = (n % u64::from(self.dispatcher.workers().max(1))) as u32;
        Ticketed::mint(&self.dispatcher, worker)
    }

    fn submit(
        &self,
        call: &mut Ticketed<VerifyIn, IdentifyOut>,
        held: &Arc<Held>,
        presented: bool,
    ) {
        let frame = Frame::new(held.input(presented), identify_out());
        let lent: crate::dispatch::Lent = held.clone();
        call.submit(
            &*self.plugin,
            slot::VERIFY,
            frame,
            DeadlineClass::Call,
            now_ns().saturating_add(VERIFY_DEADLINE.as_nanos() as u64),
            lent,
        );
    }
}

#[derive(Clone)]
pub(crate) struct InstanceMetadata {
    pub(crate) carriers: Arc<[String]>,
    pub(crate) presentation: Option<busbar_contract::auth_calls::LoginPresentation>,
    pub(crate) generation: u64,
    // An attempted epoch is never reused, even when the plugin's reply cannot be admitted.
    pub(crate) attempted_generation: u64,
}

pub struct AuthInstance {
    shared: Arc<Shared>,
    sink: AuthSink,
    facts: AuthFacts,
    metadata: Mutex<InstanceMetadata>,
    metadata_valid: AtomicBool,

    settings: SecureVec,

    /// What the instance was lent (re-lent on rotation), and that material's fingerprint: `None`
    /// when it could not be fingerprinted (the OS random source did not key the process), which a
    /// re-lend reads as "changed" and lends again.
    secrets: Mutex<Arc<KeptSecrets>>,
    lent_fingerprint: Mutex<Option<[u8; 32]>>,
    label: String,
    lifecycle: Mutex<()>,

    schedule: Option<tokio::task::JoinHandle<()>>,
    // Set by the tick schedule when it stops without the plugin's own `next_tick_ns == 0`.
    tick_failed: Arc<AtomicBool>,
}

impl std::fmt::Debug for AuthInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthInstance")
            .field("plugin", &self.shared.plugin.name())
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

pub fn split_secrets(
    plugin: &Plugin<Auth>,
    settings: &busbar_contract::plugin_settings::ResolvedSettings,
) -> (
    busbar_contract::plugin_settings::ResolvedSettings,
    Vec<busbar_contract::Secret<Vec<u8>>>,
) {
    let refs = plugin
        .context::<AuthFacts>()
        .map(|f| f.secret_refs.as_slice())
        .unwrap_or_default();
    settings.lend_secrets(refs)
}

pub(crate) struct KeptSecrets(pub(crate) Vec<busbar_contract::Secret<Vec<u8>>>);

impl KeptSecrets {
    fn new(secrets: Vec<busbar_contract::Secret<Vec<u8>>>) -> Self {
        Self(secrets)
    }

    /// The kept material's fingerprint, for "did it change" only; `None` when the process could
    /// not be keyed, so nothing can be compared and the material is treated as changed.
    fn fingerprint(
        &self,
        seal: Option<&(dyn busbar_contract::plugin::KernelSeal + Send + Sync)>,
    ) -> Option<[u8; 32]> {
        match seal {
            Some(seal) => busbar_contract::redacted::fingerprint(
                self.0.iter().map(|s| s.expose(seal).as_slice()),
            ),
            None => busbar_contract::redacted::fingerprint(std::iter::empty()),
        }
        .ok()
    }

    /// One secret blob per kept secret, pointing into the material `self` holds.
    pub(crate) fn lent<'a>(
        &'a self,
        seal: &'a (dyn busbar_contract::plugin::KernelSeal + Send + Sync),
    ) -> impl Iterator<Item = Blob> + 'a {
        self.0.iter().map(move |s| Blob {
            ptr: s.expose(seal).as_ptr(),
            len: s.expose(seal).len(),
            fmt: BLOB_OCTETS,
            flags: BLOB_SECRET,
        })
    }
}

impl zeroize::ZeroizeOnDrop for KeptSecrets {}

impl std::fmt::Debug for KeptSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeptSecrets([REDACTED; {}])", self.0.len())
    }
}

/// A READY reply's metadata extensions, checked before any byte of them is read.
#[derive(Clone, Copy)]
pub(crate) enum ReplyExtensions<'b> {
    /// The reply states none.
    Absent,
    /// Well-formed octets.
    Bytes(&'b [u8]),
}

/// The READY reply's extension `blob`, checked: absent, octets the reply owns, or `None` (malformed). The caller holds
/// the reply's lease for as long as it reads the bytes.
fn reply_extensions<'b>(blob: Blob) -> Option<ReplyExtensions<'b>> {
    if blob.fmt == BLOB_ABSENT && blob.len == 0 {
        return Some(ReplyExtensions::Absent);
    }
    if blob.fmt != BLOB_OCTETS || (blob.len != 0 && blob.ptr.is_null()) {
        return None;
    }
    // SAFETY: the validated READY reply owns these bytes until its lease is released by the caller.
    Some(ReplyExtensions::Bytes(unsafe {
        crate::dispatch::plugin::blob_bytes(blob)
    }))
}

impl AuthInstance {
    fn headers(&self, point: AuthPoint) -> Option<Headers> {
        let metadata = self
            .metadata
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.metadata_valid.load(Ordering::Acquire) {
            return None;
        }
        Some(if point == AuthPoint::Peer {
            Headers::None
        } else if self.facts.facts & FACT_INBOUND_ALL_HEADERS != 0 {
            Headers::All
        } else {
            Headers::Carriers(Arc::clone(&metadata.carriers))
        })
    }

    /// REFRESH the instance with its settings and `secrets` under the next generation; the caller
    /// holds the lifecycle lock. A refusal answers the plugin's error bytes and the reason.
    fn refresh_lent(&self, secrets: &KeptSecrets) -> Result<u64, (Option<Vec<u8>>, String)> {
        let generation = {
            let mut metadata = self
                .metadata
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let generation = metadata
                .generation
                .max(metadata.attempted_generation)
                .checked_add(1)
                .ok_or_else(|| (None, cold::generation_exhausted()))?;
            metadata.attempted_generation = generation;
            generation
        };
        self.sink.0.flushed.store(0, Ordering::Release);
        let blobs = secrets
            .blobs(self.shared.dispatcher.seal())
            .map_err(|e| (None, e))?;
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

        let was_valid = self.metadata_valid.load(Ordering::Acquire);
        let called = self.shared.plugin.call(lc::REFRESH, &mut f);
        let _lease = AnswerLease::new(&self.shared.plugin, called.lease);
        if called.outcome != Outcome::Ready {
            self.metadata_valid.store(
                was_valid && matches!(called.outcome, Outcome::Refused | Outcome::Failed),
                Ordering::Release,
            );
            let bytes = called.error.clone();
            return Err((bytes, why(called.outcome, called.error)));
        }
        let current = self.carriers();
        let metadata = crate::off_path::auth_door::instance_metadata(
            reply_extensions(f.out.extensions),
            &current,
            &self.facts,
            generation,
        );
        match metadata {
            Ok(metadata) => {
                *self
                    .metadata
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = metadata;
                self.metadata_valid.store(true, Ordering::Release);
            }
            Err(error) => {
                self.metadata_valid.store(false, Ordering::Release);
                return Err((None, error));
            }
        }
        Ok(self.sink.0.flushed.load(Ordering::Acquire))
    }

    pub fn open(
        plugin: Plugin<Auth>,
        sink: AuthSink,
        dispatcher: Arc<Dispatcher>,
        label: &str,
        settings: &[u8],
        secrets: Vec<busbar_contract::Secret<Vec<u8>>>,
    ) -> Result<Self, String> {
        let secrets = KeptSecrets::new(secrets);
        let lent_fingerprint = secrets.fingerprint(dispatcher.seal());
        let facts = plugin.context::<AuthFacts>().cloned().unwrap_or_default();
        *sink.0.family.lock().unwrap_or_else(|e| e.into_inner()) = facts.cache_family;
        let called = validate_call(&plugin, blob(settings, BLOB_JSON, 0));
        let validated = AnswerLease::new(&plugin, called.lease);
        if called.outcome != Outcome::Ready {
            return Err(why(called.outcome, called.error));
        }
        drop(validated);
        let blobs = secrets.blobs(dispatcher.seal())?;
        let mut f = open_frame(blob(settings, BLOB_JSON, 0));
        if !blobs.is_empty() {
            f.input.secrets = blobs.as_ptr();
            f.input.secrets_len = blobs.len();
        }
        let called = plugin.call(lc::OPEN, &mut f);
        if called.outcome != Outcome::Ready {
            return Err(why(called.outcome, called.error));
        }
        let metadata = crate::off_path::auth_door::instance_metadata(
            reply_extensions(f.out.head.extensions),
            &facts.carriers,
            &facts,
            1,
        );
        release(&plugin, called.lease);
        let metadata = match metadata {
            Ok(metadata) => metadata,
            Err(error) => {
                close(&plugin);
                return Err(error);
            }
        };
        drop(blobs);

        if let Err(error) = plugin.ready(&dispatcher, crate::dispatch::ready::READY_DEADLINE) {
            close(&plugin);
            return Err(error);
        }

        let plugin = Arc::new(plugin);
        let tick_failed = Arc::new(AtomicBool::new(false));
        let schedule = crate::dispatch::ticks::spawn(
            Arc::clone(&plugin),
            dispatcher.clone(),
            0,
            Arc::clone(&tick_failed),
        );
        let opened = Self {
            shared: Arc::new(Shared {
                plugin,
                dispatcher,
                minted: AtomicU64::new(0),
            }),
            sink,
            facts,
            metadata: Mutex::new(metadata),
            metadata_valid: AtomicBool::new(true),
            settings: SecureVec::from(settings),
            secrets: Mutex::new(Arc::new(secrets)),
            lent_fingerprint: Mutex::new(lent_fingerprint),
            label: cold::instance_label(label),
            lifecycle: Mutex::new(()),
            schedule,
            tick_failed,
        };
        Ok(opened)
    }

    pub fn plugin(&self) -> &Plugin<Auth> {
        &self.shared.plugin
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    #[cfg(test)]
    #[must_use]
    pub fn ticks_ended(&self) -> bool {
        self.schedule
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
    }

    #[cfg(test)]
    pub(crate) fn kept_secrets(&self) -> Arc<KeptSecrets> {
        Arc::clone(
            &self
                .secrets
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    #[cfg(test)]
    pub(crate) fn instance(&self) -> std::sync::Weak<crate::dispatch::plugin::Instance> {
        Arc::downgrade(&self.shared.plugin.inner)
    }
}

impl Drop for AuthInstance {
    fn drop(&mut self) {
        if let Some(schedule) = self.schedule.take() {
            schedule.abort();
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
        let metadata = self
            .metadata
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cold::listed_carriers(&metadata.carriers)
    }

    fn issued_shape(&self) -> Option<busbar_contract::auth_calls::IssuedShape> {
        self.facts.issued.clone()
    }

    fn inbound_points(&self) -> busbar_contract::abi::auth::AuthPoints {
        self.facts.inbound_points
    }

    fn verify_now(&self, request: &VerifyRequest) -> Option<VerifyAnswer> {
        let Some(headers) = self.headers(request.point) else {
            return Some(Verified::Failed.into());
        };
        let presented = request.credential.is_some();
        let plugin = &self.shared.plugin;

        let seal = self.shared.dispatcher.seal();
        if reveals(request) && seal.is_none() {
            return Some(Verified::Failed.into());
        }
        let held = Held::fresh(VerifyInput::copied(request, seal, &headers));
        let mut f = Frame::new(held.input(presented), identify_out());
        let called = plugin.call(slot::VERIFY, &mut f);
        let _lease = AnswerLease::new(plugin, called.lease);
        match called.outcome {
            Outcome::Refused => None,
            Outcome::Failed if called.recall.is_some() => {
                let token = called.recall?;
                let Some((cap, groups, strips)) = grown(&f.out, &held) else {
                    return Some(Verified::Failed.into());
                };
                let bigger = Held::new(Arc::clone(&held.input), cap, groups, strips);
                let mut g = Frame::new(bigger.input(presented), identify_out());
                let again = plugin.recall(token, slot::VERIFY, &mut g);
                let _again = AnswerLease::new(plugin, again.lease);
                Some(verdict(again.outcome, &g.out, &bigger, plugin))
            }
            o => Some(verdict(o, &f.out, &held, plugin)),
        }
    }

    fn verify(&self, request: VerifyRequest) -> Box<dyn Verifying> {
        let Some(headers) = self.headers(request.point) else {
            return Box::new(Settled(Some(Verified::Failed.into())));
        };
        let sh = &self.shared;
        let p = &sh.plugin;
        if p.max_inflight() != 0 && p.inflight() >= p.max_inflight() {
            return Box::new(Settled(Some(Verified::Overloaded.into())));
        }
        let Some(mut call) = sh.call() else {
            return Box::new(Settled(Some(Verified::Overloaded.into())));
        };
        let presented = request.credential.is_some();

        let seal = sh.dispatcher.seal();
        if reveals(&request) && seal.is_none() {
            return Box::new(Settled(Some(Verified::Failed.into())));
        }
        let held = Held::fresh(VerifyInput::taken(request, seal, &headers));
        sh.submit(&mut call, &held, presented);
        Box::new(Pending::new(
            call,
            Verify {
                shared: sh.clone(),
                presented,
                held,
                recalled: false,
            },
        ))
    }

    fn answering(&self) -> bool {
        // The conditions under which a crossing fails closed today: invalid metadata answers
        // `Failed`, a faulted or closed instance answers FAULT with no crossing.
        self.metadata_valid.load(Ordering::Acquire)
            && !self.shared.plugin.is_faulted()
            && self.shared.plugin.is_open()
    }

    fn reusable(&self) -> bool {
        // A failed tick does not end the schedule (it is retried on the host's backoff); a schedule
        // that stopped without the plugin's own `next_tick_ns == 0` is not carried into the next
        // build (WASTE-AUTH-SECRETS W2).
        self.answering() && !self.tick_failed.load(Ordering::Acquire)
    }

    fn refresh(&self) -> Result<u64, String> {
        let _one = match self.lifecycle.try_lock() {
            Ok(one) => one,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(cold::refresh_in_flight(&self.label));
            }
        };
        let secrets = Arc::clone(
            &self
                .secrets
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        self.refresh_lent(&secrets).map_err(|(_, why)| why)
    }

    fn relend(
        &self,
        settings: &busbar_contract::plugin_settings::ResolvedSettings,
    ) -> Result<busbar_contract::secret::AuthRelent, String> {
        use busbar_contract::secret::AuthRelent;
        let (_, secrets) = split_secrets(&self.shared.plugin, settings);
        let secrets = KeptSecrets::new(secrets);
        let fingerprint = secrets.fingerprint(self.shared.dispatcher.seal());
        // Unchanged only when both were fingerprinted and are the same: an unknown is a change.
        let unchanged = match (
            &*self
                .lent_fingerprint
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            &fingerprint,
        ) {
            (Some(lent), Some(now)) => busbar_contract::redacted::constant_time_eq(lent, now),
            _ => false,
        };
        if unchanged {
            return Ok(AuthRelent::Unchanged);
        }
        let Ok(_one) = self.lifecycle.try_lock() else {
            // An operator's refresh is in flight; the next poll re-lends.
            return Ok(AuthRelent::Unchanged);
        };
        match self.refresh_lent(&secrets) {
            Ok(_) => {
                *self
                    .secrets
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(secrets);
                *self
                    .lent_fingerprint
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = fingerprint;
                Ok(AuthRelent::Refreshed)
            }
            Err((Some(error), _))
                if error == busbar_contract::abi::sdk::life::NOT_REFRESHED.as_bytes() =>
            {
                Ok(AuthRelent::NotRefreshed)
            }
            Err((_, why)) => Err(why),
        }
    }

    fn login_presentation(&self) -> Option<busbar_contract::auth_calls::LoginPresentation> {
        self.metadata
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .presentation
            .clone()
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
        if !self.metadata_valid.load(Ordering::Acquire) {
            return Box::new(busbar_contract::auth_calls::LoginSettled(Some(
                busbar_contract::auth::LoginOutcome::Reject,
            )));
        }
        login::begin(&self.shared, request)
    }

    fn complete_login(
        &self,
        request: busbar_contract::auth_calls::LoginCallback,
    ) -> Box<dyn busbar_contract::auth_calls::LoginCall> {
        if !self.metadata_valid.load(Ordering::Acquire) {
            return Box::new(busbar_contract::auth_calls::LoginSettled(Some(
                busbar_contract::auth::LoginOutcome::Reject,
            )));
        }
        login::complete(&self.shared, request)
    }
}

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

struct Verify {
    shared: Arc<Shared>,
    presented: bool,
    held: Arc<Held>,
    recalled: bool,
}

impl Answering<VerifyIn, IdentifyOut> for Verify {
    type Out = VerifyAnswer;

    fn answer(
        &mut self,
        done: Done<VerifyIn, IdentifyOut>,
        call: &mut Ticketed<VerifyIn, IdentifyOut>,
    ) -> Option<VerifyAnswer> {
        let _lease = AnswerLease::new(&self.shared.plugin, done.lease);
        let out = done.frame.as_ref().map(|f| f.out);
        if done.short && !self.recalled {
            self.recalled = true;
            let grow = out.as_ref().and_then(|o| grown(o, &self.held));
            if let Some((cap, groups, strips)) = grow {
                self.held = Held::new(Arc::clone(&self.held.input), cap, groups, strips);
                self.shared.submit(call, &self.held, self.presented);
                return None;
            }
            return Some(Verified::Failed.into());
        }
        Some(match out {
            Some(o) => verdict(done.outcome, &o, &self.held, &self.shared.plugin),
            None => Verified::Failed.into(),
        })
    }
}

impl Verifying for Pending<VerifyIn, IdentifyOut, Verify> {
    fn settled(&mut self) -> Option<VerifyAnswer> {
        self.now()
    }

    fn faulted(&self) -> bool {
        self.any_fault()
    }
}

#[path = "auth_login.rs"]
#[doc(hidden)]
pub mod login;

#[cfg(test)]
#[path = "tests/auth_door_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/auth_carriers_tests.rs"]
mod carrier_tests;

#[cfg(test)]
#[path = "tests/auth_instance_carriers_old_api_tests.rs"]
mod instance_carriers_old_api_tests;

#[cfg(test)]
#[path = "tests/auth_header_boundary_tests.rs"]
mod header_boundary_tests;

#[cfg(test)]
#[path = "tests/auth_presentation_tests.rs"]
mod presentation_tests;
