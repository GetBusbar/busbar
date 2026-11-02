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

    strip: *mut StripName,
    strip_cap: u32,

    buf: *mut u8,
    buf_cap: usize,

    groups: *mut Span,
    groups_cap: u32,
}

// SAFETY: `named` and the three buffers point only into allocations `Held` owns and frees in `Drop`;
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
    Carriers(Vec<String>),
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
    fn new(
        req: &VerifyRequest,
        seal: Option<&(dyn busbar_contract::plugin::KernelSeal + Send + Sync)>,
        headers: &Headers,
        buf_cap: usize,
        groups_cap: u32,
        strip_cap: u32,
    ) -> Arc<Self> {
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
            credential: req
                .credential
                .as_ref()
                .and_then(|c| Some(c.expose(seal?).clone()))
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
    let reason = String::from_utf8_lossy(&text).into_owned();
    let line = format!("{what}: {reason}");
    plugin.note(severity, &line);
    match severity {
        0 => tracing::info!(plugin = %plugin.name(), "{line}"),
        _ => tracing::warn!(plugin = %plugin.name(), "{line}"),
    }
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
    #[must_use]
    pub fn new(plugin: &str) -> Self {
        Self(Arc::new(FlushSink {
            plugin: plugin.to_string(),
            family: Mutex::new(None),
            flushed: AtomicU64::new(0),
        }))
    }

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
            now_ns() + VERIFY_DEADLINE.as_nanos() as u64,
            lent,
        );
    }
}

pub struct AuthInstance {
    shared: Arc<Shared>,
    sink: AuthSink,
    facts: AuthFacts,
    carriers: Mutex<Vec<String>>,
    metadata_valid: AtomicBool,

    settings: Vec<u8>,

    secrets: KeptSecrets,
    generation: AtomicU64,
    label: String,
    lifecycle: Mutex<()>,

    schedule: Option<tokio::task::JoinHandle<()>>,
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
    settings: &serde_json::Value,
) -> (serde_json::Value, Vec<Vec<u8>>) {
    let refs = plugin
        .context::<AuthFacts>()
        .map(|f| f.secret_refs.clone())
        .unwrap_or_default();
    let mut settings = settings.clone();
    let as_bytes = |v: Option<serde_json::Value>| match v {
        Some(serde_json::Value::String(s)) => s.into_bytes(),
        _ => Vec::new(),
    };
    let secrets = busbar_contract::secret_fields::lend(
        &mut settings,
        &refs,
        false,
        |_, v| Ok::<_, std::convert::Infallible>(as_bytes(v)),
        |_, v| Ok(as_bytes(Some(v))),
    )
    .unwrap_or_else(|e| match e {});
    (settings, secrets)
}

pub(crate) struct KeptSecrets(Vec<zeroize::Zeroizing<Vec<u8>>>);

impl KeptSecrets {
    fn new(secrets: Vec<Vec<u8>>) -> Self {
        Self(secrets.into_iter().map(zeroize::Zeroizing::new).collect())
    }

    fn blobs(&self) -> Vec<Blob> {
        self.0
            .iter()
            .map(|s| Blob {
                ptr: s.as_ptr(),
                len: s.len(),
                fmt: BLOB_OCTETS,
                flags: BLOB_SECRET,
            })
            .collect()
    }
}

impl zeroize::ZeroizeOnDrop for KeptSecrets {}

impl std::fmt::Debug for KeptSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeptSecrets([REDACTED; {}])", self.0.len())
    }
}

fn instance_carriers(
    blob: Blob,
    previous: &[String],
    facts: &AuthFacts,
) -> Result<Vec<String>, String> {
    use busbar_contract::abi::auth::{EXT_CARRIERS, FACT_DEFAULT_INBOUND_STYLE};
    use busbar_contract::abi::mechanism::extensions;

    let invalid = || "auth instance returned invalid carrier metadata".to_string();
    if blob.fmt == BLOB_ABSENT && blob.len == 0 {
        return Ok(previous.to_vec());
    }
    if blob.fmt != BLOB_OCTETS || (blob.len != 0 && blob.ptr.is_null()) {
        return Err(invalid());
    }
    // SAFETY: the validated READY reply owns these bytes until its lease is released by the caller.
    let bytes = unsafe { crate::dispatch::plugin::blob_bytes(blob) };
    let mut consumed = 0;
    let mut selection = None;
    for (key, value) in extensions::entries(bytes) {
        consumed += 2 + key.len() + 4 + value.len();
        if key != EXT_CARRIERS.as_bytes() {
            continue;
        }
        if selection.is_some() {
            return Err(invalid());
        }
        let names: Vec<String> = serde_json::from_slice(value).map_err(|_| invalid())?;
        let mut selected = Vec::new();
        for name in names {
            if !facts
                .carriers
                .iter()
                .any(|declared| declared.eq_ignore_ascii_case(&name))
            {
                return Err(invalid());
            }
            let name = name.to_ascii_lowercase();
            if !selected.contains(&name) {
                selected.push(name);
            }
        }
        if selected.is_empty() && facts.facts & FACT_DEFAULT_INBOUND_STYLE != 0 {
            return Err(invalid());
        }
        selection = Some(selected);
    }
    if consumed != bytes.len() {
        return Err(invalid());
    }
    Ok(selection.unwrap_or_else(|| previous.to_vec()))
}

impl AuthInstance {
    fn headers(&self, point: AuthPoint) -> Option<Headers> {
        let carriers = self
            .carriers
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
            Headers::Carriers(carriers.clone())
        })
    }

    pub fn open(
        plugin: Plugin<Auth>,
        sink: AuthSink,
        dispatcher: Arc<Dispatcher>,
        label: &str,
        settings: &[u8],
        secrets: Vec<Vec<u8>>,
    ) -> Result<Self, String> {
        let secrets = KeptSecrets::new(secrets);
        let facts = plugin.context::<AuthFacts>().cloned().unwrap_or_default();
        *sink.0.family.lock().unwrap_or_else(|e| e.into_inner()) = facts.cache_family;
        let called = validate_call(&plugin, blob(settings, BLOB_JSON, 0));
        let validated = AnswerLease::new(&plugin, called.lease);
        if called.outcome != Outcome::Ready {
            return Err(why(called.outcome, called.error));
        }
        drop(validated);
        let blobs = secrets.blobs();
        let mut f = open_frame(blob(settings, BLOB_JSON, 0));
        if !blobs.is_empty() {
            f.input.secrets = blobs.as_ptr();
            f.input.secrets_len = blobs.len();
        }
        let called = plugin.call(lc::OPEN, &mut f);
        if called.outcome != Outcome::Ready {
            return Err(why(called.outcome, called.error));
        }
        let carriers = instance_carriers(f.out.head.extensions, &facts.carriers, &facts);
        release(&plugin, called.lease);
        let carriers = match carriers {
            Ok(carriers) => carriers,
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
        let schedule =
            crate::dispatch::auth_ticks::spawn(Arc::clone(&plugin), dispatcher.clone(), 0);
        Ok(Self {
            shared: Arc::new(Shared {
                plugin,
                dispatcher,
                minted: AtomicU64::new(0),
            }),
            sink,
            facts,
            carriers: Mutex::new(carriers),
            metadata_valid: AtomicBool::new(true),
            settings: settings.to_vec(),
            secrets,
            generation: AtomicU64::new(1),
            label: label.to_string(),
            lifecycle: Mutex::new(()),
            schedule,
        })
    }

    pub fn plugin(&self) -> &Plugin<Auth> {
        &self.shared.plugin
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    #[must_use]
    pub fn ticks_ended(&self) -> bool {
        self.schedule
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
    }

    #[cfg(test)]
    pub(crate) fn kept_secrets(&self) -> &KeptSecrets {
        &self.secrets
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
        self.carriers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
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
        let held = Held::new(
            request,
            seal,
            &headers,
            IDENTITY_BUF_BYTES,
            IDENTITY_GROUPS,
            FIELDS_MAX,
        );
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
                let bigger = Held::new(request, seal, &headers, cap, groups, strips);
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
        let held = Held::new(
            &request,
            seal,
            &headers,
            IDENTITY_BUF_BYTES,
            IDENTITY_GROUPS,
            FIELDS_MAX,
        );
        sh.submit(&mut call, &held, presented);
        Box::new(Pending::new(
            call,
            Verify {
                shared: sh.clone(),
                request,
                headers,
                presented,
                held,
                recalled: false,
            },
        ))
    }

    fn refresh(&self) -> Result<u64, String> {
        let _one = match self.lifecycle.try_lock() {
            Ok(one) => one,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(format!(
                    "auth instance `{}`: a refresh is already in flight",
                    self.label
                ))
            }
        };
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.sink.0.flushed.store(0, Ordering::Release);
        let blobs = self.secrets.blobs();
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
        if called.outcome != Outcome::Ready {
            self.metadata_valid.store(
                was_valid && matches!(called.outcome, Outcome::Refused | Outcome::Failed),
                Ordering::Release,
            );
            return Err(why(called.outcome, called.error));
        }
        let current = self.carriers();
        let carriers = instance_carriers(f.out.extensions, &current, &self.facts);
        release(&self.shared.plugin, called.lease);
        match carriers {
            Ok(carriers) => {
                *self
                    .carriers
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = carriers;
                self.metadata_valid.store(true, Ordering::Release);
            }
            Err(error) => {
                self.metadata_valid.store(false, Ordering::Release);
                return Err(error);
            }
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
    request: VerifyRequest,
    headers: Headers,
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
                let seal = self.shared.dispatcher.seal();
                self.held = Held::new(&self.request, seal, &self.headers, cap, groups, strips);
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
