// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LOGIN HALF OF AN AUTH INSTANCE (WIRE-AUTH, ARCHITECT ruling 2026-09-30 (A)(3)): the hosted
//! login's `begin_login` and `complete_login` on the one dispatcher, in the same shape as `verify`:
//! submitted on a request ticket, answered through the reply's waker, the memory the `in` lends
//! travelling with the op. The plugin runs its own token exchange over its own need, holding its own
//! client secret; the kernel names neither this crate nor the plugin.
//!
//! * `begin_login`: [`LoginOutcome::Authorize`] (`BEGIN_AUTHORIZE`) or [`LoginOutcome::Prompt`]
//!   (`BEGIN_FORM`), copied out of the plugin memory its lease holds, then the lease is released.
//! * `complete_login`: `LOGIN_IDENTITY` is [`LoginOutcome::Identify`], `LOGIN_BAD_CREDENTIAL`
//!   [`LoginOutcome::Reject`], `LOGIN_OUTAGE` [`LoginOutcome::Outage`],
//!   `LOGIN_SECURITY_CHECK_FAILED` [`LoginOutcome::SecurityCheckFailed`]. A SHORT answer is
//!   re-called ONCE with the buffers it named.
//! * Anything else (FAILED, FAULT, REFUSED, a timeout, a second short answer, the instance at
//!   `max_inflight`) is [`LoginOutcome::Reject`]: 1.5.5 refused a login plugin that failed or could
//!   not be started.
//!
//! The code, the PKCE verifier and every submitted field are secret: zeroed when the op's lent
//! memory is dropped, and never printed.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use busbar_contract::abi::auth::{
    slot, BeginLoginIn, BeginLoginOut, CompleteLoginIn, IdentifyOut, LoginField, BEGIN_AUTHORIZE,
    BEGIN_FORM, FORM_PASSWORD, IDENTITY_BUF_BYTES, IDENTITY_GROUPS, LOGIN_BAD_CREDENTIAL,
    LOGIN_IDENTITY, LOGIN_OUTAGE, LOGIN_SECURITY_CHECK_FAILED,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, DeadlineClass, Outcome, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::lifecycle::{slot as lc, ReleaseIn};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::auth::{BeginLogin, FieldKind, LoginForm, LoginOutcome, Principal};
use busbar_contract::auth_calls::{LoginCall, LoginCallback, LoginSettled, VerifyRequest};

use super::{blob, grown, identify_out, lend, lend_opt, zero, Held, Shared};
use crate::dispatch::{in_head, now_ns, out_head, Done, Frame, Reply};

/// A submitted `begin_login`'s deadline.
pub const BEGIN_LOGIN_DEADLINE: Duration = Duration::from_secs(10);

/// A submitted `complete_login`'s deadline: 1.5.5's bound on a callback's hops (six, ten seconds
/// each), now the plugin's own exchange.
pub const COMPLETE_LOGIN_DEADLINE: Duration = Duration::from_secs(60);

/// The most fields a login form may declare.
const FORM_MAX: usize = 64;

/// The instance cannot take another op now: fail closed.
fn overloaded(shared: &Shared) -> bool {
    let p = &shared.plugin;
    p.max_inflight() != 0 && p.inflight() >= p.max_inflight()
}

// ── begin_login ─────────────────────────────────────────────────────────────────────────────────

/// THE MEMORY ONE `begin_login` LENDS. Nothing in it is secret.
struct BeginHeld {
    redirect_uri: String,
    state: String,
    nonce: Option<String>,
    code_challenge: String,
    scopes: Vec<String>,
    scope_strs: Vec<AbiStr>,
}

// SAFETY: `scope_strs` points only into `scopes`, which `BeginHeld` owns and never mutates after
// construction; the plugin reads it only while the op runs.
unsafe impl Send for BeginHeld {}
// SAFETY: as above.
unsafe impl Sync for BeginHeld {}

impl BeginHeld {
    fn new(req: BeginLogin) -> Arc<Self> {
        let mut held = Self {
            redirect_uri: req.redirect_uri,
            state: req.state,
            nonce: req.nonce,
            code_challenge: req.code_challenge,
            scopes: req.scopes,
            scope_strs: Vec::new(),
        };
        held.scope_strs = held.scopes.iter().map(|s| lend(s)).collect();
        Arc::new(held)
    }

    fn input(&self) -> BeginLoginIn {
        BeginLoginIn {
            head: in_head(),
            redirect_uri: lend(&self.redirect_uri),
            state: lend(&self.state),
            nonce: lend_opt(self.nonce.as_deref()),
            code_challenge: lend(&self.code_challenge),
            scopes: if self.scope_strs.is_empty() {
                std::ptr::null()
            } else {
                self.scope_strs.as_ptr()
            },
            scopes_len: self.scope_strs.len(),
        }
    }
}

fn begin_out() -> BeginLoginOut {
    BeginLoginOut {
        head: out_head(),
        shape: 0,
        _reserved: 0,
        authorize_url: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        form: std::ptr::null(),
        form_len: 0,
    }
}

/// Plugin text under the op's lease, copied; `None` when malformed.
fn text(s: AbiStr) -> Option<String> {
    crate::dispatch::plugin::str_bytes(s).map(|b| String::from_utf8_lossy(b).into_owned())
}

/// What a READY `begin_login` answered, copied out of the plugin memory its lease holds.
fn begun(out: &BeginLoginOut) -> Option<LoginOutcome> {
    match out.shape {
        BEGIN_AUTHORIZE => text(out.authorize_url)
            .filter(|u| !u.is_empty())
            .map(LoginOutcome::Authorize),
        BEGIN_FORM => {
            if out.form.is_null() || out.form_len == 0 || out.form_len > FORM_MAX {
                return None;
            }
            // SAFETY: the kind's check refused a NULL form with a count; the form is `form_len`
            // (bounded above) `LoginField`s of plugin memory, held under the op's lease, which is
            // released only after this copy.
            let fields = unsafe { std::slice::from_raw_parts(out.form, out.form_len) };
            let fields = fields
                .iter()
                .map(|f: &LoginField| {
                    Some(busbar_contract::auth::LoginField {
                        name: text(f.name)?,
                        label: text(f.label)?,
                        kind: if f.kind == FORM_PASSWORD {
                            FieldKind::Password
                        } else {
                            FieldKind::Text
                        },
                        required: f.required == 1,
                    })
                })
                .collect::<Option<Vec<_>>>()?;
            Some(LoginOutcome::Prompt(LoginForm { fields }))
        }
        _ => None,
    }
}

/// Hand a lease back to the plugin.
fn release(shared: &Shared, lease: u64) {
    if lease == 0 {
        return;
    }
    let mut f = Frame::new(
        ReleaseIn {
            head: in_head(),
            lease,
        },
        out_head(),
    );
    let _ = shared.plugin.call(lc::RELEASE, &mut f);
}

/// Submit `begin_login` on `shared`.
pub(super) fn begin(shared: &Arc<Shared>, request: BeginLogin) -> Box<dyn LoginCall> {
    if overloaded(shared) {
        return Box::new(LoginSettled(Some(LoginOutcome::Reject)));
    }
    let Some(ticket) = shared.ticket() else {
        return Box::new(LoginSettled(Some(LoginOutcome::Reject)));
    };
    let held = BeginHeld::new(request);
    let lent: crate::dispatch::Lent = held.clone();
    let reply = shared.dispatcher.submit_lent(
        &shared.plugin,
        ticket,
        slot::BEGIN_LOGIN,
        Frame::new(held.input(), begin_out()),
        DeadlineClass::Call,
        now_ns() + BEGIN_LOGIN_DEADLINE.as_nanos() as u64,
        lent,
    );
    Box::new(Begin {
        shared: shared.clone(),
        ticket,
        _held: held,
        reply: Some(reply),
        answer: None,
    })
}

/// A submitted `begin_login`.
struct Begin {
    shared: Arc<Shared>,
    ticket: Ticket,
    _held: Arc<BeginHeld>,
    reply: Option<Reply<BeginLoginIn, BeginLoginOut>>,
    answer: Option<LoginOutcome>,
}

impl Begin {
    fn step(&mut self, cx: &mut Context<'_>) -> Poll<LoginOutcome> {
        if let Some(a) = &self.answer {
            return Poll::Ready(a.clone());
        }
        let Some(reply) = self.reply.as_mut() else {
            return Poll::Ready(LoginOutcome::Reject);
        };
        let done: Done<BeginLoginIn, BeginLoginOut> = match Pin::new(reply).poll(cx) {
            Poll::Ready(d) => d,
            Poll::Pending => return Poll::Pending,
        };
        self.reply = None;
        let answer = match (done.outcome, done.frame.as_ref()) {
            (Outcome::Ready, Some(f)) => begun(&f.out).unwrap_or(LoginOutcome::Reject),
            _ => LoginOutcome::Reject,
        };
        release(&self.shared, done.lease);
        self.answer = Some(answer.clone());
        Poll::Ready(answer)
    }
}

impl Future for Begin {
    type Output = LoginOutcome;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<LoginOutcome> {
        self.step(cx)
    }
}

impl LoginCall for Begin {
    fn settled(&mut self) -> Option<LoginOutcome> {
        let mut cx = Context::from_waker(Waker::noop());
        match self.step(&mut cx) {
            Poll::Ready(a) => Some(a),
            Poll::Pending => None,
        }
    }
}

impl Drop for Begin {
    fn drop(&mut self) {
        drop(self.reply.take());
        self.shared.dispatcher.recycle(self.ticket);
    }
}

// ── complete_login ──────────────────────────────────────────────────────────────────────────────

/// THE MEMORY ONE `complete_login` LENDS: the callback, the submitted fields pointing into it, and
/// the identity buffers the plugin writes (a [`Held`] over no request).
struct CompleteHeld {
    code: Option<Vec<u8>>,
    state: String,
    redirect_uri: Option<String>,
    code_verifier: Option<Vec<u8>>,
    nonce: Option<String>,
    submitted: Vec<(String, Vec<u8>)>,
    named: Vec<busbar_contract::abi::auth::NamedValue>,
    id: Arc<Held>,
}

// SAFETY: `named` points only into `submitted`, which `CompleteHeld` owns and never mutates after
// construction (it is zeroed only in `Drop`, once nothing reads it).
unsafe impl Send for CompleteHeld {}
// SAFETY: as above.
unsafe impl Sync for CompleteHeld {}

impl CompleteHeld {
    fn new(req: &LoginCallback, buf_cap: usize, groups_cap: u32) -> Arc<Self> {
        let login = &req.login;
        let mut held = Self {
            code: login.code.as_ref().map(|c| c.as_bytes().to_vec()),
            state: req.state.clone(),
            redirect_uri: login.redirect_uri.clone(),
            code_verifier: login.code_verifier.as_ref().map(|c| c.as_bytes().to_vec()),
            nonce: req.nonce.clone(),
            submitted: login
                .submitted
                .iter()
                .map(|(n, v)| (n.clone(), v.expose_secret().as_bytes().to_vec()))
                .collect(),
            named: Vec::new(),
            id: Held::new(&VerifyRequest::default(), buf_cap, groups_cap),
        };
        held.named = held
            .submitted
            .iter()
            .map(|(name, value)| busbar_contract::abi::auth::NamedValue {
                name: lend(name),
                value: blob(value, BLOB_OCTETS, BLOB_SECRET),
            })
            .collect();
        Arc::new(held)
    }

    fn input(&self) -> CompleteLoginIn {
        let secret = |b: &Option<Vec<u8>>| {
            b.as_deref().map_or(crate::dispatch::NO_BLOB, |b| {
                blob(b, BLOB_OCTETS, BLOB_SECRET)
            })
        };
        CompleteLoginIn {
            head: in_head(),
            code: secret(&self.code),
            state: lend(&self.state),
            redirect_uri: lend_opt(self.redirect_uri.as_deref()),
            code_verifier: secret(&self.code_verifier),
            submitted: if self.named.is_empty() {
                std::ptr::null()
            } else {
                self.named.as_ptr()
            },
            submitted_len: self.named.len(),
            out_buf: self.id.input(false).out_buf,
            nonce: lend_opt(self.nonce.as_deref()),
        }
    }
}

impl Drop for CompleteHeld {
    fn drop(&mut self) {
        for b in [&mut self.code, &mut self.code_verifier]
            .into_iter()
            .flatten()
        {
            zero(b);
        }
        for (_, v) in &mut self.submitted {
            zero(v);
        }
    }
}

/// What a completed `complete_login` answered.
fn completed(outcome: Outcome, out: &IdentifyOut, held: &CompleteHeld) -> LoginOutcome {
    if outcome != Outcome::Ready {
        return LoginOutcome::Reject;
    }
    match out.verdict {
        LOGIN_IDENTITY => {
            let id = held.id.identity(&out.identity);
            LoginOutcome::Identify(Principal {
                id: id.subject,
                name: id.name,
                roles: id.groups,
                ttl_secs: id.ttl_secs,
            })
        }
        LOGIN_OUTAGE => LoginOutcome::Outage,
        LOGIN_SECURITY_CHECK_FAILED => LoginOutcome::SecurityCheckFailed,
        LOGIN_BAD_CREDENTIAL => LoginOutcome::Reject,
        _ => LoginOutcome::Reject,
    }
}

/// Submit `complete_login` on `shared`.
pub(super) fn complete(shared: &Arc<Shared>, request: LoginCallback) -> Box<dyn LoginCall> {
    if overloaded(shared) {
        return Box::new(LoginSettled(Some(LoginOutcome::Reject)));
    }
    let Some(ticket) = shared.ticket() else {
        return Box::new(LoginSettled(Some(LoginOutcome::Reject)));
    };
    let held = CompleteHeld::new(&request, IDENTITY_BUF_BYTES, IDENTITY_GROUPS);
    let reply = submit_complete(shared, ticket, &held);
    Box::new(Complete {
        shared: shared.clone(),
        ticket,
        request,
        held,
        reply: Some(reply),
        recalled: false,
        answer: None,
    })
}

fn submit_complete(
    shared: &Shared,
    ticket: Ticket,
    held: &Arc<CompleteHeld>,
) -> Reply<CompleteLoginIn, IdentifyOut> {
    let lent: crate::dispatch::Lent = held.clone();
    shared.dispatcher.submit_lent(
        &shared.plugin,
        ticket,
        slot::COMPLETE_LOGIN,
        Frame::new(held.input(), identify_out()),
        DeadlineClass::Call,
        now_ns() + COMPLETE_LOGIN_DEADLINE.as_nanos() as u64,
        lent,
    )
}

/// A submitted `complete_login`: its reply, the one re-call a short answer earns, then its answer.
struct Complete {
    shared: Arc<Shared>,
    ticket: Ticket,
    request: LoginCallback,
    held: Arc<CompleteHeld>,
    reply: Option<Reply<CompleteLoginIn, IdentifyOut>>,
    recalled: bool,
    answer: Option<LoginOutcome>,
}

impl Complete {
    fn step(&mut self, cx: &mut Context<'_>) -> Poll<LoginOutcome> {
        loop {
            if let Some(a) = &self.answer {
                return Poll::Ready(a.clone());
            }
            let Some(reply) = self.reply.as_mut() else {
                return Poll::Ready(LoginOutcome::Reject);
            };
            let done = match Pin::new(reply).poll(cx) {
                Poll::Ready(d) => d,
                Poll::Pending => return Poll::Pending,
            };
            self.reply = None;
            let out = done.frame.as_ref().map(|f| f.out);
            if done.short && !self.recalled {
                self.recalled = true;
                if let Some((cap, groups)) = out.as_ref().and_then(|o| grown(o, &self.held.id)) {
                    self.held = CompleteHeld::new(&self.request, cap, groups);
                    self.reply = Some(submit_complete(&self.shared, self.ticket, &self.held));
                    continue;
                }
                self.answer = Some(LoginOutcome::Reject);
                continue;
            }
            self.answer = Some(match out {
                Some(o) => completed(done.outcome, &o, &self.held),
                None => LoginOutcome::Reject,
            });
        }
    }
}

impl Future for Complete {
    type Output = LoginOutcome;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<LoginOutcome> {
        self.step(cx)
    }
}

impl LoginCall for Complete {
    fn settled(&mut self) -> Option<LoginOutcome> {
        let mut cx = Context::from_waker(Waker::noop());
        match self.step(&mut cx) {
            Poll::Ready(a) => Some(a),
            Poll::Pending => None,
        }
    }
}

impl Drop for Complete {
    fn drop(&mut self) {
        drop(self.reply.take());
        self.shared.dispatcher.recycle(self.ticket);
    }
}
