// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth adapter: `AuthPort` over the auth kind's `Proxy` (IF §11.3, §8.3).
//!
//! Sync `verify` runs inline on the thread-local sync buffers and finishes without boxing. Everything that needs
//! a second step boxes once: ISSUED_WANTED (the issued-credential lookup, then the same method again), REPLAY
//! (the claim), KEYS_STALE (one single-flight, rate-limited `refresh`, then the same verify once more) and every
//! `verify_io`. A request view never crosses an await (`abi::Pair` is not `Sync`): what a second step needs is
//! copied into an owned snapshot of the encoded request before the box is built.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::auth::{self as abi, tag as t, AuthReq, Proxy};
use busbar_plugin_abi::fail::{fact, failed, refused, CallError, FaultReason};
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::host_side::driver::{Driver, Instance};
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::host_side::pool::{sync_bufs, Pool, PooledOut};
use busbar_plugin_abi::host_side::scrub::{fail_text, Scrub};
use busbar_plugin_abi::records::{tag, FactRec, Full, RecErr, Records, Reply, Writer};
use busbar_plugin_abi::types::{Bytes, Pair, Slice, Status, Str};
use tokio::sync::OnceCell;

use crate::encode::auth as enc;
use crate::instance::{ErrorBook, PluginCode};
use crate::ports::auth::{
    decode_login_identity, decode_verify_ok, AuthIn, AuthPort, Identity, LoginAnswer, LoginIn,
    OutboundAnswer, ServeIn, ServeOut, UpstreamIn, Verdict, Verify, VerifyOk,
};
use crate::ports::{CallCx, PortError};

/// What the adapter asks core for while it settles a verify: the issued-credential lookup (IF §12.8
/// `IssuedCredentials::lookup`) and the replay claim (§12.11 `ReplayGuard::claim`). The kernel implements it over
/// those two traits (the kernel depends on the loader, never the reverse, so the adapter cannot name them).
pub trait AuthCore: Send + Sync + 'static {
    /// The issued credential `id` of `kind` for this auth instance, or empty when the id is unknown or the
    /// instance is not granted the kind (same path and timing class, §12.8).
    fn issued<'a>(
        &'a self,
        auth_instance: u64,
        kind: &'a str,
        id: &'a str,
    ) -> BoxFut<'a, SecureVec>;
    /// Some(true) = first sighting (admit); Some(false) = replay; None = the guard is unavailable (fail closed).
    fn claim<'a>(
        &'a self,
        who: &'a Caller<'_>,
        key: &'a [u8],
        ttl_s: u64,
    ) -> BoxFut<'a, Option<bool>>;
}

/// The auth port over one instance's proxy.
pub struct AuthAdapter<N: Needs> {
    proxy: Proxy,
    needs: Arc<N>,
    core: Arc<dyn AuthCore>,
    /// D_CRED_HEADER*, lowercase.
    cred_headers: Box<[Box<str>]>,
    /// D_ISSUED_KIND, if declared.
    issued_kind: Option<Box<str>>,
    errors: &'static ErrorBook,
    /// The undeclared-ERROR WARN latch (`ErrorBook::resolve`).
    undeclared: AtomicBool,
    keys: KeyRefresh,
}

impl<N: Needs> AuthAdapter<N> {
    /// `describe` = the image's describe records (D_CRED_HEADER*, D_ISSUED_KIND?, D_ISSUED_SHAPE?);
    /// `unknown_key_refresh` = `auth.unknown_key_refresh_s` (default 30 s, at least 5 s, §12.11).
    pub fn new(
        proxy: Proxy,
        needs: Arc<N>,
        core: Arc<dyn AuthCore>,
        describe: Records<'_>,
        errors: &'static ErrorBook,
        unknown_key_refresh: Duration,
    ) -> Result<Self, RecErr> {
        let cred_headers = decode_cred_headers(describe)?;
        let issued_kind = enc::decode_issued_shape(describe)?.map(|(kind, _)| kind);
        Ok(AuthAdapter {
            proxy,
            needs,
            core,
            cred_headers,
            issued_kind,
            errors,
            undeclared: AtomicBool::new(false),
            keys: KeyRefresh::new(unknown_key_refresh),
        })
    }

    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }

    fn inst(&self) -> &Instance {
        self.proxy.instance()
    }

    /// The `PortError` of a REFUSED or FAILED answer: scrubbed text, the FAILED facts, the resolved ERROR.
    fn plugin_error(&self, a: &Answer<'_>) -> PortError {
        let (code, text) = a.fail().unwrap_or((0, ""));
        let error = self.errors.resolve(a.fail_error(), &self.undeclared);
        plugin_error(
            a.status,
            code,
            text,
            a.fail_fact(fact::FACT_RETRY_AFTER_S),
            a.fail_fact(fact::FACT_BACKEND_STATUS),
            error,
            &self.inst().scrub,
        )
    }

    /// One verify / verify_io answer, as what it asks of the adapter next.
    fn said(&self, a: Result<Answer<'_>, CallError>) -> Result<Said, PortError> {
        let a = a.map_err(PortError::Call)?;
        if a.status == Status::OK {
            return match decode_verify_ok(a.records()).map_err(fault)? {
                VerifyOk::Identity(id) if id.replay().is_some() => Ok(Said::Replay(id)),
                VerifyOk::Identity(id) => Ok(Said::Verdict(Verdict::Identity(id))),
                VerifyOk::IssuedWanted(id) => Ok(Said::Wanted(id)),
            };
        }
        if a.status == Status::REFUSED {
            let (code, text) = a.fail().unwrap_or((0, ""));
            return match verify_refusal(code, text, &self.inst().scrub) {
                Ok(Some(v)) => Ok(Said::Verdict(v)),
                Ok(None) => Ok(Said::Stale),
                Err(PortError::Refused { code, text, .. }) => Err(PortError::Refused {
                    code,
                    text,
                    error: self.errors.resolve(a.fail_error(), &self.undeclared),
                }),
                Err(e) => Err(e),
            };
        }
        Err(self.plugin_error(&a))
    }

    /// The sync verify, inline on the thread-local sync buffers (no pool, no box).
    fn verify_sync(&self, req: &AuthReq<'_>) -> Result<Said, PortError> {
        sync_bufs(self.inst().max_out, |_args, out| {
            self.said(self.proxy.verify(out, req))
        })
    }

    /// One verify_io chain over an encoded request.
    async fn verify_chain(&self, cx: CallCx, req: PooledOut) -> Result<Said, PortError> {
        let inst = self.inst();
        let mut drv = Driver::new(&*self.needs, caller(inst, cx));
        let owned = self
            .proxy
            .verify_io(&mut drv, req)
            .await
            .map_err(PortError::Call)?;
        self.said(Ok(owned.answer()))
    }

    /// The same verify again, from the owned snapshot, with the looked-up credential when there is one.
    async fn verify_again(
        &self,
        cx: CallCx,
        snap: &Reply,
        issued: Option<&[u8]>,
    ) -> Result<Said, PortError> {
        let inst = self.inst();
        if inst.methods & abi::M_VERIFY != 0 {
            let flags = if issued.is_some() {
                abi::REQ_ISSUED_LOOKED_UP
            } else {
                0
            };
            return snapshot_view(snap, issued.unwrap_or_default(), flags, |view| {
                self.verify_sync(view)
            })
            .map_err(fault)?;
        }
        let req = chain_req(inst.max_out, &Again { snap, issued })?;
        self.verify_chain(cx, req).await
    }

    /// Runs the steps a first answer asked for until it is a verdict: at most one issued lookup, at most one
    /// KEYS_STALE refresh, then the replay claim.
    async fn settle(
        &self,
        cx: CallCx,
        snap: Option<Reply>,
        mut said: Said,
    ) -> Result<Verdict, PortError> {
        let mut issued: Option<SecureVec> = None;
        let mut refreshed = false;
        loop {
            match said {
                Said::Verdict(v) => return Ok(v),
                Said::Replay(id) => return self.admit(cx, id).await,
                Said::Wanted(id) => {
                    let Some(kind) = self.issued_kind.as_deref().filter(|_| issued.is_none())
                    else {
                        return Err(fault(RecErr::Unknown(t::ISSUED_WANTED)));
                    };
                    issued = Some(self.core.issued(self.inst().id, kind, &id).await);
                }
                Said::Stale => {
                    if refreshed || self.inst().methods & abi::M_REFRESH == 0 {
                        return Ok(bad_credential());
                    }
                    refreshed = true;
                    let Some(round) = self.keys.begin() else {
                        return Ok(bad_credential());
                    };
                    round
                        .get_or_init(|| async move { self.refresh(cx).await.map(drop) })
                        .await
                        .clone()?;
                }
            }
            let Some(snap) = snap.as_ref() else {
                return Err(fault(RecErr::Truncated));
            };
            said = self.verify_again(cx, snap, issued.as_deref()).await?;
        }
    }

    /// Admits an identity that carried REPLAY only after core wins the claim (§12.11).
    async fn admit(&self, cx: CallCx, id: Identity) -> Result<Verdict, PortError> {
        let who = caller(self.inst(), cx);
        let Some((key, ttl_s)) = id.replay() else {
            return Ok(Verdict::Identity(id));
        };
        let won = self.core.claim(&who, key, ttl_s).await;
        match won {
            Some(true) => Ok(Verdict::Identity(id)),
            Some(false) => Ok(Verdict::Rejected {
                code: refused::R_REPLAYED,
                text: Box::from("the request was already seen"),
            }),
            None => Err(PortError::Failed {
                code: failed::F_UNAVAILABLE,
                text: Box::from("the replay guard is unavailable"),
                retry_after_s: None,
                backend_status: None,
                error: None,
            }),
        }
    }
}

impl<N: Needs> AuthPort for AuthAdapter<N> {
    fn facts(&self) -> u64 {
        self.inst().facts
    }

    fn cred_headers(&self) -> &[Box<str>] {
        &self.cred_headers
    }

    fn issued_kind(&self) -> Option<&str> {
        self.issued_kind.as_deref()
    }

    fn verify<'a>(&'a self, cx: CallCx, req: &'a AuthIn<'a>) -> Verify<'a> {
        let methods = self.inst().methods;
        if methods & abi::M_VERIFY != 0 {
            let said = match self.verify_sync(&view(req, &[], 0)) {
                Ok(Said::Verdict(v)) => return Verify::Done(Ok(v)),
                Ok(said) => said,
                Err(e) => return Verify::Done(Err(e)),
            };
            let snap = match said {
                Said::Replay(_) => None,
                _ => match snapshot(req) {
                    Ok(snap) => Some(snap),
                    Err(e) => return Verify::Done(Err(e)),
                },
            };
            return Verify::Io(Box::pin(self.settle(cx, snap, said)));
        }
        if methods & abi::M_VERIFY_IO == 0 {
            return Verify::Done(Err(PortError::Call(CallError::NotDeclared)));
        }
        let first = chain_req(self.inst().max_out, &Direct(req));
        let again = self.issued_kind.is_some() || methods & abi::M_REFRESH != 0;
        let snap = if again {
            snapshot(req).map(Some)
        } else {
            Ok(None)
        };
        Verify::Io(Box::pin(async move {
            let said = self.verify_chain(cx, first?).await?;
            self.settle(cx, snap?, said).await
        }))
    }

    fn login<'a>(
        &'a self,
        cx: CallCx,
        step: LoginIn<'a>,
    ) -> BoxFut<'a, Result<LoginAnswer, PortError>> {
        let inst = self.inst();
        let (code, offered) = match step {
            LoginIn::Begin { .. } => (abi::LOGIN_BEGIN, abi::FB_LOGIN_REDIRECT),
            LoginIn::Complete { .. } => (abi::LOGIN_COMPLETE, abi::FB_LOGIN_REDIRECT),
            LoginIn::Credential { .. } => (abi::LOGIN_CREDENTIAL, abi::FB_LOGIN_CREDENTIAL),
        };
        // A step the declared login kind does not offer is never sent (§8.3 round 8).
        if inst.methods & abi::M_LOGIN == 0 || inst.facts & offered == 0 {
            return Box::pin(core::future::ready(Err(unsupported(
                "this auth instance does not offer that login step",
            ))));
        }
        let connect = matches!(
            step,
            LoginIn::Complete {
                connect: Some(_),
                ..
            }
        );
        let req = chain_req(inst.max_out, &Login(&step));
        Box::pin(async move {
            let req = req?;
            let inst = self.inst();
            let mut drv = Driver::new(&*self.needs, caller(inst, cx));
            let owned = self
                .proxy
                .login(&mut drv, req, code)
                .await
                .map_err(PortError::Call)?;
            let a = owned.answer();
            if a.status != Status::OK {
                return Err(self.plugin_error(&a));
            }
            decode_login(code, connect, a.records()).map_err(fault)
        })
    }

    fn outbound<'a>(
        &'a self,
        cx: CallCx,
        req: &'a UpstreamIn<'a>,
    ) -> BoxFut<'a, Result<OutboundAnswer, PortError>> {
        let inst = self.inst();
        if inst.methods & abi::M_OUTBOUND == 0 {
            return Box::pin(core::future::ready(Err(PortError::Call(
                CallError::NotDeclared,
            ))));
        }
        let req = chain_req(inst.max_out, &Outbound(req));
        Box::pin(async move {
            let req = req?;
            let inst = self.inst();
            let mut drv = Driver::new(&*self.needs, caller(inst, cx));
            let owned = self
                .proxy
                .outbound(&mut drv, req)
                .await
                .map_err(PortError::Call)?;
            let a = owned.answer();
            if a.status != Status::OK {
                return Err(self.plugin_error(&a));
            }
            decode_outbound(a.records()).map_err(fault)
        })
    }

    fn refresh<'a>(&'a self, cx: CallCx) -> BoxFut<'a, Result<Option<u32>, PortError>> {
        let inst = self.inst();
        if inst.methods & abi::M_REFRESH == 0 {
            return Box::pin(core::future::ready(Err(PortError::Call(
                CallError::NotDeclared,
            ))));
        }
        let req = chain_req(inst.max_out, &Nothing);
        Box::pin(async move {
            let req = req?;
            let inst = self.inst();
            let mut drv = Driver::new(&*self.needs, caller(inst, cx));
            let owned = self
                .proxy
                .refresh(&mut drv, req)
                .await
                .map_err(PortError::Call)?;
            let a = owned.answer();
            if a.status != Status::OK {
                return Err(self.plugin_error(&a));
            }
            decode_refresh(a.records()).map_err(fault)
        })
    }

    fn serve<'a>(
        &'a self,
        cx: CallCx,
        req: &'a ServeIn<'a>,
    ) -> BoxFut<'a, Result<ServeOut, PortError>> {
        let inst = self.inst();
        // FB_PROVISION only; otherwise refused without a call (§11.3 round 29).
        if inst.methods & abi::M_SERVE == 0 || inst.facts & abi::FB_PROVISION == 0 {
            return Box::pin(core::future::ready(Err(unsupported(
                "this auth instance does not serve provisioning",
            ))));
        }
        let req = chain_req(inst.max_out, &Serve(req));
        Box::pin(async move {
            let req = req?;
            let inst = self.inst();
            let mut drv = Driver::new(&*self.needs, caller(inst, cx));
            let owned = self
                .proxy
                .serve(&mut drv, req)
                .await
                .map_err(PortError::Call)?;
            let a = owned.answer();
            if a.status != Status::OK {
                return Err(self.plugin_error(&a));
            }
            enc::decode_serve(&a).map_err(fault)
        })
    }
}

/// What a verify answer asks for next.
#[derive(Debug)]
enum Said {
    /// Final: an identity without REPLAY, NotMine or Rejected.
    Verdict(Verdict),
    /// An identity that carried REPLAY: admitted only after the claim.
    Replay(Identity),
    /// ISSUED_WANTED: look this id up, then call again.
    Wanted(Box<str>),
    /// REFUSED KEYS_STALE: refresh once, then call again.
    Stale,
}

/// The caller of one call on this instance, borrowed from it (§10.3 round 14: plain stores, no refcount RMW).
/// `chain` is overwritten by `Driver::new`; a sync call carries 0.
fn caller(inst: &Instance, cx: CallCx) -> Caller<'_> {
    Caller {
        plugin: inst.identity.as_ref(),
        kind: inst.kind,
        name: inst.name.as_ref(),
        instance: inst.id,
        slot: inst.slot,
        chain: 0,
        deadline: cx.deadline,
        stack: cx.stack,
        out_of_process: false,
        limits: inst.limits,
    }
}

/// The verify view of a port request (§8.3 AuthReq).
fn view<'r>(req: &'r AuthIn<'r>, issued: &'r [u8], flags: u32) -> AuthReq<'r> {
    AuthReq {
        flags,
        _r: 0,
        method: Str::new(req.method),
        path: Str::new(req.path),
        query: Str::new(req.query),
        authority: Str::new(req.authority),
        headers: Slice::new(req.headers),
        peer: Str::new(req.peer),
        tls_peer_cert: Bytes::new(req.tls_peer_cert),
        body: Bytes::new(req.body),
        issued: Bytes::new(issued),
        now_s: req.now_s,
    }
}

/// The owned copy of a request a second verify step reads: the verify_io encoding (`encode_verify_io`, no
/// Q_ISSUED), so the sync view and the verify_io request are both rebuilt from the same bytes.
fn snapshot(req: &AuthIn<'_>) -> Result<Reply, PortError> {
    let mut snap = Reply::new();
    Direct(req).encode(&mut snap).map_err(|_| over_max_out())?;
    Ok(snap)
}

/// Rebuilds the sync verify view from a snapshot and runs `f` on it. The view and its header array live only
/// inside this call (they are not `Send`).
fn snapshot_view<R>(
    snap: &Reply,
    issued: &[u8],
    flags: u32,
    f: impl FnOnce(&AuthReq<'_>) -> R,
) -> Result<R, RecErr> {
    let mut texts = [""; 5];
    let mut blobs: [&[u8]; 2] = [&[], &[]];
    let mut headers: Vec<Pair<'_>> = Vec::new();
    let mut now_s = 0;
    for rec in Records::new(snap.as_bytes()) {
        let rec = rec?;
        match rec.tag {
            t::Q_METHOD => texts[0] = rec.text()?,
            t::Q_PATH => texts[1] = rec.text()?,
            t::Q_QUERY => texts[2] = rec.text()?,
            t::Q_AUTHORITY => texts[3] = rec.text()?,
            t::Q_PEER => texts[4] = rec.text()?,
            t::Q_TLS_CERT => blobs[0] = rec.body,
            t::Q_BODY => blobs[1] = rec.body,
            tag::PAIR => {
                let (name, value) = rec.pair()?;
                headers.push(Pair {
                    name: Str::new(name),
                    value: Bytes::new(value),
                });
            }
            tag::FACT => now_s = rec.pod::<FactRec>()?.value,
            other => return Err(RecErr::Unknown(other)),
        }
    }
    let [method, path, query, authority, peer] = texts;
    let [tls_peer_cert, body] = blobs;
    let req = AuthIn {
        method,
        path,
        query,
        authority,
        headers: &headers,
        peer,
        tls_peer_cert,
        body,
        now_s,
    };
    Ok(f(&view(&req, issued, flags)))
}

/// One request encoding (§8.8), written into the chain's request buffer.
trait Encode {
    fn encode<W: Writer>(&self, w: &mut W) -> Result<(), Full>;
}

/// The first verify_io request.
struct Direct<'r>(&'r AuthIn<'r>);
impl Encode for Direct<'_> {
    fn encode<W: Writer>(&self, w: &mut W) -> Result<(), Full> {
        enc::encode_verify_io(w, self.0, None)
    }
}

/// The verify_io request again, from the snapshot: every record as it was, with Q_ISSUED (after a lookup)
/// written right before the closing FACT(F_NOW_S), where `encode_verify_io` puts it.
struct Again<'r> {
    snap: &'r Reply,
    issued: Option<&'r [u8]>,
}
impl Encode for Again<'_> {
    fn encode<W: Writer>(&self, w: &mut W) -> Result<(), Full> {
        for rec in Records::new(self.snap.as_bytes()).map_while(Result::ok) {
            if rec.tag == tag::FACT {
                if let Some(issued) = self.issued {
                    w.put(t::Q_ISSUED, issued)?;
                }
            }
            w.put(rec.tag, rec.body)?;
        }
        Ok(())
    }
}

struct Login<'r>(&'r LoginIn<'r>);
impl Encode for Login<'_> {
    fn encode<W: Writer>(&self, w: &mut W) -> Result<(), Full> {
        enc::encode_login(w, self.0)
    }
}

struct Outbound<'r>(&'r UpstreamIn<'r>);
impl Encode for Outbound<'_> {
    fn encode<W: Writer>(&self, w: &mut W) -> Result<(), Full> {
        enc::encode_outbound(w, self.0)
    }
}

struct Serve<'r>(&'r ServeIn<'r>);
impl Encode for Serve<'_> {
    fn encode<W: Writer>(&self, w: &mut W) -> Result<(), Full> {
        enc::encode_serve(w, self.0)
    }
}

/// `refresh` takes no request records.
struct Nothing;
impl Encode for Nothing {
    fn encode<W: Writer>(&self, _: &mut W) -> Result<(), Full> {
        Ok(())
    }
}

/// The chain's request buffer with `e` written into it. Done synchronously, before any box is built, so no
/// request view is held across an await.
fn chain_req(max_out: usize, e: &impl Encode) -> Result<PooledOut, PortError> {
    let mut req = Pool::global().acquire(max_out);
    e.encode(&mut req).map_err(|_| over_max_out())?;
    Ok(req)
}

/// D_CRED_HEADER*: lowercase header names (core strips them upstream and keys the verdict cache on them).
fn decode_cred_headers(describe: Records<'_>) -> Result<Box<[Box<str>]>, RecErr> {
    let mut names: Vec<Box<str>> = Vec::new();
    for rec in describe {
        let rec = rec?;
        if rec.tag != t::D_CRED_HEADER {
            continue;
        }
        let name = rec.text()?;
        let token =
            |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.!#$%&'*+^`|~".contains(&b);
        if name.is_empty() || !name.bytes().all(token) {
            return Err(RecErr::Size);
        }
        if !names.iter().any(|n| **n == *name) {
            names.push(Box::from(name));
        }
    }
    Ok(names.into())
}

/// A login OK answer for `step` (§8.3): BEGIN = REDIRECT then STATE; COMPLETE = GRANT for a caller connection
/// (L_CONNECT), else ID_*; CREDENTIAL = ID_*.
fn decode_login(step: u32, connect: bool, records: Records<'_>) -> Result<LoginAnswer, RecErr> {
    if step == abi::LOGIN_BEGIN {
        let mut url: Option<&str> = None;
        let mut state: Option<&[u8]> = None;
        for rec in records {
            let rec = rec?;
            match rec.tag {
                tag::METRIC => {}
                t::REDIRECT if url.is_none() => url = Some(rec.text()?),
                t::STATE if url.is_some() && state.is_none() => state = Some(rec.body),
                other => return Err(RecErr::Unknown(other)),
            }
        }
        return match (url, state) {
            (Some(url), Some(state)) => Ok(LoginAnswer::Redirect {
                url: Box::from(url),
                state: SecureVec::from(state),
            }),
            _ => Err(RecErr::Truncated),
        };
    }
    if step == abi::LOGIN_COMPLETE && connect {
        let mut grant: Option<&[u8]> = None;
        for rec in records {
            let rec = rec?;
            match rec.tag {
                tag::METRIC => {}
                t::GRANT if grant.is_none() => grant = Some(rec.body),
                other => return Err(RecErr::Unknown(other)),
            }
        }
        return grant
            .map(|g| LoginAnswer::Grant(SecureVec::from(g)))
            .ok_or(RecErr::Truncated);
    }
    decode_login_identity(records).map(LoginAnswer::Identity)
}

/// An outbound OK answer (§8.3): SET_HEADER*, SET_QUERY* (pair shape), GRANT_UPDATE?, FACT(F_CACHE_S)? (absent
/// = 0, already expired, §12.2 rule 5).
fn decode_outbound(records: Records<'_>) -> Result<OutboundAnswer, RecErr> {
    let mut out = OutboundAnswer {
        headers: Vec::new(),
        query: Vec::new(),
        cache_s: 0,
        grant_update: None,
    };
    let mut cache = false;
    for rec in records {
        let rec = rec?;
        match rec.tag {
            tag::METRIC => {}
            t::SET_HEADER => {
                let (name, value) = rec.pair()?;
                out.headers.push((Box::from(name), SecureVec::from(value)));
            }
            t::SET_QUERY => {
                let (name, value) = rec.pair()?;
                out.query.push((Box::from(name), SecureVec::from(value)));
            }
            t::GRANT_UPDATE if out.grant_update.is_none() => {
                out.grant_update = Some(SecureVec::from(rec.body));
            }
            tag::FACT if !cache => {
                let f = fact_rec(rec.pod::<FactRec>()?)?;
                if f.key != abi::F_CACHE_S {
                    return Err(RecErr::Size);
                }
                out.cache_s = u32::try_from(f.value).unwrap_or(u32::MAX);
                cache = true;
            }
            other => return Err(RecErr::Unknown(other)),
        }
    }
    Ok(out)
}

/// A refresh OK answer (§8.3): FACT(F_NEXT_REFRESH_S)?.
fn decode_refresh(records: Records<'_>) -> Result<Option<u32>, RecErr> {
    let mut next: Option<u32> = None;
    for rec in records {
        let rec = rec?;
        match rec.tag {
            tag::METRIC => {}
            tag::FACT if next.is_none() => {
                let f = fact_rec(rec.pod::<FactRec>()?)?;
                if f.key != abi::F_NEXT_REFRESH_S {
                    return Err(RecErr::Size);
                }
                next = Some(u32::try_from(f.value).unwrap_or(u32::MAX));
            }
            other => return Err(RecErr::Unknown(other)),
        }
    }
    Ok(next)
}

fn fact_rec(f: FactRec) -> Result<FactRec, RecErr> {
    if f._r != 0 {
        return Err(RecErr::Reserved);
    }
    Ok(f)
}

/// A malformed answer is the plugin breaking the contract: FAULT (§3).
fn fault(e: RecErr) -> PortError {
    PortError::Call(CallError::Fault(match e {
        RecErr::Unknown(tag) => FaultReason::UnknownTag(tag),
        other => FaultReason::BadRecords(other),
    }))
}

/// The request did not fit the instance's max_out (a request core cannot send; retrying does not help).
fn over_max_out() -> PortError {
    PortError::Failed {
        code: failed::F_LIMIT,
        text: Box::from("the request exceeds the instance's max_out"),
        retry_after_s: None,
        backend_status: None,
        error: None,
    }
}

/// A method or step this instance does not offer, refused by core without a call.
fn unsupported(what: &'static str) -> PortError {
    PortError::Refused {
        code: refused::R_UNSUPPORTED,
        text: Box::from(what),
        error: None,
    }
}

fn bad_credential() -> Verdict {
    Verdict::Rejected {
        code: abi::BAD_CREDENTIAL,
        text: Box::from("the credential names a key this instance does not hold"),
    }
}

/// A REFUSED verify answer (§8.3): NOT_MINE is `Ok(Some(NotMine))`; KEYS_STALE is `Ok(None)` (refresh once, then
/// verify again); R_UNSUPPORTED is `Err(PortError::Refused)`, never a verdict (C-CRYPTO-SELFTEST (f): a host
/// crypto algorithm the module does not offer is not a credential judgement, so nothing caches it as one; the
/// adapter adds the resolved ERROR); every other code is `Rejected` (`rejected`).
pub fn verify_refusal(code: u32, text: &str, scrub: &Scrub) -> Result<Option<Verdict>, PortError> {
    match code {
        abi::NOT_MINE => Ok(Some(Verdict::NotMine)),
        abi::KEYS_STALE => Ok(None),
        refused::R_UNSUPPORTED => Err(plugin_error(
            Status::REFUSED,
            code,
            text,
            None,
            None,
            None,
            scrub,
        )),
        _ => Ok(Some(rejected(code, text, scrub))),
    }
}

/// `Verdict::Rejected` with the plugin's text scrubbed, then cut (§12.16, `scrub::fail_text`): one lock-free
/// snapshot read and one scan, the B-SYNC REFUSED arm's whole text path.
pub fn rejected(code: u32, text: &str, scrub: &Scrub) -> Verdict {
    Verdict::Rejected {
        code,
        text: Box::from(&*fail_text(scrub, text)),
    }
}

/// The one REFUSED/FAILED mapping (IF §11.3 round 21/34): the text is always `scrub::fail_text`'s; FAILED carries
/// the backend's Retry-After and status facts; any other status is a FAULT.
pub fn plugin_error(
    status: Status,
    code: u32,
    text: &str,
    retry_after_s: Option<u64>,
    backend_status: Option<u64>,
    error: Option<PluginCode>,
    scrub: &Scrub,
) -> PortError {
    let shown = || -> Box<str> { Box::from(&*fail_text(scrub, text)) };
    if status == Status::REFUSED {
        return PortError::Refused {
            code,
            text: shown(),
            error,
        };
    }
    if status == Status::FAILED {
        return PortError::Failed {
            code,
            text: shown(),
            retry_after_s,
            backend_status,
            error,
        };
    }
    PortError::Call(CallError::Fault(FaultReason::BadStatus(status.0)))
}

/// One single-flight refresh round: every KEYS_STALE verify of the round awaits the same `refresh`.
pub type KeyRound = Arc<OnceCell<Result<(), PortError>>>;

/// KEYS_STALE handling (IF §12.11 core policy, owned by this adapter): per instance at most one `refresh` in
/// flight (later KEYS_STALE verifies join it) and at most one started per `min_interval` (at least 5 s). A
/// round whose leader is dropped is finished by the next joiner (`OnceCell::get_or_init`).
pub struct KeyRefresh {
    min_interval: Duration,
    state: Mutex<KeyState>,
}

#[derive(Default)]
struct KeyState {
    last_started: Option<Instant>,
    round: Option<KeyRound>,
}

impl KeyRefresh {
    const FLOOR: Duration = Duration::from_secs(5);

    pub fn new(min_interval: Duration) -> Self {
        KeyRefresh {
            min_interval: min_interval.max(Self::FLOOR),
            state: Mutex::new(KeyState::default()),
        }
    }

    /// Some(round) = join the refresh in flight or start one; None = declined by the rate limit.
    pub fn begin(&self) -> Option<KeyRound> {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(round) = s.round.as_ref().filter(|r| !r.initialized()) {
            return Some(Arc::clone(round));
        }
        let now = Instant::now();
        if s.last_started
            .is_some_and(|at| now.saturating_duration_since(at) < self.min_interval)
        {
            return None;
        }
        s.last_started = Some(now);
        let round = KeyRound::default();
        s.round = Some(Arc::clone(&round));
        Some(round)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Marker;
    impl Encode for Marker {
        fn encode<W: Writer>(&self, w: &mut W) -> Result<(), Full> {
            w.put_text(tag::TEXT, "marker")
        }
    }

    /// `chain_req` writes the encoder into a pooled buffer (it was a `todo!()` panic on the first auth call).
    #[test]
    fn chain_req_writes_the_encoded_records() {
        let req = chain_req(4096, &Marker).expect("fits max_out");
        assert!(req.bytes().windows(6).any(|w| w == b"marker"));
        assert!(chain_req(4096, &Nothing).expect("empty").bytes().is_empty());
    }

    fn recs(w: &Reply) -> Records<'_> {
        Records::new(w.as_bytes())
    }

    fn put_fact(w: &mut Reply, key: u32, value: u64) {
        w.put_fact(key, value).unwrap();
    }

    fn auth_in<'a>(headers: &'a [Pair<'a>]) -> AuthIn<'a> {
        AuthIn {
            method: "POST",
            path: "/v1/x",
            query: "a=1",
            authority: "gw.example",
            headers,
            peer: "10.0.0.1:443",
            tls_peer_cert: b"cert",
            body: b"{}",
            now_s: 1_700_000_000,
        }
    }

    // C-SCRUB-CUT, auth adapter: a REFUSED/FAILED text is scrubbed, then cut to 512 bytes, before it is a
    // PortError text; a short clean text passes unchanged.
    #[test]
    fn port_error_text_is_scrubbed_then_cut() {
        let scrub = Scrub::new();
        scrub.register(1, &[b"sk-live-0123456789"]);
        let e = plugin_error(
            Status::REFUSED,
            7,
            "bad key sk-live-0123456789 here",
            None,
            None,
            None,
            &scrub,
        );
        let PortError::Refused { code, text, error } = e else {
            panic!("not Refused")
        };
        assert_eq!((code, error), (7, None));
        assert!(!text.contains("sk-live-0123456789"), "{text}");
        assert!(text.contains("***"), "{text}");
        let long = "x".repeat(600);
        let e = plugin_error(Status::FAILED, 1, &long, None, None, None, &scrub);
        let PortError::Failed { text, .. } = e else {
            panic!("not Failed")
        };
        assert_eq!(text.len(), 512);
        let sixty = "y".repeat(60);
        let e = plugin_error(Status::REFUSED, 1, &sixty, None, None, None, &scrub);
        assert!(matches!(e, PortError::Refused { ref text, .. } if **text == *sixty));
    }

    // C-FAIL-FACTS, auth adapter: FAILED carries the backend's Retry-After and status facts and the resolved
    // ERROR; REFUSED carries no fact; any other status is a FAULT.
    #[test]
    fn failed_carries_the_facts_refused_does_not() {
        let scrub = Scrub::new();
        let code = PluginCode {
            plugin: "auth-oidc",
            number: 12,
        };
        let e = plugin_error(
            Status::FAILED,
            failed::F_UNAVAILABLE,
            "down",
            Some(30),
            Some(503),
            Some(code),
            &scrub,
        );
        assert_eq!(
            e,
            PortError::Failed {
                code: failed::F_UNAVAILABLE,
                text: Box::from("down"),
                retry_after_s: Some(30),
                backend_status: Some(503),
                error: Some(code),
            }
        );
        let e = plugin_error(
            Status::REFUSED,
            abi::SECURITY_CHECK,
            "nonce",
            Some(30),
            None,
            None,
            &scrub,
        );
        assert_eq!(
            e,
            PortError::Refused {
                code: abi::SECURITY_CHECK,
                text: Box::from("nonce"),
                error: None
            }
        );
        let e = plugin_error(Status::OK, 0, "", None, None, None, &scrub);
        assert_eq!(
            e,
            PortError::Call(CallError::Fault(FaultReason::BadStatus(0)))
        );
    }

    #[test]
    fn refused_verify_codes_map_to_verdicts() {
        let scrub = Scrub::new();
        assert!(matches!(
            verify_refusal(abi::NOT_MINE, "", &scrub),
            Ok(Some(Verdict::NotMine))
        ));
        assert!(matches!(
            verify_refusal(abi::KEYS_STALE, "kid", &scrub),
            Ok(None)
        ));
        let text = "z".repeat(60);
        match verify_refusal(abi::BAD_CREDENTIAL, &text, &scrub) {
            Ok(Some(Verdict::Rejected { code, text: got })) => {
                assert_eq!(code, abi::BAD_CREDENTIAL);
                assert_eq!(*got, *text);
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            verify_refusal(abi::SECURITY_CHECK, "", &scrub),
            Ok(Some(Verdict::Rejected {
                code: abi::SECURITY_CHECK,
                ..
            }))
        ));
        // R_UNSUPPORTED is a port refusal, never a verdict (C-CRYPTO-SELFTEST (f)).
        assert_eq!(
            verify_refusal(refused::R_UNSUPPORTED, "no HMAC_SHA384", &scrub).unwrap_err(),
            PortError::Refused {
                code: refused::R_UNSUPPORTED,
                text: Box::from("no HMAC_SHA384"),
                error: None,
            }
        );
    }

    #[test]
    fn a_malformed_answer_is_a_fault() {
        assert_eq!(
            fault(RecErr::Unknown(t::GRANT)),
            PortError::Call(CallError::Fault(FaultReason::UnknownTag(t::GRANT)))
        );
        assert_eq!(
            fault(RecErr::Utf8),
            PortError::Call(CallError::Fault(FaultReason::BadRecords(RecErr::Utf8)))
        );
    }

    #[test]
    fn cred_headers_are_lowercase_tokens_deduplicated() {
        let mut w = Reply::new();
        w.put_text(t::D_CRED_HEADER, "authorization").unwrap();
        w.put_text(t::D_OUTBOUND_STYLE, "bearer").unwrap();
        w.put_text(t::D_CRED_HEADER, "x-api-key").unwrap();
        w.put_text(t::D_CRED_HEADER, "authorization").unwrap();
        let got = decode_cred_headers(recs(&w)).unwrap();
        assert_eq!(
            &*got,
            &[Box::<str>::from("authorization"), Box::from("x-api-key")]
        );
        for bad in ["Authorization", "", "x api"] {
            let mut w = Reply::new();
            w.put_text(t::D_CRED_HEADER, bad).unwrap();
            assert_eq!(
                decode_cred_headers(recs(&w)).unwrap_err(),
                RecErr::Size,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn outbound_answer_decodes_headers_query_grant_and_lifetime() {
        let mut w = Reply::new();
        w.put_pair(t::SET_HEADER, "authorization", b"Bearer t")
            .unwrap();
        w.put_pair(t::SET_QUERY, "key", b"v").unwrap();
        w.put(t::GRANT_UPDATE, b"grant").unwrap();
        put_fact(&mut w, abi::F_CACHE_S, 3600);
        w.put_metric(1, 1, 1.0, &[]).unwrap();
        let out = decode_outbound(recs(&w)).unwrap();
        assert_eq!(out.headers.len(), 1);
        assert_eq!(&*out.headers[0].0, "authorization");
        assert_eq!(out.headers[0].1.as_slice(), b"Bearer t");
        assert_eq!(
            (&*out.query[0].0, out.query[0].1.as_slice()),
            ("key", &b"v"[..])
        );
        assert_eq!(out.grant_update.as_deref(), Some(&b"grant"[..]));
        assert_eq!(out.cache_s, 3600);

        // No F_CACHE_S = 0 (already expired); a lifetime past u32 is clamped.
        let mut w = Reply::new();
        w.put_pair(t::SET_HEADER, "x-goog-api-key", b"k").unwrap();
        assert_eq!(decode_outbound(recs(&w)).unwrap().cache_s, 0);
        let mut w = Reply::new();
        put_fact(&mut w, abi::F_CACHE_S, u64::MAX);
        assert_eq!(decode_outbound(recs(&w)).unwrap().cache_s, u32::MAX);

        // Another fact key, a second F_CACHE_S, a second GRANT_UPDATE or a login tag is a fault.
        let mut w = Reply::new();
        put_fact(&mut w, abi::F_EXPIRES_AT_S, 1);
        assert_eq!(decode_outbound(recs(&w)).err(), Some(RecErr::Size));
        let mut w = Reply::new();
        put_fact(&mut w, abi::F_CACHE_S, 1);
        put_fact(&mut w, abi::F_CACHE_S, 2);
        assert_eq!(
            decode_outbound(recs(&w)).err(),
            Some(RecErr::Unknown(tag::FACT))
        );
        let mut w = Reply::new();
        w.put(t::GRANT_UPDATE, b"a").unwrap();
        w.put(t::GRANT_UPDATE, b"b").unwrap();
        assert_eq!(
            decode_outbound(recs(&w)).err(),
            Some(RecErr::Unknown(t::GRANT_UPDATE))
        );
        let mut w = Reply::new();
        w.put_text(t::REDIRECT, "https://idp").unwrap();
        assert_eq!(
            decode_outbound(recs(&w)).err(),
            Some(RecErr::Unknown(t::REDIRECT))
        );
    }

    #[test]
    fn login_answers_follow_the_step() {
        let mut w = Reply::new();
        w.put_text(t::REDIRECT, "https://idp/authorize?state=k")
            .unwrap();
        w.put(t::STATE, b"st").unwrap();
        match decode_login(abi::LOGIN_BEGIN, false, recs(&w)).unwrap() {
            LoginAnswer::Redirect { url, state } => {
                assert_eq!(&*url, "https://idp/authorize?state=k");
                assert_eq!(state.as_slice(), b"st");
            }
            _ => panic!("not a redirect"),
        }
        // BEGIN without STATE, or STATE first, is malformed.
        let mut w = Reply::new();
        w.put_text(t::REDIRECT, "https://idp").unwrap();
        assert_eq!(
            decode_login(abi::LOGIN_BEGIN, false, recs(&w)).err(),
            Some(RecErr::Truncated)
        );
        let mut w = Reply::new();
        w.put(t::STATE, b"st").unwrap();
        assert_eq!(
            decode_login(abi::LOGIN_BEGIN, false, recs(&w)).err(),
            Some(RecErr::Unknown(t::STATE))
        );

        // COMPLETE of a caller connection answers GRANT; of a user login, an identity.
        let mut w = Reply::new();
        w.put(t::GRANT, b"opaque").unwrap();
        assert!(matches!(
            decode_login(abi::LOGIN_COMPLETE, true, recs(&w)),
            Ok(LoginAnswer::Grant(g)) if g.as_slice() == b"opaque"
        ));
        assert!(decode_login(abi::LOGIN_COMPLETE, false, recs(&w)).is_err());
        let mut w = Reply::new();
        w.put_text(tag::ID_SUBJECT, "ada").unwrap();
        w.put_text(tag::ID_GROUP, "eng").unwrap();
        match decode_login(abi::LOGIN_CREDENTIAL, false, recs(&w)).unwrap() {
            LoginAnswer::Identity(id) => {
                assert_eq!(id.subject(), "ada");
                assert_eq!(id.groups().collect::<Vec<_>>(), ["eng"]);
            }
            _ => panic!("not an identity"),
        }
        // A login identity carries no STRIP.
        w.put_text(t::STRIP, "authorization").unwrap();
        assert!(decode_login(abi::LOGIN_CREDENTIAL, false, recs(&w)).is_err());
    }

    #[test]
    fn refresh_answer_is_the_next_refresh_fact() {
        let w = Reply::new();
        assert_eq!(decode_refresh(recs(&w)).unwrap(), None);
        let mut w = Reply::new();
        put_fact(&mut w, abi::F_NEXT_REFRESH_S, 900);
        assert_eq!(decode_refresh(recs(&w)).unwrap(), Some(900));
        let mut w = Reply::new();
        put_fact(&mut w, abi::F_CACHE_S, 900);
        assert_eq!(decode_refresh(recs(&w)).unwrap_err(), RecErr::Size);
    }

    // The second verify_io request is the first one with Q_ISSUED right before FACT(F_NOW_S), exactly where
    // `encode_verify_io(.., Some(issued))` writes it; without a lookup it is byte-identical.
    #[test]
    fn the_snapshot_requeues_with_q_issued_before_the_clock() {
        let req = auth_in(&[]);
        let snap = snapshot(&req).unwrap();
        let mut again = Reply::new();
        Again {
            snap: &snap,
            issued: None,
        }
        .encode(&mut again)
        .unwrap();
        assert_eq!(again.as_bytes(), snap.as_bytes());

        let mut again = Reply::new();
        Again {
            snap: &snap,
            issued: Some(b"AKIDSECRET"),
        }
        .encode(&mut again)
        .unwrap();
        let mut direct = Reply::new();
        enc::encode_verify_io(&mut direct, &req, Some(b"AKIDSECRET")).unwrap();
        assert_eq!(again.as_bytes(), direct.as_bytes());
    }

    // The sync re-verify view is rebuilt from the snapshot with the looked-up credential and the flag.
    #[test]
    fn the_snapshot_rebuilds_the_sync_view() {
        let req = auth_in(&[]);
        let snap = snapshot(&req).unwrap();
        let got = snapshot_view(&snap, b"issued-key", abi::REQ_ISSUED_LOOKED_UP, |v| {
            (
                v.flags,
                v.method.len(),
                v.path.len(),
                v.query.len(),
                v.authority.len(),
                v.headers.get().len(),
                v.peer.len(),
                v.tls_peer_cert.len(),
                v.body.len(),
                v.issued.len(),
                v.now_s,
            )
        })
        .unwrap();
        assert_eq!(
            got,
            (
                abi::REQ_ISSUED_LOOKED_UP,
                4,
                5,
                3,
                10,
                0,
                12,
                4,
                2,
                10,
                1_700_000_000
            )
        );
    }

    // C-KEYS-STALE, adapter side: one refresh for a burst of KEYS_STALE verifies (100 concurrent share it),
    // and a second refresh inside the interval is declined.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn keys_stale_refreshes_once_and_declines_inside_the_interval() {
        let keys = Arc::new(KeyRefresh::new(Duration::from_secs(30)));
        let runs = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let mut joined = tokio::task::JoinSet::new();
        let rounds = Arc::new(AtomicUsize::new(0));
        for _ in 0..100 {
            let round = keys.begin().expect("joins the round in flight");
            rounds.fetch_add(1, Ordering::SeqCst);
            let (runs, gate) = (Arc::clone(&runs), Arc::clone(&gate));
            joined.spawn(async move {
                round
                    .get_or_init(|| async move {
                        runs.fetch_add(1, Ordering::SeqCst);
                        let _permit = gate.acquire().await.expect("gate open");
                        Ok(())
                    })
                    .await
                    .clone()
            });
        }
        assert_eq!(rounds.load(Ordering::SeqCst), 100);
        gate.add_permits(1);
        while let Some(done) = joined.join_next().await {
            assert_eq!(done.expect("task"), Ok(()));
        }
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "one refresh for the whole burst"
        );
        assert!(
            keys.begin().is_none(),
            "a second refresh inside the interval is declined"
        );
    }

    #[test]
    fn the_refresh_interval_has_a_five_second_floor() {
        assert_eq!(
            KeyRefresh::new(Duration::from_secs(1)).min_interval,
            Duration::from_secs(5)
        );
        assert_eq!(
            KeyRefresh::new(Duration::from_secs(30)).min_interval,
            Duration::from_secs(30)
        );
    }
}
