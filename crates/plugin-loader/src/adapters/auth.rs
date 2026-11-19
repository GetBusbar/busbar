// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth adapter: `AuthPort` over the auth kind's `Proxy` (IF §11.3, §8.3).
//!
//! Each verify invocation makes exactly one plugin call and returns inline. The kernel owns lookup,
//! refresh and replay.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::auth::{self as abi, tag as t, AuthReq};
use busbar_plugin_abi::fail::{fact, failed, refused, CallError, FaultReason};
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::host_side::driver::{Driver, Instance};
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::host_side::pool::{sync_out, Pool, PooledOut};
use busbar_plugin_abi::host_side::scrub::{fail_text, Scrub};
#[cfg(test)]
use busbar_plugin_abi::records::Reply;
use busbar_plugin_abi::records::{tag, FactRec, Full, RecErr, Records, Writer};
#[cfg(test)]
use busbar_plugin_abi::types::Pair;
use busbar_plugin_abi::types::{Bytes, Slice, Status, Str};

use crate::call::kinds::auth::Proxy;
use crate::call::Mono;
use crate::instance::ErrorBook;
use busbar_ports::auth::{
    decode_login_identity, decode_verify_ok, AuthIn, AuthPort, LoginAnswer, LoginIn,
    OutboundAnswer, ServeIn, ServeOut, UpstreamIn, Verify, VerifyAnswer, VerifyOk,
};
use busbar_ports::codec::auth as enc;
use busbar_ports::PluginCode;
use busbar_ports::{CallCx, PortError};

/// The auth port over one instance's proxy.
pub struct AuthAdapter<N: Needs> {
    proxy: Proxy,
    needs: Arc<N>,
    /// D_CRED_HEADER*, lowercase.
    cred_headers: Box<[Box<str>]>,
    /// D_ISSUED_KIND, if declared.
    issued_kind: Option<Box<str>>,
    /// D_BODY_MAX, if declared: the most body bytes the image's credential covers.
    body_max: Option<u64>,
    errors: &'static ErrorBook,
    /// The undeclared-ERROR WARN latch (`ErrorBook::resolve`).
    undeclared: AtomicBool,
}

impl<N: Needs> AuthAdapter<N> {
    /// `describe` = the image's describe records (D_CRED_HEADER*, D_ISSUED_KIND?, D_ISSUED_SHAPE?,
    /// D_BODY_MAX?);
    pub fn new(
        proxy: Proxy,
        needs: Arc<N>,
        describe: Records<'_>,
        errors: &'static ErrorBook,
    ) -> Result<Self, RecErr> {
        let cred_headers = decode_cred_headers(describe)?;
        let issued_kind = enc::decode_issued_shape(describe)?.map(|(kind, _)| kind);
        let body_max = decode_body_max(describe, proxy.instance().facts)?;
        Ok(AuthAdapter {
            proxy,
            needs,
            cred_headers,
            issued_kind,
            body_max,
            errors,
            undeclared: AtomicBool::new(false),
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

    /// One verify answer, as what it asks of the adapter next.
    fn said(&self, a: Result<Answer<'_>, CallError>) -> Result<VerifyAnswer, PortError> {
        let a = a.map_err(PortError::Call)?;
        if a.status == Status::OK {
            return match decode_verify_ok(a.records()).map_err(fault)? {
                VerifyOk::Identity(id) => Ok(VerifyAnswer::Identity(id)),
                VerifyOk::IssuedWanted(id) => Ok(VerifyAnswer::IssuedWanted(id)),
            };
        }
        if a.status == Status::REFUSED {
            let (code, text) = a.fail().unwrap_or((0, ""));
            return match verify_refusal(code, text, &self.inst().scrub) {
                Ok(v) => Ok(v),
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
    fn verify_sync(&self, at: Mono, req: &AuthReq<'_>) -> Result<VerifyAnswer, PortError> {
        sync_out(self.inst().max_out, |out| {
            self.said(self.proxy.verify(out, at, req))
        })
    }
}

impl<N: Needs> AuthPort for AuthAdapter<N> {
    fn facts(&self) -> u64 {
        self.inst().facts
    }

    fn cred_headers(&self) -> &[Box<str>] {
        &self.cred_headers
    }

    fn body_max(&self) -> Option<u64> {
        self.body_max
    }

    fn issued_kind(&self) -> Option<&str> {
        self.issued_kind.as_deref()
    }

    fn verify<'a>(&'a self, cx: CallCx, req: &AuthIn<'_>, issued: Option<&[u8]>) -> Verify<'a> {
        let methods = self.inst().methods;
        if methods & abi::M_VERIFY != 0 {
            let flags = if issued.is_some() {
                abi::REQ_ISSUED_LOOKED_UP
            } else {
                0
            };
            return Verify::Done(self.verify_sync(
                crate::call::at(&cx),
                &view(req, issued.unwrap_or_default(), flags),
            ));
        }
        // Auth 4.0 has one verify: a plugin that does not declare it verifies nothing.
        Verify::Done(Err(PortError::Call(CallError::NotDeclared)))
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
                .login(&mut drv, crate::call::at(&cx), req, code)
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
                .outbound(&mut drv, crate::call::at(&cx), req)
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
                .refresh(&mut drv, crate::call::at(&cx), req)
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
                .serve(&mut drv, crate::call::at(&cx), req)
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

/// One request encoding (§8.8), written into the chain's request buffer.
trait Encode {
    fn encode<W: Writer>(&self, w: &mut W) -> Result<(), Full>;
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
pub fn decode_cred_headers(describe: Records<'_>) -> Result<Box<[Box<str>]>, RecErr> {
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

/// D_BODY_MAX (auth 4.0): the most body bytes the image's credential covers. At most one, a Pod
/// `U64Rec`, and only from an image whose facts hold FB_NEEDS_BODY: a bound stated by an image that
/// is never handed the body, or stated twice, is a describe the loader refuses (the instance does
/// not open). `None` = the image states no bound.
pub fn decode_body_max(describe: Records<'_>, facts: u64) -> Result<Option<u64>, RecErr> {
    let mut stated: Option<u64> = None;
    for rec in describe {
        let rec = rec?;
        if rec.tag != t::D_BODY_MAX {
            continue;
        }
        let bound: busbar_plugin_abi::records::U64Rec = rec.pod()?;
        if stated.is_some() || facts & abi::FB_NEEDS_BODY == 0 {
            return Err(RecErr::Size);
        }
        stated = Some(bound.value);
    }
    Ok(stated)
}

/// A login OK answer for `step` (§8.3): BEGIN = REDIRECT then STATE; COMPLETE = GRANT for a caller connection
/// (L_CONNECT), else ID_*; CREDENTIAL = ID_*.
pub fn decode_login(step: u32, connect: bool, records: Records<'_>) -> Result<LoginAnswer, RecErr> {
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
pub fn decode_outbound(records: Records<'_>) -> Result<OutboundAnswer, RecErr> {
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
pub fn decode_refresh(records: Records<'_>) -> Result<Option<u32>, RecErr> {
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

/// Decodes the raw refusal. KEYS_STALE remains a host-policy input; unsupported is a port error.
pub fn verify_refusal(code: u32, text: &str, scrub: &Scrub) -> Result<VerifyAnswer, PortError> {
    match code {
        abi::NOT_MINE => Ok(VerifyAnswer::NotMine),
        abi::KEYS_STALE => Ok(VerifyAnswer::KeysStale),
        refused::R_UNSUPPORTED => Err(plugin_error(
            Status::REFUSED,
            code,
            text,
            None,
            None,
            None,
            scrub,
        )),
        _ => Ok(rejected(code, text, scrub)),
    }
}

/// `VerifyAnswer::Refused` with the plugin's text scrubbed, then cut (§12.16, `scrub::fail_text`): one lock-free
/// snapshot read and one scan, the B-SYNC REFUSED arm's whole text path.
pub fn rejected(code: u32, text: &str, scrub: &Scrub) -> VerifyAnswer {
    VerifyAnswer::Refused {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_stale_is_a_raw_answer_without_a_refresh() {
        assert!(matches!(
            verify_refusal(abi::KEYS_STALE, "kid k9", &Scrub::new()),
            Ok(busbar_ports::auth::VerifyAnswer::KeysStale)
        ));
    }

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

    fn body_max_rec(w: &mut Reply, value: u64) {
        w.put_pod(t::D_BODY_MAX, &busbar_plugin_abi::records::U64Rec { value })
            .unwrap();
    }

    // Signed ingress: the bound a signed route reads its body under is the image's own
    // statement, read once at describe.
    #[test]
    fn the_stated_body_bound_is_read_from_the_describe() {
        let mut w = Reply::new();
        w.put_text(t::D_CRED_HEADER, "webhook-signature").unwrap();
        body_max_rec(&mut w, 1_048_576);
        assert_eq!(
            decode_body_max(recs(&w), abi::FB_NEEDS_BODY),
            Ok(Some(1_048_576))
        );
    }

    // An image that states none verifies no signed route: nothing is assumed for it.
    #[test]
    fn an_image_that_states_no_body_bound_has_none() {
        let mut w = Reply::new();
        w.put_text(t::D_CRED_HEADER, "authorization").unwrap();
        assert_eq!(decode_body_max(recs(&w), abi::FB_NEEDS_BODY), Ok(None));
        assert_eq!(decode_body_max(recs(&w), 0), Ok(None));
    }

    // A bound from an image that is never handed the body would be a bound on nothing.
    #[test]
    fn a_body_bound_without_the_body_fact_is_refused() {
        let mut w = Reply::new();
        body_max_rec(&mut w, 4096);
        assert!(decode_body_max(recs(&w), 0).is_err());
        assert!(decode_body_max(recs(&w), abi::FB_NEEDS_BODY_HASH).is_err());
    }

    #[test]
    fn a_body_bound_stated_twice_or_malformed_is_refused() {
        let mut twice = Reply::new();
        body_max_rec(&mut twice, 4096);
        body_max_rec(&mut twice, 8192);
        assert!(decode_body_max(recs(&twice), abi::FB_NEEDS_BODY).is_err());
        let mut text = Reply::new();
        text.put_text(t::D_BODY_MAX, "4096").unwrap();
        assert!(decode_body_max(recs(&text), abi::FB_NEEDS_BODY).is_err());
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
            Ok(VerifyAnswer::NotMine)
        ));
        assert!(matches!(
            verify_refusal(abi::KEYS_STALE, "kid", &scrub),
            Ok(VerifyAnswer::KeysStale)
        ));
        let text = "z".repeat(60);
        match verify_refusal(abi::BAD_CREDENTIAL, &text, &scrub) {
            Ok(VerifyAnswer::Refused { code, text: got }) => {
                assert_eq!(code, abi::BAD_CREDENTIAL);
                assert_eq!(*got, *text);
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            verify_refusal(abi::SECURITY_CHECK, "", &scrub),
            Ok(VerifyAnswer::Refused {
                code: abi::SECURITY_CHECK,
                ..
            })
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
}
