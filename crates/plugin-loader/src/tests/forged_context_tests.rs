// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PROOF-079 (LEDGER S-R22): a native plane image that sends a forged context in a non-lifecycle call answers
//! FAULT and is quarantined.
//!
//! The context a call runs in is the session TOKEN, and only the host's handles carry it toward the plugin. The
//! plugin names one back only in the answer of a session opener (`request`, `probe`: its leading TOKEN, §6.4 step
//! 7). An image that leads the answer of any other call with a TOKEN names a session context the host did not
//! hand that call: a forged context. The call answers FAULT, the instance is charged on the registry's own slot
//! table (the process fault sink), and the next call never reaches the image.
//!
//! The image is a real linked plane image; the instance is built from its open answer exactly as the registry
//! builds it after INSTANCE, on a slot leased from the process slot table, so the quarantine is the production
//! one. Each arm runs an honest call first (the control: the same method, no TOKEN, OK and still live).

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use busbar_ffi::host::{OpenAnswer, OutLease};
use busbar_ffi::image::Admitted;
use busbar_plugin_abi::fail::{CallError, Fail, FaultReason};
use busbar_plugin_abi::host::Host;
use busbar_plugin_abi::host_side::caller::{CallStack, Caller, InstanceLimits};
use busbar_plugin_abi::host_side::driver::{Driver, Image, Instance, InstanceParts};
use busbar_plugin_abi::host_side::pool::Pool;
use busbar_plugin_abi::host_side::scrub::Scrub;
use busbar_plugin_abi::host_side::HOST;
use busbar_plugin_abi::need::ChainBytes;
use busbar_plugin_abi::plane::{self, PlaneReq, Target};
use busbar_plugin_abi::plugin::{Endpoints, Open};
use busbar_plugin_abi::records::{tag, Out, Records, Reply, TokenRec, Writer};
use busbar_plugin_abi::types::{Bytes, KindCode, Slice, Status, Str};
use busbar_plugin_abi::Plane;

use crate::call::kinds::plane::{OnSession, Proxy};
use crate::call::Mono;
use crate::instance::{ErrorBook, SlotRecord};

/// The instance's max_out.
const MAX_OUT: usize = 1 << 16;
/// The variant (`Target::attempt`, `render`'s `what`) that makes the image forge.
const FORGE: u32 = 1;
/// The context the image forges: a session token (bit 63) of a slot and generation the host never handed it.
const FORGED: u64 = busbar_ffi::TOKEN_SESSION | (1 << 32) | 7;

/// The plane image: `request` opens a session; `upstream`, `render` and the async `admin` answer OK, and on
/// [`FORGE`] lead that answer with the forged session TOKEN.
mod forger {
    use super::*;

    pub struct Forger;
    pub struct Sess;

    fn answer(variant: u32, out: &mut Out<'_>) -> Result<(), Fail> {
        if variant == FORGE {
            out.put_pod(tag::TOKEN, &TokenRec { token: FORGED })?;
        }
        Ok(())
    }

    impl Plane for Forger {
        type Session = Sess;
        fn request(
            &self,
            _h: &Host,
            _req: &PlaneReq<'_>,
            _body: Bytes<'_>,
            _out: &mut Out<'_>,
        ) -> Result<Sess, Fail> {
            Ok(Sess)
        }
        fn upstream(
            &self,
            _h: &Host,
            _s: &mut Sess,
            target: &Target<'_>,
            out: &mut Out<'_>,
        ) -> Result<(), Fail> {
            answer(target.attempt, out)
        }
        fn piece(
            &self,
            _h: &Host,
            _s: &mut Sess,
            _from: u32,
            _exchange: u32,
            _flags: u32,
            _bytes: Bytes<'_>,
            _out: &mut Out<'_>,
        ) -> Result<(), Fail> {
            Ok(())
        }
        fn end(&self, _h: &Host, _s: Sess, _out: &mut Out<'_>) -> Result<(), Fail> {
            Ok(())
        }
        fn render(
            &self,
            _h: &Host,
            _req: &PlaneReq<'_>,
            what: u32,
            _arg: Bytes<'_>,
            out: &mut Out<'_>,
        ) -> Result<(), Fail> {
            answer(what, out)
        }
        async fn admin(&self, _h: &'static Host, op: u32, _arg: ChainBytes) -> Result<Reply, Fail> {
            let mut reply = Reply::new();
            if op == FORGE {
                reply.put_pod(tag::TOKEN, &TokenRec { token: FORGED })?;
            }
            Ok(reply)
        }
    }

    impl Open for Forger {
        async fn open(_h: &'static Host, _config: ChainBytes) -> Result<Self, Fail> {
            Ok(Forger)
        }
        fn check(_h: &Host, _config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
            Ok(())
        }
    }

    busbar_plugin_abi::plugin!(Plane, Forger);
}

/// The forging image, admitted and opened, as the registry builds the instance from an OK + INSTANCE answer,
/// on a slot leased from the process slot table (whose fault sink quarantines it).
fn hosted() -> Arc<Instance> {
    let process = crate::test_host::shared_process().expect("the process plugin resources");
    let lease = process.slots().alloc(
        SlotRecord {
            kind: KindCode::Plane,
            name: Arc::from("forger"),
            scrub: Arc::new(Scrub::new()),
            errors: &ErrorBook::None,
            undeclared_warned: AtomicBool::new(false),
        },
        &crate::watchdog::describe_row(),
    );
    let admitted = Admitted::linked(&forger::PLUGIN).expect("the linked plane image admits");
    let mut out = OutLease::new(vec![0; 4096], MAX_OUT).expect("a free ACTIVE slot");
    let OpenAnswer::Done(Status::OK, Some(live)) =
        admitted.open::<plane::Marker>(&HOST, b"{}".to_vec(), 0, &mut out)
    else {
        panic!("open answers OK with INSTANCE");
    };
    drop(out);
    Instance::new(
        InstanceParts {
            image: Arc::new(Image::Linked),
            identity: Arc::from(env!("CARGO_PKG_NAME")),
            name: Arc::from("forger"),
            id: 1,
            slot: lease.slot(),
            cell: Arc::clone(lease.cell()),
            epoch: lease.epoch(),
            limits: InstanceLimits::default(),
            max_out: MAX_OUT,
            methods: plane::ALL,
            facts: 0,
            scrub: Arc::new(Scrub::new()),
            tether: Box::new(lease),
        },
        live,
    )
}

fn req() -> PlaneReq<'static> {
    PlaneReq {
        route: 0,
        flags: 0,
        auth: 0,
        _r: 0,
        method: Str::new("POST"),
        path: Str::new("/forge-context"),
        query: Str::EMPTY,
        headers: Slice::EMPTY,
        identity: Bytes::EMPTY,
        request_id: 7,
        carrier: 0,
        work: Str::EMPTY,
        ticket_record: Bytes::EMPTY,
    }
}

fn target(attempt: u32) -> Target<'static> {
    Target {
        attempt,
        flags: 0,
        dialect: Str::new("openai"),
        model: Str::EMPTY,
        base_path: Str::EMPTY,
        upstream: Str::new("member-0"),
        provider: Str::EMPTY,
        params: Slice::EMPTY,
        admission: Bytes::EMPTY,
    }
}

/// Whether the image really crossed the forged TOKEN as its answer's first record (so the FAULT is the forgery's,
/// not some other break).
fn leads_with_forged(bytes: &[u8]) -> bool {
    matches!(
        Records::new(bytes).next(),
        Some(Ok(rec)) if rec.tag == tag::TOKEN
            && rec.pod::<TokenRec>().is_ok_and(|tok| tok.token == FORGED)
    )
}

#[test]
fn a_forged_context_in_a_session_call_answers_fault_and_quarantines() {
    let inst = hosted();
    let proxy = Proxy::bind(Arc::clone(&inst)).expect("a plane instance");
    let mut buf = Pool::global().acquire(MAX_OUT);
    let (session, answer) = proxy
        .request(&mut buf, Mono::NONE, &req(), b"")
        .expect("the request opens its session");
    assert!(answer.is_ok());
    let mut session = session.expect("an OK opener has its session");
    drop(buf);

    // The control: the same non-lifecycle call without the forged context is OK and the instance stays live.
    let mut buf = Pool::global().acquire(MAX_OUT);
    let honest = session
        .upstream(&mut buf, Mono::NONE, &target(0))
        .expect("an honest upstream answers");
    assert!(honest.is_ok());
    drop(buf);
    assert!(inst.is_live(), "an honest call is not a fault");

    let mut buf = Pool::global().acquire(MAX_OUT);
    let forged = session.upstream(&mut buf, Mono::NONE, &target(FORGE)).err();
    assert!(
        leads_with_forged(buf.bytes()),
        "the image crossed the forged session TOKEN first"
    );
    assert_eq!(
        forged,
        Some(CallError::Fault(FaultReason::UnknownTag(tag::TOKEN))),
        "the forging upstream answered other than FAULT"
    );
    drop(buf);
    assert!(!inst.is_live(), "the forging instance was not quarantined");

    let mut buf = Pool::global().acquire(MAX_OUT);
    assert_eq!(
        session.upstream(&mut buf, Mono::NONE, &target(0)).err(),
        Some(CallError::Quarantined),
        "a quarantined instance was called again"
    );
}

#[test]
fn a_forged_context_in_a_plain_call_answers_fault_and_quarantines() {
    let inst = hosted();
    let proxy = Proxy::bind(Arc::clone(&inst)).expect("a plane instance");

    let mut buf = Pool::global().acquire(MAX_OUT);
    let honest = proxy
        .render(&mut buf, Mono::NONE, &req(), 0, b"")
        .expect("an honest render answers");
    assert!(honest.is_ok());
    drop(buf);
    assert!(inst.is_live(), "an honest call is not a fault");

    let mut buf = Pool::global().acquire(MAX_OUT);
    let forged = proxy.render(&mut buf, Mono::NONE, &req(), FORGE, b"").err();
    assert!(
        leads_with_forged(buf.bytes()),
        "the image crossed the forged session TOKEN first"
    );
    assert_eq!(
        forged,
        Some(CallError::Fault(FaultReason::UnknownTag(tag::TOKEN))),
        "the forging render answered other than FAULT"
    );
    drop(buf);
    assert!(!inst.is_live(), "the forging instance was not quarantined");

    let mut buf = Pool::global().acquire(MAX_OUT);
    assert_eq!(
        proxy.render(&mut buf, Mono::NONE, &req(), 0, b"").err(),
        Some(CallError::Quarantined),
        "a quarantined instance was called again"
    );
}
