// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The secret and export kinds' answer checks, through the dispatcher's `Kind` adapters: each op
//! reaches its `check_<op>`, a violation is FAULT naming its rule and field, a zeroed PENDING or
//! REFUSED `out` passes, a foreign-sized struct is FAULT, and the one
//! short-buffer op reads as short.

use std::mem::size_of;

use busbar_contract::abi::export::{self, CheckOut, ScrapeIn, ScrapeOut, ServeOut, StatusOut};
use busbar_contract::abi::mechanism::call::{
    Blob, InHead, OutHead, Outcome, RawOutcome, BLOB_ABSENT, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::check::{fault, Rule};
use busbar_contract::abi::secret::{self, ResolveIn, ResolveOut, ERROR_KIND_NOT_FOUND};

use crate::dispatch::kinds::export::Export;
use crate::dispatch::kinds::secret::Secret;
use crate::dispatch::{in_head, out_head, Answer, Kind, NO_BLOB};

fn answer<I, O>(slot: u32, outcome: Outcome, input: &I, out: &O) -> Answer<'static> {
    // SAFETY: both are live locals for the answer's use.
    unsafe {
        Answer::new(
            slot,
            outcome,
            std::ptr::from_ref(input).cast(),
            size_of::<I>(),
            std::ptr::from_ref(out).cast(),
            size_of::<O>(),
        )
    }
}

fn head(o: Outcome) -> OutHead {
    OutHead {
        outcome: RawOutcome::of(o),
        ..out_head()
    }
}

fn resolve(outcome: Outcome, secret: Blob, error_kind: u32) -> ResolveOut {
    ResolveOut {
        head: head(outcome),
        secret,
        error_kind,
        _reserved: 0,
    }
}

#[test]
fn secret_resolve_is_checked() {
    let input = ResolveIn {
        head: in_head(),
        settings: NO_BLOB,
    };
    let key = b"k";
    let material = Blob {
        ptr: key.as_ptr(),
        len: 1,
        fmt: BLOB_ABSENT,
        flags: BLOB_SECRET,
    };
    let s = secret::slot::RESOLVE;
    let mut ok = resolve(Outcome::Ready, material, 0);
    ok.head.lease = 7;
    assert_eq!(
        Secret::check(&answer(s, Outcome::Ready, &input, &ok)),
        Ok(())
    );
    let failed = resolve(Outcome::Failed, NO_BLOB, ERROR_KIND_NOT_FOUND);
    assert_eq!(
        Secret::check(&answer(s, Outcome::Failed, &input, &failed)),
        Ok(())
    );
    // RED: a FAILED answer carrying secret material.
    let leak = resolve(Outcome::Failed, material, ERROR_KIND_NOT_FOUND);
    assert_eq!(
        Secret::check(&answer(s, Outcome::Failed, &input, &leak)),
        Err(fault(Rule::Contradiction, "resolve.secret_on_failed"))
    );
    // RED: an `out` smaller than the op's struct.
    let small = head(Outcome::Ready);
    let f = Secret::check(&answer(s, Outcome::Ready, &input, &small)).unwrap_err();
    assert_eq!(f.rule, Rule::Foreign);
    assert_eq!(Secret::op_name(s), "resolve");
}

fn scrape_in(cap: usize) -> ScrapeIn {
    ScrapeIn {
        head: in_head(),
        families: std::ptr::null(),
        families_len: 0,
        buf: std::ptr::null_mut(),
        cap,
    }
}

fn scrape_out(outcome: Outcome, written: usize, needed: usize) -> ScrapeOut {
    ScrapeOut {
        head: head(outcome),
        written,
        needed,
    }
}

#[test]
fn export_scrape_is_checked_against_the_hosts_cap() {
    let s = export::slot::SCRAPE;
    let input = scrape_in(64);
    let ok = scrape_out(Outcome::Ready, 64, 0);
    assert_eq!(
        Export::check(&answer(s, Outcome::Ready, &input, &ok)),
        Ok(())
    );
    // RED: more written than the host gave.
    let over = scrape_out(Outcome::Ready, 65, 0);
    assert_eq!(
        Export::check(&answer(s, Outcome::Ready, &input, &over)),
        Err(fault(Rule::OverCap, "scrape.bytes"))
    );
    // RED: FAILED with needed <= cap wastes the one re-call.
    let wasted = scrape_out(Outcome::Failed, 0, 64);
    assert_eq!(
        Export::check(&answer(s, Outcome::Failed, &input, &wasted)),
        Err(fault(Rule::WastedRecall, "scrape.bytes"))
    );
    // SHORT: FAILED with needed above the cap, nothing written.
    let short = scrape_out(Outcome::Failed, 0, 65);
    let a = answer(s, Outcome::Failed, &input, &short);
    assert_eq!(Export::check(&a), Ok(()));
    assert!(Export::short(&a));
    assert!(!Export::short(&answer(s, Outcome::Ready, &input, &ok)));
    // RED: an `in` smaller than ScrapeIn: the cap cannot be read, so FAULT.
    let small_in = in_head();
    let f = Export::check(&answer(s, Outcome::Ready, &small_in, &ok)).unwrap_err();
    assert_eq!(f.rule, Rule::Foreign);
}

#[test]
fn export_every_slot_is_named_and_reaches_its_check() {
    for s in [
        export::slot::DELIVER,
        export::slot::SCRAPE,
        export::slot::STATUS,
        export::slot::CHECK,
        export::slot::SERVE,
    ] {
        assert_ne!(Export::op_name(s), "op");
    }
    // RED through `deliver`: FAILED error text with a length behind NULL.
    let input: InHead = in_head();
    let mut bad = head(Outcome::Failed);
    bad.error.len = 3;
    assert_eq!(
        Export::check(&answer(
            export::slot::DELIVER,
            Outcome::Failed,
            &input,
            &bad
        )),
        Err(fault(Rule::NullWithCount, "deliver.error"))
    );
}

#[test]
fn zeroed_pending_and_refused_pass_every_op() {
    let resolve_in = ResolveIn {
        head: in_head(),
        settings: NO_BLOB,
    };
    let h: InHead = in_head();
    for o in [Outcome::Pending, Outcome::Refused] {
        let out = resolve(o, NO_BLOB, 0);
        let a = answer(secret::slot::RESOLVE, o, &resolve_in, &out);
        assert_eq!(Secret::check(&a), Ok(()), "resolve {o:?}");

        let deliver = head(o);
        let a = answer(export::slot::DELIVER, o, &h, &deliver);
        assert_eq!(Export::check(&a), Ok(()), "deliver {o:?}");
        let scrape = scrape_out(o, 0, 0);
        let a = answer(export::slot::SCRAPE, o, &scrape_in(64), &scrape);
        assert_eq!(Export::check(&a), Ok(()), "scrape {o:?}");
        let status = StatusOut {
            head: head(o),
            status: NO_BLOB,
        };
        let a = answer(export::slot::STATUS, o, &h, &status);
        assert_eq!(Export::check(&a), Ok(()), "status {o:?}");
        let check = CheckOut {
            head: head(o),
            findings: NO_BLOB,
        };
        let a = answer(export::slot::CHECK, o, &h, &check);
        assert_eq!(Export::check(&a), Ok(()), "check {o:?}");
        let serve = ServeOut {
            head: head(o),
            status_code: 0,
            _reserved: [0; 6],
            headers_out: std::ptr::null(),
            headers_out_len: 0,
            body: NO_BLOB,
        };
        let a = answer(export::slot::SERVE, o, &h, &serve);
        assert_eq!(Export::check(&a), Ok(()), "serve {o:?}");
    }
}
