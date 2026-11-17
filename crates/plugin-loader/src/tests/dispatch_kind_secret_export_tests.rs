// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::mem::size_of;

use busbar_contract::abi::export::{self, CheckOut, ScrapeIn, ScrapeOut, ServeOut, StatusOut};
use busbar_contract::abi::mechanism::call::{
    Blob, InHead, OutHead, Outcome, RawOutcome, BLOB_ABSENT,
};
use busbar_contract::abi::mechanism::check::{fault, Rule};

use crate::dispatch::kinds::export::Export;
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

    let over = scrape_out(Outcome::Ready, 65, 0);
    assert_eq!(
        Export::check(&answer(s, Outcome::Ready, &input, &over)),
        Err(fault(Rule::OverCap, "scrape.bytes"))
    );

    let wasted = scrape_out(Outcome::Failed, 0, 64);
    assert_eq!(
        Export::check(&answer(s, Outcome::Failed, &input, &wasted)),
        Err(fault(Rule::WastedRecall, "scrape.bytes"))
    );

    let short = scrape_out(Outcome::Failed, 0, 65);
    let a = answer(s, Outcome::Failed, &input, &short);
    assert_eq!(Export::check(&a), Ok(()));
    assert!(Export::short(&a));
    assert!(!Export::short(&answer(s, Outcome::Ready, &input, &ok)));

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

    // A Ready answer must carry a well-formed payload on every other op too.
    let counted = Blob {
        ptr: std::ptr::null(),
        len: 3,
        fmt: BLOB_ABSENT,
        flags: 0,
    };
    let status = StatusOut {
        head: head(Outcome::Ready),
        status: counted,
    };
    let r = Export::check(&answer(
        export::slot::STATUS,
        Outcome::Ready,
        &input,
        &status,
    ));
    assert_eq!(r, Err(fault(Rule::NullWithCount, "status.status")), "{r:?}");
    let check = CheckOut {
        head: head(Outcome::Ready),
        findings: counted,
    };
    let r = Export::check(&answer(export::slot::CHECK, Outcome::Ready, &input, &check));
    assert_eq!(
        r,
        Err(fault(Rule::NullWithCount, "check.findings")),
        "{r:?}"
    );
    let serve = ServeOut {
        head: head(Outcome::Ready),
        status_code: 0,
        _reserved: [0; 6],
        headers_out: std::ptr::null(),
        headers_out_len: 2,
        body: NO_BLOB,
    };
    let r = Export::check(&answer(export::slot::SERVE, Outcome::Ready, &input, &serve));
    assert_eq!(
        r,
        Err(fault(Rule::NullWithCount, "serve.headers_out")),
        "{r:?}"
    );
}

#[test]
fn zeroed_pending_and_refused_pass_every_op() {
    let h: InHead = in_head();
    for o in [Outcome::Pending, Outcome::Refused] {
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
