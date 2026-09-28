// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hook kind's adapter: every kind op runs its `check_<op>` with the caps its `in` carries,
//! a legal answer passes, a broken rule is FAULT naming its rule and field, a zeroed PENDING or
//! REFUSED `out` passes, a foreign (too small) `in` is `Rule::Foreign`,
//! and a FAILED `decide`/`transform` naming a `*_needed` is short.

use std::mem::{size_of, MaybeUninit};

use busbar_contract::abi::hook::{
    slot, ConfigureIn, ConfigureOut, DecideIn, DecideOut, DescribeOut, NotifyIn, ServeIn, ServeOut,
    StatusOut, TransformOut, VERB_ABSTAIN, VERB_PREFER, VERB_REJECT, VERB_REWRITE,
};
use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::check::{Fault, Rule};

use crate::dispatch::kinds::hook::Hook;
use crate::dispatch::{in_head, out_head, Answer, InFrame, Kind, OutFrame};

static BYTE: u8 = 0;

/// An `in` of `T`, every field zero but its head.
fn input<T: InFrame>() -> T {
    // SAFETY: every hook `in` is plain integers, floats, raw pointers and unions of those, for
    // which the all-zero pattern is valid; `T` leads with an `InHead`, written below.
    let mut v: T = unsafe { MaybeUninit::zeroed().assume_init() };
    // SAFETY: `T: InFrame` leads with an `InHead`.
    unsafe { std::ptr::addr_of_mut!(v).cast::<InHead>().write(in_head()) };
    v
}

/// An `out` of `T` answering `outcome`, every field zero but its head.
fn output<T: OutFrame>(outcome: Outcome) -> T {
    // SAFETY: as `input`, with an `OutHead` first.
    let mut v: T = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut head = out_head();
    head.outcome = RawOutcome::of(outcome);
    // SAFETY: `T: OutFrame` leads with an `OutHead`.
    unsafe { std::ptr::addr_of_mut!(v).cast::<OutHead>().write(head) };
    v
}

/// The answer of `op` over `i` (as `in_size` bytes) and `o`, run through the hook's check.
fn check<I: InFrame, O: OutFrame>(op: u32, i: &I, in_size: usize, o: &O) -> Result<(), Fault> {
    Hook::check(&answer(op, i, in_size, o))
}

fn answer<I: InFrame, O: OutFrame>(op: u32, i: &I, in_size: usize, o: &O) -> Answer<'static> {
    // SAFETY: `o`'s head leads it (`O: OutFrame`).
    let outcome = unsafe { (*(o as *const O).cast::<OutHead>()).outcome }.outcome();
    assert!(in_size <= size_of::<I>());
    // SAFETY: `i`/`o` are live for the answer's use, `in_size`/`out` sizes within them, and
    // neither is written while the answer lives.
    unsafe {
        Answer::new(
            op,
            outcome,
            (i as *const I).cast(),
            in_size,
            (o as *const O).cast(),
            size_of::<O>(),
        )
    }
}

/// A broken rule is FAULT, naming exactly `rule` and `field`.
fn fails(r: Result<(), Fault>, rule: Rule, field: &'static str) {
    assert_eq!(r, Err(Fault { rule, field }));
}

fn foreign(r: Result<(), Fault>) {
    let f = r.expect_err("a foreign in is FAULT");
    assert_eq!((f.rule, f.field), (Rule::Foreign, "in"));
}

fn decide_in() -> DecideIn {
    let mut i: DecideIn = input();
    i.order_cap = 4;
    i.reject_message_cap = 8;
    i.restrict_tags_cap = 8;
    i.rewrite_cap = 16;
    i
}

#[test]
fn every_hook_op_is_named() {
    let names = [
        (slot::DECIDE, "decide"),
        (slot::TRANSFORM, "transform"),
        (slot::NOTIFY, "notify"),
        (slot::CONFIGURE, "configure"),
        (slot::STATUS, "status"),
        (slot::DESCRIBE, "describe"),
        (slot::SERVE, "serve"),
    ];
    for (s, n) in names {
        assert_eq!(Hook::op_name(s), n);
    }
    assert_eq!(Hook::op_name(slot::SERVE + 1), "op");
    assert_eq!(Hook::TIMEOUT, Outcome::Failed);
}

#[test]
fn decide_green_red_foreign() {
    let i = decide_in();
    let mut o: DecideOut = output(Outcome::Ready);
    o.verbs = VERB_PREFER;
    o.order_written = 4;
    assert_eq!(check(slot::DECIDE, &i, size_of::<DecideIn>(), &o), Ok(()));

    // The order cap comes from the `in`: one slot past it is FAULT.
    let mut over = o;
    over.order_written = 5;
    fails(
        check(slot::DECIDE, &i, size_of::<DecideIn>(), &over),
        Rule::OverCap,
        "decide.order_written",
    );
    // Two verbs on READY.
    let mut two = o;
    two.verbs = VERB_PREFER | VERB_REJECT;
    fails(
        check(slot::DECIDE, &i, size_of::<DecideIn>(), &two),
        Rule::NotExactlyOne,
        "decide.verbs",
    );

    foreign(check(slot::DECIDE, &i, size_of::<InHead>(), &o));
}

#[test]
fn decide_caps_are_read_from_the_in() {
    let mut i = decide_in();
    let mut o: DecideOut = output(Outcome::Ready);
    o.verbs = VERB_REJECT;
    o.reject_message_written = 8;
    o.restrict_tags_written = 8;
    assert_eq!(check(slot::DECIDE, &i, size_of::<DecideIn>(), &o), Ok(()));
    i.reject_message_cap = 7;
    fails(
        check(slot::DECIDE, &i, size_of::<DecideIn>(), &o),
        Rule::OverCap,
        "decide.reject_message_written",
    );
    i.reject_message_cap = 8;
    i.restrict_tags_cap = 7;
    fails(
        check(slot::DECIDE, &i, size_of::<DecideIn>(), &o),
        Rule::OverCap,
        "decide.restrict_tags_written",
    );
}

#[test]
fn decide_short_answer() {
    let i = decide_in();
    let mut o: DecideOut = output(Outcome::Failed);
    o.order_needed = 9;
    assert_eq!(check(slot::DECIDE, &i, size_of::<DecideIn>(), &o), Ok(()));
    assert!(Hook::short(&answer(
        slot::DECIDE,
        &i,
        size_of::<DecideIn>(),
        &o
    )));

    // A needed that fits its cap wastes the re-call.
    let mut fits = o;
    fits.order_needed = 4;
    fails(
        check(slot::DECIDE, &i, size_of::<DecideIn>(), &fits),
        Rule::WastedRecall,
        "decide.needed",
    );

    // A FAILED answer naming nothing needed is not short.
    let plain: DecideOut = output(Outcome::Failed);
    assert!(!Hook::short(&answer(
        slot::DECIDE,
        &i,
        size_of::<DecideIn>(),
        &plain
    )));
    // A READY answer is never short.
    let mut ready: DecideOut = output(Outcome::Ready);
    ready.verbs = VERB_ABSTAIN;
    assert!(!Hook::short(&answer(
        slot::DECIDE,
        &i,
        size_of::<DecideIn>(),
        &ready
    )));
}

#[test]
fn transform_green_red_foreign() {
    let i = decide_in();
    let mut o: TransformOut = output(Outcome::Ready);
    o.verbs = VERB_REWRITE;
    o.rewrite_written = 16;
    assert_eq!(
        check(slot::TRANSFORM, &i, size_of::<DecideIn>(), &o),
        Ok(())
    );

    let mut over = o;
    over.rewrite_written = 17;
    fails(
        check(slot::TRANSFORM, &i, size_of::<DecideIn>(), &over),
        Rule::OverCap,
        "transform.rewrite_written",
    );
    let mut none = o;
    none.verbs = 0;
    fails(
        check(slot::TRANSFORM, &i, size_of::<DecideIn>(), &none),
        Rule::NotExactlyOne,
        "transform.verbs",
    );

    foreign(check(slot::TRANSFORM, &i, size_of::<InHead>(), &o));
}

#[test]
fn transform_short_answer() {
    let i = decide_in();
    let mut o: TransformOut = output(Outcome::Failed);
    o.rewrite_needed = 17;
    assert_eq!(
        check(slot::TRANSFORM, &i, size_of::<DecideIn>(), &o),
        Ok(())
    );
    assert!(Hook::short(&answer(
        slot::TRANSFORM,
        &i,
        size_of::<DecideIn>(),
        &o
    )));

    // A short answer writes nothing.
    let mut wrote = o;
    wrote.reject_message_written = 1;
    fails(
        check(slot::TRANSFORM, &i, size_of::<DecideIn>(), &wrote),
        Rule::WrittenOnShort,
        "transform.written",
    );

    let plain: TransformOut = output(Outcome::Failed);
    assert!(!Hook::short(&answer(
        slot::TRANSFORM,
        &i,
        size_of::<DecideIn>(),
        &plain
    )));
}

#[test]
fn notify_green_red_foreign() {
    let i: NotifyIn = input();
    let mut o: OutHead = output(Outcome::Failed);
    o.error.ptr = &BYTE;
    o.error.len = 1;
    assert_eq!(check(slot::NOTIFY, &i, size_of::<NotifyIn>(), &o), Ok(()));

    let mut null = o;
    null.error.ptr = std::ptr::null();
    fails(
        check(slot::NOTIFY, &i, size_of::<NotifyIn>(), &null),
        Rule::NullWithCount,
        "notify.error",
    );

    foreign(check(slot::NOTIFY, &i, size_of::<InHead>(), &o));
}

#[test]
fn configure_green_red_foreign() {
    let mut i: ConfigureIn = input();
    i.version = 7;
    let mut o: ConfigureOut = output(Outcome::Ready);
    o.acked_version = 7;
    assert_eq!(
        check(slot::CONFIGURE, &i, size_of::<ConfigureIn>(), &o),
        Ok(())
    );

    // The pushed version comes from the `in`.
    let mut pushed = i;
    pushed.version = 8;
    fails(
        check(slot::CONFIGURE, &pushed, size_of::<ConfigureIn>(), &o),
        Rule::Contradiction,
        "configure.acked_version",
    );

    foreign(check(slot::CONFIGURE, &i, size_of::<InHead>(), &o));
}

#[test]
fn status_green_red_foreign() {
    let i: InHead = in_head();
    let mut o: StatusOut = output(Outcome::Ready);
    o.status.ptr = &BYTE;
    o.status.len = 1;
    o.head.lease = 3;
    assert_eq!(check(slot::STATUS, &i, size_of::<InHead>(), &o), Ok(()));

    let mut unleased = o;
    unleased.head.lease = 0;
    fails(
        check(slot::STATUS, &i, size_of::<InHead>(), &unleased),
        Rule::Missing,
        "status.lease",
    );

    foreign(check(slot::STATUS, &i, size_of::<InHead>() - 1, &o));
}

#[test]
fn describe_green_red_foreign() {
    let i: InHead = in_head();
    let o: DescribeOut = output(Outcome::Ready);
    assert_eq!(check(slot::DESCRIBE, &i, size_of::<InHead>(), &o), Ok(()));

    let mut spurious = o;
    spurious.head.lease = 3;
    fails(
        check(slot::DESCRIBE, &i, size_of::<InHead>(), &spurious),
        Rule::Contradiction,
        "describe.lease_without_material",
    );

    foreign(check(slot::DESCRIBE, &i, size_of::<InHead>() - 1, &o));
}

#[test]
fn serve_green_red_foreign() {
    let i: ServeIn = input();
    let mut o: ServeOut = output(Outcome::Ready);
    o.status_code = 200;
    o.body.ptr = &BYTE;
    o.body.len = 1;
    o.head.lease = 3;
    assert_eq!(check(slot::SERVE, &i, size_of::<ServeIn>(), &o), Ok(()));

    let mut headers = o;
    headers.headers_out_len = 2;
    fails(
        check(slot::SERVE, &i, size_of::<ServeIn>(), &headers),
        Rule::NullWithCount,
        "serve.headers_out",
    );

    foreign(check(slot::SERVE, &i, size_of::<InHead>(), &o));
}

#[test]
fn lifecycle_slots_state_no_hook_rule() {
    let i: DecideIn = input();
    let o: DecideOut = output(Outcome::Ready);
    assert_eq!(check(slot::DECIDE - 1, &i, size_of::<InHead>(), &o), Ok(()));
    assert!(!Hook::short(&answer(
        slot::SERVE,
        &i,
        size_of::<InHead>(),
        &output::<ServeOut>(Outcome::Failed)
    )));
}

/// A zeroed `out` on PENDING and on REFUSED passes every op's check: those outcomes carry no
/// verb, no buffer, no lease and no ack.
#[test]
fn zeroed_pending_and_refused_pass_every_op() {
    let d = decide_in();
    let mut c: ConfigureIn = input();
    c.version = 7;
    let h: InHead = in_head();
    let n: NotifyIn = input();
    let sv: ServeIn = input();
    for o in [Outcome::Pending, Outcome::Refused] {
        let ds = size_of::<DecideIn>();
        let hs = size_of::<InHead>();
        assert_eq!(check(slot::DECIDE, &d, ds, &output::<DecideOut>(o)), Ok(()));
        assert_eq!(
            check(slot::TRANSFORM, &d, ds, &output::<TransformOut>(o)),
            Ok(())
        );
        assert_eq!(
            check(
                slot::NOTIFY,
                &n,
                size_of::<NotifyIn>(),
                &output::<OutHead>(o)
            ),
            Ok(())
        );
        assert_eq!(
            check(
                slot::CONFIGURE,
                &c,
                size_of::<ConfigureIn>(),
                &output::<ConfigureOut>(o)
            ),
            Ok(())
        );
        assert_eq!(check(slot::STATUS, &h, hs, &output::<StatusOut>(o)), Ok(()));
        assert_eq!(
            check(slot::DESCRIBE, &h, hs, &output::<DescribeOut>(o)),
            Ok(())
        );
        assert_eq!(
            check(
                slot::SERVE,
                &sv,
                size_of::<ServeIn>(),
                &output::<ServeOut>(o)
            ),
            Ok(())
        );
    }
}
