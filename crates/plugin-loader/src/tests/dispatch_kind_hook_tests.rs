// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

fn input<T: InFrame>() -> T {
    // SAFETY: every hook `in` is plain integers, floats, raw pointers and unions of those, for
    // which the all-zero pattern is valid; `T` leads with an `InHead`, written below.
    let mut v: T = unsafe { MaybeUninit::zeroed().assume_init() };
    // SAFETY: `T: InFrame` leads with an `InHead`.
    unsafe { std::ptr::addr_of_mut!(v).cast::<InHead>().write(in_head()) };
    v
}

fn output<T: OutFrame>(outcome: Outcome) -> T {
    // SAFETY: as `input`, with an `OutHead` first.
    let mut v: T = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut head = out_head();
    head.outcome = RawOutcome::of(outcome);
    // SAFETY: `T: OutFrame` leads with an `OutHead`.
    unsafe { std::ptr::addr_of_mut!(v).cast::<OutHead>().write(head) };
    v
}

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

    let mut over = o;
    over.order_written = 5;
    fails(
        check(slot::DECIDE, &i, size_of::<DecideIn>(), &over),
        Rule::OverCap,
        "decide.order",
    );

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
        "decide.reject_message",
    );
    i.reject_message_cap = 8;
    i.restrict_tags_cap = 7;
    fails(
        check(slot::DECIDE, &i, size_of::<DecideIn>(), &o),
        Rule::OverCap,
        "decide.restrict_tags",
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

    let mut fits = o;
    fits.order_needed = 4;
    fails(
        check(slot::DECIDE, &i, size_of::<DecideIn>(), &fits),
        Rule::WastedRecall,
        "decide",
    );

    let plain: DecideOut = output(Outcome::Failed);
    assert!(!Hook::short(&answer(
        slot::DECIDE,
        &i,
        size_of::<DecideIn>(),
        &plain
    )));

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
        "transform.rewrite",
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

    let mut wrote = o;
    wrote.reject_message_written = 1;
    fails(
        check(slot::TRANSFORM, &i, size_of::<DecideIn>(), &wrote),
        Rule::WrittenOnShort,
        "transform",
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

#[test]
fn the_hook_tail_follows_the_growth_rule() {
    use crate::dispatch::kinds::hook::HookContext;
    use busbar_contract::abi::hook::{Tail, CLASS_TAP, PROMPT_NO, USER_NO};
    use busbar_contract::abi::sdk::door::statement;
    let bind = |size: usize| {
        let mut tail = Tail::EMPTY.with_access(CLASS_TAP, PROMPT_NO, USER_NO);
        tail.head.size = size as u32;

        let leaked: &'static mut [Tail; 2] = Box::leak(Box::new([tail, tail]));
        let st = busbar_contract::abi::mechanism::door::Statement {
            kind_tail: std::ptr::from_ref(&leaked[0]).cast(),
            ..statement("t", "1", 0)
        };
        <Hook as Kind>::context(&st).map(|c| {
            c.and_then(|c| c.downcast::<HookContext>().ok())
                .map(|f| f.facts.class)
        })
    };
    let host = size_of::<Tail>();
    assert_eq!(bind(host), Ok(Some(CLASS_TAP)));
    assert_eq!(bind(host + 8), Ok(Some(CLASS_TAP)), "a grown tail loads");
    assert_eq!(
        bind(host - 8),
        Err(format!(
            "a hook states a {}-byte tail, smaller than its frozen {host}",
            host - 8
        ))
    );
}

#[test]
fn a_hook_tail_admits_valid_routes_and_refuses_malformed_routes_or_requested_signals() {
    use busbar_contract::abi::hook::{Route, Tail, CLASS_GATE, PROMPT_NO, USER_NO};
    use busbar_contract::abi::mechanism::call::AbiStr;
    use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
    let routes: &'static [Route] = Box::leak(Box::new([Route {
        path: AbiStr::ZERO,
        method: AbiStr::ZERO,
        auth: 0,
        _reserved: 0,
    }]));
    static SIGNALS: [u32; 1] = [1];
    static NAME: &[u8] = b"hooks-h7";
    let plain = Tail::EMPTY.with_access(CLASS_GATE, PROMPT_NO, USER_NO);
    let bind = |t: &Tail| {
        let st = Statement {
            name: AbiStr {
                ptr: NAME.as_ptr(),
                len: NAME.len(),
            },
            kind_tail: std::ptr::from_ref(t).cast::<KindTailHead>(),
            ..Statement::ZERO
        };
        crate::dispatch::kinds::hook::facts(&st).map(|_| ())
    };
    assert_eq!(bind(&plain), Ok(()), "a tail stating neither binds");
    let routed = plain.with_routes(routes);
    let err = bind(&routed).expect_err("a route without a rooted path is refused");
    assert!(err.contains("route"), "{err}");
    let routes: &'static [Route] = Box::leak(Box::new([Route {
        path: AbiStr {
            ptr: b"/hooks/h/feedback".as_ptr(),
            len: 17,
        },
        method: AbiStr {
            ptr: b"POST".as_ptr(),
            len: 4,
        },
        auth: busbar_contract::abi::hook::ROUTE_AUTH_KEY,
        _reserved: 0,
    }]));
    assert_eq!(bind(&plain.with_routes(routes)), Ok(()));
    let signalled = plain.with_requested_signals(&SIGNALS);
    let err = bind(&signalled).expect_err("requested signals are refused");
    assert!(err.contains("requested_signals"), "{err}");
}

#[test]
fn hook_route_lists_require_alignment_before_copying() {
    use crate::dispatch::kinds::hook::HookContext;
    use busbar_contract::abi::hook::{Route, Tail, CLASS_GATE, PROMPT_NO, USER_NO};
    use busbar_contract::abi::mechanism::call::AbiStr;
    use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
    use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};

    let text = |value: &'static str| AbiStr {
        ptr: value.as_ptr(),
        len: value.len(),
    };
    let routes = [Route {
        path: text("/hooks/alignment/feedback"),
        method: text("POST"),
        auth: busbar_contract::abi::hook::ROUTE_AUTH_KEY,
        _reserved: 0,
    }; 2];
    let bind = |tail: &Tail| {
        let statement = Statement {
            name: text("alignment"),
            kind_tail: std::ptr::from_ref(tail).cast::<KindTailHead>(),
            ..Statement::ZERO
        };
        <Hook as Kind>::context(&statement).map(|context| {
            *context
                .expect("a hook has a context")
                .downcast::<HookContext>()
                .unwrap_or_else(|_| panic!("the hook context has its own type"))
        })
    };
    let mut tail = Tail::EMPTY.with_access(CLASS_GATE, PROMPT_NO, USER_NO);
    tail.routes = routes.as_ptr();
    tail.routes_len = 1;
    let context = bind(&tail).expect("an aligned route list is copied");
    assert_eq!(context.routes.len(), 1);
    assert_eq!(context.routes[0].path, "/hooks/alignment/feedback");
    assert_eq!(context.routes[0].method, RouteMethod::Post);
    assert_eq!(context.routes[0].auth, RouteAuth::Key);

    // Only the fixed loader sees this raw misaligned address; the test never dereferences it.
    let misaligned = routes.as_ptr().cast::<u8>().wrapping_add(1).cast::<Route>();
    assert!(!misaligned.is_aligned());
    tail.routes = misaligned;
    let error = bind(&tail).expect_err("a misaligned route list is refused before reading it");
    assert!(error.contains("route list is misaligned"), "{error}");

    tail.routes_len = 0;
    for pointer in [std::ptr::null(), misaligned] {
        tail.routes = pointer;
        let context = bind(&tail).expect("an empty route list ignores its pointer");
        assert!(context.routes.is_empty());
    }
    tail.routes_len = 1;
    tail.routes = std::ptr::null();
    let error = bind(&tail).expect_err("the existing NULL/count check is retained");
    assert!(error.contains("route list is null"), "{error}");
    tail.routes = routes.as_ptr();
    tail.routes_len = busbar_contract::abi::export::validate::HARD_MAX_ROUTES as usize + 1;
    let error = bind(&tail).expect_err("the existing route count bound is retained");
    assert!(error.contains("exceeds the route bound"), "{error}");
}
