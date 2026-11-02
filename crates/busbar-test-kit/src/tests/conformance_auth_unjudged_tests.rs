// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::conformance::{
    dispatcher, load, open, test_door, test_op, Leg, Subject, TestDoor, TestOp,
};
use busbar_contract::abi::auth::{
    AuthPoints, AuthTail, Ops, CAP_INBOUND, CAP_LOGIN, LOGIN_KIND_REDIRECT,
};
use busbar_contract::abi::mechanism::call::{Outcome, RawOutcome};
use busbar_contract::abi::mechanism::door::{Door, DoorParts};
use busbar_contract::abi::sdk::auth_door::{verify_tail, with_tail, VerifyPlugin};
use busbar_contract::abi::sdk::door::statement;
use std::sync::OnceLock;

pub struct Probe;
impl VerifyPlugin for Probe {
    fn open(_: &[u8], _: &[&[u8]]) -> Result<Self, &'static str> {
        Ok(Self)
    }
}
mod base {
    use super::*;
    const TAIL: &AuthTail = &AuthTail {
        caps: CAP_INBOUND | CAP_LOGIN,
        login_kind: LOGIN_KIND_REDIRECT,
        ..verify_tail(0, AuthPoints::HEAD)
    };
    busbar_contract::auth_verify_door!(
        Probe,
        with_tail(statement("login-output", "1.0.0", 2), TAIL)
    );
}
static FAULT: OnceLock<usize> = OnceLock::new();
static READY: OnceLock<usize> = OnceLock::new();
const URL: &[u8] = b"https://identity.test/login";
struct Begin<const FAIL: bool>;
impl<const FAIL: bool> TestOp for Begin<FAIL> {
    fn op(
        _: *mut std::ffi::c_void,
        _: *const std::ffi::c_void,
        out: *mut std::ffi::c_void,
    ) -> RawOutcome {
        let outcome = RawOutcome::of(if FAIL { Outcome::Fault } else { Outcome::Ready });
        // SAFETY: initialized exclusive loader frame. All bytes named here remain static; this
        // witness detects wrong observation without a probe of freed, spare or invalid memory.
        unsafe {
            let out = &mut *out.cast::<BeginLoginOut>();
            out.head.outcome = outcome;
            out.shape = BEGIN_AUTHORIZE;
            out.authorize_url = AbiStr {
                ptr: URL.as_ptr(),
                len: URL.len(),
            };
        }
        outcome
    }
}
impl<const FAIL: bool> TestDoor for Begin<FAIL> {
    fn door() -> *const Door {
        let slot = if FAIL { &FAULT } else { &READY };
        *slot.get_or_init(|| {
            let real = *base::door();
            // SAFETY: real SDK door and table are static and kind-correct.
            let ops = unsafe { real.ops().cast::<Ops>().read_unaligned() };
            let ops = Box::leak(Box::new(Ops {
                begin_login: Some(test_op::<Begin<FAIL>>),
                ..ops
            }));
            let door = unsafe {
                Door::__from_parts(DoorParts {
                    ops: std::ptr::from_ref(ops).cast(),
                    ..real.parts()
                })
            };
            Box::into_raw(Box::new(door)) as usize
        }) as *const Door
    }
}
fn answer<const FAIL: bool>() -> String {
    let s = Subject::of_raw(test_door::<Begin<FAIL>>, "unused", "{}");
    let d = dispatcher();
    let p = load::<Auth>(&s, Leg::Linked, s.bind(&d, "login-output")).unwrap();
    assert_eq!(open(&p, b"{}").outcome, Outcome::Ready);
    begin_login(&p, &serde_json::json!({}))
}
#[test]
fn a_fault_does_not_observe_its_borrowed_url() {
    let line = answer::<true>();
    assert!(
        line.starts_with("Fault ") && line.ends_with(" UNREAD"),
        "{line}"
    );
    assert!(!line.contains("identity.test"));
}
#[test]
fn the_same_ready_url_is_observed_after_the_loader_judges_it() {
    let line = answer::<false>();
    assert!(
        line.starts_with("Ready ") && line.contains("url=https://identity.test/login"),
        "{line}"
    );
}
