// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::auth_axis::AuthRows;
use crate::dispatch::{DispatchConfig, Dispatcher};
use crate::{LinkedPlugin, PluginRegistry};
use busbar_contract::abi::auth::{
    AuthPoints, AuthTail, BeginLoginOut, Ops, BEGIN_AUTHORIZE, CAP_INBOUND, CAP_LOGIN,
    LOGIN_KIND_REDIRECT,
};
use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::call::{Outcome, RawOutcome};
use busbar_contract::abi::mechanism::door::{Door, DoorParts};
use busbar_contract::abi::sdk::auth_door::{verify_tail, with_tail, VerifyPlugin};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::auth::{BeginLogin, LoginOutcome};
use std::sync::Arc;
use std::sync::OnceLock;

pub struct Probe;
impl VerifyPlugin for Probe {
    fn verify_ticketed(
        &self,
        _: &busbar_contract::abi::sdk::auth_door::VerifyView<'_>,
        _: &busbar_contract::abi::sdk::auth_door::VerifyOp,
    ) -> std::task::Poll<busbar_contract::abi::sdk::auth_door::Answer> {
        panic!("this fixture only calls its explicit login slot")
    }

    fn open_refusing(
        _: &[u8],
        _: &[&[u8]],
    ) -> Result<Self, busbar_contract::abi::sdk::life::Refusal> {
        Ok(Self)
    }

    fn reload(
        &self,
        _: &[u8],
        _: &[&[u8]],
    ) -> Result<u64, busbar_contract::abi::sdk::life::Refusal> {
        Ok(0)
    }
}
mod base {
    use super::*;
    const TAIL: &AuthTail = &verify_tail(0, AuthPoints::HEAD);
    busbar_contract::auth_verify_door!(
        Probe,
        with_tail(statement("login-output", "1.0.0", 2), TAIL)
    );
}
static FAULT: OnceLock<usize> = OnceLock::new();
static READY: OnceLock<usize> = OnceLock::new();
const URL: &[u8] = b"https://identity.test/login";
struct Begin<const FAIL: bool>;
impl<const FAIL: bool> Begin<FAIL> {
    extern "C" fn op(
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
impl<const FAIL: bool> Begin<FAIL> {
    extern "C" fn door() -> &'static Door {
        let slot = if FAIL { &FAULT } else { &READY };
        let address = *slot.get_or_init(|| {
            let real = *base::door();
            // SAFETY: real SDK door and table are static and kind-correct.
            let ops = unsafe { real.ops().cast::<Ops>().read_unaligned() };
            let ops = Box::leak(Box::new(Ops {
                begin_login: Some(Begin::<FAIL>::op),
                ..ops
            }));
            // Restate the raw login capability with the deliberately substituted login op.
            let statement = unsafe { *real.statement() };
            let tail = Box::leak(Box::new(AuthTail {
                caps: CAP_INBOUND | CAP_LOGIN,
                login_kind: LOGIN_KIND_REDIRECT,
                ..verify_tail(0, AuthPoints::HEAD)
            }));
            let statement = Box::leak(Box::new(with_tail(statement, tail)));
            let door = unsafe {
                Door::__from_parts(DoorParts {
                    statement,
                    ops: std::ptr::from_ref(ops).cast(),
                    ..real.parts()
                })
            };
            Box::into_raw(Box::new(door)) as usize
        });
        // SAFETY: the immutable descriptor and its SDK table are leaked once and remain live.
        unsafe { &*(address as *const Door) }
    }
}
fn answer<const FAIL: bool>() -> LoginOutcome {
    let registry = PluginRegistry::empty()
        .link(vec![LinkedPlugin::auth_door_named(
            "login-output",
            "login-output",
            Begin::<FAIL>::door,
        )])
        .expect("the original malicious ABI descriptor links");
    let rows = AuthRows::new(
        Arc::new(registry),
        Arc::new(Dispatcher::new(
            DispatchConfig::default(),
            busbar_contract::services::test_caller_binding(),
        )),
    );
    let auth = rows
        .open(
            "login-output",
            "login-output",
            &crate::dispatch::test_settings(&serde_json::json!({})),
        )
        .expect("SDK instance opens");
    let request = BeginLogin {
        redirect_uri: "https://host.test/callback".into(),
        state: "state".into(),
        code_challenge: "challenge".into(),
        nonce: None,
        scopes: vec![],
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(5), auth.begin_login(request))
            .await
            .expect("the immediate answer settles")
    })
}
#[test]
fn a_fault_does_not_observe_its_borrowed_url() {
    assert_eq!(answer::<true>(), LoginOutcome::Reject);
}
#[test]
fn the_same_ready_url_is_observed_after_the_loader_judges_it() {
    assert_eq!(
        answer::<false>(),
        LoginOutcome::Authorize("https://identity.test/login".into())
    );
}
