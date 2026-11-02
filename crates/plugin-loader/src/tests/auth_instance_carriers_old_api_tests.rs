// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Old-public API witness: a real OPEN reply advertises a valid configured subset through the
//! existing extensions field. No new SDK trait, lifecycle method, or production constant is used.

use super::*;
use crate::dispatch::{load_linked, Bind, ConnTable, DispatchConfig, LinkedRow};
use busbar_contract::abi::auth::{AuthPoints, Ops};
use busbar_contract::abi::mechanism::call::RawOutcome;
use busbar_contract::abi::mechanism::door::{Door, MarkWord, Statement};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::mechanism::lifecycle::{OpenIn, OpenOut};
use busbar_contract::abi::sdk::auth_door::{
    carrier, verify_tail, with_tail, Answer, Verdict, VerifyPlugin, VerifyView,
};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::Refusal;
use std::ffi::c_void;

const TEST_CARRIERS_KEY: &str = "auth.carriers";

struct OldApiChoice;
impl VerifyPlugin for OldApiChoice {
    fn open_refusing(_: &[u8], _: &[&[u8]]) -> Result<Self, Refusal> {
        Ok(Self)
    }
    fn verify(&self, _: &VerifyView<'_>) -> Answer {
        Verdict::Pass.into()
    }
}

mod base {
    use super::*;
    const CARRIERS: &[MarkWord] = &[carrier("x-first"), carrier("x-second")];
    const TAIL: &busbar_contract::abi::auth::AuthTail = &verify_tail(0, AuthPoints::HEAD);
    busbar_contract::auth_verify_door!(
        OldApiChoice,
        with_tail(
            Statement {
                mark_words: CARRIERS.as_ptr(),
                mark_words_len: CARRIERS.len(),
                ..statement("old-api-carrier-choice", "1.0.0", 8)
            },
            TAIL
        )
    );
}

fn base_ops() -> &'static Ops {
    // SAFETY: the SDK door and its complete auth table have static storage.
    unsafe { &*Door::read_parts(base::door()).ops.cast::<Ops>() }
}

extern "C" fn selected_open(
    instance: *mut c_void,
    input: *const c_void,
    output: *mut c_void,
) -> RawOutcome {
    // SAFETY: forward the same OPEN instance and complete host frames, with every nested loan
    // live through this original SDK slot crossing.
    let result = unsafe { base_ops().head.open.unwrap()(instance, input, output) };
    if result.outcome() != Outcome::Ready {
        return result;
    }
    static FIRST: std::sync::LazyLock<Vec<u8>> =
        std::sync::LazyLock::new(|| extensions::encode(&[(TEST_CARRIERS_KEY, br#"["x-first"]"#)]));
    static SECOND: std::sync::LazyLock<Vec<u8>> =
        std::sync::LazyLock::new(|| extensions::encode(&[(TEST_CARRIERS_KEY, br#"["x-second"]"#)]));
    // SAFETY: the OPEN crossing lends complete live frames; static extension bytes outlive the
    // instance and require no allocated output lease.
    unsafe {
        let settings = (*input.cast::<OpenIn>()).settings;
        let bytes = std::slice::from_raw_parts(settings.ptr, settings.len);
        let selected = match bytes {
            b"\"first\"" => Some(FIRST.as_slice()),
            b"\"second\"" => Some(SECOND.as_slice()),
            _ => None,
        };
        if let Some(selected) = selected {
            (*output.cast::<OpenOut>()).head.extensions = blob(selected, BLOB_OCTETS, 0);
        }
    }
    result
}

extern "C" fn selected_door() -> &'static Door {
    static DOOR: std::sync::OnceLock<crate::conformance::StaticDoor> = std::sync::OnceLock::new();
    DOOR.get_or_init(|| {
        let mut ops = *base_ops();
        ops.head.open = Some(selected_open);
        // SAFETY: the existing SDK door is static; the copied table keeps its SDK instance and
        // slot contracts. Only OPEN adds an existing extensions field with static owned data.
        unsafe {
            let mut parts = Door::read_parts(base::door());
            parts.ops = std::ptr::from_ref(Box::leak(Box::new(ops))).cast();
            // The copied ops table is leaked; its complete nested graph and Statement retain
            // the original SDK door's immutable static backing, independent of this value.
            crate::conformance::StaticDoor::new(Door::__from_parts(parts))
        }
    })
    .get()
}

#[test]
fn configured_instances_read_their_own_subset_from_ready_open_extensions() {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let open = |variant: &str| {
        let sink = AuthSink::new(variant);
        let plugin = load_linked::<Auth>(
            &LinkedRow::of(selected_door).unwrap(),
            Bind {
                instance: variant.into(),
                max_inflight_cap: 8,
                sink: sink.bind(),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::NoNeeds,
            },
        )
        .unwrap();
        AuthInstance::open(
            plugin,
            sink,
            dispatcher.clone(),
            variant,
            &serde_json::to_vec(variant).unwrap(),
            Vec::new(),
        )
        .unwrap()
    };
    let first = open("first");
    let second = open("second");
    let default = open("default");
    let selected = (first.carriers(), second.carriers(), default.carriers());
    for calls in [&first, &second, &default] {
        crate::dispatch::lifecycle::close(calls.plugin());
    }
    // Expected behavioral RED on e5997407: its loader returns the full Statement union for both.
    assert_eq!(selected.0, ["x-first"]);
    assert_eq!(selected.1, ["x-second"]);
    assert_eq!(selected.2, ["x-first", "x-second"]);
}
