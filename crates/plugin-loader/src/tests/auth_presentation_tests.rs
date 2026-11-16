// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::auth_axis::AuthRows;
use crate::dispatch::{DispatchConfig, Dispatcher};
use busbar_contract::abi::auth::*;
use busbar_contract::abi::sdk::door::{statement, AbiIn, AbiOut};
use busbar_contract::abi::sdk::life::{Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::plugin::markers::AuthKind;
use std::marker::PhantomData;

struct Choice {
    variant: String,
    refreshed: AtomicBool,
    refresh_count: AtomicU64,
    last_generation: AtomicU64,
}
impl Life for Choice {
    type Kind = AuthKind;
    const CANCEL: u32 = 0;
    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            variant: serde_json::from_slice::<serde_json::Value>(settings).unwrap()["variant"]
                .as_str()
                .unwrap()
                .to_string(),
            refreshed: AtomicBool::new(false),
            refresh_count: AtomicU64::new(0),
            last_generation: AtomicU64::new(1),
        })
    }
    fn extensions(&self) -> Vec<u8> {
        use busbar_contract::abi::mechanism::extensions::encode;
        use busbar_contract::auth_calls::presentation::EXT_LOGIN_PRESENTATION;
        if self.variant == "absent" {
            return Vec::new();
        }
        let refreshed = self.refreshed.load(Ordering::Acquire);
        if self.variant == "bad-open"
            || (self.variant == "bad-refresh" && self.refresh_count.load(Ordering::Acquire) == 1)
        {
            return encode(&[(
                EXT_LOGIN_PRESENTATION,
                br#"{"label":"private-malformed","icon":"<svg>"}"#,
            )]);
        }
        busbar_contract::abi::sdk::auth_door::presentation_extensions(
            &busbar_contract::auth_calls::LoginPresentation {
                label: if refreshed { "Changed" } else { "Original" }.into(),
                icon: None,
            },
        )
    }
    fn refresh(&self, _: &[u8], _: &[&[u8]], generation: u64) -> Result<Refreshed, Refusal> {
        assert!(
            generation > self.last_generation.swap(generation, Ordering::AcqRel),
            "an attempted epoch must not be reused"
        );
        let prior = self.refresh_count.fetch_add(1, Ordering::AcqRel);
        if self.variant == "refuse" && prior == 0 {
            return Err(Refusal::refused("retain previous instance"));
        }
        self.refreshed.store(true, Ordering::Release);
        Ok(Refreshed::default())
    }
}
struct Empty<I, O>(PhantomData<(I, O)>);
impl<I: AbiIn, O: AbiOut> SafeSlot for Empty<I, O> {
    type Kind = AuthKind;
    type In = I;
    type Out = O;
    type State = busbar_contract::abi::sdk::life::Held<Choice>;
    fn call(
        _: Instance<'_, Self::State, AuthKind>,
        _: Lent<'_, I>,
        mut out: Out<'_, O>,
    ) -> Outcome {
        out.fail(Refusal::refused("unused fixture operation"))
    }
}
const TAIL: AuthTail = {
    let mut tail = AuthTail::EMPTY;
    tail.caps = CAP_LOGIN;
    tail.login_kind = LOGIN_KIND_REDIRECT;
    tail
};
busbar_contract::plugin_door! {
    ops: busbar_contract::abi::auth::Ops,
    statement: busbar_contract::abi::sdk::auth_door::with_tail(statement("presentation-choice", "1.0.0", 8), &TAIL),
    lifecycle: life(Choice),
    kind_ops: {
        verify: Safe<Empty<VerifyIn, IdentifyOut>>,
        begin_login: Safe<Empty<BeginLoginIn, BeginLoginOut>>,
        complete_login: Safe<Empty<CompleteLoginIn, IdentifyOut>>,
        open_outbound: Safe<Empty<OpenOutboundIn, OpenOutboundOut>>,
        outbound_ready: Safe<Empty<OutboundReadyIn, OutboundReadyOut>>,
        fields: Safe<Empty<FieldsIn, FieldsOut>>,
    },
}

#[test]
fn presentation_is_admitted_after_open_and_atomically_replaced_only_on_valid_refresh() {
    let registry = crate::PluginRegistry::empty()
        .link(vec![crate::LinkedPlugin::auth_door(
            "presentation-choice",
            door,
        )])
        .unwrap();
    let rows = AuthRows::new(
        Arc::new(registry),
        Arc::new(Dispatcher::new(
            DispatchConfig::default(),
            busbar_contract::services::test_caller_binding(),
        )),
    );
    let open = |variant: &str| {
        rows.open(
            "presentation-choice",
            variant,
            &crate::dispatch::test_settings(&serde_json::json!({"variant": variant})),
        )
    };
    let error = open("bad-open").err().unwrap();
    assert!(
        error.contains("malformed auth login presentation JSON"),
        "{error}"
    );
    assert!(!error.contains("private-malformed"));
    assert_eq!(open("absent").unwrap().login_presentation(), None);
    let normal = open("normal").unwrap();
    let old = normal.login_presentation().unwrap();
    normal.refresh().unwrap();
    assert_eq!(normal.login_presentation().unwrap().label, "Changed");
    assert_eq!(old.label, "Original");
    for variant in ["refuse", "bad-refresh"] {
        let instance = open(variant).unwrap();
        assert!(instance.refresh().is_err());
        assert_eq!(instance.login_presentation().unwrap().label, "Original");
        instance
            .refresh()
            .expect("the next valid generation is admitted");
        assert_eq!(instance.login_presentation().unwrap().label, "Changed");
    }
}
