// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_plugin_abi::fail::fact::PJ_END_USER;
use busbar_plugin_abi::kinds::hook::hook as abi;
use busbar_ports::{FactRef, FactVal};

use super::Call;

/// Borrow the exact typed plane projection for one configured hook call.
pub(super) fn signals<'a>(facts: &'a [(u32, FactVal)], call: &Call) -> Vec<(u32, FactRef<'a>)> {
    let identity = call.user.sends_user() && call.port.facts() & abi::FB_WANTS_IDENTITY != 0;
    facts
        .iter()
        .filter(|(key, _)| *key != PJ_END_USER || identity)
        .map(|(key, value)| {
            let value = match value {
                FactVal::U(value) => FactRef::U(*value),
                FactVal::Text(value) => FactRef::Text(value),
            };
            (*key, value)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PolicyOnError, PromptAccess, UserAccess};
    use busbar_plugin_abi::kinds::hook::hook as abi;
    use busbar_ports::hook::{HookCall, HookPort, HookView};
    use busbar_ports::CallCx;
    use std::sync::Arc;
    use std::time::Duration;

    struct WantsIdentity;
    impl HookPort for WantsIdentity {
        fn points(&self) -> u32 {
            1 << abi::POINT_ROUTE
        }
        fn facts(&self) -> u64 {
            abi::FB_WANTS_IDENTITY
        }
        fn on<'a>(&'a self, _: CallCx, _: u32, _: &'a HookView<'a>) -> HookCall<'a> {
            unreachable!("projection construction makes no plugin call")
        }
    }

    #[test]
    fn a_native_hook_demand_never_grants_end_user_access() {
        let call = Call {
            name: Arc::from("shape-only"),
            port: Arc::new(WantsIdentity),
            timeout: Duration::from_secs(1),
            prompt: PromptAccess::No,
            user: UserAccess::No,
            signals: Default::default(),
            on_error: PolicyOnError::Reject,
            on_empty: PolicyOnError::Reject,
            fallbacks: Vec::new(),
            strategy: None,
        };
        let facts = vec![
            (PJ_END_USER, FactVal::Text("private-user".into())),
            (
                busbar_plugin_abi::fail::fact::PJ_MESSAGE_COUNT,
                FactVal::U(7),
            ),
        ];
        let view = signals(&facts, &call);
        assert!(!view.iter().any(|(key, _)| *key == PJ_END_USER));
        assert!(matches!(view.as_slice(), [(_, FactRef::U(7))]));
    }
}
