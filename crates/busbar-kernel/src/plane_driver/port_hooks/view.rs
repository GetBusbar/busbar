// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_plugin_abi::fail::fact::{PJ_END_USER, PJ_TEXT_COMPLETE};
use busbar_ports::{FactRef, FactVal};

use super::Call;

/// One hook call's signals, on the stack up to 32 (the projection's facts plus the call's own).
pub(super) type Signals<'a> = smallvec::SmallVec<[(u32, FactRef<'a>); 32]>;

/// Borrow the exact typed plane projection for one configured hook call: PJ_END_USER only when the
/// call receives the identity, PJ_TEXT_COMPLETE only when it receives the content.
pub(super) fn signals<'a>(facts: &'a [(u32, FactVal)], call: &Call, content: bool) -> Signals<'a> {
    let identity = super::call::lends_caller(call);
    let mut out = Signals::new();
    out.extend(
        facts
            .iter()
            .filter(|(key, _)| *key != PJ_END_USER || identity)
            .filter(|(key, _)| *key != PJ_TEXT_COMPLETE || content)
            .map(|(key, value)| {
                let value = match value {
                    FactVal::U(value) => FactRef::U(*value),
                    FactVal::Text(value) => FactRef::Text(value),
                };
                (*key, value)
            }),
    );
    out
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
            // Every bit an image could declare, the retired identity bit (4) among them.
            u64::MAX
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
        let view = signals(&facts, &call, true);
        assert!(!view.iter().any(|(key, _)| *key == PJ_END_USER));
        assert!(matches!(view.as_slice(), [(_, FactRef::U(7))]));
    }
}
