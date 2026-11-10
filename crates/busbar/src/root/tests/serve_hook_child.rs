// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::sdk::{exchange, hook};
use std::sync::Mutex;
use std::task::Poll;

const NAME: &str = "neutral-child-gate";
type ChildAnswer = Result<(u64, Vec<u8>), String>;
static ANSWERS: Mutex<Vec<ChildAnswer>> = Mutex::new(Vec::new());
static OPENS: Mutex<usize> = Mutex::new(0);

pub struct Open;
struct ChildGate;
impl hook::HookOpen for Open {
    fn open(_: &str) -> Result<Box<dyn hook::Hook>, String> {
        Ok(Box::new(ChildGate))
    }
    fn open_with(opening: &hook::Opening<'_>) -> Result<Box<dyn hook::Hook>, String> {
        assert!(
            opening.secrets.is_empty(),
            "child credentials stay in the host"
        );
        Self::open(opening.settings)
    }
}
impl hook::Hook for ChildGate {
    fn decide(
        &self,
        view: &hook::Decoded<'_>,
        op: &exchange::Op<'_, busbar_contract::plugin::markers::HookKind>,
    ) -> Poll<hook::Verdict> {
        assert!(view.user.is_none());
        let seq = op
            .context(|| {
                *OPENS.lock().unwrap_or_else(|p| p.into_inner()) += 1;
                Arc::new(Mutex::new(0_u32))
            })
            .unwrap();
        let mut seq = seq.lock().unwrap_or_else(|p| p.into_inner());
        let services = op.host().and_then(|host| host.services()).unwrap();
        loop {
            let handle = busbar_contract::abi::mechanism::ticket::CompletionHandle {
                ticket: op.ticket(),
                seq: *seq,
                _reserved: 0,
            };
            let mut bytes = [0_u8; 32];
            let answer = match services.hook_child(handle, b"bounded", &mut bytes) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok((status, bytes))) => Ok((status, bytes.to_vec())),
                Poll::Ready(Err(error)) => Err(format!("{error:?}")),
            };
            ANSWERS
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(answer);
            *seq += 1;
            if *seq == 2 {
                return Poll::Ready(hook::Verdict::Abstain);
            }
        }
    }
}
mod fixture {
    busbar_contract::export_plugin! {
        hook: super::Open,
        statement: busbar_contract::abi::sdk::hook::statement_with_tail(
            busbar_contract::abi::sdk::door::statement(super::NAME, "1.6.0", 8),
            &busbar_contract::abi::sdk::hook::tail(
                busbar_contract::abi::hook::CLASS_GATE,
                busbar_contract::abi::hook::PROMPT_NO,
                busbar_contract::abi::hook::USER_NO,
            ),
        ),
    }
}
fn grant(instance: &str) -> busbar_kernel::hook_child::Grant {
    busbar_kernel::hook_child::Grant {
        revision: 1,
        plane: instance.into(),
        operation: "POST".into(),
        target: "/call/local".into(),
        target_binding: "m".into(),
        max_input_bytes: 32,
        max_output_bytes: 32,
        max_children: 1,
        timeout_ms: 1_000,
        max_budget_micros: 1_000_000,
    }
}
fn install(g: &Governed, grant: busbar_kernel::hook_child::Grant) -> Arc<App> {
    ANSWERS.lock().unwrap_or_else(|p| p.into_inner()).clear();
    *OPENS.lock().unwrap_or_else(|p| p.into_inner()) = 0;
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        g.served.planes[0].kernel.clone(),
        busbar_kernel::host_services::caller_binding(),
    ));
    assert!(dispatcher.lend_seal(busbar_kernel::seal::lend()));
    assert!(dispatcher.install_runtime(tokio::runtime::Handle::current()));
    let axis = Arc::new(
        crate::root::loader::hook_door::HookRows::new(&[fixture::door], None, dispatcher).unwrap(),
    );
    let rows = crate::root::loader::PluginRegistry::empty()
        .link(vec![crate::root::loader::LinkedPlugin::door_of_kind(
            busbar_contract::abi::mechanism::kind::HOOK,
            NAME,
            fixture::door,
        )])
        .unwrap();
    let env = busbar_kernel::hooks::HookEnv::with_axis(
        Arc::new(rows),
        axis,
        g.app.hook_env.secret_resolver.clone(),
    );
    let cfg = serde_json::from_value(serde_json::json!({
        "kind": "gate", "module": NAME, "timeout_ms": 5_000,
        "on_error": "weighted", "prompt": "no", "user": "no",
        "child_dispatch": grant,
    }))
    .unwrap();
    let mut next = (*g.app).clone();
    next.hook_registry = std::collections::HashMap::from([(NAME.to_string(), cfg)]);
    next.global_hooks = vec![NAME.to_string()];
    next.global_gates =
        busbar_kernel::hooks::resolve_gate_hooks(&next.hook_registry, &next.global_hooks, &env, 1);
    assert_eq!(next.global_gates.len(), 1);
    next.hook_env = env;
    let next = Arc::new(next);
    g.apply(next.clone());
    next
}

#[tokio::test]
async fn hook_child_uses_normal_admission_and_replays_without_credentials() {
    let _one = PUBLISHING.lock().await;
    let g = governed("hook-child-admission", true).await;
    let next = install(&g, grant("hook-child-admission"));
    super::super::validate_hook_children(&g.served, &next).unwrap();
    assert_eq!(g.post("/call/local", true).await, (200, "ping".into()));
    assert_eq!(
        *OPENS.lock().unwrap_or_else(|p| p.into_inner()),
        1,
        "the originating gate is skipped in its child"
    );
    assert_eq!(
        *ANSWERS.lock().unwrap_or_else(|p| p.into_inner()),
        vec![Ok((200, b"bounded".to_vec())); 2]
    );
    assert_eq!(
        g.requests().await,
        2,
        "normal parent and single child admission"
    );
    assert_eq!(g.money.open_units(), 0);
    assert_eq!(g.post.open_units(), 0);
    let book = g.book.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(book.audit_records.len(), 2);
    let parent = book
        .audit_records
        .iter()
        .find(|r| r.what.parent.is_none())
        .unwrap();
    let child = book
        .audit_records
        .iter()
        .find(|r| r.what.parent.is_some())
        .unwrap();
    assert_eq!(child.what.parent, Some(parent.what.unit_key));
    assert_eq!(child.subject, parent.subject);
}

#[tokio::test]
async fn hook_child_unknown_binding_refuses_at_boot_and_runtime() {
    let _one = PUBLISHING.lock().await;
    let g = governed("hook-child-binding", true).await;
    let mut invalid = grant("hook-child-binding");
    invalid.target_binding = "missing".into();
    let next = install(&g, invalid);
    assert!(super::super::validate_hook_children(&g.served, &next)
        .unwrap_err()
        .contains("unknown target binding"));
    let mut unknown_plane = (*next).clone();
    unknown_plane
        .hook_registry
        .get_mut(NAME)
        .unwrap()
        .child_dispatch = Some(grant("missing-plane"));
    assert!(
        super::super::validate_hook_children(&g.served, &unknown_plane)
            .unwrap_err()
            .contains("unknown configured plane")
    );
    let mut unknown_claim = (*next).clone();
    let mut unserved = grant("hook-child-binding");
    unserved.target = "/unserved".into();
    unknown_claim
        .hook_registry
        .get_mut(NAME)
        .unwrap()
        .child_dispatch = Some(unserved);
    assert!(
        super::super::validate_hook_children(&g.served, &unknown_claim)
            .unwrap_err()
            .contains("not a claim")
    );
    assert_eq!(g.post("/call/local", true).await, (200, "ping".into()));
    assert_eq!(g.requests().await, 1, "no unauthorized child was admitted");
    assert!(ANSWERS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .all(|answer| match answer {
            Ok((status, _)) => *status >= 400,
            Err(_) => true,
        }));
    assert_eq!(ANSWERS.lock().unwrap_or_else(|p| p.into_inner()).len(), 2);
}

#[tokio::test]
async fn hook_child_deadline_cancels_and_retires_pending_child() {
    let _one = PUBLISHING.lock().await;
    let g = governed("hook-child-deadline", true).await;
    let mut pending = grant("hook-child-deadline");
    pending.target = "/call/local-child-pending".into();
    pending.timeout_ms = 1_000;
    install(&g, pending);
    assert_eq!(g.post("/call/local", true).await, (200, "ping".into()));
    assert!(
        g.served.planes[0]
            .kernel
            .drain_plane_cleanup(super::super::RECORD_DRAIN)
            .await
    );
    assert_eq!(g.requests().await, 2);
    assert_eq!(g.money.open_units(), 0);
    assert_eq!(g.post.open_units(), 0);
    assert_eq!(ANSWERS.lock().unwrap_or_else(|p| p.into_inner()).len(), 2);
    assert!(ANSWERS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .all(|answer| match answer {
            Ok((status, _)) => *status >= 400,
            Err(_) => true,
        }));
    let book = g.book.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(book.audit_records.len(), 2);
    let child = book
        .audit_records
        .iter()
        .find(|r| r.what.parent.is_some())
        .unwrap();
    assert!(
        matches!(
            child.outcome.unit_end,
            busbar_contract::caps::Outcome::Aborted(busbar_contract::caps::Abort::Kernel {
                reason: busbar_contract::caps::ReasonCode::ClientGone,
            })
        ),
        "the actual child was cancelled: {:?}",
        child.outcome
    );
    assert!(
        child.usage.lines.is_empty(),
        "a local abort incurs no upstream usage"
    );
}
