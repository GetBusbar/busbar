// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The node's open-call table as a served session pump reaches it: the pump plans the client-served
//! leg into the table, the client's reply is taken, and a session's teardown frees its rows.

use std::sync::Arc;

use busbar_contract::ids::UnitKey;
use busbar_plane_streaming::governed::GovernedCalls;
use busbar_plane_streaming::open_calls::{NodeCalls, OpenToolCalls};

use crate::ir::codec::{OpenAiRealtimeCodec, WireEvent};
use crate::runtime::{Carrier, GovernedSession, SessionCore, ToolExecutor};

/// A tool executor that serves no tool: every call the session sees is the client's to answer.
#[derive(Debug)]
struct ServesNoTool;

#[async_trait::async_trait]
impl ToolExecutor for ServesNoTool {
    fn serves(&self, _name: &str) -> bool {
        false
    }
    async fn execute(&self, _name: &str, _arguments: &[u8]) -> Vec<u8> {
        b"{\"executed\":\"in-process\"}".to_vec()
    }
}

/// A real session pump bound to `port`'s table as `session`, serving no tool.
fn pump_serving_no_tool(port: &Arc<NodeCalls>, session: u64) -> SessionCore<OpenAiRealtimeCodec> {
    SessionCore::new(
        OpenAiRealtimeCodec,
        None,
        Arc::new(ServesNoTool),
        Carrier::sideband(),
        None,
    )
    .with_governed(GovernedSession {
        session,
        calls: Arc::clone(port) as Arc<dyn GovernedCalls>,
    })
}

/// One OpenAI Realtime wire frame.
fn realtime_frame(json: &serde_json::Value) -> WireEvent {
    WireEvent(bytes::Bytes::from(
        serde_json::to_vec(json).expect("serializes"),
    ))
}

/// The upstream frames a plan writes, as one string.
fn upstream_text(plan: &crate::runtime::Outbound) -> String {
    plan.upstream
        .iter()
        .map(|w| String::from_utf8_lossy(&w.0).to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

/// **Q72(1) / R4: the served session plans the client-served leg, so the client's answer is taken.**
///
/// The call is announced to a real session pump bound to the node's real table, and the pump is the
/// only thing that can have entered the wait. The tool is one the node does not serve, so nothing is
/// executed in-process; the client's own `function_call_output` for that call is then accepted and
/// carried to the model. Before the writer was wired the table stayed empty and this reply was
/// refused (`refused_reply`). The RED arm: a reply naming a call nobody planned is still refused and
/// reaches the model on no wire.
#[tokio::test]
async fn a_served_session_plans_the_client_leg_and_accepts_its_reply() {
    let port = Arc::new(NodeCalls::new(Arc::new(OpenToolCalls::new()), keys()));
    let core = pump_serving_no_tool(&port, 5_151);

    for f in [
        serde_json::json!({"type":"response.output_item.added",
            "item":{"type":"function_call","call_id":"call_cli","name":"client_tool"}}),
        serde_json::json!({"type":"response.function_call_arguments.delta",
            "call_id":"call_cli","delta":"{}"}),
        serde_json::json!({"type":"response.function_call_arguments.done","call_id":"call_cli"}),
    ] {
        let plan = core.on_server_frame(realtime_frame(&f)).await;
        assert!(
            plan.upstream.is_empty(),
            "a tool the node does not serve is never executed in-process: {}",
            upstream_text(&plan)
        );
    }
    assert_eq!(
        port.table().open(),
        1,
        "the pump planned the client-served leg into the node's own table"
    );

    let forged = core.on_client_frame(realtime_frame(&serde_json::json!({
        "type":"conversation.item.create",
        "item":{"type":"function_call_output","call_id":"call_unplanned","output":"1"}})));
    assert!(
        forged.refused_reply,
        "a reply for an unplanned call is refused"
    );
    assert!(
        forged.upstream.is_empty(),
        "and it reaches the model on no wire at all: {}",
        upstream_text(&forged)
    );

    let answered = core.on_client_frame(realtime_frame(&serde_json::json!({
        "type":"conversation.item.create",
        "item":{"type":"function_call_output","call_id":"call_cli","output":"42"}})));
    assert!(
        !answered.refused_reply,
        "the client's reply for a planned client-served call is accepted"
    );
    let up = upstream_text(&answered);
    assert!(
        up.contains("function_call_output")
            && up.contains("call_cli")
            && up.contains("response.create"),
        "the accepted reply reaches the model and asks it to continue: {up}"
    );
    assert_eq!(
        port.table().rows(),
        0,
        "and the wait left the table, ending and all"
    );
}

/// **A served session's teardown forgets its calls.** A session that ends with a client-served call
/// still open leaves nothing behind in the node's table.
#[tokio::test]
async fn a_served_sessions_teardown_forgets_the_calls_it_had_open() {
    let port = Arc::new(NodeCalls::new(Arc::new(OpenToolCalls::new()), keys()));
    let core = Arc::new(pump_serving_no_tool(&port, 6_161));
    for f in [
        serde_json::json!({"type":"response.output_item.added",
            "item":{"type":"function_call","call_id":"call_left","name":"client_tool"}}),
        serde_json::json!({"type":"response.function_call_arguments.done","call_id":"call_left"}),
    ] {
        let _ = core.on_server_frame(realtime_frame(&f)).await;
    }
    assert_eq!(
        port.table().open(),
        1,
        "the call is waiting when the session ends"
    );

    let rt = crate::runtime::build_runtime(&(), None)
        .downcast::<crate::runtime::VoiceRuntime>()
        .expect("the plane's own runtime");
    let handle = rt.bind_session("acct", "call-teardown");
    handle.open(1).expect("the session's row opens");
    crate::runtime::serve_to_teardown(Arc::clone(&core), handle, async {}, || 2).await;
    assert_eq!(
        port.table().rows(),
        0,
        "the ended session's calls left the table at its teardown"
    );
}

/// A node allocator for the port under test: unique keys from 1, as the kernel's mint hands them.
fn keys() -> Box<dyn Fn() -> UnitKey + Send + Sync> {
    let next = std::sync::atomic::AtomicU64::new(1);
    Box::new(move || UnitKey::new(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)))
}
