//! An in-band system turn reaches a hook AS A TURN, exactly as 1.5.5 showed it (#85, R8).
//!
//! On the dialects that carry the system prompt inside the turn array (openai, cohere, responses),
//! 1.5.5 projected the wire array: a `{role: "system"}` entry was a turn at its wire position, under
//! the role it was written in, and the prompt view's `system` held only the dialect's own system
//! FIELD. A `prompt: rw` hook's reply replaces the whole turn array, so a view that moves the system
//! turn into `system` makes the hook's reply DELETE the operator's system prompt upstream (codeaudit
//! HEAD-1, busbar-hook-headroom). Every expectation below is what v1.5.5's
//! `build_prompt_projection` / `build_rewrite_request` / `apply_rewrite_to_body` produced.

use super::*;
use busbar_contract::hooks::{
    Candidate, PolicyResult, RewriteReply, RoutingContext, RoutingDecision, RoutingPolicy,
    RoutingRequest, TransformOutcome,
};
use std::sync::{Arc, Mutex};

/// What a hook was shown, captured off the wire-facing request.
#[derive(Debug, Clone, PartialEq)]
struct Seen {
    system: Option<String>,
    messages: Vec<(String, String)>,
    message_count: usize,
    system_chars: usize,
    total_chars: usize,
}

/// A headroom-shaped compressor: echoes every turn it is shown as `{role, content}`, keeps a
/// `system` turn and the last turn (the ask) verbatim, and replaces every other turn's text. This
/// is the shape of `headroom-hook`'s `compress` (src/compress.rs), whose system branch is the one a
/// hook can only take when it is shown the system turn.
struct Compressor(Mutex<Option<Seen>>);

#[async_trait::async_trait]
impl RoutingPolicy for Compressor {
    async fn decide(
        &self,
        _r: &RoutingRequest<'_>,
        _c: &[Candidate<'_>],
        _x: &RoutingContext<'_>,
        _b: std::time::Duration,
    ) -> PolicyResult {
        Ok(RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        "system-turn-compressor"
    }
    async fn transform(
        &self,
        req: &RoutingRequest<'_>,
        _budget: std::time::Duration,
    ) -> TransformOutcome {
        let prompt = req.prompt.as_ref().expect("a rw hook is shown the prompt");
        let messages: Vec<(String, String)> = prompt
            .messages
            .iter()
            .map(|(r, t)| (r.to_string(), t.to_string()))
            .collect();
        *self.0.lock().unwrap() = Some(Seen {
            system: prompt.system.as_deref().map(str::to_string),
            messages: messages.clone(),
            message_count: req.message_count,
            system_chars: req.system_chars,
            total_chars: req.total_chars,
        });
        let last = messages.len().saturating_sub(1);
        TransformOutcome::Rewrite(RewriteReply {
            messages: messages
                .iter()
                .enumerate()
                .map(|(i, (role, text))| {
                    let text = if i == last || role == "system" {
                        text.clone()
                    } else {
                        "COMPRESSED".to_string()
                    };
                    serde_json::json!({"role": role, "content": text})
                })
                .collect(),
            tools: vec![],
        })
    }
}

/// Run ONE rw hook over `v` at `proto`; return what it saw.
async fn rewrite(v: &mut Value, proto: &str) -> Seen {
    let hook = Arc::new(Compressor(Mutex::new(None)));
    let hooks: Vec<(std::time::Duration, Arc<dyn RoutingPolicy>)> =
        vec![(std::time::Duration::from_millis(50), hook.clone())];
    let (host, _rt) = crate::engine::test_host_rt(&crate::test_support::TestApp::new().build());
    let applied = apply_global_rewrites(
        &*host,
        &hooks,
        v,
        "pool",
        proto,
        busbar_contract::operation::OpVerb::CHAT,
        false,
        1,
    )
    .await
    .expect("no rewrite hook rejected");
    assert!(applied, "the compressor commits a rewrite");
    let seen = hook.0.lock().unwrap().clone();
    seen.expect("the hook fired")
}

fn turns(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(r, t)| (r.to_string(), t.to_string()))
        .collect()
}

/// THE FINDING. An openai request whose operator system prompt rides `messages[0]`, and a rw hook
/// that commits a rewrite: the upstream body keeps the system turn, byte-identical to 1.5.5.
#[tokio::test]
async fn a_rewrite_keeps_the_in_band_system_turn_upstream() {
    crate::testkit::install_test_seams();
    let mut v = serde_json::json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "OPERATOR SYSTEM PROMPT"},
            {"role": "user", "content": "a long earlier turn"},
            {"role": "assistant", "content": "an earlier answer"},
            {"role": "user", "content": "the ask"}
        ]
    });
    let seen = rewrite(&mut v, "openai").await;
    assert_eq!(
        seen,
        Seen {
            system: None,
            messages: turns(&[
                ("system", "OPERATOR SYSTEM PROMPT"),
                ("user", "a long earlier turn"),
                ("assistant", "an earlier answer"),
                ("user", "the ask"),
            ]),
            message_count: 4,
            system_chars: 0,
            total_chars: 22 + 19 + 17 + 7,
        },
        "the hook must be shown the 1.5.5 view"
    );
    assert_eq!(
        serde_json::to_string(&v["messages"]).unwrap(),
        r#"[{"content":"OPERATOR SYSTEM PROMPT","role":"system"},{"content":"COMPRESSED","role":"user"},{"content":"COMPRESSED","role":"assistant"},{"content":"the ask","role":"user"}]"#,
        "the operator's system prompt must reach the provider, exactly as 1.5.5 sent it"
    );
}

/// Position and role survive: a `developer` turn mid-conversation is shown where it stood, under
/// `developer`, and it is written back there.
#[tokio::test]
async fn a_mid_conversation_developer_turn_keeps_its_place_and_role() {
    crate::testkit::install_test_seams();
    let mut v = serde_json::json!({
        "model": "o3",
        "messages": [
            {"role": "user", "content": "u1"},
            {"role": "developer", "content": "DEV"},
            {"role": "user", "content": "u2"}
        ]
    });
    let seen = rewrite(&mut v, "openai").await;
    assert_eq!(seen.system, None);
    assert_eq!(
        seen.messages,
        turns(&[("user", "u1"), ("developer", "DEV"), ("user", "u2")])
    );
    assert_eq!((seen.message_count, seen.system_chars, seen.total_chars), (3, 0, 7));
    assert_eq!(
        v["messages"],
        serde_json::json!([
            {"role": "user", "content": "COMPRESSED"},
            {"role": "developer", "content": "COMPRESSED"},
            {"role": "user", "content": "u2"}
        ]),
        "1.5.5 shipped whatever the hook answered for the developer turn"
    );
}

/// Cohere carries its system prompt in `messages` too.
#[tokio::test]
async fn cohere_in_band_system_turn_is_a_turn() {
    crate::testkit::install_test_seams();
    let mut v = serde_json::json!({
        "model": "command-r",
        "messages": [
            {"role": "system", "content": "OPERATOR SYSTEM PROMPT"},
            {"role": "user", "content": "earlier"},
            {"role": "user", "content": "hi"}
        ]
    });
    let seen = rewrite(&mut v, "cohere").await;
    assert_eq!(seen.system, None);
    assert_eq!(
        seen.messages,
        turns(&[
            ("system", "OPERATOR SYSTEM PROMPT"),
            ("user", "earlier"),
            ("user", "hi")
        ])
    );
    assert_eq!((seen.message_count, seen.system_chars), (3, 0));
    assert_eq!(v["messages"][0]["role"], "system");
    assert_eq!(v["messages"][0]["content"], "OPERATOR SYSTEM PROMPT");
}

/// Responses: `instructions` is the dialect's own system FIELD (shown as `system`), and a
/// `system`-role input item is a turn.
#[test]
fn responses_instructions_are_system_and_a_system_item_is_a_turn() {
    crate::testkit::install_test_seams();
    let v = serde_json::json!({
        "model": "gpt-4o",
        "instructions": "INSTR",
        "input": [
            {"role": "system", "content": "S"},
            {"role": "user", "content": "hi"}
        ]
    });
    let f = read_hook_facts(
        &v,
        &[],
        APPLICATION_JSON,
        "responses",
        Some(busbar_contract::operation::OpVerb::CHAT),
    )
    .unwrap_or_else(|_| panic!("the responses reader accepts this body"));
    let p = f.prompt();
    assert_eq!(p.system.as_deref(), Some("INSTR"));
    let got: Vec<(String, String)> = p
        .messages
        .iter()
        .map(|(r, t)| (r.to_string(), t.to_string()))
        .collect();
    assert_eq!(got, turns(&[("system", "S"), ("user", "hi")]));
    let shape = f.shape();
    assert_eq!((shape.turn_count, shape.system_chars), (2, 5));
}
