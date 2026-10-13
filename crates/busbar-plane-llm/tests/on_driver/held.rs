// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hook tests the legacy llm crate carries beyond the 1.5.5 set, held on the driver before that
//! crate is deleted: the access amendment a hook handed the prompt leaves (`hook_access_tests`),
//! the operation-general projection (`hook_non_chat_projection_tests`) and the in-band system turn
//! (`hook_system_turn_tests`), each under its name with its values. The two seat-order tests ride
//! the serving path's real admission and ledger, and are held there.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::hooks::{
    Candidate, PolicyResult, RewriteReply, RoutingContext, RoutingDecision, RoutingPolicy,
    RoutingRequest, TransformOutcome,
};
use busbar_kernel::audit::amend::{node_recent, Access, AmendBody, Reader};
use busbar_kernel::config::PolicyOnError;
use busbar_kernel::hooks::{FallbackHook, ResolvedPolicy};
use serde_json::{json, Value};

use super::policies::capturing;
use crate::rig::{member, Answered, Hooks, Pool, Rig};

// ── the access amendment ─────────────────────────────────────────────────────────────────────────

/// Every hook access the node journal holds for `name` (the journal is process-wide: every hook
/// here carries a name no other test uses).
fn accesses(name: &str) -> Vec<Access> {
    node_recent()
        .into_iter()
        .filter_map(|a| match a.body {
            AmendBody::Access(access) if access.reader == Reader::Hook && access.name == name => {
                Some(access)
            }
            _ => None,
        })
        .collect()
}

/// A hook that abstains, rewrites nothing and swallows a tap: only its name matters.
struct Named {
    name: &'static str,
    fails: bool,
}

#[async_trait::async_trait]
impl RoutingPolicy for Named {
    async fn decide(
        &self,
        _: &RoutingRequest<'_>,
        _: &[Candidate<'_>],
        _: &RoutingContext<'_>,
        _: Duration,
    ) -> PolicyResult {
        if self.fails {
            return Err("deliberately broken".into());
        }
        Ok(RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        self.name
    }
    async fn transform(&self, _: &RoutingRequest<'_>, _: Duration) -> TransformOutcome {
        TransformOutcome::Abstain
    }
}

fn named(name: &'static str) -> Arc<dyn RoutingPolicy> {
    Arc::new(Named { name, fails: false })
}

fn policy(
    primary: Arc<dyn RoutingPolicy>,
    send_prompt: bool,
    send_user: bool,
    on_error_chain: Vec<FallbackHook>,
) -> ResolvedPolicy {
    ResolvedPolicy::Policy {
        policy: primary,
        on_error: PolicyOnError::Weighted,
        on_error_chain,
        timeout: Duration::from_millis(500),
        send_prompt,
        send_user,
        on_empty: PolicyOnError::Reject,
    }
}

fn access_body() -> Value {
    json!({
        "model": "m0",
        "max_tokens": 16,
        "system": "sys prompt",
        "metadata": {"user_id": "alice"},
        "messages": [{"role": "user", "content": "hello"}]
    })
}

fn one() -> Pool {
    Pool {
        name: "p",
        members: vec![member("m0", "m0")],
    }
}

async fn decide(resolved: ResolvedPolicy) {
    let rig = Rig::new(
        one(),
        None,
        Hooks {
            policy: Some(resolved),
            ..Hooks::default()
        },
    );
    rig.fire(&access_body()).await;
}

#[tokio::test]
async fn a_decision_gate_handed_the_prompt_leaves_exactly_one_access_amendment() {
    decide(policy(
        named("access-decide-prompt"),
        true,
        true,
        Vec::new(),
    ))
    .await;
    let seen = accesses("access-decide-prompt");
    assert_eq!(seen.len(), 1, "one access per hand-over: {seen:?}");
    assert_eq!(seen[0].op_class.as_str(), "anthropic");
    assert_eq!(
        seen[0].fields,
        vec!["content".to_string(), "identity".to_string()],
        "field NAMES that crossed, never their values"
    );
}

#[tokio::test]
async fn a_decision_gate_handed_only_the_shape_leaves_no_access_amendment() {
    decide(policy(
        named("access-decide-shape"),
        false,
        true,
        Vec::new(),
    ))
    .await;
    assert!(accesses("access-decide-shape").is_empty());
}

#[tokio::test]
async fn an_on_error_fallback_handed_the_prompt_leaves_its_own_access_amendment() {
    let primary: Arc<dyn RoutingPolicy> = Arc::new(Named {
        name: "access-primary-fails",
        fails: true,
    });
    let fallback = FallbackHook {
        policy: named("access-fallback-prompt"),
        timeout: Duration::from_millis(500),
        send_prompt: true,
        send_user: false,
        on_empty: PolicyOnError::Reject,
    };
    decide(policy(primary, true, false, vec![fallback])).await;
    assert_eq!(accesses("access-primary-fails").len(), 1);
    let seen = accesses("access-fallback-prompt");
    assert_eq!(
        seen.len(),
        1,
        "the fallback was handed the prompt: {seen:?}"
    );
    assert_eq!(seen[0].fields, vec!["content".to_string()]);
}

#[tokio::test]
async fn an_on_error_fallback_without_the_prompt_grant_leaves_no_access_amendment() {
    let primary: Arc<dyn RoutingPolicy> = Arc::new(Named {
        name: "access-primary-fails-2",
        fails: true,
    });
    let fallback = FallbackHook {
        policy: named("access-fallback-shape"),
        timeout: Duration::from_millis(500),
        send_prompt: false,
        send_user: false,
        on_empty: PolicyOnError::Reject,
    };
    decide(policy(primary, true, false, vec![fallback])).await;
    assert!(accesses("access-fallback-shape").is_empty());
}

#[tokio::test]
async fn a_rewrite_hook_handed_the_prompt_leaves_exactly_one_access_amendment() {
    let rig = Rig::new(
        one(),
        None,
        Hooks {
            rewrites: vec![(Duration::from_millis(500), named("access-rewrite"))],
            ..Hooks::default()
        },
    );
    rig.fire(&access_body()).await;
    let seen = accesses("access-rewrite");
    assert_eq!(seen.len(), 1, "one access per hand-over: {seen:?}");
    assert_eq!(seen[0].fields, vec!["content".to_string()]);
}

#[tokio::test]
async fn a_global_tap_leaves_an_access_amendment_only_when_handed_the_prompt() {
    let ms = Duration::from_millis(500);
    let mut hooks = Hooks::default();
    hooks.taps.request = vec![
        (ms, true, named("access-tap-prompt"), Vec::new()),
        (ms, false, named("access-tap-shape"), Vec::new()),
    ];
    let rig = Rig::new(one(), None, hooks);
    rig.fire(&json!({
        "model": "p",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 10
    }))
    .await;
    assert_eq!(accesses("access-tap-prompt").len(), 1);
    assert!(accesses("access-tap-shape").is_empty());
}

// ── the operation-general projection ─────────────────────────────────────────────────────────────

/// The exact strings a `prompt: ro` hook is shown for `body` posted to `path`, flattened across
/// turns, and the size signal.
async fn gate_view(path: &str, content_type: &str, body: &[u8]) -> (String, usize) {
    let (seen, policy) = capturing(true, false, None);
    let rig = Rig::new(
        Pool {
            name: "p",
            members: vec![member("m0", "m0").provider("oai")],
        },
        None,
        Hooks {
            policy: Some(policy),
            ..Hooks::default()
        },
    );
    rig.fire_with(
        &crate::common::TestUnits::passing(),
        path,
        &[("content-type", content_type)],
        body,
    )
    .await;
    let captured = seen.lock().unwrap().clone();
    let c = captured.unwrap_or_else(|| panic!("the hook was shown the request at {path}"));
    let (system, messages) = c.prompt.expect("a prompt: ro hook is shown the prompt");
    let mut out: Vec<String> = system.into_iter().collect();
    out.extend(messages.into_iter().map(|(_, t)| t));
    (out.join("\n"), c.total_chars)
}

async fn json_view(path: &str, v: Value) -> (String, usize) {
    gate_view(
        path,
        "application/json",
        &serde_json::to_vec(&v).expect("body serializes"),
    )
    .await
}

#[tokio::test]
async fn embeddings_body_is_no_longer_gate_blind() {
    let (view, chars) = json_view(
        "/v1/embeddings",
        json!({"model": "m0", "input": "SCREEN-THIS-INPUT"}),
    )
    .await;
    assert!(chars > 0, "embeddings request must not project empty");
    assert!(view.contains("SCREEN-THIS-INPUT"));
}

#[tokio::test]
async fn image_body_is_no_longer_gate_blind() {
    let (view, _) = json_view(
        "/v1/images/generations",
        json!({"model": "m0", "prompt": "SCREEN-THIS-PROMPT"}),
    )
    .await;
    assert!(view.contains("SCREEN-THIS-PROMPT"));
}

#[tokio::test]
async fn speech_body_projects_input_and_instructions() {
    // The OpenAI `/v1/audio/speech` request body as a client sends it.
    let v: Value = serde_json::from_str(include_str!("speech_request.json"))
        .expect("the speech request fixture is JSON");
    let (view, _) = json_view("/v1/audio/speech", v).await;
    assert!(view.contains("SPEAK-THIS"));
    assert!(
        view.contains("STYLE-INSTRUCTIONS"),
        "instructions must be screened"
    );
}

#[tokio::test]
async fn moderation_body_projects_text_and_marks_image_url_opaque() {
    let (view, _) = json_view(
        "/v1/moderations",
        json!({
            "model": "m0",
            "input": [
                {"type": "text", "text": "SCREEN-THIS-TEXT"},
                {"type": "image_url", "image_url": {"url": "https://x.test/y.png"}}
            ]
        }),
    )
    .await;
    assert!(view.contains("SCREEN-THIS-TEXT"));
    // The image URL is present-but-unscreenable, shown as the marker — not empty, not leaked.
    assert!(view.contains(busbar_contract::ir::facts::OPAQUE_CONTENT_MARKER));
    assert!(!view.contains("x.test"));
}

#[tokio::test]
async fn rerank_body_projects_query_and_documents() {
    let (view, _) = json_view(
        "/v2/rerank",
        json!({"model": "m0", "query": "THE-QUERY", "documents": ["DOC-ONE", "DOC-TWO"]}),
    )
    .await;
    assert!(view.contains("THE-QUERY") && view.contains("DOC-ONE") && view.contains("DOC-TWO"));
}

#[tokio::test]
async fn transcription_prompt_is_seen_through_the_byte_seam() {
    let boundary = "----busbartestBOUNDARY";
    let body = format!(
        "--{b}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nm0\r\n\
         --{b}\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\nSCREEN-THIS-PROMPT\r\n\
         --{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.mp3\"\r\n\
         Content-Type: audio/mpeg\r\n\r\nRAWAUDIOBYTES\r\n\
         --{b}--\r\n",
        b = boundary
    );
    let ct = format!("multipart/form-data; boundary={boundary}");
    let (view, _) = gate_view("/v1/audio/transcriptions", &ct, body.as_bytes()).await;
    assert!(
        view.contains("SCREEN-THIS-PROMPT"),
        "the multipart transcription prompt must be screenable through the byte reader"
    );
}

// ── the in-band system turn ──────────────────────────────────────────────────────────────────────

/// What a hook was shown.
#[derive(Debug, Clone, PartialEq)]
struct Seen {
    system: Option<String>,
    messages: Vec<(String, String)>,
    message_count: usize,
    total_chars: usize,
}

/// A headroom-shaped compressor: echoes every turn as `{role, content}`, keeps a `system` turn and
/// the last turn verbatim, and replaces every other turn's text.
struct Compressor(Mutex<Option<Seen>>);

#[async_trait::async_trait]
impl RoutingPolicy for Compressor {
    async fn decide(
        &self,
        _: &RoutingRequest<'_>,
        _: &[Candidate<'_>],
        _: &RoutingContext<'_>,
        _: Duration,
    ) -> PolicyResult {
        Ok(RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        "system-turn-compressor"
    }
    async fn transform(&self, req: &RoutingRequest<'_>, _: Duration) -> TransformOutcome {
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
                    json!({"role": role, "content": text})
                })
                .collect(),
            tools: vec![],
        })
    }
}

/// One rw hook over `v` posted to `path` in a same-dialect pool served by `provider`: what the
/// hook saw, and the body the far end was sent.
async fn rewrite(path: &str, provider: &'static str, v: Value) -> (Seen, Value) {
    let hook = Arc::new(Compressor(Mutex::new(None)));
    let rig = Rig::new(
        Pool {
            name: "p",
            members: vec![member("m0", "m0").provider(provider)],
        },
        None,
        Hooks {
            rewrites: vec![(Duration::from_millis(50), hook.clone())],
            ..Hooks::default()
        },
    );
    let answer: Answered = rig
        .fire_with(
            &crate::common::TestUnits::passing(),
            path,
            &[("content-type", "application/json")],
            &serde_json::to_vec(&v).expect("body serializes"),
        )
        .await;
    let seen = hook.0.lock().unwrap().clone().expect("the hook fired");
    let sent = answer
        .sent
        .last()
        .expect("the rewritten request was dispatched");
    (
        seen,
        serde_json::from_slice(&sent.body).expect("the far end's body is JSON"),
    )
}

fn turns(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(r, t)| (r.to_string(), t.to_string()))
        .collect()
}

#[tokio::test]
async fn a_rewrite_keeps_the_in_band_system_turn_upstream() {
    let (seen, sent) = rewrite(
        "/v1/chat/completions",
        "oai",
        json!({
            "model": "m0",
            "messages": [
                {"role": "system", "content": "OPERATOR SYSTEM PROMPT"},
                {"role": "user", "content": "a long earlier turn"},
                {"role": "assistant", "content": "an earlier answer"},
                {"role": "user", "content": "the ask"}
            ]
        }),
    )
    .await;
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
            total_chars: 22 + 19 + 17 + 7,
        },
        "the hook must be shown the 1.5.5 view"
    );
    assert_eq!(
        serde_json::to_string(&sent["messages"]).unwrap(),
        r#"[{"content":"OPERATOR SYSTEM PROMPT","role":"system"},{"content":"COMPRESSED","role":"user"},{"content":"COMPRESSED","role":"assistant"},{"content":"the ask","role":"user"}]"#,
        "the operator's system prompt must reach the provider, exactly as 1.5.5 sent it"
    );
}

#[tokio::test]
async fn a_mid_conversation_developer_turn_keeps_its_place_and_role() {
    let (seen, sent) = rewrite(
        "/v1/chat/completions",
        "oai",
        json!({
            "model": "m0",
            "messages": [
                {"role": "user", "content": "u1"},
                {"role": "developer", "content": "DEV"},
                {"role": "user", "content": "u2"}
            ]
        }),
    )
    .await;
    assert_eq!(seen.system, None);
    assert_eq!(
        seen.messages,
        turns(&[("user", "u1"), ("developer", "DEV"), ("user", "u2")])
    );
    assert_eq!((seen.message_count, seen.total_chars), (3, 7));
    assert_eq!(
        sent["messages"],
        json!([
            {"role": "user", "content": "COMPRESSED"},
            {"role": "developer", "content": "COMPRESSED"},
            {"role": "user", "content": "u2"}
        ]),
        "1.5.5 shipped whatever the hook answered for the developer turn"
    );
}

#[tokio::test]
async fn cohere_in_band_system_turn_is_a_turn() {
    let (seen, sent) = rewrite(
        "/v2/chat",
        "coh",
        json!({
            "model": "m0",
            "messages": [
                {"role": "system", "content": "OPERATOR SYSTEM PROMPT"},
                {"role": "user", "content": "earlier"},
                {"role": "user", "content": "hi"}
            ]
        }),
    )
    .await;
    assert_eq!(seen.system, None);
    assert_eq!(
        seen.messages,
        turns(&[
            ("system", "OPERATOR SYSTEM PROMPT"),
            ("user", "earlier"),
            ("user", "hi")
        ])
    );
    assert_eq!(seen.message_count, 3);
    assert_eq!(sent["messages"][0]["role"], "system");
    assert_eq!(sent["messages"][0]["content"], "OPERATOR SYSTEM PROMPT");
}

#[tokio::test]
async fn responses_instructions_are_system_and_a_system_item_is_a_turn() {
    let (seen, policy) = capturing(true, false, None);
    let rig = Rig::new(
        one(),
        None,
        Hooks {
            policy: Some(policy),
            ..Hooks::default()
        },
    );
    rig.fire_with(
        &crate::common::TestUnits::passing(),
        "/v1/responses",
        &[("content-type", "application/json")],
        &serde_json::to_vec(&json!({
            "model": "m0",
            "instructions": "INSTR",
            "input": [
                {"role": "system", "content": "S"},
                {"role": "user", "content": "hi"}
            ]
        }))
        .unwrap(),
    )
    .await;
    let c = seen.lock().unwrap().clone().expect("the hook was shown it");
    let (system, messages) = c.prompt.expect("prompt shown");
    assert_eq!(system.as_deref(), Some("INSTR"));
    assert_eq!(messages, turns(&[("system", "S"), ("user", "hi")]));
    assert_eq!(c.message_count, 2);
}
