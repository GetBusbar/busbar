// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A REWRITE HOOK'S NAMED `on_error` FALLBACK (Aikido 1074606944, #103). A `prompt: rw` gate whose
//! `on_error` names another hook hands that hook the request as it stood before the failed
//! rewrite when its rewrite fails (malformed, failed or timed out), and the fallback's decision
//! governs. No part of the failed rewrite is ever sent anywhere: not to the fallback, not upstream.
//! When the fallback cannot decide either, the chain's terminal applies.
//!
//! These drive the resolved rewrite chain exactly as boot builds it ([`resolve_rewrite_hooks`])
//! over real hook transports, so the primary's malformed rewrite crosses the same
//! `transformed()` reading the plane uses.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::hook::{DecideOut, TransformOut};
use busbar_contract::abi::host::hook::{DecideFrame, NotifyFrame};
use busbar_contract::abi::sdk::hook::{RewriteVerdict, Verdict};
use busbar_contract::hook_calls::{Answered, HookAxis, HookCalls, Pending, Probed};
use busbar_contract::hooks::TransformOutcome;

use super::*;
use crate::config::{HookCfg, HookKind, PromptAccess, UserAccess};

const PRIMARY: &str = "redactor";
const PRIMARY_PLUGIN: &str = "redactor-plugin";
const SCREEN: &str = "screen";
const SCREEN_PLUGIN: &str = "screen-plugin";
const ORIGINAL: &str = "my card is 4111 1111 1111 1111";
const PARTIAL: &str = "my card is [REDACTED]";

/// How the primary rewrite hook fails.
#[derive(Clone, Copy, Debug)]
enum Primary {
    /// A requested rewrite that is not a rewrite (`messages` is not an array).
    Malformed,
    /// A requested rewrite whose messages read but whose `tools` do not: a part rewrite.
    Partial,
    /// No answer inside the deadline.
    TimedOut,
}

/// What the named fallback answers.
#[derive(Clone, Copy, Debug)]
enum Screen {
    Pass,
    Refuse,
    Down,
}

/// Every request the fallback was sent, as the `(role, text)` turns it could read.
type Seen = Arc<Mutex<Vec<Vec<(String, String)>>>>;

struct RewriteCalls(Primary);

impl HookCalls for RewriteCalls {
    fn name(&self) -> &str {
        PRIMARY
    }
    fn decide(&self, _: Arc<DecideFrame>, _: Duration) -> Pending<Answered<DecideOut>> {
        Box::pin(async { Answered::Broken("a rewrite hook is not asked to decide".into()) })
    }
    fn transform(&self, frame: Arc<DecideFrame>, _: Duration) -> Pending<Answered<TransformOut>> {
        let primary = self.0;
        Box::pin(async move {
            let rewrite = match primary {
                Primary::TimedOut => return Answered::TimedOut,
                Primary::Malformed => br#"{"messages":"half"}"#.to_vec(),
                Primary::Partial => format!(
                    r#"{{"messages":[{{"role":"user","content":"{PARTIAL}"}}],"tools":"x"}}"#
                )
                .into_bytes(),
            };
            // `TransformOut` carries raw pointers (not `Send`), so it is built inside the future.
            let (outcome, out) = frame.answer_transform(&RewriteVerdict::Rewrite(rewrite));
            Answered::Answer {
                outcome,
                out,
                error: None,
                frame,
            }
        })
    }
    fn notify(&self, _: Arc<NotifyFrame>, _: Duration) -> Pending<()> {
        Box::pin(std::future::ready(()))
    }
    fn configure(
        &self,
        _: &str,
        _: &busbar_contract::plugin_settings::ResolvedSettings,
        _: u64,
        _: Duration,
    ) -> Pending<Result<(), String>> {
        Box::pin(std::future::ready(Ok(())))
    }
    fn status(&self, _: Duration) -> Pending<Option<Vec<u8>>> {
        Box::pin(std::future::ready(None))
    }
    fn describe(&self, _: Duration) -> Pending<Option<Vec<u8>>> {
        Box::pin(std::future::ready(None))
    }
}

struct ScreenCalls {
    answer: Screen,
    seen: Seen,
}

impl HookCalls for ScreenCalls {
    fn name(&self) -> &str {
        SCREEN
    }
    fn decide(&self, frame: Arc<DecideFrame>, _: Duration) -> Pending<Answered<DecideOut>> {
        let turns: Vec<(String, String)> = frame.decoded(|d| {
            d.prompt
                .as_ref()
                .map(|p| {
                    p.messages
                        .iter()
                        .map(|(r, t)| (r.to_string(), t.to_string()))
                        .collect()
                })
                .unwrap_or_default()
        });
        self.seen.lock().unwrap().push(turns);
        let answer = self.answer;
        Box::pin(async move {
            let verdict = match answer {
                Screen::Down => return Answered::TimedOut,
                Screen::Pass => Verdict::Abstain,
                Screen::Refuse => Verdict::Reject {
                    status: Some(451),
                    message: "a card number may not leave".into(),
                },
            };
            // `DecideOut` carries raw pointers (not `Send`), so it is built inside the future.
            let (outcome, out) = frame.answer_decide(&verdict);
            Answered::Answer {
                outcome,
                out,
                error: None,
                frame,
            }
        })
    }
    fn transform(&self, _: Arc<DecideFrame>, _: Duration) -> Pending<Answered<TransformOut>> {
        Box::pin(async {
            Answered::Broken("the fallback decides; it is not asked to rewrite".into())
        })
    }
    fn notify(&self, _: Arc<NotifyFrame>, _: Duration) -> Pending<()> {
        Box::pin(std::future::ready(()))
    }
    fn configure(
        &self,
        _: &str,
        _: &busbar_contract::plugin_settings::ResolvedSettings,
        _: u64,
        _: Duration,
    ) -> Pending<Result<(), String>> {
        Box::pin(std::future::ready(Ok(())))
    }
    fn status(&self, _: Duration) -> Pending<Option<Vec<u8>>> {
        Box::pin(std::future::ready(None))
    }
    fn describe(&self, _: Duration) -> Pending<Option<Vec<u8>>> {
        Box::pin(std::future::ready(None))
    }
}

/// An axis serving the two hooks: the primary rewrite hook and its named fallback.
struct Axis {
    primary: Primary,
    screen: Screen,
    seen: Seen,
}

impl HookAxis for Axis {
    fn probe(
        &self,
        _: &str,
        _: &str,
        _: &busbar_contract::plugin_settings::ResolvedSettings,
    ) -> Option<Probed> {
        None
    }
    fn open(
        &self,
        module: &str,
        _: &str,
        _: &busbar_contract::plugin_settings::ResolvedSettings,
        _: Duration,
    ) -> Result<Arc<dyn HookCalls>, String> {
        match module {
            PRIMARY_PLUGIN => Ok(Arc::new(RewriteCalls(self.primary))),
            SCREEN_PLUGIN => Ok(Arc::new(ScreenCalls {
                answer: self.screen,
                seen: Arc::clone(&self.seen),
            })),
            other => Err(format!("no hook plugin '{other}'")),
        }
    }
    fn linked(&self, module: &str) -> bool {
        module == PRIMARY_PLUGIN || module == SCREEN_PLUGIN
    }
    fn call_budget(&self) -> Duration {
        Duration::from_secs(1)
    }
    fn first_party(&self, _: &str) -> bool {
        true
    }
}

fn gate(plugin: &str, prompt: PromptAccess, on_error: &str) -> HookCfg {
    HookCfg {
        kind: HookKind::Gate,
        plugin: plugin.to_string(),
        timeout_ms: 1000,
        on_error: on_error.to_string(),
        prompt,
        user: UserAccess::No,
        priority: 0,
        settings: serde_json::Map::new().into(),
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    }
}

/// The primary rewrite hook (`prompt: rw`, `on_error: screen`) as boot resolves it, with the
/// fallback `screen` (`prompt: ro`) whose own `on_error` is `terminal`.
fn resolved(primary: Primary, screen: Screen, terminal: &str) -> (Arc<dyn RoutingPolicy>, Seen) {
    resolved_with(primary, screen, PromptAccess::Ro, terminal)
}

fn resolved_with(
    primary: Primary,
    screen: Screen,
    screen_prompt: PromptAccess,
    terminal: &str,
) -> (Arc<dyn RoutingPolicy>, Seen) {
    let seen: Seen = Arc::default();
    let env = HookEnv::with_axis(
        Arc::new(busbar_plugin_loader::PluginRegistry::empty()),
        Arc::new(Axis {
            primary,
            screen,
            seen: Arc::clone(&seen),
        }),
        Arc::new(crate::config::secret::SecretResolver::builtins_only()),
    );
    let mut hooks = std::collections::HashMap::new();
    hooks.insert(
        PRIMARY.to_string(),
        gate(PRIMARY_PLUGIN, PromptAccess::Rw, SCREEN),
    );
    hooks.insert(
        SCREEN.to_string(),
        gate(SCREEN_PLUGIN, screen_prompt, terminal),
    );
    let mut chain = resolve_rewrite_hooks(&hooks, &[PRIMARY.to_string()], &env, 0);
    assert_eq!(
        chain.len(),
        1,
        "the `prompt: rw` gate resolves as one rewrite hook"
    );
    let (_, policy) = chain.remove(0);
    (policy, seen)
}

/// The request the rewrite pass hands the primary: one user turn carrying the original text.
fn request() -> RoutingRequest<'static> {
    RoutingRequest {
        request_id: 1,
        pool: "pool",
        ingress_protocol: "test-dialect",
        requested_model: None,
        message_count: 1,
        tool_count: 0,
        has_tools: false,
        total_chars: ORIGINAL.len(),
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: Some(PromptProjection {
            system: None,
            messages: vec![("user".into(), ORIGINAL.into())],
        }),
        identity: None,
        signals: SignalBag::new(),
        session: None,
    }
}

fn original_turns() -> Vec<Vec<(String, String)>> {
    vec![vec![("user".to_string(), ORIGINAL.to_string())]]
}

/// The rewrite pass's entry into a resolved rewrite hook.
async fn rewrite(policy: &dyn RoutingPolicy) -> TransformOutcome {
    policy
        .transform_recording(&request(), Duration::from_secs(1), &Recorded)
        .await
}

struct Recorded;

#[async_trait::async_trait]
impl busbar_contract::hooks::ReadRecorder for Recorded {
    async fn record(&self, hook: &str, identity: bool) -> bool {
        assert_eq!(hook, SCREEN);
        assert!(!identity);
        true
    }
}

#[tokio::test]
async fn a_plane_rejected_rewrite_screens_the_unchanged_request() {
    let (policy, seen) = resolved(Primary::Malformed, Screen::Refuse, "weighted");
    let outcome = policy
        .fallback_rewrite_recording(&request(), &Recorded)
        .await;
    assert!(matches!(
        outcome,
        Some(TransformOutcome::Reject { status: 451, .. })
    ));
    assert_eq!(*seen.lock().unwrap(), original_turns());
}

#[tokio::test]
async fn fallback_content_is_not_sent_without_a_confirmed_read() {
    let (policy, seen) = resolved(Primary::Malformed, Screen::Pass, "weighted");
    let outcome = policy.transform(&request(), Duration::from_secs(1)).await;
    assert!(matches!(outcome, TransformOutcome::Reject { .. }));
    assert!(seen.lock().unwrap().is_empty());
}

/// (a) The primary's rewrite fails (malformed, or no answer in time): the named fallback is sent
/// the original request, and its decision governs. Here it passes, so the request proceeds
/// unmodified even though the chain's terminal is `reject`: the terminal applies only when the
/// fallback cannot decide.
#[tokio::test]
async fn a_failed_rewrite_hands_the_original_request_to_the_named_fallback() {
    for primary in [Primary::Malformed, Primary::TimedOut] {
        let (policy, seen) = resolved(primary, Screen::Pass, "reject");
        let outcome = rewrite(&*policy).await;
        assert_eq!(
            *seen.lock().unwrap(),
            original_turns(),
            "{primary:?}: the fallback is sent the original request, once"
        );
        assert!(
            matches!(outcome, TransformOutcome::Failed { .. }),
            "{primary:?}: the fallback passed, so the request proceeds with its original body \
             (the terminal `reject` does not apply): {outcome:?}"
        );
    }
}

/// (b) The fallback refuses: the request is refused with the fallback's own answer, even though
/// the chain's terminal (`weighted`) would have let it through.
#[tokio::test]
async fn a_fallback_that_refuses_after_a_failed_rewrite_refuses_the_request() {
    for primary in [Primary::Malformed, Primary::Partial, Primary::TimedOut] {
        let (policy, seen) = resolved(primary, Screen::Refuse, "weighted");
        let outcome = rewrite(&*policy).await;
        assert_eq!(*seen.lock().unwrap(), original_turns(), "{primary:?}");
        match outcome {
            TransformOutcome::Reject { status, message } => {
                assert_eq!(status, 451, "{primary:?}: the fallback's own status");
                assert_eq!(message, "a card number may not leave", "{primary:?}");
            }
            other => panic!("{primary:?}: the fallback's refusal refuses the request: {other:?}"),
        }
    }
}

/// (c) A part rewrite (its messages read, its tools do not) is a failed rewrite. Whatever the
/// fallback answers, none of it is sent anywhere: the fallback reads the original turns, and the
/// outcome is never a rewrite, so the plane forwards the original body or refuses (the plane's
/// own arms for `Failed` and `Reject`).
#[tokio::test]
async fn no_part_of_a_failed_rewrite_reaches_the_fallback_or_the_upstream() {
    for screen in [Screen::Pass, Screen::Refuse, Screen::Down] {
        for terminal in ["weighted", "reject"] {
            let (policy, seen) = resolved(Primary::Partial, screen, terminal);
            let outcome = rewrite(&*policy).await;
            let case = format!("{screen:?}, terminal {terminal}");
            assert_eq!(
                *seen.lock().unwrap(),
                original_turns(),
                "{case}: the fallback reads the original turns, never the part rewrite"
            );
            assert!(
                !matches!(outcome, TransformOutcome::Rewrite(_)),
                "{case}: no part of a failed rewrite goes upstream: {outcome:?}"
            );
        }
    }
}

/// The fallback cannot decide either (no answer in time): the chain's terminal applies, and a
/// `reject` terminal fails closed with the shared required-hook answer.
#[tokio::test]
async fn a_fallback_that_also_fails_leaves_the_terminal_to_decide() {
    let (policy, _) = resolved(Primary::Malformed, Screen::Down, "reject");
    match rewrite(&*policy).await {
        TransformOutcome::Reject { status, message } => {
            assert_eq!(status, REQUIRED_HOOK_UNAVAILABLE_STATUS);
            assert_eq!(message, REQUIRED_HOOK_UNAVAILABLE_MESSAGE);
        }
        other => panic!("a `reject` terminal refuses: {other:?}"),
    }
    let (policy, _) = resolved(Primary::Malformed, Screen::Down, "weighted");
    let outcome = rewrite(&*policy).await;
    assert!(
        matches!(outcome, TransformOutcome::Failed { .. }),
        "a `weighted` terminal proceeds with the original body: {outcome:?}"
    );
}
