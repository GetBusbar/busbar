// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::hooks::{
    Candidate, FallbackHook, ResolvedPolicy, RoutingContext, RoutingDecision, RoutingRequest,
};
use busbar_contract::hook_wire::reply::{clamp_reject_status, sanitize_reject_message};
use busbar_contract::ir::facts::{ContentItem, IrFacts, ScreenedContent, Slot};
use busbar_kernel_audit::record::{HookApplied, HookHead};
use std::borrow::Cow;

pub(crate) enum GateVerdict {
    Proceed,

    Reject {
        status: u16,
        message: String,

        hook: String,
    },
}

pub(crate) struct GateSubject<'a> {
    pub(crate) facts: &'a (dyn IrFacts + Sync),

    pub(crate) container: &'a str,

    pub(crate) ingress_protocol: &'a str,

    pub(crate) request_id: u64,

    pub(crate) key: Option<&'a busbar_contract::records::VirtualKey>,

    pub(crate) incremental: Option<IncrementalScan<'a>>,

    pub(crate) session: Option<&'a [u8]>,

    pub(crate) reads: &'a HookReads<'a>,
}

pub(crate) type HookReads<'a> = dyn Fn(&str, Option<&str>, &str, bool) + Send + Sync + 'a;

/// The gate's tenant of the session substrate: one bounded cache slot per content piece screened
/// clean for a `(session, hook)`, so a long session re-screens only NEW or evicted content instead
/// of the whole growing context every turn.
///
/// The screening HOOK never learns about sessions — this bookkeeping is pure neutral core (a session
/// id + [`ContentItem::screening_digest`]). Safe degradation: a cold/evicted slot just means more gets
/// re-screened — never wrong, only less optimised. A BLOCKED (rejected) piece is never recorded, so it
/// is re-screened on retry. An OPAQUE piece is always re-surfaced (a presence signal, never cleared).
#[derive(Clone, Copy)]
pub(crate) struct IncrementalScan<'a> {
    /// The neutral session substrate the cleared pieces live in.
    pub(crate) store: &'a crate::session::SessionStore,
    /// This request's session identity (a stable hash of the session key already read at ingress).
    pub(crate) session: crate::session::SessionKey,
    /// Epoch millis for the substrate's TTL — passed in, no ambient clock here.
    pub(crate) now_ms: u64,
}

struct ClearedPiece {
    session: crate::session::SessionKey,
    clearance: Box<str>,
    digest: Box<str>,
}

impl IncrementalScan<'_> {
    const OWNER: crate::session::OwnerKey = "gate.screen";

    pub(crate) fn derive_session_key_octets(
        sid: &[u8],
        principal_id: &str,
        hook_generation: u64,
    ) -> crate::session::SessionKey {
        let head = format!(
            "g={hook_generation}\u{1f}p{}={principal_id}\u{1f}s{}=",
            principal_id.len(),
            sid.len()
        );
        let mut hash = busbar_kernel::store::FNV1A_OFFSET_BASIS;
        for &byte in head.as_bytes().iter().chain(sid) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(busbar_kernel::store::FNV1A_PRIME);
        }
        crate::session::SessionKey(hash)
    }

    fn piece_key(&self, clearance: &str, digest: &str) -> crate::session::SessionKey {
        use std::hash::{Hash, Hasher};
        let mut index = std::collections::hash_map::DefaultHasher::new();
        (self.session, clearance, digest).hash(&mut index);
        crate::session::SessionKey(index.finish())
    }

    fn unscreened<'i>(&self, clearance: &str, items: &ScreenedContent<'i>) -> ScreenedContent<'i> {
        items.select(|item, text| {
            if matches!(item, ContentItem::Opaque { .. }) {
                return true;
            }
            let digest = item.digest_of(text);
            let cleared = self.store.get::<ClearedPiece>(
                self.piece_key(clearance, &digest),
                Self::OWNER,
                self.now_ms,
            );
            !cleared.is_some_and(|piece| {
                piece.session == self.session
                    && piece.clearance.as_ref() == clearance
                    && piece.digest.as_ref() == digest
            })
        })
    }

    fn mark_cleared(&self, clearance: &str, screened: &ScreenedContent<'_>) {
        for (item, text) in screened.iter() {
            if !matches!(item, ContentItem::Opaque { .. }) {
                let digest = item.digest_of(text);
                self.store.put(
                    self.piece_key(clearance, &digest),
                    Self::OWNER,
                    std::sync::Arc::new(ClearedPiece {
                        session: self.session,
                        clearance: clearance.into(),
                        digest: digest.into_boxed_str(),
                    }),
                    self.now_ms,
                    false,
                    None,
                );
            }
        }
    }
}

fn clearance_of(container: &str, hook: &str) -> String {
    format!("c{}={container}\u{1f}h={hook}", container.len())
}

fn context<'a>(subject: &'a GateSubject<'_>) -> RoutingContext<'a> {
    RoutingContext {
        pool: subject.container,

        budget_remaining: None,
        budget: &[],
    }
}

const NO_CANDIDATES: &[Candidate<'static>] = &[];

pub(crate) async fn decide_over(
    gates: &[(u16, ResolvedPolicy)],
    subject: &GateSubject<'_>,
    readable: bool,
    ran: &mut Vec<HookApplied>,
) -> GateVerdict {
    if gates.is_empty() {
        return GateVerdict::Proceed;
    }

    let items = subject.facts.content();

    let all = ScreenedContent::over(&items);
    for (
        _,
        ResolvedPolicy::Policy {
            policy,
            on_error,
            on_error_chain,
            timeout,
            send_prompt,
            send_user,
            ..
        },
    ) in gates
    {
        let clearance = clearance_of(subject.container, policy.name());

        let screened: Option<ScreenedContent> = subject
            .incremental
            .as_ref()
            .filter(|_| readable && *send_prompt)
            .map(|inc| inc.unscreened(&clearance, &all));
        if screened.as_ref().is_some_and(|s| s.is_empty()) {
            continue;
        }
        let content: &ScreenedContent = screened.as_ref().unwrap_or(&all);
        let fallback = Fallback {
            chain: on_error_chain,
            terminal: on_error,
            subject,
            content,
            send_prompt: *send_prompt,
            send_user: *send_user,
            readable,
            failed: policy.name(),
        };
        if *send_prompt && !readable {
            tracing::warn!(
                hook = policy.name(),
                container = subject.container,
                protocol = subject.ingress_protocol,
                "request gate cannot read the request's content; applying its on_error"
            );
            if let Some(v) = fallback.walk(ran).await {
                return v;
            }
            continue;
        }
        let (req, content_delivered) = project(subject, content, *send_prompt, *send_user);
        if *send_prompt {
            (subject.reads)(
                policy.name(),
                subject.key.map(|k| k.id.as_str()),
                subject.ingress_protocol,
                *send_user,
            );
        }
        let ctx = context(subject);
        let answer = match tokio::time::timeout(
            *timeout,
            policy.decide(&req, NO_CANDIDATES, &ctx, *timeout),
        )
        .await
        {
            Ok(Ok(d)) => d,

            Ok(Err(e)) => {
                tracing::warn!(
                    hook = policy.name(),
                    container = subject.container,
                    protocol = subject.ingress_protocol,
                    error = %e,
                    "request gate failed; applying its on_error"
                );
                if let Some(v) = fallback.walk(ran).await {
                    return v;
                }
                continue;
            }
            Err(_) => {
                tracing::warn!(
                    hook = policy.name(),
                    container = subject.container,
                    protocol = subject.ingress_protocol,
                    timeout_ms = timeout.as_millis() as u64,
                    "request gate deadline exceeded; applying its on_error"
                );
                if let Some(v) = fallback.walk(ran).await {
                    return v;
                }
                continue;
            }
        };
        if let Some(v) = verdict_of(answer, policy.name(), subject) {
            ran.push(gate_ran(policy.name(), HookHead::Veto, false));
            return v;
        }

        ran.push(gate_ran(policy.name(), HookHead::Pass, false));

        if let (true, Some(inc), Some(s)) = (
            content_delivered,
            subject.incremental.as_ref(),
            screened.as_ref(),
        ) {
            inc.mark_cleared(&clearance, s);
        }
    }
    GateVerdict::Proceed
}

fn failed_gate(hook: &str, closed: bool) -> HookApplied {
    let head = if closed {
        HookHead::Veto
    } else {
        HookHead::Pass
    };
    gate_ran(hook, head, true)
}

fn gate_ran(hook: &str, head: HookHead, failed: bool) -> HookApplied {
    HookApplied {
        hook: hook.to_string(),
        head,
        failed,
    }
}

fn verdict_of(
    answer: RoutingDecision,
    hook: &str,
    subject: &GateSubject<'_>,
) -> Option<GateVerdict> {
    match answer {
        RoutingDecision::Reject { status, message } => Some(GateVerdict::Reject {
            status: clamp_reject_status(status),
            message: sanitize_reject_message(&message),
            hook: hook.to_string(),
        }),

        RoutingDecision::Prefer(_) | RoutingDecision::Restrict { .. } => {
            tracing::debug!(
                hook,
                container = subject.container,
                protocol = subject.ingress_protocol,
                "request gate answered with a candidate-set verb on a protocol that routes to \
                 one registered upstream; ignored (only `reject` applies here)"
            );
            None
        }
        RoutingDecision::Abstain => None,
    }
}

struct Fallback<'f, 's> {
    chain: &'f [FallbackHook],
    terminal: &'f crate::config::PolicyOnError,
    subject: &'f GateSubject<'s>,
    content: &'f ScreenedContent<'f>,

    send_prompt: bool,
    send_user: bool,

    readable: bool,
    failed: &'f str,
}

impl Fallback<'_, '_> {
    async fn walk(&self, ran: &mut Vec<HookApplied>) -> Option<GateVerdict> {
        let at = ran.len();
        let verdict = self.links(ran).await;
        ran.insert(at, failed_gate(self.failed, verdict.is_some()));
        verdict
    }

    async fn links(&self, ran: &mut Vec<HookApplied>) -> Option<GateVerdict> {
        let subject = self.subject;
        for fb in self.chain {
            let send_prompt = self.send_prompt && fb.send_prompt;
            let send_user = self.send_user && fb.send_user;
            if fb.send_prompt && !self.readable {
                tracing::warn!(
                    fallback = fb.policy.name(),
                    container = subject.container,
                    "on_error fallback hook cannot read the request's content; continuing down the \
                     chain"
                );
                ran.push(gate_ran(fb.policy.name(), HookHead::Pass, true));
                continue;
            }
            let (req, _) = project(subject, self.content, send_prompt, send_user);
            if send_prompt {
                (subject.reads)(
                    fb.policy.name(),
                    subject.key.map(|k| k.id.as_str()),
                    subject.ingress_protocol,
                    send_user,
                );
            }
            let ctx = context(subject);
            match tokio::time::timeout(
                fb.timeout,
                fb.policy.decide(&req, NO_CANDIDATES, &ctx, fb.timeout),
            )
            .await
            {
                Ok(Ok(answer)) => {
                    tracing::info!(
                        hook = self.failed,
                        fallback = fb.policy.name(),
                        container = subject.container,
                        "on_error fallback hook answered for the failed gate"
                    );
                    let verdict = verdict_of(answer, fb.policy.name(), subject);
                    let head = if verdict.is_some() {
                        HookHead::Veto
                    } else {
                        HookHead::Pass
                    };
                    ran.push(gate_ran(fb.policy.name(), head, false));
                    return verdict;
                }

                Ok(Err(e)) => {
                    tracing::warn!(
                        fallback = fb.policy.name(),
                        container = subject.container,
                        error = %e,
                        "on_error fallback hook failed; continuing down the chain"
                    );
                    ran.push(gate_ran(fb.policy.name(), HookHead::Pass, true));
                }
                Err(_) => {
                    tracing::warn!(
                        fallback = fb.policy.name(),
                        container = subject.container,
                        timeout_ms = fb.timeout.as_millis() as u64,
                        "on_error fallback hook deadline exceeded; continuing down the chain"
                    );
                    ran.push(gate_ran(fb.policy.name(), HookHead::Pass, true));
                }
            }
        }
        fail_closed(self.terminal, self.failed)
    }
}

fn fail_closed(on_error: &crate::config::PolicyOnError, hook: &str) -> Option<GateVerdict> {
    crate::hooks::failed_call_refuses(on_error).then(|| GateVerdict::Reject {
        status: crate::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS,
        message: crate::hooks::REQUIRED_HOOK_UNAVAILABLE_MESSAGE.to_string(),
        hook: hook.to_string(),
    })
}

fn project<'a>(
    subject: &'a GateSubject<'_>,
    items: &'a ScreenedContent<'a>,
    send_prompt: bool,
    send_user: bool,
) -> (RoutingRequest<'a>, bool) {
    let shape = subject.facts.shape();
    let mut content_delivered = false;
    let prompt = send_prompt.then(|| {
        let prompt = crate::hooks::PromptProjection {
            system: join_system(items),
            messages: items
                .iter()
                .filter(|(i, _)| i.slot() != Slot::System)
                .map(|(i, t)| (Cow::Borrowed(i.author()), Cow::Owned(t.to_string())))
                .collect(),
        };
        let was_empty = prompt.system.is_none() && prompt.messages.is_empty();
        let prompt = crate::hooks::content_capped(prompt);

        content_delivered = was_empty || prompt.system.is_some() || !prompt.messages.is_empty();
        prompt
    });
    let request = RoutingRequest {
        request_id: subject.request_id,
        pool: subject.container,
        ingress_protocol: subject.ingress_protocol,

        requested_model: None,
        message_count: shape.turn_count,
        tool_count: 0,
        has_tools: shape.has_tools,
        total_chars: shape.text_chars,

        system_chars: items.counts().1,
        max_tokens: shape.max_tokens,
        stream: subject.facts.wants_stream(),

        prompt,
        identity: send_user.then(|| crate::hooks::CallerIdentity {
            key_id: subject.key.map(|k| k.id.clone()),
            key_name: subject.key.map(|k| k.name.clone()),

            user: subject.facts.end_user().map(str::to_string),
        }),

        signals: Default::default(),
        session: subject.session,
    };
    (request, content_delivered)
}

/// The session substrate the door path's incremental scan reads: the node's session store, the
/// hook-config generation a clearance is bound to, and the clock. The composition root hands it
/// only under the operator's `incremental_scan` opt-in; `None` there = every request is screened
/// whole.
#[derive(Clone, Copy)]
pub(crate) struct ScanSubstrate<'a> {
    /// The neutral session substrate the cleared-sets live in.
    pub(crate) store: &'a crate::session::SessionStore,
    /// The hook-config generation (`config_version`): a policy change re-screens everything.
    pub(crate) generation: u64,
    /// Epoch millis for the substrate's TTL.
    pub(crate) now_ms: u64,
}

pub(crate) struct DoorSubject<'a> {
    pub(crate) projected: Option<&'a [u8]>,

    pub(crate) container: &'a str,

    pub(crate) dialect: &'a str,

    pub(crate) request_id: u64,

    pub(crate) key: Option<&'a busbar_contract::records::VirtualKey>,

    pub(crate) session: Option<&'a [u8]>,

    pub(crate) scan: Option<ScanSubstrate<'a>>,

    pub(crate) reads: &'a HookReads<'a>,

    pub(crate) plane: DoorShape<'a>,
}

/// The plane-derived fields of a door request's hook view (THE DESIGN Appendix B.9 l.5436-5437:
/// `project` answers `max_tokens`, the flags and the end user): what the gate shows a hook where
/// the kernel's reading of the projected body has no answer of its own. The sizes stay summed over
/// the content the gate shows (the one-walk rule `InvokeReq::shape` states), so a size signal can
/// never drift from what was screened.
#[derive(Clone, Copy, Default)]
pub(crate) struct DoorShape<'a> {
    /// The caller's output cap, as the plane read it.
    pub(crate) max_tokens: Option<u32>,
    /// The caller asked for a stream, as the plane read it.
    pub(crate) stream: bool,
    /// The end user, as the plane read it.
    pub(crate) end_user: Option<&'a str>,
}

struct DoorFacts<'a> {
    projection: GateProjection,
    plane: DoorShape<'a>,
}

impl IrFacts for DoorFacts<'_> {
    fn verb(&self) -> busbar_contract::operation::OpVerb {
        busbar_contract::operation::OpVerb::INVOKE
    }

    fn wants_stream(&self) -> bool {
        self.plane.stream
    }

    fn end_user(&self) -> Option<&str> {
        self.plane.end_user
    }

    fn shape(&self) -> busbar_contract::ir::facts::Shape {
        let items = self.content();
        let (text_chars, system_chars) = busbar_contract::ir::facts::Shape::counts_over(&items);
        busbar_contract::ir::facts::Shape {
            turn_count: 1,
            has_tools: true,
            tool_count: 1,
            text_chars,
            system_chars,
            max_tokens: self.plane.max_tokens,
        }
    }

    fn content(&self) -> Vec<ContentItem<'_>> {
        vec![ContentItem::Data {
            author: "user",
            slot: Slot::ToolArgs(0),
            label: self
                .projection
                .body
                .get("tool")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default(),
            value: &self.projection.body,
        }]
    }
}

struct GateProjection {
    body: serde_json::Value,
}

impl Drop for GateProjection {
    fn drop(&mut self) {
        wipe_projected_value(&mut self.body);
    }
}

fn wipe_projected_value(value: &mut serde_json::Value) {
    use zeroize::Zeroize as _;
    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(items) => items.iter_mut().for_each(wipe_projected_value),
        serde_json::Value::Object(members) => {
            for (mut name, mut value) in std::mem::take(members) {
                name.zeroize();
                wipe_projected_value(&mut value);
            }
        }
        _ => {}
    }
}

fn read_projected(projected: Option<&[u8]>) -> Option<GateProjection> {
    let mut document = GateProjection {
        body: serde_json::from_slice(projected?).ok()?,
    };
    if document
        .body
        .get("tool")
        .and_then(serde_json::Value::as_str)
        .is_none()
    {
        return Some(document);
    }
    let mut normalized = GateProjection {
        body: serde_json::Value::Object(Default::default()),
    };
    if let serde_json::Value::Object(fields) = &mut normalized.body {
        for name in ["tool", "arguments"] {
            fields.insert(
                name.to_string(),
                document
                    .body
                    .get_mut(name)
                    .map_or(serde_json::Value::Null, serde_json::Value::take),
            );
        }
    }
    Some(normalized)
}

pub(crate) async fn decide_door(
    gates: &[(u16, ResolvedPolicy)],
    door: &DoorSubject<'_>,
    ran: &mut Vec<HookApplied>,
) -> GateVerdict {
    if gates.is_empty() {
        return GateVerdict::Proceed;
    }
    let read = read_projected(door.projected);
    let readable = read.is_some();
    let facts = DoorFacts {
        projection: read.unwrap_or_else(|| GateProjection {
            body: serde_json::Value::Null,
        }),
        plane: door.plane,
    };
    let session = door.session.filter(|s| !s.is_empty());
    let principal = door.key.map(|k| k.id.as_str()).unwrap_or("");
    let incremental = door.scan.zip(session).map(|(scan, sid)| IncrementalScan {
        store: scan.store,
        session: IncrementalScan::derive_session_key_octets(sid, principal, scan.generation),
        now_ms: scan.now_ms,
    });
    let subject = GateSubject {
        facts: &facts,
        container: door.container,
        ingress_protocol: door.dialect,
        request_id: door.request_id,
        key: door.key,
        incremental,
        session,
        reads: door.reads,
    };
    decide_over(gates, &subject, readable, ran).await
}

fn join_system<'a>(items: &'a ScreenedContent<'a>) -> Option<Cow<'a, str>> {
    let mut parts = items
        .iter()
        .filter(|(i, _)| i.slot() == Slot::System)
        .map(|(_, t)| t)
        .peekable();
    let first = parts.next()?;
    if parts.peek().is_none() {
        return (!first.is_empty()).then_some(Cow::Owned(first.to_string()));
    }
    let mut out = first.to_string();
    for p in parts {
        out.push('\n');
        out.push_str(p);
    }
    (!out.is_empty()).then_some(Cow::Owned(out))
}

#[cfg(test)]
#[path = "tests/gate_tests.rs"]
mod gate_tests;
