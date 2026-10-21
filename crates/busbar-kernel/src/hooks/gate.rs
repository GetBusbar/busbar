// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REQUEST GATE, FIRED FROM ANY PROTOCOL — one function, one projection, one verdict, for a
//! request the shared pipeline knows only through [`busbar_contract::ir::facts::IrFacts`].
//!
//! # Why this exists, and why it is not in `proxy/`
//!
//! Hooks were a MODEL-PLANE feature by accident of where they were wired, not by design. Every
//! firing site lived in `proxy/engine`, every projection was built by walking a chat body, and the
//! consequence was written down in five places as though it were a law of the protocol: "hooks do
//! not run on tool calls". It was never a law. It was unfinished wiring — the config grammar for
//! attaching a hook to an MCP server (`tools.hooks:`, `tools.<server>.hooks:`) and to an A2A agent
//! (`agents.hooks:`, `agents.<agent>.hooks:`) already parsed, already validated, already refused a
//! cross-plane reference, and then did nothing, because nothing fired it.
//!
//! A hook is a policy decision about ONE REQUEST. The owner's ruling is the whole design: *"it's 1
//! request object 1 response. llm mcp or agent dont matter."* So the seam takes what every protocol
//! can produce — an `IrFacts` — and knows nothing else. There is no protocol name in a condition
//! here, no plane enum, no `if this is MCP`. The protocol appears exactly twice: as the
//! `ingress_protocol` LABEL a hook is told (data, never a branch) and as the `container` name, and
//! both are supplied by the caller's own arm.
//!
//! # What a hook is sent
//!
//! The SAME [`RoutingRequest`] wire the model plane sends, built from the IR rather than from a
//! body: `pool` is the container the request is addressed to (a pool, an MCP server, an A2A agent),
//! `ingress_protocol` names the dialect, the shape signals come from [`IrFacts::shape`], and — behind
//! the hook's own `prompt:` grant — `messages` carries the content projection, one entry per
//! [`busbar_contract::ir::facts::ContentItem`], each rendered by `screenable_text`. A hook therefore screens a
//! tool call's arguments through exactly the field it already screens a prompt through, and a gate
//! written for the model plane works here with no change.
//!
//! **`candidates` is EMPTY, and that is a fact rather than a gap.** These protocols route to one
//! registered upstream chosen by the caller's own grant, not to a ranked set — so there is nothing
//! to rank, and the two verbs that speak about a candidate set (`order`, `restrict`) have nothing to
//! act on. They are IGNORED here, loudly at `debug`, rather than silently: a hook that tries to
//! reorder something that has no order has been told the wrong thing about the request, and the
//! honest answer is that the verb does not apply, not a synthesised candidate list.
//!
//! # The verdict
//!
//! `reject` is the verb that matters, and it is the one this seam exists to deliver: a gate stops
//! the request before anything is dispatched. Gates fire IN PRIORITY ORDER and the FIRST rejection
//! wins — sequentially, and deliberately so, unlike the model plane's concurrent phase-2 reconcile:
//! there is no candidate set for the reconcile to intersect, so concurrency would buy latency on a
//! path where the common answer is "no gates at all" and would spend a deadline on gates whose
//! verdict is already irrelevant. A short-circuit on the first reject is both cheaper and the same
//! answer.
//!
//! A gate that FAILS (errors, times out, panics across the ABI) does not proceed by default: its
//! `on_error` FALLBACK CHAIN is walked first, each link under its own deadline and grants, and the
//! first link that answers decides; only when every link fails does the chain's terminal decide,
//! exactly as 1.5.5 walked it (v1.5.5 `crates/busbar/src/proxy/hooks.rs:1083-1180`; THE DESIGN
//! §11.7 l.1357-1358, `on_error` stays 1.5.5's). `reject` there means a gate an operator declared
//! load-bearing cannot be skipped by being broken.

use crate::hooks::{
    Candidate, FallbackHook, ResolvedPolicy, RoutingContext, RoutingDecision, RoutingRequest,
};
use busbar_contract::hook_wire::reply::{clamp_reject_status, sanitize_reject_message};
use busbar_contract::ir::facts::{ContentItem, IrFacts, ScreenedContent, Slot};
use busbar_kernel_audit::record::{HookApplied, HookHead};
use std::borrow::Cow;

/// The answer a firing site acts on. Deliberately NOT the model plane's `PolicyOutcome`: that type
/// carries `Order`/`Restrict`/`Weighted`, three answers about a candidate set, and a caller here
/// would have to know they cannot happen. A two-armed verdict cannot be misread.
pub(crate) enum GateVerdict {
    /// No gate objected (or none is attached). The request proceeds.
    Proceed,
    /// A gate refused the request. `status` is held to the 4xx band by the one shared clamp
    /// (outside 400..=499 is 403) and `message` is the hook's own, re-sanitized by the one shared
    /// sanitizer, as 1.5.5's seam did (v1.5.5 `crates/busbar/src/proxy/hooks.rs:1228-1232`, the
    /// reject arm) — a hook cannot mint a 5xx, a success, or a
    /// header-injecting message through this path. A load-bearing gate that could not answer is
    /// the shared [`crate::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS`] refusal instead.
    Reject {
        status: u16,
        message: String,
        /// The transport/policy name, for the audit row and the log line: "it was refused" is not
        /// an operator-actionable fact unless it says by WHAT.
        hook: &'static str,
    },
}

/// Everything the seam needs about one request, gathered so no argument can be transposed with
/// another. Borrowed throughout: nothing here is stored past the call.
pub(crate) struct GateSubject<'a> {
    /// The request, behind the family-blind seam. The ONLY thing this module learns about it.
    ///
    /// `+ Sync` because this borrow is held across the gate's `.await`, and an axum handler's future
    /// must be `Send`. It is a bound on the OBJECT, not a new obligation on the IR: every IR type is
    /// plain owned data.
    pub(crate) facts: &'a (dyn IrFacts + Sync),
    /// The CONTAINER the request is addressed to — a pool, an MCP server, an A2A agent. This is
    /// the routing fact `IrFacts` deliberately cannot answer (see that trait's note on the absent
    /// `target()`), so the firing site, which resolved it, supplies it.
    pub(crate) container: &'a str,
    /// The dialect label, verbatim onto the wire. DATA: no code here compares it.
    pub(crate) ingress_protocol: &'a str,
    /// The request-spine correlation id, so a hook can join this decision to the request's other
    /// records.
    pub(crate) request_id: u64,
    /// The caller's resolved governance key, for the `user: ro` identity projection. `None` when
    /// governance is disabled or the plane resolved no key.
    pub(crate) key: Option<&'a busbar_contract::records::VirtualKey>,
    /// Incremental scan: when `Some`, screen only the content pieces this session has not already had
    /// cleared for each hook (the session-substrate tenant, design G5). `None` = screen the full
    /// projection every time — the default, byte-identical to pre-incremental behaviour.
    pub(crate) incremental: Option<IncrementalScan<'a>>,
    /// The request's session, opaque octets the plane named, shown to every hook on its request
    /// view ([`RoutingRequest::session`]); `None` = the request names none.
    pub(crate) session: Option<&'a [u8]>,
}

/// The gate's tenant of the session substrate: a per-`(session, hook)` set of the content-piece
/// digests already screened clean, so a long session re-screens only NEW content instead of the whole
/// growing context every turn.
///
/// The screening HOOK never learns about sessions — this bookkeeping is pure neutral core (a session
/// id + [`ContentItem::screening_digest`]). Safe degradation: a cold/evicted slot just means more gets
/// re-screened — never wrong, only less optimised. A BLOCKED (rejected) piece is never recorded, so it
/// is re-screened on retry. An OPAQUE piece is always re-surfaced (a presence signal, never cleared).
#[derive(Clone, Copy)]
pub(crate) struct IncrementalScan<'a> {
    /// The neutral session substrate the cleared-set lives in.
    pub(crate) store: &'a crate::session::SessionStore,
    /// This request's session identity (a stable hash of the session key already read at ingress).
    pub(crate) session: crate::session::SessionKey,
    /// Epoch millis for the substrate's TTL — passed in, no ambient clock here.
    pub(crate) now_ms: u64,
}

/// clearance identity ([`clearance_of`]: the container and the hook) → the set of content-piece
/// digests cleared for it this session.
type ClearedSets =
    std::sync::Mutex<std::collections::HashMap<String, std::collections::HashSet<String>>>;

impl IncrementalScan<'_> {
    const OWNER: crate::session::OwnerKey = "gate.screen";

    /// Derive the screen-cache session identity, BINDING it to the caller PRINCIPAL and the
    /// hook-config GENERATION — never the client-chosen session id alone.
    ///
    /// The raw `x-session-id` / `contextId` is CLIENT-supplied and freely shared, so keying the
    /// cleared-set on `fnv1a(sid)` alone was two holes at once: (1) a CONFUSED DEPUTY — content
    /// screened clean under a privileged principal counted as cleared for a DIFFERENT principal that
    /// reused the same session id; and (2) STALE CLEARANCE — after a gate/policy was TIGHTENED,
    /// previously-cleared content stayed cleared because the key carried no policy generation. Folding
    /// the resolved principal id and the monotonic config generation into the opaque `u64` confines
    /// every cleared set to exactly one `(principal, policy-generation, session)`; a mismatch on
    /// either simply misses the slot and re-screens (safe degradation, never a wrongful skip).
    ///
    /// Domain-separated: each field is length-tagged and delimited so no boundary can alias into
    /// another (principal `"a"` + sid `"b"` can never collide with principal `""` + sid `"ab"`).
    ///
    /// The session is opaque octets (the request view's `session`, which no reader interprets), its
    /// bytes last, so a UTF-8 session keys exactly as its string does.
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

    /// Get-or-create this session's cleared-sets slot. The get-then-put is not atomic, but a lost race
    /// only drops a cleared entry (→ a re-screen), which is safe degradation.
    fn sets(&self) -> std::sync::Arc<ClearedSets> {
        if let Some(m) = self
            .store
            .get::<ClearedSets>(self.session, Self::OWNER, self.now_ms)
        {
            return m;
        }
        let m = std::sync::Arc::new(ClearedSets::default());
        self.store.put(
            self.session,
            Self::OWNER,
            m.clone(),
            self.now_ms,
            false,
            None,
        );
        m
    }

    /// The pieces to actually screen under `clearance` ([`clearance_of`]): everything not yet
    /// cleared for it, plus every opaque piece (always re-surfaced). Order is preserved.
    fn unscreened<'i>(&self, clearance: &str, items: &ScreenedContent<'i>) -> ScreenedContent<'i> {
        let sets = self.sets();
        let guard = sets.lock().unwrap_or_else(|e| e.into_inner());
        let cleared = guard.get(clearance);
        items.select(|item, text| {
            matches!(item, ContentItem::Opaque { .. })
                || cleared.is_none_or(|set| !set.contains(&item.digest_of(text)))
        })
    }

    /// Record the (non-opaque) pieces just screened clean under `clearance`, so the next turn skips
    /// them.
    fn mark_cleared(&self, clearance: &str, screened: &ScreenedContent<'_>) {
        let sets = self.sets();
        let mut guard = sets.lock().unwrap_or_else(|e| e.into_inner());
        let set = guard.entry(clearance.to_string()).or_default();
        for (item, text) in screened.iter() {
            if !matches!(item, ContentItem::Opaque { .. }) {
                set.insert(item.digest_of(text));
            }
        }
    }
}

/// THE CLEARANCE IDENTITY a cleared piece is recorded under: the CONTAINER the gate was shown
/// (`pool`) and the hook, length-tagged so no boundary aliases. A hook attached to two containers
/// may answer differently for each (its verdict can read `pool`), so a piece it cleared for one
/// container is screened again for the other: the session key binds the principal and the hook
/// generation, and this binds the container, so a mismatch on any of them misses the slot and
/// re-screens (safe degradation, never a wrongful skip; audit Q128 p15#2).
fn clearance_of(container: &str, hook: &str) -> String {
    format!("c{}={container}\u{1f}h={hook}", container.len())
}

/// The context every gate of this request is shown.
fn context<'a>(subject: &'a GateSubject<'_>) -> RoutingContext<'a> {
    RoutingContext {
        pool: subject.container,
        // No pool-scoped budget signal on these planes: the budget a request here spends is the
        // caller key's, and it is metered by the plane's own admission. A field that carried a
        // number derived from something else would be worse than an absent one.
        budget_remaining: None,
        budget: &[],
    }
}

/// The candidate set is EMPTY — see the module header for why that is the truth about these
/// protocols rather than a projection that has not been built yet.
const NO_CANDIDATES: &[Candidate<'static>] = &[];

/// FIRE the gates attached to this container, in priority order, and return the first verdict that
/// stops the request, told whether the request's content could be READ.
///
/// ZERO COST when nothing is attached: an empty slice returns before any projection is built, which
/// is the same shape (and the same guarantee) as the model plane's `global_gates.is_empty()`
/// early-out. Each gate that ran is pushed onto `ran` in the order it ran, with its decision head
/// and whether it failed (THE DESIGN §1: the audit record's "controls (... hooks applied)"). A gate
/// the incremental scan had nothing new for was not asked and is not pushed. A failed gate's
/// `on_error` links are pushed after it, each as it ran ([`Fallback::walk`]): a link the walk asked
/// is a hook applied.
///
/// When the content could not be read (a door plane's projected body that is absent or not JSON),
/// a gate granted the content cannot screen it: it is a gate that could not answer, and its
/// `on_error` decides, never a gate shown empty content that abstains (audit Q128 p15#3). A
/// shape-only gate (`prompt: no`) reads no content and fires as it always does.
pub(crate) async fn decide_over(
    gates: &[(u16, ResolvedPolicy)],
    subject: &GateSubject<'_>,
    readable: bool,
    ran: &mut Vec<HookApplied>,
) -> GateVerdict {
    if gates.is_empty() {
        return GateVerdict::Proceed;
    }
    // The content items are materialised ONCE and borrowed by every gate's projection: the walk is
    // over the IR and cannot differ between gates, and re-walking per gate would be the same answer
    // computed N times.
    let items = subject.facts.content();
    // …and each item's screenable text is RENDERED once, here, for the whole pass. A `Data` item
    // serializes its payload on every `screenable_text()`, and every gate asks for it several times
    // over (the size sum, the cleared-set digest, the prompt projection), so rendering per reader
    // grew the cost with the number of attached gates for an answer that cannot change between them.
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
        // Incremental scan (G5 tenant): screen only the pieces this session hasn't cleared for THIS
        // hook on THIS container. `None` → the full item set, byte-identical to pre-incremental
        // behaviour.
        let screened: Option<ScreenedContent> = subject
            .incremental
            .as_ref()
            .filter(|_| readable)
            .map(|inc| inc.unscreened(&clearance, &all));
        if screened.as_ref().is_some_and(|s| s.is_empty()) {
            // Nothing new to screen for this hook this turn — it proceeds without a sidecar call.
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
        let req = project(subject, content, *send_prompt, *send_user);
        if *send_prompt {
            crate::audit::amend::hook_read(
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
            // The gate could not answer. Its `on_error` chain, then its terminal, decides, and
            // `reject` is the terminal an operator picks when the gate is load-bearing: a broken
            // security gate must not become an open one.
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
            // The gate answered, and its reject stops the unit.
            ran.push(gate_ran(policy.name(), HookHead::Veto, false));
            return v;
        }
        // The gate answered, and nothing else acts on these protocols: it passed the unit.
        ran.push(gate_ran(policy.name(), HookHead::Pass, false));
        // A clean pass (no reject returned above): record the pieces just screened as cleared for this
        // hook on this container, so the next turn in this session skips them. Rejects never reach
        // here — a blocked piece is deliberately NOT cached and is re-screened on retry.
        if let (Some(inc), Some(s)) = (subject.incremental.as_ref(), screened.as_ref()) {
            inc.mark_cleared(&clearance, s);
        }
    }
    GateVerdict::Proceed
}

/// A gate keyed `hook` that could not answer, as it ran: a veto when its `on_error` (a link's reject,
/// or the terminal) closed, else a pass. The failure is kept either way.
fn failed_gate(hook: &str, closed: bool) -> HookApplied {
    let head = if closed {
        HookHead::Veto
    } else {
        HookHead::Pass
    };
    gate_ran(hook, head, true)
}

/// A gate keyed `hook` as it ran: its head, and whether it failed.
fn gate_ran(hook: &str, head: HookHead, failed: bool) -> HookApplied {
    HookApplied {
        hook: hook.to_string(),
        head,
        failed,
    }
}

/// One answer a gate (or a fallback link) gave, as the verdict a firing site acts on:
/// `Some` only for a reject.
///
/// The reject is RE-CLAMPED and RE-SANITIZED at the seam that acts on it, with the one shared rule
/// (`clamp_reject_status`: outside 400..=499 is 403; `sanitize_reject_message`), exactly as 1.5.5's
/// seam did for every primary and fallback answer (v1.5.5 `crates/busbar/src/proxy/hooks.rs:1191`
/// and its reject arm at `:1228-1232`; THE DESIGN §11.7
/// l.1357-1358, the status clamp and the message cap stay 1.5.5's): no policy implementation,
/// shipped or in-process, can mint a 5xx, a success or an injecting message here (audit Q128
/// p15#5).
fn verdict_of(
    answer: RoutingDecision,
    hook: &'static str,
    subject: &GateSubject<'_>,
) -> Option<GateVerdict> {
    match answer {
        RoutingDecision::Reject { status, message } => Some(GateVerdict::Reject {
            status: clamp_reject_status(status),
            message: sanitize_reject_message(&message),
            hook,
        }),
        // The two candidate-set verbs. Nothing to act on, and saying so at `debug` is what stops an
        // operator concluding their compliance restrict is in force here.
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

/// A failed gate's `on_error`: its resolved fallback CHAIN and the TERMINAL it bottoms out on, with
/// what the failed gate was shown.
struct Fallback<'f, 's> {
    chain: &'f [FallbackHook],
    terminal: &'f crate::config::PolicyOnError,
    subject: &'f GateSubject<'s>,
    content: &'f ScreenedContent<'f>,
    /// The failed gate's own grants: a link sees at most what the failed gate was granted.
    send_prompt: bool,
    send_user: bool,
    /// Whether the request's content could be read (a link granted the content cannot screen an
    /// unreadable request either, so it is a link that failed).
    readable: bool,
    failed: &'static str,
}

impl Fallback<'_, '_> {
    /// WALK the chain as 1.5.5 walked it (v1.5.5 `crates/busbar/src/proxy/hooks.rs:1119-1180`,
    /// `run_on_error_chain`; THE DESIGN §11.7 l.1357-1358): each link in order, under ITS deadline,
    /// projected per ITS grants and never past the failed gate's (`prompt` only when both grant
    /// it, as 1.5.5's `fb.send_prompt { req.prompt.clone() }` did); the FIRST link that answers
    /// decides, exactly as a primary would (its reject stops the request, any other answer
    /// proceeds). Every link failing lands on the terminal ([`fail_closed`]). An empty chain (a
    /// terminal named directly, the common case) goes straight to the terminal (audit Q128
    /// p15#1).
    ///
    /// The failed gate and every link the walk asked are pushed onto `ran` as they ran (one record
    /// of the hooks applied, THE DESIGN §1): the failed gate first, its head what its chain made of
    /// it ([`failed_gate`]), then each link: one that answered with its own head, one that failed
    /// (or could not read the content it was granted) as a failed pass.
    async fn walk(&self, ran: &mut Vec<HookApplied>) -> Option<GateVerdict> {
        let at = ran.len();
        let verdict = self.links(ran).await;
        ran.insert(at, failed_gate(self.failed, verdict.is_some()));
        verdict
    }

    /// The chain's links in order, then its terminal: [`Fallback::walk`]'s answer, each link asked
    /// pushed onto `ran`.
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
            let req = project(subject, self.content, send_prompt, send_user);
            if send_prompt {
                crate::audit::amend::hook_read(
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
                // This link failed too — follow the chain to the next (its own on_error was
                // flattened into this chain at resolution).
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

/// A failed gate's terminal, as a verdict. `Some` only for `reject` — the two ranking terminals
/// (`weighted`, `first`) are statements about which candidate to pick, and with no candidates they
/// mean exactly "this gate has no verdict", which is a proceed.
///
/// The door gate is one more seat that calls a hook, so it asks the one disposition rule
/// ([`crate::hooks::failed_call_refuses`]) and answers the one client-facing refusal every other
/// seat answers ([`crate::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS`] and its message): a broken
/// load-bearing gate is the same retryable condition on every plane (audit kernel-K4 #7).
fn fail_closed(on_error: &crate::config::PolicyOnError, hook: &'static str) -> Option<GateVerdict> {
    crate::hooks::failed_call_refuses(on_error).then(|| GateVerdict::Reject {
        status: crate::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS,
        message: crate::hooks::REQUIRED_HOOK_UNAVAILABLE_MESSAGE.to_string(),
        hook,
    })
}

/// Build ONE gate's projection from the facts, gated by THAT gate's grants.
///
/// Built per gate rather than once per request because the grants are per hook: a `prompt: no` gate
/// must not merely have the content withheld from its wire, it must never have had it built, which
/// is also what keeps the cost of a shape-only gate a shape-only cost.
fn project<'a>(
    subject: &'a GateSubject<'_>,
    items: &'a ScreenedContent<'a>,
    send_prompt: bool,
    send_user: bool,
) -> RoutingRequest<'a> {
    let shape = subject.facts.shape();
    RoutingRequest {
        request_id: subject.request_id,
        pool: subject.container,
        ingress_protocol: subject.ingress_protocol,
        // RESERVED on the shared wire (it is projected by no transport today), so this is carried
        // for a future reader rather than claimed as a delivered signal. The target a hook can
        // actually READ rides the content projection, as the label of the item that carries the
        // arguments.
        requested_model: None,
        message_count: shape.turn_count,
        tool_count: 0,
        has_tools: shape.has_tools,
        total_chars: shape.text_chars,
        // The system slot's chars, summed over the SAME items the projection shows.
        system_chars: items.counts().1,
        max_tokens: shape.max_tokens,
        stream: subject.facts.wants_stream(),
        // Under the hook content ceiling, the one rule every seat that hands a hook the prompt
        // applies (audit kernel-K4 #8).
        prompt: send_prompt.then(|| {
            crate::hooks::content_capped(crate::hooks::PromptProjection {
                system: join_system(items),
                messages: items
                    .iter()
                    .filter(|(i, _)| i.slot() != Slot::System)
                    .map(|(i, t)| (Cow::Borrowed(i.author()), Cow::Owned(t.to_string())))
                    .collect(),
            })
        }),
        identity: send_user.then(|| crate::hooks::CallerIdentity {
            key_id: subject.key.map(|k| k.id.clone()),
            key_name: subject.key.map(|k| k.name.clone()),
            // The BODY's end-user field, which is a different fact from the key: a protocol whose
            // requests carry none answers `None` here rather than borrowing the key's identity for
            // it.
            user: subject.facts.end_user().map(str::to_string),
        }),
        // No request-phase catalog signal is wired to this seam in this pass; the core fields above
        // are what these protocols can answer today.
        signals: Default::default(),
        session: subject.session,
    }
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

/// One request on THE DOOR PATH, as the request gate sees it: the plane's own `project` answer
/// (its projected body, the container it names, its dialect label, its opaque session and its own
/// projected fields) and what the kernel resolved (the request id and the caller's key).
pub(crate) struct DoorSubject<'a> {
    /// The plane's projected body (`ProjectOut::body`), the invoke IR's `{tool, arguments}`
    /// document for an invocation; `None` = the plane stated no body.
    pub(crate) projected: Option<&'a [u8]>,
    /// The container the request is addressed to.
    pub(crate) container: &'a str,
    /// The dialect label, verbatim onto the hook's view.
    pub(crate) dialect: &'a str,
    /// The request-spine correlation id.
    pub(crate) request_id: u64,
    /// The caller's resolved key (its `id` binds the incremental scan's clearance).
    pub(crate) key: Option<&'a busbar_contract::records::VirtualKey>,
    /// The request view's session ([`busbar_contract::abi::hook::RequestView::session`]);
    /// `None` or empty = the request names none.
    pub(crate) session: Option<&'a [u8]>,
    /// The incremental scan's substrate, under the operator's opt-in.
    pub(crate) scan: Option<ScanSubstrate<'a>>,
    /// The plane's own projected fields the body cannot answer.
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

/// A door request's facts: the content and the sizes from the kernel's reading of the projected
/// body, the fields the body cannot answer from the plane's own projection ([`DoorShape`]).
struct DoorFacts<'a> {
    invoke: busbar_contract::ir::invoke::InvokeReq,
    plane: DoorShape<'a>,
}

impl IrFacts for DoorFacts<'_> {
    fn verb(&self) -> busbar_contract::operation::OpVerb {
        self.invoke.verb()
    }

    fn wants_stream(&self) -> bool {
        self.plane.stream || self.invoke.wants_stream()
    }

    fn end_user(&self) -> Option<&str> {
        self.plane.end_user.or_else(|| self.invoke.end_user())
    }

    fn shape(&self) -> busbar_contract::ir::facts::Shape {
        let shape = self.invoke.shape();
        busbar_contract::ir::facts::Shape {
            max_tokens: self.plane.max_tokens.or(shape.max_tokens),
            ..shape
        }
    }

    fn content(&self) -> Vec<ContentItem<'_>> {
        self.invoke.content()
    }
}

/// The kernel's reading of a door plane's projected body: `Some` when the body is JSON (the
/// invoke document read as one; any other document screened WHOLE as the arguments of an unnamed call, so
/// no projected content is dropped), `None` when the plane stated no body or one that is not JSON
/// (nothing a content gate can screen).
fn read_projected(projected: Option<&[u8]>) -> Option<busbar_contract::ir::invoke::InvokeReq> {
    let doc: serde_json::Value = serde_json::from_slice(projected?).ok()?;
    let named = doc
        .get("tool")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let (name, arguments) = match named {
        Some(name) => (
            name,
            doc.get("arguments")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        ),
        None => (String::new(), doc),
    };
    Some(busbar_contract::ir::invoke::InvokeReq {
        tool: name,
        arguments,
        extra: Default::default(),
    })
}

/// FIRE THE GATES OF A REQUEST SERVED THROUGH A PLANE'S DOOR (ARCHITECT RULING 2026-10-03,
/// the session half): the same gate the engine fired (each gate that ran pushed onto `ran`), over
/// the plane's projected body, with the incremental scan KEYED ON THE VIEW'S SESSION, bound to the
/// caller principal and the hook generation exactly as the engine's was
/// ([`IncrementalScan::derive_session_key_octets`]), and each clearance bound to the container
/// ([`clearance_of`]). A request whose view names no session, or
/// a node that did not opt in, screens the whole projection every time.
///
/// The hook view is the plane's projection (THE DESIGN Appendix B.9 l.5436-5437, Law 0): the
/// content of its projected body, and its own `max_tokens`, stream flag and end user
/// ([`DoorShape`]). A body the plane did not state, or one that is not JSON, is content no gate
/// can screen: a gate granted the content applies its `on_error` (chain, then terminal) instead
/// of being shown empty content it would pass (audit Q128 p15#3).
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
        invoke: read.unwrap_or_else(|| busbar_contract::ir::invoke::InvokeReq {
            tool: String::new(),
            arguments: serde_json::Value::Null,
            extra: Default::default(),
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
    };
    decide_over(gates, &subject, readable, ran).await
}

/// The system slot, flattened — `None` when the request has none, which is what the wire contract
/// says absence means (a granted hook keys the grant off `messages`, never off `system`).
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
