// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ORDERED REQUEST VALIDATOR: the one place that answers *"is this still what the operator
//! approved?"*, in one order, for every protocol.
//!
//! ```text
//! identity  ->  grant  ->  artifact still matches what was approved  ->  snapshot generation live
//! ```
//!
//! ## Why this is one function and not a rule
//!
//! The question is asked on every plane at the same point in the pipeline. Before this module it
//! was asked in several places with several coverages: one plane wrote the sequence down in one
//! site and stamped the snapshot generation onto its resolved candidate, and the sibling plane
//! repeated the trust half at three call sites with no generation check at all. Three call sites
//! drift, and a fourth path added later that forgets a step is a silent hole — because no site owns
//! the sequence, nothing fails when a step is missed.
//!
//! So the sequence is a VALUE here, not a habit there. [`Ask`] has one field per step and there is
//! no field through which a step could be omitted: a caller that has no principal says so with
//! `None` (which is only honest where governance is off), a caller that names no capability says so
//! with `None`, and a caller admitting for the first time says so with
//! [`Generations::at_admission`] rather than by leaving the generation out.
//!
//! ## What a protocol supplies, and it is exactly one thing
//!
//! **The FINGERPRINT.** How you compute the identity of the thing being asked for — a signature over
//! a canonicalised document, a hash of a schema and its description — is a fact about a wire format
//! and belongs to the reader that parses it. [`Fingerprint::observe`] is that, and it is a CLOSURE
//! rather than a value so the validator decides *when* it runs. It runs at the artifact step and
//! never before, which is what keeps a refusal from leaking the thing it is refusing access to: a
//! caller with no grant learns that it is ungranted and nothing about what the upstream is currently
//! offering.
//!
//! A protocol supplies **no step, no order and no skip**. That is not a style preference. A protocol
//! that CAN skip a step is a protocol that will, and the skip is invisible — it looks like a shorter
//! argument list.
//!
//! ## The refusal vocabulary is `crate::audit::vocab`'s, and it stays PLURAL
//!
//! This module DEFINES no words. [`reason`] re-exports them from [`crate::audit::vocab`], which is
//! the right home rather than a compromise: the words are the tokens a chained record carries, so
//! they belong to the evidence rather than to whichever gate produced them. A validator that
//! defined its own copy would have re-opened, from the other side, exactly the defect the audit
//! unification closed — two streams answering an operator differently about one decision.
//!
//! What this module DOES insist on is that they stay plural. Collapsing them into one "refused"
//! would be the cheap unification and the wrong one: `not_granted`, `egress_denied` and
//! `upstream_failed` are three different operator actions (grant a scope, edit the target's egress
//! list, go and look at the far end), and a chain that spells them the same cannot tell an operator
//! which of the three happened. `upstream_failed` is in that list and is deliberately NOT an arm of
//! [`Refusal`] — it is what a request that passed every step here can still become, and keeping it
//! beside the refusal words is what makes "busbar blocked this" and "the far end broke" one glance
//! apart.
//!
//! ## Not on the admission hot path
//!
//! This runs per dispatch, and it makes no store call and awaits nothing — every input is either
//! already in hand or an in-memory index read. It is not reachable from the metering admission
//! decision, which has its own stricter rule.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_api::VirtualKey;

use super::{Approval, PinnedArtifact, Sighting, TrustState};

/// THE GENERATION SOURCE. Monotonic, process-global, taken once per snapshot BUILD.
///
/// One counter for every snapshot in the process rather than one per protocol, because the value's
/// only job is to be different after a change and a second counter is a second thing to keep
/// monotonic. Starts at 1 so `0` is never live and can be used as an unambiguous "nothing selected".
static GENERATION: AtomicU64 = AtomicU64::new(1);

/// Take the next generation. Called once per snapshot build; never on a request path.
pub(crate) fn next_generation() -> u64 {
    GENERATION.fetch_add(1, Ordering::Relaxed)
}

/// THE STABLE REFUSAL WORDS, RE-EXPORTED FROM THE ONE AUDIT VOCABULARY.
///
/// **Nothing is defined here.** The words are `crate::audit::vocab`'s, and that is the right home
/// rather than a compromise: they are the tokens a chained record carries, so they belong to the
/// evidence rather than to the gate that happens to produce them. Two streams spelling one refusal
/// two ways is precisely what the audit unification existed to end, and a validator that defined its
/// own copy would have re-opened it from the other side.
///
/// The re-export exists so this module reads as one thing — [`Refusal::reason`] is total over the
/// arms below, and a reader checking that every arm has a word should not have to leave the file.
///
/// A NEW WORD GOES TO `audit::vocab` AND IS RE-EXPORTED HERE, never added here. `IDENTITY_NOT_LIVE`
/// is this unit's, and it is defined there with its reasoning beside the words it sits with.
pub(crate) mod reason {
    pub(crate) use crate::audit::vocab::{
        REASON_ARTIFACT_DRIFTED as ARTIFACT_DRIFTED, REASON_EGRESS_DENIED as EGRESS_DENIED,
        REASON_GENERATION_MOVED as GENERATION_MOVED, REASON_IDENTITY_NOT_LIVE as IDENTITY_NOT_LIVE,
        REASON_NOT_GRANTED as NOT_GRANTED, REASON_NOT_SERVING as NOT_SERVING,
    };
}

/// WHY A REQUEST MAY NOT PROCEED. One arm per step, in step order.
///
/// Every arm names something an operator can act on, and the arms are kept apart rather than
/// collapsed because the actions differ — see the module header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// STEP 1. The principal is not live.
    IdentityNotLive { principal: String },
    /// STEP 2. The caller's grant does not reach `kind:name`.
    NotGranted { kind: String, name: String },
    /// STEP 2. The target's standing list does not name this caller.
    EgressDenied { from: String },
    /// STEP 3. The registration is not `Approved`, so it serves nothing whatever else is true.
    NotServing {
        state: TrustState,
        reason: Option<String>,
    },
    /// STEP 3. The named capability is offered at a fingerprint nobody approved.
    ArtifactDrifted {
        capability: String,
        observed: String,
    },
    /// STEP 3. The reader could produce NO fingerprint that could match, and said why. A separate
    /// arm from [`Refusal::ArtifactDrifted`] under the same word, because the two are the same
    /// refusal to an operator and two different facts to a protocol rendering it: one has a value to
    /// show and one has a sentence.
    Unobservable {
        capability: String,
        why: &'static str,
    },
    /// STEP 4. The snapshot moved between admission and dispatch.
    GenerationMoved { admitted: u64, live: u64 },
}

impl Refusal {
    /// The stable word, named once so a new arm cannot land without one.
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Refusal::IdentityNotLive { .. } => reason::IDENTITY_NOT_LIVE,
            Refusal::NotGranted { .. } => reason::NOT_GRANTED,
            Refusal::EgressDenied { .. } => reason::EGRESS_DENIED,
            Refusal::NotServing { .. } => reason::NOT_SERVING,
            Refusal::ArtifactDrifted { .. } | Refusal::Unobservable { .. } => {
                reason::ARTIFACT_DRIFTED
            }
            Refusal::GenerationMoved { .. } => reason::GENERATION_MOVED,
        }
    }

    /// WHICH STEP refused, `1..=4`. Read by the tests that pin the ORDER, which is the property this
    /// module exists to hold: an assertion that a given input is refused proves nothing about
    /// sequencing, and an assertion about WHICH step refused it proves everything.
    pub(crate) fn step(&self) -> u8 {
        match self {
            Refusal::IdentityNotLive { .. } => 1,
            Refusal::NotGranted { .. } | Refusal::EgressDenied { .. } => 2,
            Refusal::NotServing { .. }
            | Refusal::ArtifactDrifted { .. }
            | Refusal::Unobservable { .. } => 3,
            Refusal::GenerationMoved { .. } => 4,
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::IdentityNotLive { principal } => write!(
                f,
                "`{principal}` is no longer live, so the standing decision it was admitted under no \
                 longer applies"
            ),
            Refusal::NotGranted { kind, name } => {
                write!(f, "this caller is not granted `{kind}:{name}`")
            }
            Refusal::EgressDenied { from } => write!(
                f,
                "`{from}` is not on this registration's standing egress list, so it may not reach it"
            ),
            Refusal::NotServing {
                state,
                reason: why,
            } => match why {
                Some(r) => write!(f, "the registration is {state:?} and serves nothing: {r}"),
                None => write!(
                    f,
                    "the registration is {state:?} and serves nothing; work its changes queue and \
                     re-approve it"
                ),
            },
            Refusal::ArtifactDrifted {
                capability,
                observed,
            } => write!(
                f,
                "`{capability}` is offered at {observed}, which is not what the operator approved; \
                 the call is refused until an operator re-approves it"
            ),
            Refusal::Unobservable { capability, why } => write!(
                f,
                "`{capability}` cannot be dispatched against: {why}. The call is refused until an \
                 operator works the change."
            ),
            Refusal::GenerationMoved { admitted, live } => write!(
                f,
                "the registry moved from generation {admitted} to {live} between admission and \
                 dispatch; the call is refused rather than sent against a snapshot the operator has \
                 already replaced. Retry."
            ),
        }
    }
}

/// ONE GRANT THE ASK NEEDS. Every one listed must be held; the list is conjunctive.
///
/// Two arms, because they are two different facts with two different remedies — see
/// [`reason::EGRESS_DENIED`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum Grant<'a> {
    /// The CALLER's own grant over a named thing, asked of its key.
    Scope { kind: &'a str, name: &'a str },
    /// The TARGET's standing list of who may reach it. `from` must appear in `allowed`; an empty
    /// `allowed` is NOBODY, never everybody.
    Egress {
        from: &'a str,
        allowed: &'a [String],
    },
}

/// WHAT THE UPSTREAM IS OFFERING RIGHT NOW, as the protocol's own reader sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Observed {
    /// The fingerprint, computed the way this wire format computes one.
    At(String),
    /// The reader can produce no fingerprint that could match, and says why in words for an
    /// operator: nothing has been observed since the approval moved, the last contact failed, the
    /// capability is no longer offered.
    Drifted(&'static str),
}

/// THE PROTOCOL'S ONE CONTRIBUTION: the capability being asked for, and how to fingerprint it.
///
/// `observe` is a closure and not a value so that the VALIDATOR decides when it runs. See the module
/// header: reading the upstream's current shape on behalf of a caller that has no grant is a refusal
/// that has failed at half its job.
pub(crate) struct Fingerprint<'a> {
    /// The capability's name AS THE APPROVAL RECORDS IT — the operator's word, never an upstream's
    /// free text.
    pub(crate) capability: &'a str,
    /// How this wire format computes its artifact's identity.
    pub(crate) observe: &'a dyn Fn() -> Observed,
}

impl std::fmt::Debug for Fingerprint<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fingerprint")
            .field("capability", &self.capability)
            .finish_non_exhaustive()
    }
}

/// THE GENERATION PAIR: what the request was admitted under, and what is live now.
///
/// A pair rather than one number so the no-op case has to be SAID. A caller admitting for the first
/// time has nothing older to compare against, and [`Generations::at_admission`] is that statement —
/// visible at the call site, greppable, and impossible to reach by leaving an argument out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Generations {
    admitted: u64,
    live: u64,
}

impl Generations {
    /// ADMISSION: there is no earlier snapshot to have outlived, because this is the one the request
    /// is arriving on. The step still runs; it just cannot fail yet.
    pub(crate) fn at_admission(live: u64) -> Self {
        Self {
            admitted: live,
            live,
        }
    }

    /// DISPATCH: the request was admitted under `admitted` and the live snapshot is `live` now.
    pub(crate) fn since(admitted: u64, live: u64) -> Self {
        Self { admitted, live }
    }
}

/// EVERYTHING THE ORDERED GATE JUDGES, one field per step.
pub(crate) struct Ask<'a, A: PinnedArtifact> {
    /// STEP 1 — IDENTITY. `None` ONLY where governance is disabled and there is therefore no
    /// principal to carry a grant. It is not a way past the gate: with no principal there is also no
    /// grant to narrow, and every step below still runs.
    pub(crate) principal: Option<&'a VirtualKey>,
    /// Seconds, for the expiry comparison. The caller's clock, so a test can move it.
    pub(crate) now: u64,
    /// STEP 2 — GRANT. Conjunctive; an empty list is a request that needs no grant, which is a
    /// statement the call site is making out loud.
    pub(crate) grants: &'a [Grant<'a>],
    /// STEP 3 — the standing decision, and what was last observed against it. The registration-level
    /// half of the artifact question is derived from these two by the lifecycle itself.
    pub(crate) approval: &'a Approval<A>,
    pub(crate) sighting: &'a Sighting<A>,
    /// STEP 3 — the per-capability half, where the wire names a capability. `None` where it names
    /// none: an ask addressed to the registration itself has no capability to fingerprint, and
    /// inventing one would be inventing an approval.
    pub(crate) capability: Option<Fingerprint<'a>>,
    /// STEP 4 — GENERATION.
    pub(crate) generation: Generations,
}

/// STEPS 1 AND 2 ALONE — IDENTITY, THEN GRANT — for a caller asking WHAT EXISTS rather than asking
/// to USE something.
///
/// ## Why the catalogue stops here, and why that is not a skipped step
///
/// A catalogue answers "what may this caller SEE". That is the same identity question and the same
/// grant question [`validate_request`] asks, and it is deliberately NOT the artifact question: the
/// MCP catalogue LISTS what it will not dispatch, because an operator's view of what is waiting in
/// the approval queue is the catalogue's job and hiding a pending entry makes the queue invisible.
/// A2A's catalogue does ask the artifact question, because on that plane a listing IS an admission —
/// so the difference is in WHAT EACH PLANE ASKS FOR, stated at its own call site, and never in which
/// steps a shared function decided to run.
///
/// **This is an entry point, not a lenient default.** [`validate_request`] calls it for its first
/// two steps, so there is exactly ONE identity check and ONE grant evaluator in busbar; a caller
/// that holds an artifact and calls this instead would be silently excusing the artifact step, which
/// is why the two are named for the two different questions rather than for a step count.
pub(crate) fn validate_visibility(
    principal: Option<&VirtualKey>,
    now: u64,
    grants: &[Grant<'_>],
) -> Result<(), Refusal> {
    // ── 1. IDENTITY ─────────────────────────────────────────────────────────────────────────────
    // A tombstoned principal's row survives forever so billing and audit keep resolving it, which
    // means liveness is the check and the row's existence is not.
    if let Some(p) = principal {
        if !p.is_live() || !p.enabled || p.expires_at.is_some_and(|exp| now >= exp) {
            return Err(Refusal::IdentityNotLive {
                principal: p.id.clone(),
            });
        }
    }

    // ── 2. GRANT ────────────────────────────────────────────────────────────────────────────────
    for grant in grants {
        match grant {
            Grant::Scope { kind, name } => {
                // With no principal there is no grant to narrow. That is the same posture the rest
                // of the tree takes for an ungoverned deployment, and it is stated once, here,
                // rather than at each call site as a skipped call.
                let held = principal.is_none_or(|p| p.scope_allowed(kind, name));
                if !held {
                    return Err(Refusal::NotGranted {
                        kind: (*kind).to_string(),
                        name: (*name).to_string(),
                    });
                }
            }
            Grant::Egress { from, allowed } => {
                if !allowed.iter().any(|s| s == from) {
                    return Err(Refusal::EgressDenied {
                        from: (*from).to_string(),
                    });
                }
            }
        }
    }
    Ok(())
}

/// THE ORDERED GATE. Every request, whatever protocol it arrived on, passes through this.
///
/// The order is the whole content of the function, and each position is a decision:
///
/// 1. **IDENTITY** first, because a principal that no longer exists has no grant to read and no
///    approval to have been admitted under.
/// 2. **GRANT** before anything about the upstream, so a refusal never leaks the thing it refuses.
/// 3. **ARTIFACT**: the registration-level state first — a suspended or quarantined registration
///    serves nothing whatever a single capability's fingerprint says — and only then the named
///    capability's fingerprint, computed HERE.
/// 4. **GENERATION** last, because it is the cheapest and the least specific: "something moved,
///    retry" is a worse message than any of the three above and should only be reached when none of
///    them applies.
pub(crate) fn validate_request<A: PinnedArtifact>(ask: &Ask<'_, A>) -> Result<(), Refusal> {
    // ── 1. IDENTITY, then 2. GRANT ──────────────────────────────────────────────────────────────
    // The first two steps are [`validate_visibility`], called rather than restated, so the ONE
    // grant evaluator in busbar stays one. See that function for who else asks for them alone.
    validate_visibility(ask.principal, ask.now, ask.grants)?;

    // ── 3. ARTIFACT ─────────────────────────────────────────────────────────────────────────────
    // The registration first. This is the lifecycle's OWN derivation, so the answer a dispatch gets
    // is by construction the answer the operator's views are computed from.
    let state = ask.approval.state(ask.sighting);
    if state != TrustState::Approved {
        return Err(Refusal::NotServing {
            state,
            reason: ask.approval.suspension().map(str::to_string),
        });
    }
    if let Some(fp) = &ask.capability {
        // THE PROTOCOL'S CLOSURE, RUN HERE AND NOWHERE EARLIER.
        match (fp.observe)() {
            Observed::Drifted(why) => {
                return Err(Refusal::Unobservable {
                    capability: fp.capability.to_string(),
                    why,
                })
            }
            Observed::At(digest) => {
                // `Approval::serves` is the SAME comparison the operator's changes queue is
                // rendered from, rather than a second opinion that could disagree with it at
                // exactly the moment a call races a quarantine.
                if !ask.approval.serves(fp.capability, &digest) {
                    return Err(Refusal::ArtifactDrifted {
                        capability: fp.capability.to_string(),
                        observed: digest,
                    });
                }
            }
        }
    }

    // ── 4. GENERATION ───────────────────────────────────────────────────────────────────────────
    // Movement is refusal, without inspecting the new snapshot. Deciding whether a particular change
    // mattered means re-deriving the whole selection, and a "did this specific change affect me"
    // test is exactly the reasoning that lets a revocation slip through.
    if ask.generation.admitted != ask.generation.live {
        return Err(Refusal::GenerationMoved {
            admitted: ask.generation.admitted,
            live: ask.generation.live,
        });
    }
    Ok(())
}

/// A DECISION MADE AT OPEN AND TRUSTED WHILE OPEN — the standing-permission primitive.
///
/// A long-lived response (a poll loop, a detached runner) cannot re-run the whole of
/// [`validate_request`] per frame, because most of its inputs are re-derived per frame anyway. What
/// it must NOT do is carry the PRINCIPAL forward: an `Arc<VirtualKey>` cloned into a `'static`
/// future is an identity resolved once and believed for the whole life of the stream, so a key
/// deleted for compromise does not bite until the stream ends.
///
/// So this holds the principal's ID and re-resolves it, rather than holding the principal. The
/// re-resolution is an in-memory index read — no store round trip, nothing to await — which is what
/// makes it affordable on every poll.
///
/// **THE BOUND IS PART OF THE CONTRACT AND IS NOT A CONSOLATION.** `lifetime` is what makes the
/// class of thing this guards finite: whatever cannot be re-checked cannot outlive it. Callers pass
/// their own hard cap so the two numbers are provably the same one.
#[derive(Clone, Debug)]
pub(crate) struct Standing {
    /// The principal ID, NOT the principal. `None` only where governance is disabled.
    principal: Option<String>,
    snapshot: Snapshot,
    opened_at: Instant,
    lifetime: Duration,
}

/// WHAT A LONG-LIVED RESPONSE'S RELATIONSHIP TO THE SNAPSHOT IS, and it is not the same for all of
/// them — which is why it is a type rather than a number that some caller passes `0` for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Snapshot {
    /// PINNED. The response was admitted under one snapshot and must not outlive it: everything it
    /// will do was decided against that snapshot, so a move is a lapse.
    PinnedTo(u64),
    /// WATCHING. A move is what this response EXISTS TO REPORT, not a lapse.
    ///
    /// Only honest where the response re-derives everything it says from the LIVE snapshot on every
    /// frame — which is exactly what makes the move harmless, and is a property of the caller that
    /// the caller states here rather than one this module can check.
    Watching,
}

/// A `Standing` permission that no longer stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Lapsed {
    /// The principal is gone, disabled or expired — re-resolved, not remembered.
    Identity(Refusal),
    /// The snapshot the request was admitted under has been replaced.
    Generation(Refusal),
    /// The hard cap was reached. Not a failure: a long-lived response with no end is one a client
    /// cannot tell from a hung one.
    Expired,
}

impl Standing {
    /// OPEN. Takes the principal only to read its ID off — the value is deliberately not stored.
    pub(crate) fn opened(
        principal: Option<&VirtualKey>,
        snapshot: Snapshot,
        lifetime: Duration,
    ) -> Self {
        Self {
            principal: principal.map(|p| p.id.clone()),
            snapshot,
            opened_at: Instant::now(),
            lifetime,
        }
    }

    /// RE-ASK, and hand back the principal AS IT IS NOW.
    ///
    /// The returned key is what the frame's grant must be read from. Returning it rather than a bare
    /// `Ok(())` is what stops a caller re-checking here and then reading a stale copy anyway.
    pub(crate) fn still_permitted(
        &self,
        governance: Option<&crate::governance::GovState>,
        live: u64,
        now: u64,
    ) -> Result<Option<Arc<VirtualKey>>, Lapsed> {
        if self.opened_at.elapsed() >= self.lifetime {
            return Err(Lapsed::Expired);
        }
        if let Snapshot::PinnedTo(admitted) = self.snapshot {
            if admitted != live {
                return Err(Lapsed::Generation(Refusal::GenerationMoved {
                    admitted,
                    live,
                }));
            }
        }
        let Some(id) = self.principal.as_deref() else {
            // Governance is off, so there is no principal and nothing to re-resolve.
            return Ok(None);
        };
        // Fail CLOSED on a governance runtime that has gone away underneath an open response: a
        // principal that was enforced at open and cannot be re-resolved now is not a principal this
        // frame may be written under.
        let resolved = governance
            .and_then(|g| g.lookup_by_sub(id))
            .ok_or_else(|| {
                Lapsed::Identity(Refusal::IdentityNotLive {
                    principal: id.to_string(),
                })
            })?;
        if !resolved.is_live()
            || !resolved.enabled
            || resolved.expires_at.is_some_and(|exp| now >= exp)
        {
            return Err(Lapsed::Identity(Refusal::IdentityNotLive {
                principal: id.to_string(),
            }));
        }
        Ok(Some(resolved))
    }
}

#[cfg(test)]
#[path = "tests/validate_tests.rs"]
mod validate_tests;
