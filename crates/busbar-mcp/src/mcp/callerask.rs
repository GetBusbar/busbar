// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUSBAR'S OWN ASK — an `InputRequiredResult` composed entirely from OPERATOR CONFIGURATION,
//! filtered by the CALLER'S declared capabilities, and sealed with a `requestState` busbar mints.
//!
//! ## The one sentence this module exists to keep true
//!
//! **A [`CallerAsk`] is authored by the operator. An [`super::inputreq::Ask`] arrives from an
//! upstream and terminates. There is no conversion between them, in either direction, and there
//! cannot be one.**
//!
//! That is not a comment asking to be believed, and — since 2026-08-12 — it is not a source scan
//! asking to be trusted either. It is a fact about what is CONSTRUCTIBLE.
//!
//! [`CallerAsk`] lives in the private [`authored`] submodule below with all three of its fields
//! private to that module, and `authored` exports exactly one constructor:
//! `CallerAsk::from_config(&str, &AskEntryCfg)`. Nothing in this file, in this plane, or in this
//! crate can produce a `CallerAsk` from anything other than an operator-written `AskEntryCfg` —
//! not by a struct literal, not by a `From` impl, not by mutating one after the fact. An
//! `impl From<super::inputreq::Ask> for CallerAsk` is not merely forbidden; it cannot be written,
//! because its body has no way to build the value it would have to return.
//!
//! This REPLACES `tests/callerask_tests.rs::callerask_names_nothing_upstream_derived`, which
//! `include_str!`-scanned this file for the words `inputreq` / `upstream` / `ServerAsk` /
//! `RpcOutcome`. That scan defended a real invariant by an accident of geography: it was a fact
//! about a PATH, and the path stops existing when this tree is rebuilt. The invariant does not.
//! The failure mode it guarded — somebody adds `{{upstream.…}}` substitution into `params` "for
//! convenience", and the whole design becomes laundering with extra steps while looking like a
//! feature — is now a compile error rather than a grep result.
//!
//! ## Why busbar may ask at all, when it refuses to relay
//!
//! `mrtr.mdx` addresses two roles, "Servers" and "Clients", and says nothing whatsoever about a
//! party that is both — a grep of the file for `intermediar|proxy|gateway|on behalf` returns
//! nothing. Its send-side requirements are ALL `MAY`: no sentence anywhere obliges a server to emit
//! an `InputRequiredResult`. So the question is not what busbar is permitted to forward; it is what
//! busbar is willing to say in its own name.
//!
//! busbar already answers that question the same way one field over. From `scripts/mcp-subject/boot.sh`:
//! *"busbar publishes the OPERATOR's description rather than the upstream's: what an approval means
//! is that this operator vouched for this tool, and echoing text the upstream can rewrite at will
//! would let it edit its own approval."* An ask is that rule applied to one more field, and it is
//! the field where it matters most: if busbar will not echo an upstream's DESCRIPTION, it certainly
//! will not echo an upstream's DEMAND FOR AUTHORITY.
//!
//! ## What is honestly acquired, and why the grammar is shaped to make it visible
//!
//! An operator who declares an `elicitation/create` has built a human-in-the-loop confirmation gate.
//! An operator who declares a `sampling/createMessage` has asked the CALLER'S model to run a
//! completion on the CALLER'S budget — the mirror image of what `inputreq`'s deny-by-default
//! protects busbar from, pointed the other way. That is why `ask_caller` is per capability,
//! operator-written, literal, and absent by default: absence means no ask, which is the behaviour of
//! every deployment that does not opt in.
//!
//! ## The empty-filter trap
//!
//! If filtering by the caller's declared capabilities removes EVERY ask in a round, the answer is
//! [`AskDecision::Refuse`] and never [`AskDecision::Proceed`]. Proceeding would hand every caller a
//! way to strip an operator's confirmation gate by declaring no capabilities — the gate would be
//! opt-out, by the party it exists to gate. `mrtr.mdx:245` independently forbids an empty
//! `InputRequiredResult`, so refusing is also the only conformant answer; but the security reason is
//! the one that would still hold if the specification said nothing.

use super::config::{AskEntryCfg, AskRoundCfg};
use busbar_substrate::plane::approvals::{self, AskState, Sealer};

/// The three client-side methods an ask may name, and the capability key each is gated by.
///
/// A closed set, matched by exact string: `mrtr.mdx:184-192` names exactly these, and a fourth that
/// the protocol grows later must be a deliberate addition here rather than something that flows
/// through because nobody wrote it down.
const ELICITATION: &str = "elicitation/create";
const SAMPLING: &str = "sampling/createMessage";
const ROOTS: &str = "roots/list";

pub(crate) use authored::CallerAsk;

/// THE PRIVACY BOUNDARY, and it is the entire enforcement of this module's one sentence.
///
/// Rust's field privacy is MODULE-scoped, not type-scoped: a private field is readable and writable
/// by every line of the module that declares it. So a `CallerAsk` declared at this file's top level
/// with private fields would still be freely constructible by the rest of this file — including by
/// an `impl From<super::inputreq::Ask>` somebody adds two hundred lines down. Putting the type in
/// its OWN module shrinks that blast radius to the handful of lines below, which contain exactly one
/// constructor and no other way in.
///
/// What this buys, stated as the compiler sees it: outside `authored`, `CallerAsk`'s fields do not
/// exist. There is no struct literal, no `..Default::default()`, no field assignment, no `&mut`
/// accessor and no `From` impl that could produce one, because none of them can name a field. The
/// only expression in the entire crate whose type is `CallerAsk` is a call to `from_config`, whose
/// single data argument is an `&AskEntryCfg` — the operator's deserialised YAML.
///
/// The residual, named rather than hidden: this makes the ONLY input an `AskEntryCfg`. It does not
/// stop someone forging an `AskEntryCfg` at runtime out of upstream text and passing THAT. That
/// residual is closed on the other side, by `structure-lint.sh`'s `H-operator-authored-ask` choke
/// point, which bans constructing an `AskEntryCfg` anywhere but the config module that deserialises
/// it. Two halves, both mechanical, neither of them a grep for a module name.
mod authored {
    use super::AskEntryCfg;

    /// ONE ask busbar is making of its caller — an entry of the `inputRequests` map.
    ///
    /// Its ONLY constructor is [`CallerAsk::from_config`]. There is deliberately no `From` impl, no
    /// `new(method, params)`, and no field that is anything but a clone of operator configuration.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct CallerAsk {
        /// The server-assigned key of this entry in `inputRequests`. The operator writes it, because
        /// the conformance suite asserts one of them (`user_name`) BY NAME and because the retry
        /// addresses its answer to it.
        key: String,
        /// `elicitation/create`, `sampling/createMessage` or `roots/list`.
        method: String,
        /// The request `params`, verbatim from the operator's YAML. No templating, no substitution,
        /// no value from any upstream response — see the module header for why that is structural.
        params: serde_json::Value,
    }

    impl CallerAsk {
        /// THE ONLY CONSTRUCTOR. Takes an operator-written map entry and nothing else. There is
        /// deliberately no `From` impl and no `new(method, params)`: every field of a `CallerAsk` is
        /// a clone of configuration, and the only way to get one is to hold configuration.
        pub(crate) fn from_config(key: &str, cfg: &AskEntryCfg) -> Self {
            Self {
                key: key.to_string(),
                method: cfg.method.clone(),
                params: cfg.params.clone().unwrap_or_else(|| serde_json::json!({})),
            }
        }

        /// The `inputRequests` map key this entry is published under.
        pub(crate) fn key(&self) -> &str {
            &self.key
        }

        /// The client-side method this ask names.
        pub(crate) fn method(&self) -> &str {
            &self.method
        }

        /// The request `params`, by shared reference. Deliberately NOT `&mut`: a mutable accessor
        /// would hand back the exact edit this module's privacy exists to prevent.
        pub(crate) fn params(&self) -> &serde_json::Value {
            &self.params
        }
    }
}

impl CallerAsk {
    /// The capability key the CALLER must have declared for this ask to be legal to send.
    /// `mrtr.mdx:246`: "Servers MUST NOT send an `inputRequests` that the client has not declared
    /// support for in its capabilities."
    fn capability_key(&self) -> Option<&'static str> {
        match self.method() {
            ELICITATION => Some("elicitation"),
            SAMPLING => Some("sampling"),
            ROOTS => Some("roots"),
            // A method outside the closed set has no capability that could declare it, so it can
            // never be legal to send. `None` is filtered out below rather than passed through.
            _ => None,
        }
    }
}

/// What to do with this request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AskDecision {
    /// No ask is configured, or every configured round is already answered. Dispatch normally.
    Proceed,
    /// Emit an `InputRequiredResult` carrying these asks and this sealed state.
    Ask {
        asks: Vec<CallerAsk>,
        request_state: String,
        /// Which round this ask ENDS, for the meter and the audit row.
        round: u32,
    },
    /// Refuse, with a busbar-attributed reason. NEVER "proceed anyway".
    Refuse(Refusal),
}

/// Why busbar refused rather than asking or proceeding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The caller declared none of the capabilities this round's asks need. Refusing rather than
    /// proceeding is the empty-filter trap in the module header.
    NoDeclaredCapability {
        capability: String,
        round: u32,
        /// The DISTINCT client-capability keys this round's asks needed, in the operator's own
        /// order. Carried because the refusal is only actionable if it names what to declare, and
        /// `capability` above is the namespaced TOOL — a different noun that happens to share the
        /// word.
        required: Vec<&'static str>,
    },
    /// The per-server cap on caller-facing rounds was reached.
    RoundCapExceeded { capability: String, cap: u32 },
    /// The presented `requestState` failed verification.
    StateRejected(approvals::Rejected),
    /// The caller sent `inputResponses` or `requestState` on a capability that declares no ask, so
    /// there is nothing they could be answering.
    Unsolicited { capability: String },
    /// A retry that presented VERIFIED state for an outstanding round and answered nothing at all.
    ///
    /// Deliberately narrow. `input-required-result-missing-input-response` makes re-asking a
    /// `SHOULD`, and that case — a caller sending `inputResponses` with no state, or with the wrong
    /// keys — lands on the opening round and is answered with a fresh ask rather than here. What is left is a
    /// caller holding good state that answered nothing, which is not a caller that can be helped by
    /// being asked the same thing again.
    Unanswered { capability: String, missing: String },
    /// busbar has no signing key, so it cannot seal state, so it must not ask.
    NoSealer { capability: String },
}

impl Refusal {
    /// The stable audit reason word.
    pub(crate) fn audit_reason(&self) -> &'static str {
        match self {
            Refusal::NoDeclaredCapability { .. } => "ask_no_declared_capability",
            Refusal::RoundCapExceeded { .. } => "ask_round_cap",
            Refusal::StateRejected(r) => r.audit_reason(),
            Refusal::Unsolicited { .. } => "ask_unsolicited_state",
            Refusal::Unanswered { .. } => "ask_unanswered",
            Refusal::NoSealer { .. } => "ask_no_sealer",
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::NoDeclaredCapability {
                capability, round, ..
            } => write!(
                f,
                "`{capability}` requires input from you before it runs, and your \
                 `_meta.io.modelcontextprotocol/clientCapabilities` declares none of the \
                 capabilities round {round} of that exchange needs. Declaring no capabilities does \
                 not skip the operator's gate; it means the call cannot proceed."
            ),
            Refusal::RoundCapExceeded { capability, cap } => write!(
                f,
                "this exchange with `{capability}` has already used its {cap} input rounds. The cap \
                 is hard and it is carried inside the request state, so it cannot be reset by \
                 replaying an earlier one."
            ),
            Refusal::StateRejected(r) => write!(f, "{r}"),
            Refusal::Unsolicited { capability } => write!(
                f,
                "`{capability}` did not ask you for any input, so `inputResponses` and \
                 `requestState` have nothing to answer. This server does not accept request state it \
                 did not mint."
            ),
            Refusal::Unanswered {
                capability,
                missing,
            } => write!(
                f,
                "the retry of `{capability}` answered none of the requested inputs (expected \
                 `{missing}`)."
            ),
            Refusal::NoSealer { capability } => write!(
                f,
                "`{capability}` is configured to request input, but this deployment has no \
                 `auth.signing_key` and therefore cannot mint the integrity-protected `requestState` \
                 the protocol requires. The call is refused rather than served with unprotected \
                 state."
            ),
        }
    }
}

/// The caller's side of the retry: what it answered, and the state it echoed.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Retry<'a> {
    /// `params.inputResponses`, if present.
    pub(crate) responses: Option<&'a serde_json::Value>,
    /// `params.requestState`, if present.
    pub(crate) state: Option<&'a str>,
}

/// Everything about the request that the seal binds to.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Bind<'a> {
    /// The authenticated principal — the inbound key id. `mrtr.mdx:235`.
    pub(crate) principal: &'a str,
    /// `tools/call` or `prompts/get`.
    pub(crate) method: &'a str,
    /// The namespaced capability.
    pub(crate) capability: &'a str,
    /// The live catalogue generation.
    pub(crate) generation: u64,
    /// Unix seconds.
    pub(crate) now: u64,
    /// The principal's LIVE roots epoch — what a received `notifications/roots/list_changed` moves.
    /// Sealed into state exactly when the exchange includes a `roots/list` ask, and compared on
    /// redemption; see [`crate::mcp::roots`].
    pub(crate) roots_epoch: u64,
}

/// THE APPROVAL MACHINERY: what mints continuation state, and what redeems it once.
///
/// One parameter rather than two because they are one thing viewed from either end — a `Sealer` with
/// no way to retire what it issues mints approvals nothing spends, which is precisely the defect the
/// spent-approval ledger exists to close, and a call site that could pass the first without the
/// second is a call site that can reintroduce it. The ledger is not named here any longer: the
/// completion arm redeems through the host `approval_redeem_q` slot, which pulls the shared ledger
/// host-side, so this carries the host handle rather than a `&SpentTokenLedger` an extracted plane
/// could not hold.
#[derive(Clone, Copy)]
pub(crate) struct Approvals<'a> {
    /// Mints and opens the sealed `requestState`. `None` is a deployment with no signing key, which
    /// refuses to ask at all rather than issue state it could not verify.
    pub(crate) sealer: Option<&'a Sealer>,
    /// The neutral host seam the completion arm redeems the one-time approval through — its
    /// `approval_redeem` method spends against the shared spent-approval ledger it pulls host-side,
    /// minting the transient `HostCtx` internally, so this carries no raw `HostCtx` across the plane.
    pub(crate) host: &'a dyn busbar_substrate::plane_host::EngineHost,
}

/// THE DECISION. Config, caller input, a clock — and the ledger of approvals already spent. It is
/// not in scope of any upstream response and cannot be — see the module header.
///
/// `rounds` is the operator's ordered list of rounds for THIS capability; an empty list means the
/// capability declares no ask, which is the default and is today's behaviour.
///
/// NOT PURE, and only in one place: the arm that COMPLETES an exchange marks the approval it
/// consumed as spent. That effect lives here rather than at the call site on purpose — a caller that
/// had to remember to record the spend is a caller that can forget, and the check and the record
/// have to be one atomic act or two concurrent redemptions both pass it.
pub(crate) fn decide(
    rounds: &[AskRoundCfg],
    cap: u32,
    caller_capabilities: &serde_json::Value,
    retry: Retry<'_>,
    bind: Bind<'_>,
    args_digest: &str,
    approvals: Approvals<'_>,
) -> AskDecision {
    let Approvals { sealer, host } = approvals;
    // (1) A capability that declares NO ask never asks, and never accepts state either. Accepting
    // state here would mean busbar verifying a blob it had no reason to have minted.
    if rounds.is_empty() {
        if retry.state.is_some() || retry.responses.is_some() {
            return AskDecision::Refuse(Refusal::Unsolicited {
                capability: bind.capability.to_string(),
            });
        }
        return AskDecision::Proceed;
    }

    // (2) WHICH ROUND IS THIS? Read from the sealed state, never from a counter busbar holds between
    // requests and never from anything the caller can write. A caller with no state has not started one.
    // The approval this request is presenting, if it is presenting one: the nonce that identifies it
    // and the instant past which it could not be opened anyway. Carried down to the completion arm,
    // which is the only place it is spent.
    let mut presented: Option<(String, u64)> = None;
    let next_round = match retry.state {
        None => {
            // `mrtr.mdx` client requirements: a client MUST NOT invent state. Responses without one
            // are answering nothing.
            0u32
        }
        Some(blob) => {
            let Some(sealer) = sealer else {
                return AskDecision::Refuse(Refusal::NoSealer {
                    capability: bind.capability.to_string(),
                });
            };
            let opened = match sealer.open(blob, bind.now) {
                Ok(s) => s,
                Err(e) => return AskDecision::Refuse(Refusal::StateRejected(e)),
            };
            if let Err(e) = opened.matches(
                bind.principal,
                bind.method,
                bind.capability,
                args_digest,
                bind.generation,
            ) {
                return AskDecision::Refuse(Refusal::StateRejected(e));
            }
            // THE ROOTS EPOCH, compared only on state that carries one — which is only state minted
            // for an exchange that asks for roots. The caller's own
            // `notifications/roots/list_changed` moved the live value, so a roots answer sealed
            // before it is an answer the caller has disavowed, and redeeming it would dispatch on
            // stale roots inside the very TTL window the seal polices. Checked AFTER `matches`, so
            // it can only ever refuse the legitimate holder — see `Rejected::StaleRoots` on why
            // that ordering is what makes its distinct message safe to say.
            if opened
                .roots_epoch
                .is_some_and(|sealed| sealed != bind.roots_epoch)
            {
                return AskDecision::Refuse(Refusal::StateRejected(
                    approvals::Rejected::StaleRoots,
                ));
            }
            presented = Some((
                opened.nonce.clone(),
                opened.issued_at.saturating_add(opened.ttl_secs),
            ));
            opened.round.saturating_add(1)
        }
    };

    // (3) THE BOUND, checked against the round we would be about to serve. Carried in the seal, so a
    // caller replaying round-1 state for ever is replaying a round-1 index for ever and never gets
    // past `cap`.
    if next_round >= cap && (next_round as usize) < rounds.len() {
        return AskDecision::Refuse(Refusal::RoundCapExceeded {
            capability: bind.capability.to_string(),
            cap,
        });
    }

    // (4) EVERY ROUND ANSWERED ⇒ the exchange is complete and the call proceeds. This is the ONLY
    // arm that dispatches, and reaching it requires a verified state for the last configured round.
    let Some(this_round) = rounds.get(next_round as usize) else {
        // AND THE APPROVAL IS NOW SPENT. Everything above proves the state was busbar's, was this
        // caller's, was for this exact request and has not lapsed — all of which is equally true of
        // the SECOND presentation of a state already redeemed. Without this, an operator who gated a
        // tool because it moves money got confirm-once, execute-many.
        //
        // `rounds` is non-empty here (the empty case returned at step 1), so an exchange can only
        // complete by presenting state, and `presented` is therefore always `Some`. The `else` is
        // the fail-closed reading of a shape that cannot occur rather than a case with a meaning.
        let Some((nonce, expires_at)) = presented else {
            return AskDecision::Refuse(Refusal::StateRejected(approvals::Rejected::AlreadySpent));
        };
        // THE REDEMPTION runs through the neutral host seam's `approval_redeem`, which spends against
        // the shared spent-approval ledger it pulls host-side — the atomic check-and-record stays
        // behind the seam, so this arm names no `SpentTokenLedger` (nor the `#[repr(C)]` query POD) an
        // extracted plane could not hold. `true` is the FIRST redemption and allows; already-spent, a
        // ledger that could not answer, and a caught fault all come back `false` and land on the same
        // fail-closed refusal.
        if !host.approval_redeem(&nonce, expires_at, bind.now) {
            return AskDecision::Refuse(Refusal::StateRejected(approvals::Rejected::AlreadySpent));
        }
        return AskDecision::Proceed;
    };

    // (5) A round past the first must actually have been answered. `missing-input-response` makes
    // re-asking the SHOULD, and that case lands on the opening round above and is answered with a fresh ask.
    if next_round > 0 {
        let answered = retry
            .responses
            .and_then(|v| v.as_object())
            .is_some_and(|m| !m.is_empty());
        if !answered {
            let previous = rounds
                .get(next_round as usize - 1)
                .map(|r| r.keys().cloned().collect::<Vec<_>>().join(", "))
                .unwrap_or_default();
            return AskDecision::Refuse(Refusal::Unanswered {
                capability: bind.capability.to_string(),
                missing: previous,
            });
        }
    }

    // (6) THE CAPABILITY FILTER. `mrtr.mdx:246`. An ask whose method the caller has not declared is
    // dropped, and an ask naming a method outside the closed set is dropped too — it has no
    // capability that could declare it.
    let asks: Vec<CallerAsk> = this_round
        .iter()
        .map(|(key, cfg)| CallerAsk::from_config(key, cfg))
        .filter(|a| {
            a.capability_key()
                .is_some_and(|k| declared(caller_capabilities, k))
        })
        .collect();

    // (7) THE EMPTY-FILTER TRAP. See the module header: this must be `Refuse`, never `Proceed`.
    if asks.is_empty() {
        // The keys this round WOULD have needed, computed from the operator's own asks rather than
        // guessed, de-duplicated but order-preserving so two runs report one refusal identically.
        let mut required: Vec<&'static str> = Vec::new();
        for (key, cfg) in this_round.iter() {
            if let Some(k) = CallerAsk::from_config(key, cfg).capability_key() {
                if !required.contains(&k) {
                    required.push(k);
                }
            }
        }
        return AskDecision::Refuse(Refusal::NoDeclaredCapability {
            capability: bind.capability.to_string(),
            round: next_round,
            required,
        });
    }

    // (8) SEAL. No key, no ask.
    let Some(sealer) = sealer else {
        return AskDecision::Refuse(Refusal::NoSealer {
            capability: bind.capability.to_string(),
        });
    };
    let Ok(nonce) = approvals::nonce() else {
        // Entropy failure. Refusing is the only safe arm: a predictable nonce is a replay window.
        return AskDecision::Refuse(Refusal::NoSealer {
            capability: bind.capability.to_string(),
        });
    };
    // Does ANY configured round of this exchange ask for roots? Judged over the whole exchange
    // rather than this round alone, because an earlier round's roots answer feeds the final
    // dispatch exactly as a later one's does — a multi-round exchange whose first round gathered
    // roots is stale from the first round on.
    let exchange_asks_roots = rounds
        .iter()
        .flat_map(|round| round.values())
        .any(|cfg| cfg.method == ROOTS);
    let request_state = sealer.mint(&AskState {
        principal: bind.principal.to_string(),
        method: bind.method.to_string(),
        capability: bind.capability.to_string(),
        args_digest: args_digest.to_string(),
        generation: bind.generation,
        round: next_round,
        nonce,
        issued_at: bind.now,
        ttl_secs: approvals::DEFAULT_TTL_SECS,
        // Present exactly when the exchange includes a roots ask, so a roots announcement cannot
        // invalidate a caller's unrelated confirmations. See `crate::mcp::roots`.
        roots_epoch: exchange_asks_roots.then_some(bind.roots_epoch),
    });
    AskDecision::Ask {
        asks,
        request_state,
        round: next_round,
    }
}

/// ONE round's asks, built from the operator's map and filtered to what THIS caller declared it can
/// answer — the same construction and the same filter [`decide`] applies to the synchronous loop.
///
/// Exposed for the SEP-2663 task path (`super::tasks`), which asks the same operator-written rounds
/// from inside a task rather than across a retry. It is the same rule in both places for the reason
/// `mrtr.mdx:246` gives: a server must not send an `inputRequests` the client has not declared
/// support for, and where the ask is carried does not change who has to be able to answer it.
///
/// There is deliberately no `request_state` here and none is minted. SEP-2663 removed the field
/// from the v2 wire: a task is addressed by its own `taskId`, which busbar minted and holds, so
/// there is no round-trip through the caller for a seal to protect.
pub(crate) fn asks_for_round(
    round: &AskRoundCfg,
    capabilities: &serde_json::Value,
) -> Vec<CallerAsk> {
    round
        .iter()
        .map(|(key, cfg)| CallerAsk::from_config(key, cfg))
        .filter(|ask| {
            ask.capability_key()
                .is_some_and(|k| declared(capabilities, k))
        })
        .collect()
}

/// Has the caller declared `key` in `_meta.io.modelcontextprotocol/clientCapabilities`?
///
/// PRESENCE of the member, per the schema — the value is an options object and `{}` is a complete
/// declaration. `null` is deliberately NOT a declaration: it is what a client sends when it means
/// "no", and reading it as yes would be busbar deciding on a client's behalf what that client can
/// do, which is the exact thing `ingress` refuses to do when the whole member is absent.
fn declared(capabilities: &serde_json::Value, key: &str) -> bool {
    capabilities.get(key).is_some_and(|v| !v.is_null())
}

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/callerask_tests.rs"]
mod callerask_tests;

// THE GATE JUDGED FROM OUTSIDE IT: one approval, presented twice, against a real upstream that
// records what it was told to do. Separate from the file above because nothing in it may reach into
// the decision — the claim is about what a caller can make happen, not about which arm answered.
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/confirm_once_tests.rs"]
mod confirm_once_tests;
