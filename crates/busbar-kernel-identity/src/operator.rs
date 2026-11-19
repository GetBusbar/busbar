// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The operator credential.

use std::sync::Arc;

use busbar_contract::auth::{AuthVerdict, Principal};
use busbar_contract::auth_calls::{AuthCalls, Replay, Strip, Verified, VerifyAnswer};

/// A linked auth row: the key configuration names it by (and the auth catalog, `/info` and every
pub type LinkedAuth = (&'static str, &'static str, AuthDoor);
/// The door a linked auth row is opened through (`abi::auth`, one dispatcher).
pub type AuthDoor = busbar_contract::abi::mechanism::door::DoorFn;

/// THE OPERATOR CREDENTIAL'S FROZEN WORDS, as the composition root's migration table spells them: the
/// provider configuration names it by (the `auth.admin_auth:` default, the one `module:` whose
/// definition may carry `token:`, and a reserved hook name) and the principal id it identifies the
/// operator as. Kind-neutral values; which words they are is the root's business.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OperatorWords {
    /// The operator credential's provider key.
    pub provider: &'static str,
    /// The fixed principal id the operator credential identifies the operator as.
    pub principal_id: &'static str,
    /// The operator row's canonical plugin name: `module:` may name it as well as `provider`.
    pub canonical: &'static str,
    /// Whether the operator row is first-party (linked, or signed by a busbar release key).
    pub first_party: bool,
}

/// The auth rows this build LINKS (the composition root's, or a test binary's), with the rows'
/// names listed once at install so a reader borrows them. Linking a row never makes it the
/// operator: the operator is judged from the admitted rows' claims ([`install_operator`]).
pub(crate) static LINKED: std::sync::OnceLock<(&[LinkedAuth], Vec<&'static str>)> =
    std::sync::OnceLock::new();

/// What process start bound: the judged operator credential, or `Deferred` to the startup upgrade.
pub(crate) static OPERATOR: std::sync::OnceLock<OperatorBinding> = std::sync::OnceLock::new();

/// A `Deferred` start's judgement, bound once by the startup upgrade (`bind_deferred`).
pub(crate) static DEFERRED: std::sync::OnceLock<Judged> = std::sync::OnceLock::new();

/// Nothing bound: no operator.
static NO_OPERATOR: Judged = Judged {
    words: Ok(None),
    inert: Vec::new(),
};

// Installed once, when the build starts: off the request path.
pub use crate::off_path::operator::{
    bind_deferred, choose, compare, deferred_refusal, inert_operator, install_linked,
    install_operator, misplaced_definition_token, misplaced_token, no_default_admin_chain,
    no_mint_path, open_admin_posture_removed, operator_admission_path, operator_changed,
    operator_file_policy, operator_install_remedy, operator_token, third_party_operator,
    two_operators, unreadable_statement, Judged, OperatorBinding,
};

#[cfg(any(test, feature = "test-support"))]
static TEST_WORDS: std::sync::OnceLock<OperatorWords> = std::sync::OnceLock::new();

/// Supply operator metadata without admitting any auth row. The first metadata hand-in stands; an
/// operator judged from admitted rows takes precedence.
#[cfg(any(test, feature = "test-support"))]
pub fn install_test_words(words: OperatorWords) {
    let _ = TEST_WORDS.set(words);
}

/// This build's linked auth rows, in registration order.
pub fn linked() -> &'static [LinkedAuth] {
    LINKED.get().map(|l| l.0).unwrap_or_default()
}

/// The operator credential bound for this process: the judgement of the rows the start scan
/// admitted, or the startup upgrade's (`Err` until a `Deferred` start binds it). Nothing bound is
/// no operator.
pub fn judged() -> Result<&'static Judged, String> {
    match OPERATOR.get() {
        None => Ok(&NO_OPERATOR),
        Some(OperatorBinding::Bound(judged)) => Ok(judged),
        Some(OperatorBinding::Deferred) => DEFERRED.get().ok_or_else(deferred_refusal),
    }
}

/// The bound operator claim, if one first-party row is the operator.
fn bound() -> Option<&'static busbar_contract::auth_calls::OperatorClaim> {
    let judged = match OPERATOR.get()? {
        OperatorBinding::Bound(judged) => judged,
        OperatorBinding::Deferred => DEFERRED.get()?,
    };
    judged.words.as_ref().ok()?.as_ref()
}

/// The operator credential's provider key, as configuration spells it: the admitted operator row's
/// key, or `""` when no row is the operator.
pub fn provider() -> &'static str {
    words().provider
}

/// The principal id the operator row states it identifies the operator as.
pub fn principal_id() -> &'static str {
    words().principal_id
}

/// The operator credential's words: the bound operator row's, else explicit test metadata, else
/// none.
pub fn words() -> OperatorWords {
    if let Some(claim) = bound() {
        return OperatorWords {
            provider: &claim.provider,
            principal_id: &claim.principal,
            canonical: &claim.canonical,
            first_party: claim.first_party,
        };
    }
    #[cfg(any(test, feature = "test-support"))]
    if let Some(words) = TEST_WORDS.get() {
        return *words;
    }
    OperatorWords::default()
}

/// The names of this build's linked auth rows, in registration order.
pub fn linked_names() -> &'static [&'static str] {
    LINKED.get().map_or(&[], |l| l.1.as_slice())
}

/// Whether the bound operator row answers `op`: by its key or its canonical name. The empty word is
/// never answered.
pub fn answered(op: &str) -> bool {
    !op.is_empty() && bound().is_some_and(|c| op == c.provider || op == c.canonical)
}

/// Whether `module` names the operator keyed `op`: the key itself, or the bound operator row's
/// canonical plugin name.
pub fn names(op: &str, module: &str) -> bool {
    module == op || bound().is_some_and(|c| op == c.provider && module == c.canonical)
}

/// What the operator credential answered one request: a verdict — identified, a bad credential
/// (1.5.5's refusal bytes), or not its credential — and what rides with it. A verifier that is
/// overloaded or answered no verdict is refused (a `Reject`, fail-closed). One that answered NO
/// VERDICT is marked [`Self::no_verdict`]: a server-side failure, not the caller's bad credential,
/// which an HTTP caller answers with 503 and `Retry-After`, never 401.
#[derive(Debug)]
pub struct Judgement {
    /// The verdict.
    pub verdict: AuthVerdict,
    /// The verifier answered NO VERDICT (FAILED, FAULT, a timeout: a module failure, e.g. an IdP
    /// whose key set is unavailable). The verdict is then a `Reject` — the request is refused
    /// whoever reads it — and a caller that answers HTTP answers it 503 with `Retry-After`, never
    /// the bad credential's 401 (SIGN-auth-kind 2026-10-30).
    pub no_verdict: bool,
    /// The replay claim the identity asks for (THE DESIGN §6, Inbound verify): the caller admits
    /// the identity only once it wins the claim. `None` = none (or no identity).
    pub replay: Option<Box<Replay>>,
    /// The credential lines and query keys the plugin named, whatever its verdict: the transport
    /// strips them before any plane sees the request (THE DESIGN §6.4).
    pub strips: Vec<Strip>,
}

impl Judgement {
    /// `verdict` alone: no claim, nothing named.
    #[must_use]
    pub fn of(verdict: AuthVerdict) -> Self {
        Self {
            verdict,
            no_verdict: false,
            replay: None,
            strips: Vec::new(),
        }
    }

    /// A refusal for a verifier that answered NO VERDICT ([`Self::no_verdict`]), keeping the lines
    #[must_use]
    pub fn without_verdict(strips: Vec<Strip>) -> Self {
        Self {
            no_verdict: true,
            strips,
            ..Self::of(AuthVerdict::Reject)
        }
    }

    /// A `verify` answer as a chain reads it: the verdict, the identity's replay claim, and the
    #[must_use]
    pub fn answered(answer: VerifyAnswer) -> Self {
        if matches!(answer.verified, Verified::Failed) {
            return Self::without_verdict(answer.strips);
        }
        let (verdict, replay) = match answer.verified {
            Verified::Identity(id) => (
                AuthVerdict::Identify(Principal {
                    id: id.subject,
                    name: id.name,
                    roles: id.groups,
                    ttl_secs: id.ttl_secs,
                }),
                id.replay,
            ),
            Verified::Reject => (AuthVerdict::Reject, None),
            Verified::Pass => (AuthVerdict::Pass, None),
            Verified::Overloaded | Verified::Failed => (AuthVerdict::Reject, None),
        };
        Self {
            verdict,
            no_verdict: false,
            replay,
            strips: answer.strips,
        }
    }
}

/// The operator credential, as the auth axis answered it.
pub enum OperatorCredential {
    /// No admitted auth row answers the operator credential's provider.
    Unanswered,
    /// A row answers it and no operator-backed entry carries settings: nothing to judge, so a
    /// backed provider passes to the next chain position (and identifies no one).
    Unset,
    /// One instance per backed provider that carries settings, each opened with its own settings
    /// exactly as every auth instance is; a backed provider with none is unset.
    Opened(foldhash::HashMap<String, Arc<dyn AuthCalls>>),
}

/// The operator credential on an admin chain: the credential the auth axis answered, and the
pub struct Operator {
    cred: OperatorCredential,
    names: foldhash::HashSet<String>,
    /// The carriers the operator credential's row states (its Statement's carrier marks, in order):
    carriers: Vec<String>,
}

impl Operator {
    /// An operator credential from its parts, as building the admin chain made them (see
    /// `Operator::new` and `Operator::open`, which run once, when the admin chain is built).
    pub(crate) fn from_parts(cred: OperatorCredential, names: foldhash::HashSet<String>) -> Self {
        Self {
            cred,
            names,
            carriers: Vec::new(),
        }
    }

    /// THE ONE JUDGEMENT: whether the provider `name`, whose `identity-providers:` definition names
    pub fn backed(
        op: &str,
        name: &str,
        module: Option<&str>,
        is_op: &dyn Fn(&str) -> bool,
    ) -> bool {
        module.map_or(name == op, is_op)
    }

    /// The carriers the operator credential's row states, in its Statement's order: the admin
    #[must_use]
    pub fn carriers(&self) -> &[String] {
        &self.carriers
    }

    /// Whether the admin-chain provider `name` is the operator credential.
    pub fn is(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    /// The opened operator instance the backed provider `name` is judged by, if it has one.
    pub fn instance(&self, name: &str) -> Option<&Arc<dyn AuthCalls>> {
        match &self.cred {
            OperatorCredential::Opened(opened) if self.is(name) => opened.get(name),
            _ => None,
        }
    }

    /// Whether the backed provider `name` is the operator credential with no settings: unset.
    pub fn unset(&self, name: &str) -> bool {
        self.is(name)
            && !matches!(self.cred, OperatorCredential::Unanswered)
            && self.instance(name).is_none()
    }

    /// Whether a principal `id` that the admin-chain provider `name` identified is the operator: the
    pub fn mints(&self, name: Option<&str>, id: &str, principal_id: &str) -> bool {
        name.is_some_and(|n| self.is(n)) && id == principal_id
    }
}

impl std::ops::Deref for Operator {
    type Target = OperatorCredential;
    fn deref(&self) -> &OperatorCredential {
        &self.cred
    }
}

impl std::ops::DerefMut for Operator {
    fn deref_mut(&mut self) -> &mut OperatorCredential {
        &mut self.cred
    }
}
