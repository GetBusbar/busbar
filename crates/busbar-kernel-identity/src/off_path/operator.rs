// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The operator credential's build-time half: the linked rows installed, the operator judged from
//! the admitted rows' claims and bound, the admin chain's operator credential built, and its
//! refusal and migration text spelled.

use std::sync::Arc;

use busbar_contract::auth_calls::{AuthCalls, OperatorClaim, OperatorClaims};

use crate::operator::{LinkedAuth, Operator, OperatorCredential, DEFERRED, LINKED, OPERATOR};

/// Install this build's linked auth rows. Linking a row never makes it the operator.
pub fn install_linked(rows: &'static [LinkedAuth]) {
    let _ = LINKED.get_or_init(|| (rows, rows.iter().map(|r| r.0).collect()));
}

/// The operator credential judged from the admitted rows' claims (OPERATOR-FROM-ADMITTED-AUTH
/// §3.3): `words` is the one first-party claim (`Ok(None)`: none), or the refusal every config
/// read answers; `inert` holds the non-first-party claims, which never become the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judged {
    /// The operator, none, or why there is none that can be trusted.
    pub words: Result<Option<OperatorClaim>, String>,
    /// The claims that are not first-party.
    pub inert: Vec<OperatorClaim>,
}

/// What process start binds: a judgement, or `Deferred` to the startup upgrade's own view of a
/// pre-1.6 `plugins:` block (§3.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorBinding {
    /// Judged from the start scan's rows.
    Bound(Judged),
    /// Bound once, later, by the startup upgrade ([`bind_deferred`]).
    Deferred,
}

/// THE ONE JUDGEMENT of the operator claims: first-party claims only, at most one. Two or more is
/// no operator and a refusal naming every claimant; an unreadable statement is a refusal (it
/// cannot say whether it is an operator); a claim that is not first-party is inert, whatever the
/// first-party outcome. Pure: the same claims give the same judgement.
#[must_use]
pub fn choose(claims: &OperatorClaims) -> Judged {
    let (mut first_party, inert): (Vec<OperatorClaim>, Vec<OperatorClaim>) =
        claims.claims.iter().cloned().partition(|c| c.first_party);
    let words = if !claims.unreadable.is_empty() {
        Err(unreadable_statement(&claims.unreadable))
    } else if first_party.len() > 1 {
        let rows: Vec<&str> = first_party.iter().map(|c| c.provider.as_str()).collect();
        Err(two_operators(&rows))
    } else {
        Ok(first_party.pop())
    };
    Judged { words, inert }
}

/// Bind the operator credential for the process lifetime, at process start, before any config is
/// read. The first binding stands.
pub fn install_operator(binding: OperatorBinding) {
    let _ = OPERATOR.set(binding);
}

/// Bind the judgement of a `Deferred` start: once, by the startup upgrade, from its own converted
/// `plugins:` view. Refused when process start bound the operator, or when it is already bound.
pub fn bind_deferred(judged: Judged) -> Result<(), String> {
    match OPERATOR.get() {
        Some(OperatorBinding::Deferred) => DEFERRED.set(judged).map_err(|_| {
            config_text(format_args!(
                "the operator credential of this start is already bound; it binds once"
            ))
        }),
        _ => Err(config_text(format_args!(
            "the operator credential was bound at process start; nothing is deferred"
        ))),
    }
}

/// THE RESTART CHECK: `now` (a build's or validate's judgement) against `was` (the bound one), as a
/// whole result: refused or not, the operator's key, canonical name, principal and trust bit, and
/// the inert claims by canonical name. Version and signer are not compared, so a same-fact upgrade
/// of the operator plugin is no change.
pub fn compare(was: &Judged, now: &Judged) -> Result<(), String> {
    if judged_key(was) == judged_key(now) {
        return Ok(());
    }
    Err(operator_changed(&describe(was), &describe(now)))
}

type ClaimKey<'a> = (&'a str, &'a str, &'a str, bool);

fn judged_key(j: &Judged) -> (Result<Option<ClaimKey<'_>>, &str>, Vec<&str>) {
    let words = match &j.words {
        Ok(claim) => Ok(claim.as_ref().map(|c| {
            (
                c.provider.as_str(),
                c.canonical.as_str(),
                c.principal.as_str(),
                c.first_party,
            )
        })),
        Err(refusal) => Err(refusal.as_str()),
    };
    let mut inert: Vec<&str> = j.inert.iter().map(|c| c.canonical.as_str()).collect();
    inert.sort();
    inert.dedup();
    (words, inert)
}

fn describe(j: &Judged) -> String {
    let words = match &j.words {
        Ok(Some(c)) => format!(
            "operator '{}' (plugin {}, principal '{}')",
            c.provider, c.canonical, c.principal
        ),
        Ok(None) => "no operator".to_owned(),
        Err(refusal) => format!("no operator ({refusal})"),
    };
    if j.inert.is_empty() {
        return words;
    }
    let inert: Vec<&str> = j.inert.iter().map(|c| c.provider.as_str()).collect();
    format!("{words}, ignoring {}", inert.join(", "))
}

/// The one place the operator credential's refusal and migration text is spelled into a `String`:
/// configuration checking and migration, at boot or on an admin edit, never a request.
#[cold]
pub(crate) fn config_text(text: std::fmt::Arguments<'_>) -> String {
    std::fmt::format(text)
}

impl Operator {
    /// The operator credential of the operator provider `op`, answering for `op` referenced bare,
    /// built once, when the admin chain is built.
    pub fn new(op: &str) -> Self {
        let names = std::iter::once(op.to_owned()).collect();
        Operator::from_parts(OperatorCredential::Unanswered, names)
    }

    /// The operator credential of `op`, answering for every provider it backs: `Unanswered` when no
    /// admitted row answers `op`; else each backed provider's instance in `opened` (opened with its
    /// own settings), and a backed provider with none is unset. Built once, when the admin chain is
    /// built.
    pub fn open<'a>(
        op: &str,
        defs: impl Iterator<Item = (&'a str, &'a str)> + Clone,
        is_op: &dyn Fn(&str) -> bool,
        answered: bool,
        opened: foldhash::HashMap<String, Arc<dyn AuthCalls>>,
    ) -> Self {
        let lookup = defs.clone();
        let module_of = |name: &str| lookup.clone().find(|d| d.0 == name).map(|d| d.1);
        let names = std::iter::once(op)
            .chain(defs.map(|d| d.0))
            .filter(|name| Self::backed(op, name, module_of(name), is_op))
            .map(str::to_owned)
            .collect();
        let cred = match (answered, opened.is_empty()) {
            (false, _) => OperatorCredential::Unanswered,
            (true, true) => OperatorCredential::Unset,
            (true, false) => OperatorCredential::Opened(opened),
        };
        Operator::from_parts(cred, names)
    }
}

/// THE OPERATOR CREDENTIAL'S REFUSALS. Each echoes only operator configuration and admitted row
/// names (OPERATOR-FROM-ADMITTED-AUTH §3.5).
///
/// A 1.5 `token:` on the operator-backed `identity-providers.<name>` definition: 1.6 takes the
/// plugin's own `settings` instead.
pub fn operator_token(name: &str) -> String {
    operator_token_at(&format!("identity-providers.{name}"))
}

/// A 1.5 `token:` on the operator-backed chain entry `name` of `auth.<plane>`.
pub fn operator_token_entry(plane: &str, name: &str) -> String {
    operator_token_at(&format!("auth.{plane}[{name}]"))
}

fn operator_token_at(at: &str) -> String {
    config_text(format_args!(
        "{at}: `token:` is the 1.5 operator credential. 1.6 takes the plugin's `settings` instead; \
         see docs/migration-1.6.md#operator-credential. Replace `token:` with `settings: {{sha256: \
         \"<SHA-256 of the token, 64 lower-case hex>\"}}` in config.yaml."
    ))
}

/// The install remedy a 1.5 `token:` carries when no admitted row is the operator credential.
pub fn operator_install_remedy() -> String {
    config_text(format_args!(
        "no admitted first-party auth plugin states the operator credential: install the \
         first-party operator credential plugin in plugins.dir (plugins.enabled: true)"
    ))
}

/// More than one first-party auth row states the operator credential.
pub fn two_operators(rows: &[&str]) -> String {
    config_text(format_args!(
        "more than one first-party auth plugin states the operator credential ({}): at most one \
         may; remove all but one from plugins.dir",
        rows.join(", ")
    ))
}

/// Auth rows whose Statement does not read: they cannot be judged as or against the operator.
pub fn unreadable_statement(rows: &[(String, String)]) -> String {
    let rows = rows
        .iter()
        .map(|(row, error)| format!("auth plugin '{row}' states facts that do not read ({error})"))
        .collect::<Vec<_>>()
        .join("; ");
    config_text(format_args!(
        "{rows}: it cannot be judged as or against the operator credential; replace or remove it"
    ))
}

/// `referrer` names `row`, which states the operator credential but is not first-party.
pub fn third_party_operator(row: &str, referrer: &str) -> String {
    config_text(format_args!(
        "{referrer} names '{row}', which states the operator credential but is not first-party. \
         1.6.0 takes the operator statement from first-party plugins only. Install the first-party \
         operator credential, or remove the reference."
    ))
}

/// An unreferenced non-first-party row states the operator credential: it is ignored (a warning).
pub fn inert_operator(row: &str) -> String {
    config_text(format_args!(
        "auth plugin '{row}' states the operator credential but is not first-party; it is ignored \
         as the operator. Remove it from plugins.dir, or narrow plugins.trust, to silence this."
    ))
}

/// An operator-backed definition set anywhere but config.yaml.
pub fn operator_file_policy(name: &str) -> String {
    config_text(format_args!(
        "identity-providers.{name} is backed by the operator credential, which is set only in \
         config.yaml: creating it, re-pointing a definition to it, or changing its settings \
         through the admin API is refused"
    ))
}

/// The operator a build or validate judges differs from the one bound at process start.
pub fn operator_changed(was: &str, now: &str) -> String {
    config_text(format_args!(
        "the operator credential is bound for the process lifetime: this process started with \
         {was}, and this configuration's admitted plugins give {now}. Restart to change it; the \
         running configuration keeps serving"
    ))
}

/// The operator credential of a start that upgrades a pre-1.6 `plugins:` block is not bound yet.
pub fn deferred_refusal() -> String {
    config_text(format_args!(
        "the `plugins:` block is in a pre-1.6 shape; the startup upgrade converts it on the next \
         serve start, and only then is the operator credential judged"
    ))
}

/// No `auth.admin_auth` is set and no admitted row is the operator: there is no admin credential.
pub fn no_default_admin_chain() -> String {
    config_text(format_args!(
        "auth.admin_auth is not set and no admitted first-party auth plugin states the operator \
         credential, so there is no admin credential. Install the first-party operator credential \
         plugin and give it `settings` in identity-providers, or set auth.admin_auth explicitly \
         (`admin_auth: []` is the open dev posture)."
    ))
}

/// A `token:` on the chain entry backed by `module`, which is not the operator credential's.
pub fn misplaced_token(op: &str, module: &str) -> String {
    config_text(format_args!(
        "auth chain entry '{module}' sets `token:`, which belongs to the built-in `{op}` module \
         only; move it, e.g.:\n\n    admin_auth:\n      - {op}: {{ token: {{ env: \
         BUSBAR_ADMIN_TOKEN }} }}\n"
    ))
}

/// A `token:` on the `identity-providers.<name>` definition backed by `module`.
pub fn misplaced_definition_token(op: &str, name: &str, module: &str) -> String {
    config_text(format_args!(
        "identity-providers.{name}: `token:` is the built-in `{op}` operator credential and is \
         meaningless on `module: {module}`"
    ))
}

/// `keys` in the data-plane chain with no admin credential able to mint a key. It never shows an
/// empty operator word and never offers `mint`, which is not a scope.
pub fn no_mint_path(op: &str) -> String {
    let operator = if op.is_empty() {
        "install the first-party operator credential plugin in plugins.dir and name it in \
         auth.admin_auth with its `settings`"
            .to_owned()
    } else {
        format!("name `{op}` in auth.admin_auth with its `settings` in config.yaml")
    };
    config_text(format_args!(
        "auth.chain names the built-in `keys` verifier, but no admin credential can mint a key, so \
         the data plane would reject every request. Either {operator}, or define an admin provider \
         with `max_admin_scope: full` whose role bindings grant `admin_scope: full`, or remove \
         `keys` from auth.chain."
    ))
}
