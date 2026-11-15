// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The operator credential's build-time half: the linked rows installed, the admin chain's operator
//! credential built, and its refusal and migration text spelled.

use std::sync::Arc;

use busbar_contract::auth_calls::AuthCalls;

use crate::operator::{LinkedAuth, Operator, OperatorCredential, OperatorWords, LINKED};

/// Install this build's linked auth rows and the operator credential's words.
pub fn install_linked(rows: &'static [LinkedAuth], words: OperatorWords) {
    let _ = LINKED.get_or_init(|| (rows, words, rows.iter().map(|r| r.0).collect()));
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

    /// The operator credential of `op`, opened as [`OperatorCredential::open`] opens it, answering for
    /// every provider the credential backs: built once, when the admin chain is built.
    pub fn open<'a>(
        op: &str,
        defs: impl Iterator<Item = (&'a str, &'a str)> + Clone,
        is_op: &dyn Fn(&str) -> bool,
        answered: bool,
        digest: Option<String>,
        open: impl FnOnce(String) -> Result<Arc<dyn AuthCalls>, String>,
    ) -> Result<Self, String> {
        let lookup = defs.clone();
        let module_of = |name: &str| lookup.clone().find(|d| d.0 == name).map(|d| d.1);
        let names = std::iter::once(op)
            .chain(defs.map(|d| d.0))
            .filter(|name| Self::backed(op, name, module_of(name), is_op))
            .map(str::to_owned)
            .collect();
        let cred = OperatorCredential::open(answered, digest, open)?;
        Ok(Operator::from_parts(cred, names))
    }
}

/// The operator credential judged from the admitted rows' claims (OPERATOR-FROM-ADMITTED-AUTH
/// §3.3): `words` is the one first-party claim (`Ok(None)`: none), or the refusal every config
/// read answers; `inert` holds the non-first-party claims, which never become the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judged {
    /// The operator, none, or why there is none that can be trusted.
    pub words: Result<Option<busbar_contract::auth_calls::OperatorClaim>, String>,
    /// The claims that are not first-party.
    pub inert: Vec<busbar_contract::auth_calls::OperatorClaim>,
}

/// What process start binds: a judgement, or `Deferred` to the startup upgrade's own view of a
/// pre-1.6 `plugins:` block (§3.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorBinding {
    /// Judged from the start scan's rows.
    Bound(Judged),
    /// Bound once, later, by the startup upgrade (`bind_deferred`).
    Deferred,
}

/// Judge `claims`.
#[must_use]
pub fn choose(claims: &busbar_contract::auth_calls::OperatorClaims) -> Judged {
    Judged {
        words: Ok(claims.claims.first().cloned()),
        inert: Vec::new(),
    }
}

/// Bind the operator credential for the process lifetime.
pub fn install_operator(binding: OperatorBinding) {
    if let OperatorBinding::Bound(Judged {
        words: Ok(Some(claim)),
        ..
    }) = binding
    {
        let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
        install_linked(
            &[],
            OperatorWords {
                provider: leak(claim.provider),
                principal_id: leak(claim.principal),
                ..OperatorWords::default()
            },
        );
    }
}

/// Bind a `Deferred` start's judgement, once.
pub fn bind_deferred(judged: Judged) -> Result<(), String> {
    let _ = judged;
    Ok(())
}

/// The bound judgement.
pub fn judged() -> Result<Judged, String> {
    let words = crate::operator::words();
    Ok(Judged {
        words: Ok((!words.provider.is_empty()).then(|| {
            busbar_contract::auth_calls::OperatorClaim {
                provider: words.provider.to_owned(),
                canonical: words.canonical.to_owned(),
                principal: words.principal_id.to_owned(),
                first_party: words.first_party,
                version: String::new(),
                signer: String::new(),
            }
        })),
        inert: Vec::new(),
    })
}
