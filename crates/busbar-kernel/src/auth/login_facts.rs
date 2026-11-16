// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The login kind read from an auth image's describe facts, and the one mapping of a login port error onto
//! `LoginOutcome` (IF §8.3 "Round 8, login kind" and "Round 21, login outcomes"). Core decides the page, the
//! status and the delay; the plugin states facts only.

use busbar_contract::auth::{LoginKind, LoginOutcome};
use busbar_plugin_abi::auth::{
    FB_LOGIN_CREDENTIAL, FB_LOGIN_REDIRECT, LOGIN_BEGIN, LOGIN_COMPLETE, LOGIN_CREDENTIAL,
    SECURITY_CHECK,
};
use busbar_plugin_loader::ports::PortError;

/// Why a describe's login facts are refused (DescribeInvalid). Core text, never plugin text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginFactsInvalid {
    /// `login` is declared with neither FB_LOGIN_REDIRECT nor FB_LOGIN_CREDENTIAL.
    NoKind,
    /// Both FB_LOGIN_REDIRECT and FB_LOGIN_CREDENTIAL are set.
    BothKinds,
    /// A login bit is set on an image that does not declare `login`.
    KindWithoutLogin,
}

impl LoginFactsInvalid {
    /// The DescribeInvalid text.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::NoKind => {
                "auth describe declares login but neither FB_LOGIN_REDIRECT nor FB_LOGIN_CREDENTIAL"
            }
            Self::BothKinds => {
                "auth describe sets both FB_LOGIN_REDIRECT and FB_LOGIN_CREDENTIAL; a login is exactly one kind"
            }
            Self::KindWithoutLogin => {
                "auth describe sets a FB_LOGIN_* bit but does not declare login"
            }
        }
    }
}

/// Round 8: the login an auth image offers, from `Described.facts` and whether its D_METHODS holds `login`,
/// read once at `Registry::add` before any instance opens. `Ok(None)` = the image offers no login.
pub fn login_kind(
    facts: u64,
    declares_login: bool,
) -> Result<Option<LoginKind>, LoginFactsInvalid> {
    let redirect = facts & FB_LOGIN_REDIRECT != 0;
    let credential = facts & FB_LOGIN_CREDENTIAL != 0;
    match (declares_login, redirect, credential) {
        (false, false, false) => Ok(None),
        (false, _, _) => Err(LoginFactsInvalid::KindWithoutLogin),
        (true, true, true) => Err(LoginFactsInvalid::BothKinds),
        (true, false, false) => Err(LoginFactsInvalid::NoKind),
        (true, true, false) => Ok(Some(LoginKind::Redirect)),
        (true, false, true) => Ok(Some(LoginKind::Credential)),
    }
}

/// Whether a login of `kind` offers `step` (LOGIN_BEGIN, LOGIN_COMPLETE, LOGIN_CREDENTIAL). A step the declared
/// kind does not offer is never sent: core refuses the request R_UNSUPPORTED itself.
#[must_use]
pub fn offers(kind: LoginKind, step: u32) -> bool {
    match kind {
        LoginKind::Redirect => step == LOGIN_BEGIN || step == LOGIN_COMPLETE,
        LoginKind::Credential => step == LOGIN_CREDENTIAL,
    }
}

/// Round 21: the one place a failed login step becomes a `LoginOutcome` (today's LOGIN_OUTAGE, decided by
/// core). FAILED carries the provider's Retry-After fact unchanged (the hosted page clamps it, 1..=3600, default
/// 5); a deadline is an outage with no stated delay; REFUSED SECURITY_CHECK is the security-check page; any other
/// REFUSED is "Sign-in was declined"; any other call error is an outage with no stated delay.
#[must_use]
pub fn login_failure(error: &PortError) -> LoginOutcome {
    match error {
        PortError::Failed { retry_after_s, .. } => LoginOutcome::Outage {
            retry_after_secs: *retry_after_s,
        },
        PortError::Refused { code, .. } if *code == SECURITY_CHECK => {
            LoginOutcome::SecurityCheckFailed
        }
        PortError::Refused { .. } => LoginOutcome::Reject,
        // `CallError::Deadline` and every other call error: an outage with no stated delay.
        PortError::Call(_) => LoginOutcome::Outage {
            retry_after_secs: None,
        },
    }
}
