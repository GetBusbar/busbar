// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AUTH INSTANCES THAT RE-LEND THEIR OWN CREDENTIALS: an auth plugin opened over a settings block
//! whose secret references rotate (a workload-identity subject token file, a rotated client
//! certificate) takes the new material without a reload.
//!
//! The host re-resolves the instance's settings every 30 s ± 10 % through the build's own
//! resolver. When the material lent from them changed, the plugin's `refresh` takes it in place
//! (its warm tokens and caches kept); a plugin with no `refresh` gets a new instance opened over
//! the new settings and swapped in whole. A refusal keeps the running instance (BUSBAR-8028).

use std::sync::{Arc, Mutex};
use std::time::Instant;

use busbar_contract::auth::BeginLogin;
use busbar_contract::auth::LoginKind;
use busbar_contract::auth_calls::{
    AuthAxis, AuthCalls, IssuedShape, LoginCall, LoginCallback, LoginPresentation, VerifyAnswer,
    VerifyRequest, Verifying,
};
use busbar_contract::plugin_settings::ResolvedSettings;
use busbar_contract::secret::{AuthRelent, RelendCause, RelendRefused};

use crate::preflight::{RelendStreak, RELEND_EVERY};

/// How an instance's settings are re-resolved from what it was opened over.
pub type Reresolve = Box<dyn Fn() -> Result<ResolvedSettings, String> + Send + Sync>;

/// An auth instance the host re-lends: every call goes to the instance it holds now. Opened and
/// built once per config build, off the request path (`crate::off_path::auth::keys::relend`).
pub struct RelendingAuth {
    pub(crate) name: String,
    pub(crate) module: String,
    pub(crate) label: String,
    pub(crate) axis: Arc<dyn AuthAxis>,
    pub(crate) reresolve: Reresolve,
    pub(crate) current: arc_swap::ArcSwap<Arc<dyn AuthCalls>>,
    pub(crate) streak: Mutex<RelendStreak>,
    pub(crate) report: &'static dyn crate::refresh::Report,
}

impl RelendingAuth {
    fn now(&self) -> Arc<dyn AuthCalls> {
        Arc::clone(&self.current.load())
    }

    /// One re-lend poll at `now`.
    pub fn relend_now(&self, now: Instant) {
        let Ok(mut streak) = self.streak.try_lock() else {
            return;
        };
        let refused = |cause, text| RelendRefused { cause, text };
        let outcome = (self.reresolve)()
            .map_err(|text| refused(RelendCause::Unresolvable, text))
            .and_then(|resolved| {
                match self
                    .now()
                    .relend(&resolved)
                    .map_err(|text| refused(RelendCause::Refused, text))?
                {
                    AuthRelent::NotRefreshed => {
                        let successor = self
                            .axis
                            .open(&self.module, &self.label, &resolved)
                            .map_err(|text| refused(RelendCause::ReopenFailed, text))?;
                        Ok(Some((successor, "reopened")))
                    }
                    AuthRelent::Refreshed => Ok(Some((self.now(), "refreshed"))),
                    AuthRelent::Unchanged => Ok(None),
                }
            });
        if crate::refresh::stopping() {
            return;
        }
        match outcome {
            Ok(None) => {}
            Ok(Some((successor, how))) => {
                self.current.store(Arc::new(successor));
                streak.applied(self.report, &self.label, how);
            }
            Err(refused) => streak.failed(self.report, &self.label, &refused, now),
        }
    }
}

impl crate::refresh::Refreshable for RelendingAuth {
    fn refresh(&self, now: Instant) -> Instant {
        self.relend_now(now);
        now + crate::retry::spread(RELEND_EVERY, 0.1, crate::retry::unit())
    }
}

impl AuthCalls for RelendingAuth {
    fn name(&self) -> &str {
        &self.name
    }

    fn facts(&self) -> u32 {
        self.now().facts()
    }

    fn credential_kinds(&self) -> Vec<String> {
        self.now().credential_kinds()
    }

    fn issued_shape(&self) -> Option<IssuedShape> {
        self.now().issued_shape()
    }

    fn inbound_points(&self) -> busbar_contract::route::AuthPoints {
        self.now().inbound_points()
    }

    fn carriers(&self) -> Arc<[String]> {
        self.now().carriers()
    }

    fn verify_now(&self, request: &VerifyRequest) -> Option<VerifyAnswer> {
        self.now().verify_now(request)
    }

    fn verify(&self, request: VerifyRequest) -> Box<dyn Verifying> {
        self.now().verify(request)
    }

    fn refresh(&self) -> Result<u64, String> {
        self.now().refresh()
    }

    fn relend(&self, settings: &ResolvedSettings) -> Result<AuthRelent, String> {
        self.now().relend(settings)
    }

    fn answering(&self) -> bool {
        self.now().answering()
    }

    fn reusable(&self) -> bool {
        self.now().reusable()
    }

    fn login_presentation(&self) -> Option<LoginPresentation> {
        self.now().login_presentation()
    }

    fn login_kind(&self) -> Option<LoginKind> {
        self.now().login_kind()
    }

    fn begin_login(&self, request: BeginLogin) -> Box<dyn LoginCall> {
        self.now().begin_login(request)
    }

    fn complete_login(&self, request: LoginCallback) -> Box<dyn LoginCall> {
        self.now().complete_login(request)
    }
}

#[cfg(test)]
#[path = "tests/relend_tests.rs"]
mod tests;
