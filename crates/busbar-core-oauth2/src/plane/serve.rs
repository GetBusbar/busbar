// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The authorization server's request path: what a request to the plane runs. The plane's
//! build, its generation hand-over and its sweep run off the request path, in [`super`].

use std::sync::Arc;

use super::{
    AsPlane, RegistrationWindow, Registrations, REGISTRATIONS_PER_WINDOW, REGISTRATION_WINDOW,
};

pub(super) struct Throttle {
    pub(super) limiter: Arc<oauth_as::FixedWindowRateLimiter>,
    pub(super) registrations: Arc<Registrations>,
}

impl oauth_as::RateLimiter for Throttle {
    fn check(&self, attempt: oauth_as::Attempt<'_>) -> oauth_as::RateLimitDecision {
        if let oauth_as::Attempt::ClientRegistration = attempt {
            return self.registrations.check();
        }
        oauth_as::RateLimiter::check(&*self.limiter, attempt)
    }

    fn record(&self, attempt: oauth_as::Attempt<'_>, outcome: oauth_as::AttemptOutcome) {
        if let oauth_as::Attempt::ClientRegistration = attempt {
            if outcome == oauth_as::AttemptOutcome::Succeeded {
                self.registrations.admitted();
            }
            return;
        }
        oauth_as::RateLimiter::record(&*self.limiter, attempt, outcome);
    }
}

tokio::task_local! {
    /// The registration request this task is answering ([`AsPlane::handle`]), and whether it holds
    /// a share of the budget.
    static REGISTERING: Answering;
}

struct Answering {
    budget: Arc<Registrations>,
    held: std::cell::Cell<bool>,
}

impl Drop for Answering {
    fn drop(&mut self) {
        if self.held.get() {
            self.budget.release();
        }
    }
}

impl Registrations {
    fn window(&self) -> std::sync::MutexGuard<'_, RegistrationWindow> {
        let mut w = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let index =
            busbar_kernel::store::monotonic_ns() / 1_000_000_000 / REGISTRATION_WINDOW.as_secs();
        if w.index != index {
            w.index = index;
            w.admitted = 0;
        }
        w
    }

    fn check(&self) -> oauth_as::RateLimitDecision {
        let mut w = self.window();
        if w.admitted + w.in_flight >= REGISTRATIONS_PER_WINDOW {
            return oauth_as::RateLimitDecision::Deny;
        }
        match REGISTERING.try_with(|answering| answering.held.replace(true)) {
            Ok(false) => w.in_flight += 1,

            Ok(true) => {}
            Err(_) => w.admitted += 1,
        }
        oauth_as::RateLimitDecision::Allow
    }

    fn admitted(&self) {
        if REGISTERING.try_with(|_| ()).is_ok() {
            self.window().admitted += 1;
        }
    }

    fn release(&self) {
        let mut w = self.window();
        w.in_flight = w.in_flight.saturating_sub(1);
    }
}

impl AsPlane {
    pub(crate) async fn verify_dpop(
        &self,
        presented: busbar_kernel::oauth_as::seam::DpopPresentation,
    ) -> bool {
        use base64::Engine as _;
        use oauth_as::store::Storage as _;
        let htu = format!("{}{}", self.identity.origin(), presented.path);
        let Ok(proof) = oauth_as::dpop::verify_proof_with_crypto(
            &crate::crypto_provider::FacadeCrypto,
            &self.dpop_verifiers,
            &presented.proof,
            &presented.method,
            &htu,
            crate::shared::now_time(),
        ) else {
            return false;
        };
        let ath = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(busbar_contract::crypto::sha256(presented.token.as_bytes()));
        let ath_matches = oauth_as::jwt::CompactJws::parse(&presented.proof)
            .is_ok_and(|jws| jws.claim_str("ath") == Some(ath.as_str()));
        let bound_to_proof_key =
            oauth_as::jwt::CompactJws::parse(&presented.token).is_ok_and(|jws| {
                jws.payload
                    .get("cnf")
                    .and_then(|cnf| cnf.get("jkt"))
                    .and_then(|jkt| jkt.as_str())
                    == Some(proof.jkt.as_str())
            });
        if !ath_matches || !bound_to_proof_key {
            return false;
        }

        if !matches!(
            self.server.store().get_token(&presented.token).await,
            Ok(Some(_))
        ) {
            return false;
        }

        let replay_id = format!("dpop-resource:{}:{}", proof.jkt, proof.jti);
        matches!(
            self.server
                .store()
                .claim_replay_id(&replay_id, proof.replay_until)
                .await,
            Ok(true)
        )
    }

    pub(crate) async fn handle<B>(&self, request: http::Request<B>) -> oauth_as::http::Response
    where
        B: axum::body::HttpBody,
    {
        if let Some(document) = &self.plain_metadata {
            if request.method() == http::Method::GET
                && request.uri().path() == self.identity.metadata_path()
            {
                let mut response =
                    http::Response::new(oauth_as::http::Body::from(document.clone()));
                response.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/json;charset=UTF-8"),
                );
                return response;
            }
        }
        let registering = request.method() == http::Method::POST
            && request.uri().path() == self.identity.register_path();

        let answer = Box::pin(self.service.handle(request));
        if !registering {
            return answer.await;
        }

        let answering = Answering {
            budget: Arc::clone(&self.carried.registrations),
            held: std::cell::Cell::new(false),
        };
        REGISTERING.scope(answering, answer).await
    }

    /// The authorization endpoint, for the browser `/authorize` resolved: its consent session is
    /// read from the store, any answer staked for this request WITH the browser's T is spent into
    /// the hooks' cache, and the library answers with `browser` lent to its hooks.
    pub(crate) async fn authorize<B>(
        &self,
        request: http::Request<B>,
        browser: crate::consent::Browser,
    ) -> oauth_as::http::Response
    where
        B: axum::body::HttpBody,
    {
        // The staked key is read before the first await: the request body is not Sync, so no borrow
        // of the request may live across a suspension point.
        let staked = staked_key(&request);
        self.prepare(staked, &browser).await;
        crate::consent::as_browser(browser, self.handle(request)).await
    }

    pub(crate) async fn granted_scope(
        &self,
        client_id: &str,
        requested: Option<&str>,
    ) -> Result<String, oauth_as::store::StorageError> {
        use oauth_as::store::Storage as _;
        if let Some(raw) = requested {
            return Ok(oauth_as::scope::ScopeSet::parse(raw)
                .map_or_else(|_| raw.to_string(), |set| set.to_string()));
        }
        let client = self
            .server
            .store()
            .get_client(&oauth_as::client::ClientId::new(client_id))
            .await?
            .ok_or_else(|| {
                oauth_as::store::StorageError::new("the client could not be resolved")
            })?;
        Ok(granted_default(&client).to_string())
    }

    pub(crate) async fn pushed(&self, request_uri: &str) -> Option<crate::cimd::Pushed> {
        self.server.store().pushed(request_uri).await
    }

    pub(crate) async fn mark_pushed_shown(&self, request_uri: &str) -> bool {
        self.server.store().mark_pushed_shown(request_uri).await
    }

    /// Open a consent session: kept in the store first, cached here only once the store took it.
    pub(crate) async fn open_session(
        &self,
        subject: &str,
        id: String,
    ) -> Result<String, oauth_as::store::StorageError> {
        self.carried
            .store()
            .open_session(&id, subject, crate::consent::SESSION_TTL)
            .await?;
        Ok(self.sessions.open(subject, id))
    }

    /// Record a consent answer in the store. An answer the store did not keep is an error, never a
    /// silent success.
    pub(crate) async fn stake(
        &self,
        id: &str,
        key: String,
        approve: bool,
    ) -> Result<(), oauth_as::store::StorageError> {
        self.carried
            .store()
            .stake(id, &key, approve, crate::consent::SESSION_TTL)
            .await
    }

    pub(crate) async fn is_staked(&self, id: &str, key: &str) -> bool {
        self.carried
            .store()
            .is_staked(id, key)
            .await
            .unwrap_or(false)
    }

    /// Keep an operator form's CSRF token in the store, bound to form session `id` (the page's own
    /// cookie), to `subject`, and to `key`, which names WHAT the form answers (the consent request
    /// and the starting browser, or the device user code). Store-kept, so any node takes it back.
    pub(crate) async fn issue_form(
        &self,
        id: &str,
        key: &str,
        subject: &str,
    ) -> Result<(), oauth_as::store::StorageError> {
        let store = self.carried.store();
        store
            .open_session(id, subject, crate::consent::SESSION_TTL)
            .await?;
        store
            .stake(id, key, true, crate::consent::SESSION_TTL)
            .await?;
        Ok(())
    }

    /// Take back an operator form's CSRF token: `true` once, for the session, subject and key it was
    /// issued with, and never again.
    pub(crate) async fn consume_form(
        &self,
        id: &str,
        key: &str,
        subject: &str,
    ) -> Result<bool, oauth_as::store::StorageError> {
        let store = self.carried.store();
        if store.session_subject(id).await?.as_deref() != Some(subject) {
            return Ok(false);
        }
        Ok(store.spend(id, key).await? == Some(true))
    }

    /// The PENDING device grant an operator typed the user code of, for the confirm page: looked up
    /// under the same RFC 8628 s5.1 throttle as an approval, and refused exactly as an approval of it
    /// would be (unknown, expired, already decided).
    pub(crate) async fn pending_device(
        &self,
        entered_user_code: &str,
    ) -> Result<oauth_as::DeviceGrant, oauth_as::DeviceApprovalError> {
        use oauth_as::store::Storage as _;
        let attempt = oauth_as::Attempt::DeviceUserCodeEntry;
        let limiter: &dyn oauth_as::RateLimiter = &*self.carried.limiter;
        if limiter.check(attempt) == oauth_as::RateLimitDecision::Deny {
            return Err(oauth_as::DeviceApprovalError::RateLimited);
        }
        let normalized = oauth_as::device::normalize_user_code(entered_user_code);
        let outcome = match self
            .server
            .store()
            .find_device_grant_by_user_code(&normalized)
            .await
        {
            Err(e) => Err(oauth_as::DeviceApprovalError::Storage(e)),
            Ok(None) => Err(oauth_as::DeviceApprovalError::UnknownUserCode),
            Ok(Some(grant)) if crate::shared::now_time() >= grant.expires_at => {
                Err(oauth_as::DeviceApprovalError::Expired)
            }
            Ok(Some(grant)) if grant.state != oauth_as::DeviceGrantState::Pending => {
                Err(oauth_as::DeviceApprovalError::NotPending)
            }
            Ok(Some(grant)) => Ok(grant),
        };
        limiter.record(
            attempt,
            if outcome.is_ok() {
                oauth_as::AttemptOutcome::Succeeded
            } else {
                oauth_as::AttemptOutcome::Failed
            },
        );
        outcome
    }

    async fn prepare(&self, staked: Option<String>, browser: &crate::consent::Browser) {
        let store = self.carried.store();
        let id = &browser.session;
        let Ok(Some(subject)) = store.session_subject(id).await else {
            return;
        };
        self.sessions.hydrate(id, &subject);
        let (Some(key), Some(handle)) = (staked, browser.handle.as_deref()) else {
            return;
        };
        let key = crate::consent::handled_key(&key, handle);
        match store.spend(id, &key).await {
            Ok(Some(approve)) => self.sessions.plant(id, key, approve),
            Ok(None) => {}
            Err(e) => tracing::debug!(error = %e, "oauth_as: the consent answer could not be read"),
        }
    }
}

/// The key an answer to this authorization request was staked under (before its T is bound in):
/// [`crate::consent::pushed_key`] for a pushed request, else [`crate::consent::request_key`] over the
/// request's exact bytes.
fn staked_key<B>(request: &http::Request<B>) -> Option<String> {
    let pairs = request
        .uri()
        .query()
        .map(crate::routes::form_urlencoded_pairs)
        .unwrap_or_default();
    let param = |name: &str| {
        pairs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    let client_id = param("client_id")?;
    Some(match param("request_uri") {
        Some(handle) => crate::consent::pushed_key(&client_id, &handle),
        None => crate::consent::request_key(
            &client_id,
            request.uri().path_and_query().map_or("", |p| p.as_str()),
        ),
    })
}

fn granted_default(client: &oauth_as::client::Client) -> oauth_as::scope::ScopeSet {
    oauth_as::scope::ScopeSet::from_tokens(
        client
            .default_scopes
            .iter()
            .map(|s| s.as_str())
            .filter(|s| client.allowed_scopes.contains(s)),
    )
    .unwrap_or_default()
}

pub(crate) fn seam_verify_dpop(
    plane: &Arc<dyn std::any::Any + Send + Sync>,
    presented: busbar_kernel::oauth_as::seam::DpopPresentation,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> {
    let plane = Arc::clone(plane).downcast::<AsPlane>().ok();
    Box::pin(async move {
        match plane {
            Some(plane) => plane.verify_dpop(presented).await,
            None => false,
        }
    })
}
