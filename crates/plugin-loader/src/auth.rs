// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The AUTH seam of the kind-neutral loader: [`DynAuth`], a [`busbar_api::AuthModule`] backed by a
//! dynamically-loaded plugin whose kind was bound to `auth` at load. Its verdict carries only an
//! identity-only [`busbar_plugin::cold::auth::Identity`] (→ [`busbar_api::Principal`]); a misbehaving
//! plugin is FAIL-CLOSED (rejected, never admitted).

use crate::{stage, wire_up_raw, RawPlugin};
use busbar_api::{
    AuthModule, AuthOutcome, AuthPlugin, BeginLogin, CompleteLogin, LoginKind, LoginModule,
    LoginOutcome, Principal,
};
use busbar_plugin::cold::{
    auth::{AuthRequest, AuthResponse},
    kind as abi_kind,
};

/// An `AuthModule` loaded from a dynamic library over the kind-neutral ABI. The module's stable
/// `name()` and `cacheable()` are resolved ONCE at load (the C ABI can't return a `&'static str`, so
/// the loaded name is leaked to `'static` — a bounded, one-per-plugin leak of a non-secret id).
pub struct DynAuth {
    raw: RawPlugin,
    name: &'static str,
    cacheable: bool,
    /// Warn-once-per-module latch for the `authenticate` fail-closed path. On a cache miss a broken
    /// auth plugin is called on EVERY request and rejects every time, so an unlatched `warn!` spams
    /// per request. Warn on the TRANSITION into the failing state; hold at `debug!` while it persists.
    /// A clean verdict (Identify/Pass) clears it, so a later fault re-warns. The FAIL-CLOSED Reject is
    /// unchanged — this gates only the log level, never the verdict.
    auth_fault_warned: std::sync::atomic::AtomicBool,
}

impl AuthModule for DynAuth {
    fn name(&self) -> &'static str {
        self.name
    }

    fn authenticate(&self, candidate: Option<&str>) -> AuthOutcome {
        let req = AuthRequest::Authenticate {
            credential: candidate.unwrap_or("").to_string(),
        };
        match self.raw.transport_call::<AuthRequest, AuthResponse>(&req) {
            Ok(AuthResponse::Identity(id)) => {
                // A clean verdict: clear the fault latch so a future fault re-warns.
                self.auth_fault_warned
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                AuthOutcome::Identify(Principal::from(id))
            }
            Ok(AuthResponse::Reject) => {
                self.auth_fault_warned
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                AuthOutcome::Reject
            }
            Ok(AuthResponse::Pass) => {
                self.auth_fault_warned
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                AuthOutcome::Pass
            }
            // A wrong-variant response, or a transport/module error, is FAIL-CLOSED: a misbehaving
            // plugin must never admit a caller. `Reject` (not `Pass`) — a credential may have been
            // presented; with no candidate the middleware's all-Pass path denies anyway, so Reject
            // never admits on error either way. Warn once per fault window per module (reset on the
            // next clean verdict); continued failures log `debug!`. The Reject verdict is unchanged.
            Ok(other) => {
                if !self
                    .auth_fault_warned
                    .swap(true, std::sync::atomic::Ordering::Relaxed)
                {
                    tracing::warn!(
                        module = self.name,
                        "auth plugin returned an unexpected response variant ({other:?}); rejecting"
                    );
                } else {
                    tracing::debug!(
                        module = self.name,
                        "auth plugin still returning an unexpected response variant ({other:?}); rejecting"
                    );
                }
                AuthOutcome::Reject
            }
            Err(e) => {
                if !self
                    .auth_fault_warned
                    .swap(true, std::sync::atomic::Ordering::Relaxed)
                {
                    tracing::warn!(module = self.name, error = %e, "auth plugin call failed; rejecting");
                } else {
                    tracing::debug!(module = self.name, error = %e, "auth plugin call still failing; rejecting");
                }
                AuthOutcome::Reject
            }
        }
    }

    fn cacheable(&self) -> bool {
        self.cacheable
    }
}

impl LoginModule for DynAuth {
    /// Resolve the plugin's pure classification. FAIL-CLOSED to [`LoginKind::Redirect`] (the trait
    /// default) on a wrong-variant response or a transport/module error — e.g. an older plugin whose
    /// ABI predates the `LoginKind` op. The chooser calls this ONCE at load, so it is side-effect-free.
    fn login_kind(&self) -> LoginKind {
        match self
            .raw
            .transport_call::<AuthRequest, AuthResponse>(&AuthRequest::LoginKind)
        {
            Ok(AuthResponse::LoginKind(k)) => k.into(),
            Ok(other) => {
                tracing::warn!(
                    module = self.name,
                    "auth plugin returned an unexpected response to login_kind ({other:?}); \
                     defaulting to Redirect"
                );
                LoginKind::Redirect
            }
            Err(e) => {
                tracing::warn!(module = self.name, error = %e, "auth plugin login_kind failed; defaulting to Redirect");
                LoginKind::Redirect
            }
        }
    }

    fn begin_login(&self, req: &BeginLogin) -> LoginOutcome {
        let wire = AuthRequest::BeginLogin(req.clone().into());
        map_begin_login(self.name, self.raw.transport_call(&wire))
    }

    fn complete_login(&self, req: &CompleteLogin) -> LoginOutcome {
        let wire = AuthRequest::CompleteLogin(req.clone().into());
        map_complete_login(self.name, self.raw.transport_call(&wire))
    }
}

/// FAIL-CLOSED mapping of a `begin_login` transport result → [`LoginOutcome`]. The two honest START
/// shapes — `AuthorizeUrl` (redirect flow) and `Prompt` (credential flow) — plus an explicit `Reject`
/// ride through; a wrong-variant response (a v1 / verify-only plugin that can only answer `Pass`, or
/// any other shape) and a transport/module error both collapse to `Reject` — a misbehaving plugin
/// never drives a login forward. Pure, so it is unit-tested without FFI.
fn map_begin_login(name: &str, resp: Result<AuthResponse, String>) -> LoginOutcome {
    match resp {
        Ok(
            r @ (AuthResponse::AuthorizeUrl(_) | AuthResponse::Prompt(_) | AuthResponse::Reject),
        ) => r.into_login_outcome(),
        Ok(other) => {
            tracing::warn!(
                module = name,
                "auth plugin returned an unexpected response to begin_login ({other:?}); rejecting"
            );
            LoginOutcome::Reject
        }
        Err(e) => {
            tracing::warn!(module = name, error = %e, "auth plugin begin_login failed; rejecting");
            LoginOutcome::Reject
        }
    }
}

/// FAIL-CLOSED mapping of a `complete_login` transport result → [`LoginOutcome`]. `TokenExchange`
/// (run another hop), `Identity` (done), and `Reject` are the valid verdicts; anything else, or a
/// transport error, is `Reject`.
fn map_complete_login(name: &str, resp: Result<AuthResponse, String>) -> LoginOutcome {
    match resp {
        Ok(
            r @ (AuthResponse::TokenExchange(_) | AuthResponse::Identity(_) | AuthResponse::Reject),
        ) => r.into_login_outcome(),
        Ok(other) => {
            tracing::warn!(
                module = name,
                "auth plugin returned an unexpected response to complete_login ({other:?}); rejecting"
            );
            LoginOutcome::Reject
        }
        Err(e) => {
            tracing::warn!(module = name, error = %e, "auth plugin complete_login failed; rejecting");
            LoginOutcome::Reject
        }
    }
}

impl std::fmt::Debug for DynAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynAuth")
            .field("name", &self.name)
            .field("path", &self.raw.path)
            .finish()
    }
}

/// Load an AUTH module from EXACTLY the verified library `bytes` (TOCTOU-safe), returning the
/// verify-only [`AuthModule`] seam the data-plane chain consumes. The concrete [`DynAuth`] is ALSO a
/// [`LoginModule`]; a caller that needs the login capability (the hosted browser flow) uses
/// [`load_login_from_bytes`] instead, which returns the unified [`AuthPlugin`] box.
pub fn load_auth_from_bytes(
    bytes: &[u8],
    cfg_json: &str,
    display: &str,
    manifest_kind: &str,
) -> Result<Box<dyn AuthModule>, String> {
    Ok(Box::new(build_dyn_auth(
        bytes,
        cfg_json,
        display,
        manifest_kind,
    )?))
}

/// Load an auth plugin as the unified [`AuthPlugin`] handle (verify + login). Same verified-bytes,
/// same frozen contract as [`load_auth_from_bytes`]; the only difference is the boxed trait object
/// KEEPS the [`LoginModule`] capability so the core can drive `begin_login`/`complete_login`. Used by
/// the 1.5.2 hosted login flow (`auth.methods`). A verify-only plugin still loads here — its login
/// methods fail closed by the module's own default/ABI behavior.
pub fn load_login_from_bytes(
    bytes: &[u8],
    cfg_json: &str,
    display: &str,
    manifest_kind: &str,
) -> Result<Box<dyn AuthPlugin>, String> {
    Ok(Box::new(build_dyn_auth(
        bytes,
        cfg_json,
        display,
        manifest_kind,
    )?))
}

/// Build the concrete [`DynAuth`] from EXACTLY the verified library `bytes` (TOCTOU-safe). Enforces
/// the frozen contract (transport, kind==`auth` && kind==manifest), then resolves the module's
/// `name()` / `cacheable()` ONCE. `manifest_kind` is the trust-verified signed-manifest `kind`.
fn build_dyn_auth(
    bytes: &[u8],
    cfg_json: &str,
    display: &str,
    manifest_kind: &str,
) -> Result<DynAuth, String> {
    let (lib, staged) = stage::load_library_from_bytes(bytes, display)?;
    let raw = wire_up_raw(
        lib,
        cfg_json,
        display.to_string(),
        abi_kind::AUTH,
        manifest_kind,
        Some(staged),
    )?;

    let name = match raw.transport_call::<AuthRequest, AuthResponse>(&AuthRequest::Name) {
        Ok(AuthResponse::Name(n)) => n,
        Ok(other) => {
            return Err(format!(
                "auth plugin '{}' returned {other:?} for Name (expected Name)",
                raw.path
            ))
        }
        Err(e) => return Err(format!("auth plugin '{}' Name query failed: {e}", raw.path)),
    };
    let cacheable = match raw.transport_call::<AuthRequest, AuthResponse>(&AuthRequest::Cacheable) {
        Ok(AuthResponse::Cacheable(c)) => c,
        Ok(other) => {
            return Err(format!(
                "auth plugin '{}' returned {other:?} for Cacheable (expected Cacheable)",
                raw.path
            ))
        }
        Err(e) => {
            return Err(format!(
                "auth plugin '{}' Cacheable query failed: {e}",
                raw.path
            ))
        }
    };
    // `AuthModule::name` is `&'static str`. INTERN it so a repeated open of the same auth plugin
    // (per chain rebuild / reload) reuses ONE allocation rather than leaking a fresh one every time.
    let name: &'static str = crate::intern_name(&name);
    Ok(DynAuth {
        raw,
        name,
        cacheable,
        auth_fault_warned: std::sync::atomic::AtomicBool::new(false),
    })
}

#[cfg(test)]
#[path = "tests/login_tests.rs"]
mod login_tests;
