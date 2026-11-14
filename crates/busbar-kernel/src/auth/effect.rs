// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-owned authority carried to effect admission, including across detached tasks.
//! A replay claim is spent once at request admission, never again by this recheck.

use super::AdminDoor;
use crate::config::transaction::TxnError;
use crate::state::{App, AppHandle};
use axum::http::HeaderMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// A host-admin effect may change a provider's Store without publishing a new App. Fence
// verification answers obtained before such an effect completed, including pending answers.
static COMPLETED_EFFECTS: AtomicU64 = AtomicU64::new(0);

/// Own until an admitted Store mutation finishes, including an uncertain outcome. Dropping
/// this token invalidates concurrent verification answers; it holds no mutex or permit.
#[must_use = "retain the completion token until the admitted Store mutation finishes"]
pub struct Completion(());

impl Completion {
    pub(crate) fn new() -> Self {
        Self(())
    }
}

impl Drop for Completion {
    fn drop(&mut self) {
        COMPLETED_EFFECTS.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub struct Context {
    method: String,
    target: String,
    headers: HeaderMap,
    actor: Option<String>,
    roles: std::collections::BTreeSet<String>,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EffectContext").finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Authority {
    pub full_operator: bool,
}

pub fn actor(door: &AdminDoor) -> Option<&str> {
    match door {
        AdminDoor::Identified(p, _) | AdminDoor::Listed(p, _, _) => Some(&p.id),
        _ => None,
    }
}

fn roles(door: &AdminDoor) -> std::collections::BTreeSet<String> {
    match door {
        AdminDoor::Identified(p, _) | AdminDoor::Listed(p, _, _) => {
            p.roles.iter().cloned().collect()
        }
        _ => Default::default(),
    }
}

/// Named mutation verbs contribute a Full *required rung*, not full operator authority.
/// Only a whole-rung grant (including the explicit open development posture) qualifies.
pub fn full_operator(door: &AdminDoor) -> bool {
    use busbar_contract::authz::Scope;
    match door {
        AdminDoor::Open => true,
        AdminDoor::Identified(_, grants) => grants.allows(Scope::Full),
        AdminDoor::Listed(_, _, list) => list.rungs.allows(Scope::Full),
        AdminDoor::Denied | AdminDoor::Unavailable(_) => false,
    }
}

impl Context {
    pub fn new(method: &str, target: &str, headers: HeaderMap, admitted: &AdminDoor) -> Self {
        Self {
            method: method.into(),
            target: target.into(),
            headers,
            actor: actor(admitted).map(str::to_owned),
            roles: roles(admitted),
        }
    }

    pub async fn revalidate(&self, app: &App) -> Result<Authority, TxnError> {
        let completed = COMPLETED_EFFECTS.load(Ordering::SeqCst);
        let door = super::judge_admin_door(
            app,
            &self.method,
            &self.target,
            &self.headers,
            false,
            false,
            &mut Vec::new(),
        )
        .await
        .map_err(|_| TxnError::Forbidden)?;
        if COMPLETED_EFFECTS.load(Ordering::SeqCst) != completed
            || actor(&door) != self.actor.as_deref()
            || roles(&door) != self.roles
            || !super::admin_door_admits(&door, &self.method, &self.target)
        {
            return Err(TxnError::Forbidden);
        }
        Ok(Authority {
            full_operator: full_operator(&door),
        })
    }

    pub(crate) fn survives(&self, app: &App) -> bool {
        let door = super::probe_admin_door(app, &self.method, &self.target, &self.headers, false);
        actor(&door) == self.actor.as_deref() && full_operator(&door)
    }
}

/// Admission for a Store-only effect that cannot publish configuration. The snapshot pins
/// its Store and policy together; it does not take the config mutation lock. Call `revalidate`
/// again after any per-resource or worker queue, immediately before the first effect.
/// `start` returns the completion token that must remain owned through that effect.
///
/// Final App and completion-epoch checks fence config publication and completed host effects.
/// Earlier publication or host-effect completion refuses a stale plan/verification answer;
/// a later revocation cannot undo an admitted write. Providers are queried afresh after waits.
/// Revocation outside host effects still depends on the provider's verification consistency.
/// No host mutex is held while that provider answers.
pub struct PinnedEffect {
    app: Arc<App>,
    context: Option<Context>,
}

impl PinnedEffect {
    pub async fn admit(
        handle: &Arc<AppHandle>,
        context: Option<Context>,
    ) -> Result<Self, TxnError> {
        let effect = Self {
            app: handle.load(),
            context,
        };
        effect.revalidate(handle).await?;
        Ok(effect)
    }

    pub fn app(&self) -> &Arc<App> {
        &self.app
    }

    pub async fn start(&self, handle: &Arc<AppHandle>) -> Result<Completion, TxnError> {
        self.revalidate(handle).await?;
        Ok(Completion::new())
    }

    pub async fn revalidate(&self, handle: &Arc<AppHandle>) -> Result<(), TxnError> {
        let completed = COMPLETED_EFFECTS.load(Ordering::SeqCst);
        if !Arc::ptr_eq(&self.app, &handle.load()) {
            return Err(TxnError::Forbidden);
        }
        if let Some(context) = &self.context {
            context.revalidate(&self.app).await?;
        }
        if !Arc::ptr_eq(&self.app, &handle.load())
            || COMPLETED_EFFECTS.load(Ordering::SeqCst) != completed
        {
            return Err(TxnError::Forbidden);
        }
        Ok(())
    }
}

tokio::task_local! { static EFFECT: Option<Context>; }

pub fn current() -> Option<Context> {
    EFFECT.try_with(Clone::clone).ok().flatten()
}

pub async fn scope<F: Future>(context: Option<Context>, future: F) -> F::Output {
    EFFECT.scope(context, future).await
}

impl crate::inbound::RequestAdmission {
    pub fn effect_context(&self) -> Context {
        let head = &self.inner.original;
        let target = match &head.query {
            Some(query) => format!("{}?{query}", head.target),
            None => head.target.clone(),
        };
        Context::new(
            &head.method,
            &target,
            self.original_headers().clone(),
            &self.admin_verdict().door,
        )
    }
}
