// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-owned authority carried to effect admission, including across detached tasks.
//! A replay claim is spent once at request admission, never again by this recheck.

use super::AdminDoor;
use crate::config::transaction::TxnError;
use crate::state::App;
use axum::http::HeaderMap;
use std::future::Future;

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
        if actor(&door) != self.actor.as_deref()
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
            crate::inbound::header_map(head),
            &self.admin_verdict().door,
        )
    }
}
