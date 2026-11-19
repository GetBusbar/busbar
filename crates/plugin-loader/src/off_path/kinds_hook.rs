// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hook kind's Statement read, which runs once per load and bind, never per request (lint
//! ruling Q4): moved from `dispatch::kinds::hook` with its behaviour unchanged.
//!
//! Every caller, at the move: [`read`] from `Hook`'s `Kind::context` and
//! `Kind::optional_by_statement` (the loader calls both once per load and bind, `dispatch::load`)
//! and the test-only `hook::facts`/`hook::routes`; [`route`] from
//! `cold::dispatch::kinds::hook_routes`, called by [`read`] only; [`owned`] from [`read`] and
//! [`route`].
//!
//! It holds no `unsafe`: the tail, its route list and the Statement's mark words are read through
//! the safe primitives `dispatch::kinds::hook` keeps (`hook_tail`, `tail_routes`, `mark_words`),
//! so the unsafe register (unsafe.yaml) keeps its per-file counts.

use busbar_contract::abi::hook::{self, CLASS_GATE, CLASS_TAP, PROMPT_RW, USER_RO};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::hook_calls::HookFacts;
use busbar_contract::plugin_settings::sugar_words::MARK_WORD_HOOK;
use busbar_contract::route::{Route, RouteAuth, RouteMethod};

use crate::dispatch::kinds::hook::{hook_tail, mark_words, tail_routes, NO_TAIL, SIGNALS_REFUSED};

pub(crate) fn owned(s: busbar_contract::abi::mechanism::call::AbiStr) -> Option<String> {
    crate::dispatch::plugin::str_bytes(s)
        .and_then(|b| std::str::from_utf8(b).ok())
        .map(crate::cold::dispatch::kinds::statement_text)
}

/// One declared hook route, copied out once at bind.
pub(crate) fn route(r: &hook::Route) -> Result<Route, String> {
    use crate::cold::dispatch::kinds as cold;
    let path = owned(r.path).ok_or("a hook route's path is malformed")?;
    let method = owned(r.method).ok_or("a hook route's method is malformed")?;
    if !path.starts_with('/') {
        return Err("a hook route's path must start with '/'".into());
    }
    let method = [
        RouteMethod::Get,
        RouteMethod::Post,
        RouteMethod::Put,
        RouteMethod::Patch,
        RouteMethod::Delete,
    ]
    .into_iter()
    .find(|m| m.as_str() == method)
    .ok_or_else(|| cold::hook_route_method(&path))?;
    let auth = match r.auth {
        hook::ROUTE_AUTH_NONE => RouteAuth::None,
        hook::ROUTE_AUTH_KEY => RouteAuth::Key,
        hook::ROUTE_AUTH_ADMIN => RouteAuth::Admin,
        _ => return Err(cold::hook_route_auth(&path)),
    };
    Ok(Route { path, method, auth })
}

pub(crate) fn read(st: &Statement) -> Result<(HookFacts, Vec<Route>), String> {
    use crate::cold::dispatch::kinds as cold;
    let name = owned(st.name).ok_or("a hook's name is over-long")?;
    if st.kind_tail.is_null() {
        return Err(cold::refusal(NO_TAIL));
    }
    let t = hook_tail(st)?;
    if t.kind_class != CLASS_GATE && t.kind_class != CLASS_TAP {
        return Err(cold::hook_tail_states("class", t.kind_class));
    }
    if t.prompt_access > PROMPT_RW {
        return Err(cold::hook_tail_states("prompt access", t.prompt_access));
    }
    if t.user_access > USER_RO {
        return Err(cold::hook_tail_states("user access", t.user_access));
    }
    if (t.routes_len != 0 && t.routes.is_null())
        || t.routes_len as u64 > busbar_contract::export_calls::codes::HARD_MAX_ROUTES
    {
        return Err("the hook tail's route list is null or exceeds the route bound".into());
    }
    if t.requested_signals_len != 0 {
        return Err(cold::refusal(SIGNALS_REFUSED));
    }
    let mut facts = HookFacts {
        name,
        class: t.kind_class,
        prompt: t.prompt_access,
        user: t.user_access,
        infallible: t.infallible != 0,
        words: Vec::new(),
    };
    // The route count and NULL checks above come first.
    let routes = tail_routes(&t)
        .ok_or("the hook tail's route list is misaligned or exceeds the byte bound")?;
    let declared_routes = cold::hook_routes(routes)?;
    for m in mark_words(st).iter().filter(|m| m.class == MARK_WORD_HOOK) {
        facts
            .words
            .push(owned(m.word).ok_or("a hook word is over-long")?);
    }
    Ok((facts, declared_routes))
}
