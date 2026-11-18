// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The export kind's Statement read, which runs once per load and bind, never per request (lint
//! ruling Q4): moved from `dispatch::kinds::export` with its behaviour unchanged.
//!
//! Every caller, at the move: [`facts`] from `Export`'s `Kind::context` and
//! `Kind::optional_by_statement` (the loader calls both once per load and bind, `dispatch::load`);
//! [`route`], [`family`] and [`owned`] from `cold::dispatch::kinds` (`export_routes`,
//! `export_families`, `export_label_keys`), called by [`facts`] and [`family`] only, and from
//! [`facts`]/[`family`] themselves.
//!
//! It holds no `unsafe`: the tail, its lists, the Statement's families and extensions and each
//! family's label keys are formed and checked by the safe primitives `dispatch::kinds::export`
//! keeps (`stated_tail`, `label_keys`), so the unsafe register (unsafe.yaml) keeps its per-file
//! counts.

use busbar_contract::abi::export;
use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::route::{Route, RouteAuth, RouteMethod};
use busbar_contract::export_stream::ExportStream;

use crate::dispatch::kinds::export::{label_keys, stated_tail, ExportFacts, StatedTail};

pub(crate) fn owned(s: AbiStr) -> Option<String> {
    crate::dispatch::plugin::str_bytes(s)
        .and_then(|b| std::str::from_utf8(b).ok())
        .map(crate::cold::dispatch::kinds::statement_text)
}

pub(crate) fn route(r: &export::Route) -> Result<Route, String> {
    let path = owned(r.path).ok_or("an export route's path is over-long")?;
    let method = owned(r.method).ok_or("an export route's method is over-long")?;
    let methods = [
        RouteMethod::Get,
        RouteMethod::Post,
        RouteMethod::Put,
        RouteMethod::Patch,
        RouteMethod::Delete,
    ];
    let method = methods
        .into_iter()
        .find(|m| m.as_str() == method)
        .ok_or_else(|| crate::cold::dispatch::kinds::export_route_method(&path, &method))?;
    let auth = match r.auth {
        export::ROUTE_AUTH_NONE => RouteAuth::None,
        export::ROUTE_AUTH_KEY => RouteAuth::Key,
        _ => RouteAuth::Admin,
    };
    Ok(Route { path, method, auth })
}

/// One declared metric family, copied out once at bind: its name, its `FAMILY_*` kind and its
/// label keys.
pub(crate) fn family(
    f: &busbar_contract::abi::mechanism::door::MetricFamily,
) -> Result<(String, u8, Vec<String>), String> {
    let keys = crate::cold::dispatch::kinds::export_label_keys(label_keys(f))
        .ok_or("a metric family's label key is over-long")?;
    let name = owned(f.name).ok_or("a metric family's name is over-long")?;
    Ok((name, f.kind, keys))
}

pub(crate) fn facts(st: &Statement) -> Result<ExportFacts, String> {
    let StatedTail {
        streams,
        routes,
        families: declared,
        ext,
    } = stated_tail(st)?;
    let routes = crate::cold::dispatch::kinds::export_routes(routes)?;
    let families = crate::cold::dispatch::kinds::export_families(declared)?;
    let span_records = busbar_contract::abi::mechanism::extensions::span_records(ext)?;
    let whole_batches = busbar_contract::abi::mechanism::extensions::whole_batches(ext)?;
    use busbar_contract::abi::mechanism::extensions;
    let public_routes = extensions::route_paths(ext, extensions::EXT_PUBLIC_ROUTES)?;
    let persistent_routes = extensions::route_paths(ext, extensions::EXT_PERSISTENT_ROUTES)?;
    if public_routes
        .iter()
        .any(|path| !routes.iter().any(|route| route.path == *path))
        || persistent_routes
            .iter()
            .any(|path| !public_routes.contains(path))
    {
        return Err(
            "listener route policy names an undeclared route or a non-public persistent route"
                .into(),
        );
    }
    let recorder = busbar_contract::export_calls::recorder_protocol(ext)?;
    if recorder && !streams.contains(&(ExportStream::Metrics as u8)) {
        return Err("a recorder declaration requires the metrics stream".into());
    }
    let streams = crate::cold::dispatch::kinds::statement_list(streams);
    Ok(ExportFacts {
        recorder,
        span_records,
        whole_batches,
        public_routes,
        persistent_routes,
        streams,
        routes,
        families,
        one_instance: st.marks & busbar_contract::abi::mechanism::door::MARK_ONE_INSTANCE != 0,
    })
}
