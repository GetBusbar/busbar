// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Snapshot authority across a real SDK export door, independent of product rendering.

use crate as busbar_kernel;
use busbar_contract::abi::mechanism::endpoint::EndpointRequest;
use busbar_contract::export_calls::ExportCalls;
use busbar_contract::route::{Route, RouteAuth, RouteMethod};
use std::sync::Arc;

#[path = "snapshot_export_fixture.rs"]
mod fixture;

fn get(path: &str) -> EndpointRequest {
    EndpointRequest {
        method: "GET".into(),
        path: path.into(),
        query: String::new(),
        headers: vec![],
        body: vec![],
    }
}

