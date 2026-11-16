// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The export adapter: `ExportPort` over the export kind's `Proxy` (IF §11.3). L7.

use busbar_plugin_abi::kinds::export::export::{CustodyRec, Proxy};
use busbar_plugin_abi::records::{RecErr, Records};

use crate::ports::export::{Delivered, RecorderNeeds, ScopeInfo};

/// What one export image's describe stated (§8.5), decoded and validated once at open.
pub struct Described {
    /// One bit per declared STREAM_* id.
    pub streams: u32,
    pub scopes: Vec<ScopeInfo>,
    pub recorder: Option<RecorderNeeds>,
    pub span_records: bool,
    pub confirm: bool,
}

pub fn decode_describe(
    describe: Records<'_>,
    methods: u64,
    facts: u64,
) -> Result<Described, RecErr> {
    let _ = (describe, methods, facts);
    todo!()
}

pub fn delivered_from(
    accepted: u64,
    append: Option<(u32, &[u8])>,
    custody: Option<CustodyRec>,
    dest_count: u32,
) -> Result<Delivered, RecErr> {
    let _ = (accepted, append, custody, dest_count);
    todo!()
}

/// The export port over one instance's proxy.
pub struct ExportAdapter {
    proxy: Proxy,
}

impl ExportAdapter {
    pub fn new(proxy: Proxy) -> Self {
        Self { proxy }
    }

    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }
}
