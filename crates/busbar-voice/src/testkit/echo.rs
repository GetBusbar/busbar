// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TEST EXECUTOR that serves every tool by echoing the call back as a JSON object: enough to prove
//! correlation (the right `name` and `arguments` reached the right call) without a tool registry.
//! Test builds only; production relays every call to the caller (`ClientRelay`).

use async_trait::async_trait;
use busbar_plane_streaming::tools::ToolExecutor;

/// Echoes the call: `{"tool":<name>,"echo":<arguments>}`.
#[derive(Debug, Default, Clone, Copy)]
pub struct EchoToolExecutor;

#[async_trait]
impl ToolExecutor for EchoToolExecutor {
    async fn execute(&self, name: &str, arguments: &[u8]) -> Vec<u8> {
        let args = String::from_utf8_lossy(arguments);
        format!(r#"{{"tool":"{name}","echo":{args}}}"#).into_bytes()
    }
}
