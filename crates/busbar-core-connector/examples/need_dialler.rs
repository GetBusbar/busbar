// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UNIVERSAL-NEEDS FIXTURE (a test fixture, never a product plugin): a SECRET-kind plugin that
//! declares one outbound need and reaches the network the only way a plugin may — through the
//! connection table its host handed THIS instance at open. Its one secret is what an echo far end sends back for
//! `ping`. Built by `cargo test` as a `cdylib` and loaded dropped in by
//! `tests/universal_needs.rs`; it shows that any plugin of any kind reaches the network only
//! through a need.

use busbar_contract::abi::host::conn::HostConns;
use busbar_contract::conn::{ConnError, NeedId, OpenDesc, NO_TICKET};
use busbar_contract::secret::{SecretModule, SecretModuleError, SecretResult};

/// The one need this plugin declares: an outbound byte stream to the target its settings name.
pub const NEED: NeedId = NeedId(0);

/// The fixture's module. Its instance state is the table its host handed it at open, if any: the
/// secret kind's open hands none yet, so an instance holds `None` and answers
/// [`ConnError::Unarmed`] — decided per instance, never per image.
struct NeedDialler {
    table: Option<HostConns>,
}

impl SecretModule for NeedDialler {
    fn resolve(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
    ) -> SecretResult<Vec<u8>> {
        let target = settings
            .get("target")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| SecretModuleError::invalid("`target` is required"))?;
        let dial = |e: ConnError| SecretModuleError::unavailable(e.to_string());
        let table = self.table.ok_or(ConnError::Unarmed).map_err(dial)?;
        let c = table
            .open(
                NEED,
                &OpenDesc {
                    target,
                    ..OpenDesc::default()
                },
            )
            .map_err(dial)?;
        table.write(c, b"ping", true, false).map_err(dial)?;
        let mut buf = [0_u8; 64];
        // Nothing blocks: a read with nothing ready is pending, and this one-shot fixture reports
        // that as unavailable rather than wait.
        let piece = table.read(c, NO_TICKET, &mut buf).map_err(dial)?;
        let _ = table.close(c);
        Ok(buf[..piece.len].to_vec())
    }
}

fn open(_cfg: &str) -> Result<Box<dyn SecretModule>, String> {
    Ok(Box::new(NeedDialler { table: None }))
}

busbar_contract::export_secret_plugin!(open);
