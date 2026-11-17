// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Initial native listener suppliers and upgrade targets from one complete serving generation.

use std::sync::Arc;

use busbar_plugin_abi::transport::{FB_DATAGRAM, FB_SERVER};

use super::min3_boot::transports::{declaring, ServedTransport};

/// The already admitted/opened transport table. Connections retain this immutable generation through
/// security preparation and any upgrade; publishing a new table cannot change their selected instance.
#[derive(Clone)]
pub(crate) struct NativeFramers {
    served: Arc<[ServedTransport]>,
}

impl NativeFramers {
    /// Consume the boot's complete transport table after its protocol declarations were validated.
    pub(crate) fn new(served: Vec<ServedTransport>) -> Self {
        Self {
            served: served.into(),
        }
    }

    /// Exactly one instance explicitly declares this configuration slot. Image names, ALPN and
    /// upgrade protocols are never fallback selectors. Unknown declarations create no listeners.
    pub(crate) fn for_slot(&self, slot: &str) -> Result<ServedTransport, String> {
        let mut suppliers = self.served.iter().filter(|one| {
            one.port
                .listener_slots()
                .iter()
                .any(|declared| declared.as_ref() == slot)
        });
        let one = suppliers.next().ok_or_else(|| {
            format!("{slot}: no native transport declares this initial listener slot")
        })?;
        if let Some(other) = suppliers.next() {
            return Err(format!(
                "{slot}: native transport instances `{}` and `{}` both declare this initial listener slot",
                one.instance, other.instance
            ));
        }
        if one.port.facts() & FB_SERVER == 0 || one.port.facts() & FB_DATAGRAM != 0 {
            return Err(format!(
                "{slot}: native transport `{}` is not an accepting stream framer",
                one.instance
            ));
        }
        Ok(one.clone())
    }

    /// Upgrade resolution stays within the same immutable table and uses only D_PROTOCOL.
    pub(crate) fn upgrade(&self, protocol: &str) -> Option<ServedTransport> {
        declaring(&self.served, protocol).cloned()
    }
}
