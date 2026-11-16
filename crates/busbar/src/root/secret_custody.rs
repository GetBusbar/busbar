// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The secret kind on the MIN-3 path (W2-SW-SECRET; IF §11.3, §12.2): the process's open secret instances,
//! by configured name, and the one custody over them. A secret reference `{module, settings}` names a
//! configured secret instance; custody reaches it through its `SecretPort` and hands the plugin the
//! reference's `settings` only, never its `module` (I2).

use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Instant;

use arc_swap::ArcSwap;
use busbar_contract::secret_ref::SecretRef;
use busbar_contract::secure::SecureVec;
use busbar_kernel::custody::{
    Custody, CustodyDenied, CustodyEvent, CustodyHost, CustodyKey, SecretCustody, SecretSource,
};
use busbar_plugin_loader::ports::CallCx;
use foldhash::HashMap;

/// The open secret instances, by the operator's configured instance name. Copied on write: an instance opens
/// or closes once per boot, reload or admin install; every resolve is one lock-free load.
#[derive(Default)]
pub(crate) struct SecretTable {
    open: ArcSwap<HashMap<Box<str>, SecretSource>>,
    grow: Mutex<()>,
}

impl SecretTable {
    /// `name`'s instance is open (boot step 2a or 2c, a reload, an admin install). A reopen replaces the old
    /// instance, whose cached values the caller drops with [`BootSecrets::closed`].
    pub(crate) fn opened(&self, name: &str, source: SecretSource) -> Option<SecretSource> {
        let _grow = self.grow.lock().unwrap_or_else(PoisonError::into_inner);
        let current = self.open.load_full();
        let mut next = (*current).clone();
        let old = next.insert(Box::from(name), source);
        self.open.store(Arc::new(next));
        old
    }

    /// `name`'s instance closed; the returned source is the one that was open.
    fn closed(&self, name: &str) -> Option<SecretSource> {
        let _grow = self.grow.lock().unwrap_or_else(PoisonError::into_inner);
        let current = self.open.load_full();
        if !current.contains_key(name) {
            return None;
        }
        let mut next = (*current).clone();
        let old = next.remove(name);
        self.open.store(Arc::new(next));
        old
    }

    fn get(&self, module: &str) -> Option<SecretSource> {
        self.open.load().get(module).cloned()
    }
}

/// What custody reads from the process: the open secret instances. Plugin-facing bindings (`ConfigBinder::secret`,
/// §12.7) and instance scrub sets (the registry's slot table, §10.6) are the registry's; until it supplies them a
/// SECRET Need is refused (ForeignHandle, then Unavailable), never served unmasked.
pub(crate) struct Host {
    table: Arc<SecretTable>,
}

impl CustodyHost for Host {
    fn binding(&self, _key: CustodyKey) -> Option<SecretRef> {
        None
    }

    fn scrub(
        &self,
        _who: &busbar_plugin_abi::host_side::caller::Caller<'_>,
    ) -> Option<Arc<busbar_plugin_abi::host_side::scrub::Scrub>> {
        None
    }

    fn source(&self, module: &str) -> Option<SecretSource> {
        self.table.get(module)
    }

    fn audit(
        &self,
        who: &busbar_plugin_abi::host_side::caller::Caller<'_>,
        handle: u32,
        event: CustodyEvent,
    ) {
        let row = match event {
            CustodyEvent::HandleForeign => "secret_handle_foreign",
            CustodyEvent::TooShortToScrub => "secret_too_short_to_scrub",
            CustodyEvent::Resolved => "secret_resolve",
        };
        tracing::info!(
            target: "busbar::audit",
            event = row,
            kind = ?who.kind,
            instance = who.name,
            handle,
        );
    }

    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// The process's secret kind: its open instances and the custody that resolves every reference through them.
pub(crate) struct BootSecrets {
    table: Arc<SecretTable>,
    custody: Custody<Host>,
}

impl Default for BootSecrets {
    fn default() -> Self {
        let table = Arc::new(SecretTable::default());
        let custody = Custody::new(Host {
            table: Arc::clone(&table),
        });
        BootSecrets { table, custody }
    }
}

impl BootSecrets {
    pub(crate) fn table(&self) -> &SecretTable {
        &self.table
    }

    /// `name`'s instance closed (reload, admin uninstall, shutdown): custody forgets its per-instance entries.
    pub(crate) fn closed(&self, name: &str) {
        if let Some(old) = self.table.closed(name) {
            self.custody.drop_instance(old.instance);
        }
    }

    /// A kernel-internal secret (admin token, signing key, at-rest keys, mTLS material): by reference, with an
    /// empty call stack. Errors carry no source name and no text (§12.2 step 4).
    pub(crate) async fn resolve_ref(
        &self,
        deadline: Instant,
        reference: &SecretRef,
    ) -> Result<SecureVec, CustodyDenied> {
        let cx = CallCx {
            deadline,
            request_id: 0,
            stack: Default::default(),
        };
        self.custody.resolve_ref(cx, reference).await
    }
}

/// The process's one secret kind, whichever reader asks first.
pub(crate) fn the() -> &'static BootSecrets {
    static SECRETS: OnceLock<BootSecrets> = OnceLock::new();
    SECRETS.get_or_init(BootSecrets::default)
}

#[cfg(test)]
#[path = "tests/secret_switch_over.rs"]
mod tests;
