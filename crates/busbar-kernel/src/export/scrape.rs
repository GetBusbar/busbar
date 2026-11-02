// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::plugin_routes::PluginHttpDispatch;
use crate::state::App;
use busbar_contract::abi::host::service::{SNAPSHOT_SCOPE_HOOKS, SNAPSHOT_SCOPE_WHOLE};
use busbar_contract::abi::mechanism::endpoint::*;
use busbar_contract::services::Snapshot;
use std::cell::RefCell;
use std::sync::Arc;

pub(crate) const NOT_GRANTED: &str = "the snapshot is lent only to the crossing granted it";

const UNKNOWN_SCOPE: &str = "no such snapshot scope";

struct Lend {
    app: Option<Arc<App>>,
}

thread_local! {
    /// The snapshot lent to the crossing running on this thread, if one is.
    static LENT: RefCell<Option<Lend>> = const { RefCell::new(None) };
}

fn lend<R>(app: Option<Arc<App>>, f: impl FnOnce() -> R) -> R {
    struct Restore(Option<Lend>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let prior = self.0.take();
            LENT.with(|l| *l.borrow_mut() = prior);
        }
    }
    let prior = LENT.with(|l| l.borrow_mut().replace(Lend { app }));
    let _restore = Restore(prior);
    f()
}

pub(crate) struct Granted(pub(crate) Arc<dyn PluginHttpDispatch>);

impl PluginHttpDispatch for Granted {
    fn handle_http(&self, req: &EndpointRequest) -> EndpointResponse {
        lend(None, || self.0.handle_http(req))
    }

    fn handle_http_with_app(&self, app: &Arc<App>, req: &EndpointRequest) -> EndpointResponse {
        lend(Some(Arc::clone(app)), || {
            self.0.handle_http_with_app(app, req)
        })
    }
}

pub(crate) fn read(scope: u32) -> Snapshot {
    let Some(lent) = LENT.with(|l| l.borrow_mut().take()) else {
        return Snapshot::Refused(NOT_GRANTED);
    };
    let answer = match scope {
        SNAPSHOT_SCOPE_WHOLE => whole(lent.app.as_deref()),
        SNAPSHOT_SCOPE_HOOKS => Snapshot::Families(
            lent.app
                .as_deref()
                .map(crate::snapshot::hooks::families)
                .unwrap_or_default(),
        ),
        _ => Snapshot::Refused(UNKNOWN_SCOPE),
    };
    LENT.with(|l| *l.borrow_mut() = Some(lent));
    answer
}

fn whole(app: Option<&App>) -> Snapshot {
    let installed = crate::snapshot::recorder_installed();
    if let Some(app) = app.filter(|_| installed) {
        crate::snapshot::refresh_scrape_gauges(app);
        super::plugin::status();
    }
    crate::snapshot::snapshot().map_or(Snapshot::NotReady, Snapshot::Families)
}

#[cfg(test)]
#[path = "tests/scrape_tests.rs"]
pub(crate) mod tests;
