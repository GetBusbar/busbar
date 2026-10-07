// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST SNAPSHOT SERVICE, KERNEL SIDE — what `snapshot.read` (`abi::host::service`) answers.
//!
//! `/metrics` and `/metrics/hooks` are not the kernel's (owner law 2026-09-27: "the kernel owns no
//! route that exists for one plugin: /metrics and /metrics/hooks leave core"; ARCHITECT Q-U2-4).
//! They are LISTENER NEEDS of the scrape sink — the export instance subscribed to `metrics`, granted
//! first-party (#65) — declared in its own `routes` list and answered by its own `serve`. What
//! stays the host's is what only the host can hold: the recorder every emit site writes, its
//! scrape-time gauges, the hook-metrics cache, and THIS service, which hands that data to the one
//! crossing the host granted it.
//!
//! THE GRANT. The scrape sink's routes are dispatched through [`Granted`], which LENDS the snapshot
//! to the crossing on its thread (the export `serve` is ticket-less, on the caller's thread) for the
//! crossing's length. Any other caller — another plugin's route, a plugin's own thread, or a crossing
//! the read itself makes (each export instance's `status`) — is REFUSED ([`NOT_GRANTED`]).
//!
//! THE SCOPES, a kind-neutral argument (never a plugin's name):
//! * `SNAPSHOT_SCOPE_WHOLE` — with the recorder installed, the scrape-time gauges are refreshed from
//!   the LIVE `App` and every export sink's `status` is folded (the recorder then holds everything it
//!   will report); then the recorder's WHOLE snapshot. NOT READY while the recorder is not installed
//!   (its install runs on a background thread, and every data-plane listener accepts the moment its
//!   own bind completes, so a scrape can land first): the sink answers `503`, `Retry-After: 1` —
//!   "not ready, retry" and "nothing to say" stay distinguishable on the wire.
//! * `SNAPSHOT_SCOPE_HOOKS` — the hook-reported families ([`crate::snapshot::hooks::families`]),
//!   stale-while-revalidate: it never waits on a hook.

use crate::plugin_routes::PluginHttpDispatch;
use crate::state::App;
use busbar_contract::abi::host::service::{SNAPSHOT_SCOPE_HOOKS, SNAPSHOT_SCOPE_WHOLE};
use busbar_contract::abi::mechanism::endpoint::*;
use busbar_contract::services::Snapshot;
use std::cell::RefCell;
use std::sync::Arc;

/// The refusal of a `snapshot.read` from a crossing the host did not grant the snapshot.
pub(crate) const NOT_GRANTED: &str = "the snapshot is lent only to the crossing granted it";

/// The refusal of a `snapshot.read` of a scope the host does not hold.
const UNKNOWN_SCOPE: &str = "no such snapshot scope";

/// What the grant lends one crossing: the `App` its route dispatch serves (`None` on the app-less
/// arm, which reads the recorder without refreshing it from a live `App`).
struct Lend {
    app: Option<Arc<App>>,
}

thread_local! {
    /// The snapshot lent to the crossing running on this thread, if one is.
    static LENT: RefCell<Option<Lend>> = const { RefCell::new(None) };
}

/// Lend the snapshot (over `app`) to the crossing `f` makes on this thread; whatever was lent
/// before is restored after.
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

/// THE GRANT: the scrape sink's route dispatch, its crossings lent the snapshot.
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

/// `snapshot.read` of `scope`, for the crossing on this thread: REFUSED unless it was lent the
/// snapshot. The lend is taken for the read, so a crossing the read makes is not lent it.
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

/// The WHOLE snapshot: with the recorder installed and a live `app`, its scrape-time gauges are
/// refreshed and every export sink's `status` folded first; NOT READY before the recorder is.
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
