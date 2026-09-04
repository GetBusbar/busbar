// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BOOT REPLAY of the durable demotion record into the live MCP sightings cache.
//!
//! The record itself — the row store and the one settle rule — is engine trust state and lives in
//! core's plane quarantine store, behind the neutral `PlaneStore` seam. What stays here is the one piece that reaches into
//! `crate::mcp::client` to seed the plane's in-memory catalogue: the boot-time replay. A later phase
//! moves this to a plane boot hook; until then it is the MCP plane's own concern and stays with it.

/// BOOT REPLAY: put every recorded demotion back into the live sightings cache, so it is in force
/// before the first request is served.
///
/// Only servers the operator STILL REGISTERS are replayed. A row naming a registration that has
/// since been deleted is dropped on the floor: seeding a cache entry for it would make a demotion
/// outlive the thing it was about, and the operator deleting a registration is a stronger statement
/// than the sweep that demoted it.
///
/// The replayed entry carries a DEFAULT refresh ledger, which is what makes the first sweep after a
/// restart due immediately. That is not incidental: the replay says what was last SEEN, and it must
/// not also claim the server was recently CHECKED, or a restart would buy a demoted upstream a fresh
/// freshness window on the way to being re-observed.
///
/// Returns how many were replayed, for the boot line.
pub(crate) fn hydrate(
    host: &std::sync::Arc<dyn busbar_substrate::plane_host::EngineHost>,
    store: Option<&std::sync::Arc<dyn busbar_substrate::plane::store::PlaneStore>>,
) -> usize {
    // The durable demotion rows come off the GENERIC plane store directly (the neutral opaque
    // `PlaneRecord` envelope, kind `demotion`), decoded HERE into the plane's own `McpDemotionRow` —
    // the plane owns its row schema, and the store speaks only bytes. `None` under `store: memory`.
    let Some(store) = store else {
        return 0;
    };
    let bodies = match store.list_plane_records(
        crate::record::KIND_DEMOTION,
        &busbar_api::PlaneSelector::All,
    ) {
        Ok(bodies) => bodies,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "the durable MCP demotion records could NOT be read at boot; any upstream demoted \
                 before the last restart is not replayed until it is next observed"
            );
            return 0;
        }
    };
    if bodies.is_empty() {
        return 0;
    }
    // The bound-snapshot runtime — this replay seeds exactly the generation the host was minted over.
    let rt = super::runtime_of(host);
    let mut replayed = 0usize;
    for body in bodies {
        let row = match crate::record::McpDemotionRow::from_body(&body) {
            Ok(row) => row,
            Err(_) => continue,
        };
        let Some(entry) = rt.catalogue.server(&row.server) else {
            tracing::info!(
                server = %row.server,
                "a durable MCP demotion record names a server this deployment no longer registers; \
                 it is not replayed"
            );
            continue;
        };
        let Ok(id) = crate::mcp::client::identity::ServerId::new(&entry.id) else {
            continue;
        };
        let approval = entry.approval.clone();
        let reason = row.reason.clone();
        rt.sightings.apply(|servers| {
            let sc = servers.entry(id.as_str().to_string()).or_insert_with(|| {
                crate::mcp::client::catalogue::ServerCatalogue::seeded(id.clone(), approval)
            });
            sc.sighting = busbar_substrate::trust::Sighting::Demoted(reason);
        });
        replayed += 1;
    }
    replayed
}
