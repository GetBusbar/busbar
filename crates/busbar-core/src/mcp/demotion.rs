// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BOOT REPLAY of the durable demotion record into the live MCP sightings cache.
//!
//! The record itself — the row store and the one settle rule — is engine trust state and lives in
//! [`crate::plane::quarantine`]. What stays here is the one piece that reaches into
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
pub(crate) fn hydrate(app: &crate::state::App) -> usize {
    let rows = app.mcp_demotions.list();
    if rows.is_empty() {
        return 0;
    }
    let mut replayed = 0usize;
    for row in rows {
        let Some(entry) = super::runtime(app).catalogue.server(&row.server) else {
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
        super::runtime(app).sightings.apply(|servers| {
            let sc = servers.entry(id.as_str().to_string()).or_insert_with(|| {
                crate::mcp::client::catalogue::ServerCatalogue::seeded(id.clone(), approval)
            });
            sc.sighting = crate::trust::Sighting::Demoted(reason);
        });
        replayed += 1;
    }
    replayed
}
