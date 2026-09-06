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
        // AN UNDECODABLE ROW FAILS CLOSED, and it is the one row on this path that must.
        //
        // This was `Err(_) => continue`: a row that would not decode was dropped on the floor with
        // no log line, no diagnostic and no count. A demotion row exists BECAUSE an upstream was
        // quarantined — a live observation disagreed with the operator's approval — and
        // `docs/mcp.md` states the property the replay is here to keep: *"a quarantine survives a
        // restart… a restart does not silently re-open it"*. Skipping the row re-opened it exactly
        // that way. Worse, the record is a security control and the store is the thing an attacker
        // with write access reaches first: corrupting ONE byte of one row was a supported way to
        // un-quarantine a drifted upstream across the next restart, and it left no trace.
        //
        // So the row is not skipped. The `server` field is SALVAGED from the raw body — a row that
        // fails to decode as a whole very often still carries a legible name, because the failure is
        // a missing or changed field elsewhere — and the demotion is replayed on that name with a
        // reason saying why. Only a body with no salvageable name has nothing to act on, and that
        // one still raises the diagnostic. The row is never deleted here either way: destroying the
        // evidence is the one thing the restart that found it must not do.
        let row = match crate::record::McpDemotionRow::from_body(&body) {
            Ok(row) => row,
            Err(e) => {
                let salvaged = salvage_server(&body);
                busbar_substrate::diag_warn!(
                    crate::diagnostics::MCP_DEMOTION_ROW_UNREADABLE,
                    error = %e,
                    server = salvaged.as_deref().unwrap_or("<unreadable>"),
                    "a durable MCP demotion record could not be decoded at boot; the quarantine it \
                     records is held rather than dropped"
                );
                let Some(server) = salvaged else {
                    // Nothing to hold the quarantine ON. The diagnostic above is the whole answer:
                    // busbar will not invent a server name, and it will not pretend the row was
                    // absent either — an operator now has a coded record that one was unreadable.
                    continue;
                };
                crate::record::McpDemotionRow {
                    server,
                    reason: "a durable demotion record for this server could not be decoded at \
                             boot; the quarantine is held until an operator clears it deliberately"
                        .to_string(),
                    recorded_at: 0,
                }
            }
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

/// The `server` field of a demotion body that did NOT decode as a whole row.
///
/// A last resort and deliberately a narrow one: the body is parsed as generic JSON and exactly one
/// string member is read. It recovers the ordinary corruption — a field added, removed or retyped
/// somewhere else in the row — without ever inventing a name, which is what lets the replay hold a
/// quarantine whose full terms it can no longer read.
///
/// An empty name is treated as no name. A demotion keyed by the empty string would seed a cache
/// entry nothing routes to, which is a quarantine that looks enforced and is not.
fn salvage_server(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()?
        .get("server")?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}
