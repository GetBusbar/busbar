// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NODE'S ONE STORE HANDLE, driven through a plane's record legs and read back through the
//! published store face.
//!
//! Every cell here uses the RAM default — `busbar_core::governance::MemoryStore`, which is what a
//! configuration naming no store module gets. It is not a double: it is the backend a default
//! deployment actually runs, reached through the same `busbar_api::Store` face a durable module is
//! reached through, so a record that lands here is a record that lands on any of them.

use std::sync::Arc;

use busbar_api::{PlaneSelector, Store as AbiStore};
use busbar_plane_mcp::records;

use crate::root::store::node_adapter;
use crate::root::units_mcp::{RecordAnswer, RecordLeg, Records};

/// The RAM default, as a node with no configured store module runs it.
fn ram_store() -> Arc<dyn AbiStore> {
    Arc::new(busbar_core::governance::MemoryStore::new())
}

/// One leg over one schema, with the two clock fields a record carries.
fn leg<'a>(
    schema: busbar_contract::ids::RecordSchemaId,
    op: &'static str,
    key: &'a str,
    body: &'a [u8],
) -> RecordLeg<'a> {
    RecordLeg {
        schema,
        op,
        key,
        parent: None,
        seq: 0,
        body,
        terminal: false,
        now: 1_700_000_000,
        expires_at: 1_700_000_060,
    }
}

/// **A RECORD WRITTEN THROUGH THE MCP LEG'S `records` IS READ BACK THROUGH THE STORE FACE.**
///
/// The whole of what the production store adapter is for, stated as a run rather than as a
/// sentence. The root binds the node's ONE store handle behind the published ABI; the plane's
/// record legs are bound to that adapter and to nothing else; a `put` through the leg lands on the
/// store, and the reader is the STORE, not the view that wrote it. Before there was a production
/// adapter there was nothing in the tree to bind `records` to at all, so every read-back was a read
/// from a fixture the same test had written.
#[test]
fn a_record_written_through_the_mcp_leg_is_read_back_through_the_store_face() {
    let store = ram_store();
    let adapter = node_adapter(Arc::clone(&store));
    let records = Records::new(&adapter);

    let written = records
        .run(&leg(
            records::SCHEMA_CATALOGUE,
            records::OP_PUT,
            "fs",
            b"{\"tools\":[]}",
        ))
        .expect("the plane declares put on its catalogue schema");
    assert_eq!(
        written,
        RecordAnswer::Written,
        "the leg reported the write landed"
    );

    let read_back = store
        .get_plane_record(records::SCHEMA_CATALOGUE.as_str(), "fs")
        .expect("the store answered the read");
    assert_eq!(
        read_back.as_deref(),
        Some(&b"{\"tools\":[]}"[..]),
        "the record the leg wrote came back OFF THE STORE FACE, byte for byte — not off the view \
         that wrote it"
    );
}

/// **THE ADAPTER IS OVER THE NODE'S ONE HANDLE, NOT A COPY OF IT.**
///
/// The property the whole binding rests on: what the record legs write through and what the audit
/// and call streams read through are the SAME store. An adapter that wrapped a clone of the store's
/// contents would serve a node whose planes wrote onto books nothing read, and both halves would
/// look healthy because an empty store answers every read.
#[test]
fn the_adapter_passes_the_node_s_own_store_handle_through() {
    let store = ram_store();
    let adapter = node_adapter(Arc::clone(&store));
    assert!(
        Arc::ptr_eq(&adapter.store(), &store),
        "the adapter hands back the very handle it was bound to"
    );
}

/// **A SCAN THROUGH THE LEG SEES WHAT AN APPEND THROUGH THE LEG WROTE.**
///
/// The second operation every plane's leg uses, and the one that proves the parent selector reaches
/// the same rows: an append under a parent, then a scan of that parent, through the one store the
/// root bound.
#[test]
fn an_appended_record_is_in_the_store_s_own_scan_of_its_parent() {
    let store = ram_store();
    let adapter = node_adapter(Arc::clone(&store));
    let records = Records::new(&adapter);

    let mut appended = leg(records::SCHEMA_CALL, records::OP_APPEND, "call-1", b"first");
    appended.parent = Some("vk-1");
    assert_eq!(
        records
            .run(&appended)
            .expect("the plane declares append on its call schema"),
        RecordAnswer::Written,
        "the append landed"
    );

    let rows = store
        .list_plane_records(
            records::SCHEMA_CALL.as_str(),
            &PlaneSelector::Parent("vk-1".to_string()),
        )
        .expect("the store answered the scan");
    assert_eq!(
        rows,
        vec![b"first".to_vec()],
        "the store's own scan of the parent carries the record the leg appended"
    );
}
