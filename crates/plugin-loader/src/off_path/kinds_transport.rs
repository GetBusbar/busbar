// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport kind's Statement read, which runs once per load, bind or boot, never per request
//! (lint ruling Q4): moved from `dispatch::kinds::transport` with its behaviour unchanged; that
//! module re-exports the paths its callers use.
//!
//! Every caller, at the move: [`tail_facts`] from `Transport`'s `Kind::context` (the loader calls
//! it once per load and bind, `dispatch::load`), [`stated`] and [`linked_facts`]; [`linked_facts`]
//! from the root's boot (`root/boot.rs`) and the connector's linked-row readers
//! (`busbar-core-connector` `doors.rs` `stated_row`, `row_facts`, `claims_of`, `upgrades_of`,
//! `lines_of`: the boot seal and the generated linked-row tables, `busbar/build.rs`,
//! `root/linked.rs`); [`stated`] has no caller outside the loader's tests.
//!
//! It holds no `unsafe`: the tail and its lists are judged and formed by the safe primitive
//! `dispatch::kinds::transport::stated_tail`, beside the kind's other unsafe code, so the unsafe
//! register (unsafe.yaml) keeps its per-file counts.

use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::transport;
use busbar_contract::abi::transport::check::{
    check_fault_cover, check_fault_rows, check_offered_points, check_status_rows,
};
use busbar_contract::records::size_limits::Fault;

use crate::dispatch::kinds::transport::{
    owned, stated_tail, StatedTail, Transport, TransportFacts,
};

pub fn stated(
    door_fn: busbar_contract::abi::mechanism::door::DoorFn,
) -> Result<TransportFacts, String> {
    let st = crate::dispatch::load::statement_of(crate::dispatch::load::raw(door_fn))
        .map_err(crate::cold::dispatch::kinds::load_refusal)?;
    tail_facts(&st)
}

pub(crate) fn tail_facts(st: &Statement) -> Result<TransportFacts, String> {
    use crate::cold::dispatch::kinds as cold;
    let StatedTail {
        tail,
        rows,
        names,
        under,
        settings,
        extensions,
        status,
        faults,
        ported,
    } = stated_tail(st)?;
    let broke = |f: Fault| cold::tail_fault("transport", f);
    let offered = check_offered_points(extensions).map_err(broke)?;
    let seals =
        busbar_contract::abi::transport::check::check_sealed_values(extensions).map_err(broke)?;
    let adopts_session =
        busbar_contract::abi::mechanism::extensions::get(
            extensions,
            busbar_contract::abi::transport::adopted_session::EXT_ADOPTED_SESSION,
        ) == Some(busbar_contract::abi::transport::adopted_session::SUPPORT_ADOPTED_SESSION);
    let claims = cold::transport_names(names, "claim")?;

    let lines = cold::transport_claims_where(&claims, rows, |row| {
        row.unit0_trigger == busbar_contract::transport::codes::UNIT0_FIRST_LINE
    });
    let upgrades = cold::transport_claims_where(&claims, rows, |row| {
        row.unit0_trigger == busbar_contract::transport::codes::UNIT0_UPGRADE
    });
    let sessions = cold::transport_claims_where(&claims, rows, |row| row.session == 1);

    check_status_rows(status, tail.claim_rows_len as u64).map_err(broke)?;
    check_fault_rows(faults, tail.claim_rows_len as u64).map_err(broke)?;
    check_fault_cover(status, faults).map_err(broke)?;
    let status_namespaces = cold::transport_status_namespaces(rows)?;
    for row in status {
        if status_namespaces[row.claim as usize].is_none() {
            return Err("a numbered status table requires its claim's namespace".into());
        }
    }
    let handoff_status = transport::status::handoff(extensions, &claims)?;
    let listener_bindings = transport::listener_bindings::read(extensions, &claims)?;
    if !listener_bindings.is_empty()
        && (tail.role != transport::ROLE_FRAMER || tail.facts & transport::FACT_ACCEPTS == 0)
    {
        return Err("listener-bindings requires an accepting framer".into());
    }
    let name = owned(st.name, "Statement name")?;
    let status_rows = cold::transport_status_rows(status);
    let composes_over = cold::transport_names(under, "composes_over")?;
    let settings_keys = cold::transport_settings_keys(settings)?;
    Ok(TransportFacts {
        status_namespaces,
        handoff_status,
        listener_bindings,
        adopts_session,
        name,
        datagram: tail.framing == busbar_contract::transport::codes::FRAMING_DATAGRAM,
        accepts: tail.facts & busbar_contract::transport::codes::FACT_ACCEPTS != 0,
        dials: tail.facts & transport::FACT_DIALS != 0,
        detaches: tail.facts & transport::FACT_DETACHES != 0,
        adopts: tail.facts & transport::FACT_ADOPTS != 0,
        status_rows,
        offered,
        seals,
        role: tail.role,
        claims,
        upgrades,
        sessions,
        lines,
        composes_over,
        settings_keys,
        ported,
    })
}

pub fn linked_facts(
    door: busbar_contract::abi::mechanism::door::DoorFn,
) -> Result<TransportFacts, String> {
    let v = crate::dispatch::load::validate::<Transport>(crate::dispatch::load::raw(door))
        .map_err(crate::cold::dispatch::kinds::load_refusal)?;
    tail_facts(&v.statement)
}
