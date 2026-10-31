// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The dealt blob's section: empty, unwritten and `null` are the empty section; the section's
//! value otherwise, its sibling sections left alone; a blob that is not JSON or not a map refused.
//! The one cancel rule ends the units each plane's own cancel ended (plane-mcp, plane-a2a,
//! plane-decisions, plane-llm and plane-streaming, transcribed below) and answers as it did.

use super::*;

#[test]
fn the_dealt_blob_is_read_at_the_planes_section() {
    assert_eq!(dealt_section(b"", "tools"), Ok(None));
    assert_eq!(dealt_section(b"{}", "tools"), Ok(None));
    assert_eq!(dealt_section(br#"{"models":{"m":{}}}"#, "tools"), Ok(None));
    assert_eq!(dealt_section(br#"{"tools":null}"#, "tools"), Ok(None));
    assert_eq!(
        dealt_section(br#"{"tools":{"servers":[1]},"models":{}}"#, "tools"),
        Ok(Some(serde_json::json!({"servers": [1]})))
    );
    assert_eq!(
        dealt_section(br#"{"tools":[]}"#, "tools"),
        Ok(Some(serde_json::json!([])))
    );
}

#[test]
fn a_blob_that_is_not_a_map_of_sections_is_refused() {
    assert_eq!(dealt_section(b"[]", "tools"), Err(NOT_A_MAP.to_string()));
    assert_eq!(dealt_section(b"7", "tools"), Err(NOT_A_MAP.to_string()));
    assert_eq!(
        dealt_section(b"{", "tools"),
        Err(serde_json::from_slice::<serde_json::Value>(b"{")
            .expect_err("not JSON")
            .to_string())
    );
    assert_eq!(
        NOT_A_MAP,
        "the dealt settings are not a map of the plane's sections"
    );
}

// ── the one cancel rule, against the five planes' own ────────────────────────────────────────────

use std::collections::BTreeMap;

use crate::abi::mechanism::ticket::Ticket;
use crate::abi::plane::{CANCEL_ABORTED, CANCEL_OK_PARTIAL};
use crate::abi::sdk::publish::Keyed;

/// A unit as every plane's table holds one: the ticket its pieces came on, whether its far end
/// answered, and (a2a) whether a cancel marked it over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Unit {
    ticket: Option<Ticket>,
    answered: bool,
    over: bool,
}

type Table = BTreeMap<u64, Unit>;

const fn ticket(n: u32) -> Ticket {
    Ticket {
        slot: n,
        generation: 1,
    }
}

/// plane-mcp `tool_door.rs` `Cancel`: every unit on the ticket, and the named one, leaves.
fn mcp(mut m: Table, t: Ticket, unit: u64) -> (bool, Table) {
    let cancelled = |k: &u64, u: &Unit| u.ticket == Some(t) || (unit != 0 && *k == unit);
    let answered = m.iter().any(|(k, u)| cancelled(k, u) && u.answered);
    m.retain(|k, u| !cancelled(k, &*u));
    (answered, m)
}

/// plane-a2a `agent_door.rs` `Cancel`: the named unit when held, else every unit on the ticket,
/// is marked over and kept.
fn a2a(mut m: Table, t: Ticket, unit: u64) -> (bool, Table) {
    let mut answered = false;
    if let Some(u) = m.get_mut(&unit).filter(|_| unit != 0) {
        u.over = true;
        answered = u.answered;
    } else if t != Ticket::NONE {
        for u in m.values_mut().filter(|u| u.ticket == Some(t)) {
            u.over = true;
            answered |= u.answered;
        }
    }
    (answered, m)
}

/// plane-decisions `plane_door.rs` `Cancel`: the named unit, else the first on the ticket, leaves.
fn decisions(mut m: Table, t: Ticket, unit: u64) -> (bool, Table) {
    let key = if unit != 0 {
        Some(unit)
    } else {
        m.iter().find(|(_, u)| u.ticket == Some(t)).map(|(k, _)| *k)
    };
    let answered = key.and_then(|k| m.remove(&k)).is_some_and(|u| u.answered);
    (answered, m)
}

/// The ticket bindings plane-llm's `UnitBook` and plane-streaming's `Units` keep beside the units.
fn bindings(m: &Table) -> std::collections::HashMap<Ticket, u64> {
    m.iter()
        .filter_map(|(k, u)| u.ticket.filter(|t| *t != Ticket::NONE).map(|t| (t, *k)))
        .collect()
}

/// plane-llm `UnitBook::cancel` (its PARTIAL/ABORTED half): the named unit, else the one bound to
/// the ticket, leaves.
fn llm(mut m: Table, t: Ticket, unit: u64) -> (bool, Table) {
    let unit = if unit == 0 {
        match bindings(&m).get(&t) {
            Some(u) => *u,
            None => return (false, m),
        }
    } else {
        unit
    };
    let answered = m.remove(&unit).is_some_and(|u| u.answered);
    (answered, m)
}

/// plane-streaming `Units::far_answered` then `Units::cancel`: the unit bound to the ticket and
/// the named one leave.
fn streaming(mut m: Table, t: Ticket, unit: u64) -> (bool, Table) {
    let by_ticket = bindings(&m).get(&t).copied();
    let named = || by_ticket.into_iter().chain((unit != 0).then_some(unit));
    let answered = named().any(|u| m.get(&u).is_some_and(|h| h.answered));
    for u in named() {
        m.remove(&u);
    }
    (answered, m)
}

fn helper(m: &Table, t: Ticket, unit: u64, ending: Ending) -> (bool, Table) {
    let units = Keyed::new();
    for (k, u) in m {
        units.insert(*k, *u);
    }
    let answered = UnitCancel { ticket: t, unit }.end(
        &units,
        ending,
        |u| u.ticket,
        |u| {
            u.over = true;
            u.answered
        },
    );
    (answered, units.with_all(std::mem::take))
}

/// Every table of up to three units, each with no ticket or one of three, each answered or not.
fn tables() -> Vec<Table> {
    let slots: Vec<Option<Unit>> = std::iter::once(None)
        .chain(
            [None, Some(ticket(1)), Some(ticket(2)), Some(ticket(3))]
                .into_iter()
                .flat_map(|t| {
                    [false, true].map(|answered| {
                        Some(Unit {
                            ticket: t,
                            answered,
                            over: false,
                        })
                    })
                }),
        )
        .collect();
    let mut out = Vec::new();
    for a in &slots {
        for b in &slots {
            for c in &slots {
                let m: Table = [(1, a), (2, b), (3, c)]
                    .into_iter()
                    .filter_map(|(k, u)| u.map(|u| (k, u)))
                    .collect();
                out.push(m);
            }
        }
    }
    out
}

/// Whether the table and cancel are ones the host makes: a ticket is unique per instance, so no two
/// units hold one, and a cancel's ticket names no unit but the one it names (`0` names none).
fn in_contract(m: &Table, t: Ticket, unit: u64) -> bool {
    let mut tickets: Vec<u32> = m
        .values()
        .filter_map(|u| u.ticket)
        .map(|t| t.slot)
        .collect();
    let held = tickets.len();
    tickets.sort_unstable();
    tickets.dedup();
    tickets.len() == held && (unit == 0 || m.iter().all(|(k, u)| *k == unit || u.ticket != Some(t)))
}

#[test]
fn the_one_cancel_rule_answers_as_each_plane_did() {
    let cancels: Vec<(Ticket, u64)> = [Ticket::NONE, ticket(1), ticket(2), ticket(3), ticket(4)]
        .into_iter()
        .flat_map(|t| (0..=4).map(move |u| (t, u)))
        .collect();
    let (mut checked, mut beyond) = (0usize, 0usize);
    for m in tables() {
        for &(t, unit) in &cancels {
            let removed = helper(&m, t, unit, Ending::Remove);
            let kept = helper(&m, t, unit, Ending::Keep);
            // a2a's own rule, on every input: the same units marked, the same answer.
            assert_eq!(kept, a2a(m.clone(), t, unit), "a2a {m:?} {t:?} {unit}");
            // Removing drops exactly the units keeping marks.
            let marked: Table = kept.1.into_iter().filter(|(_, u)| !u.over).collect();
            assert_eq!(removed.0, kept.0);
            assert_eq!(
                removed.1.keys().collect::<Vec<_>>(),
                marked.keys().collect::<Vec<_>>()
            );
            if !in_contract(&m, t, unit) {
                beyond += 1;
                continue;
            }
            checked += 1;
            let removed = (removed.0, strip(removed.1));
            for (plane, theirs) in [
                ("mcp", mcp(m.clone(), t, unit)),
                ("decisions", decisions(m.clone(), t, unit)),
                ("llm", llm(m.clone(), t, unit)),
                ("streaming", streaming(m.clone(), t, unit)),
            ] {
                assert_eq!(removed, theirs, "{plane} {m:?} {t:?} {unit}");
            }
        }
    }
    // Every case was reached: those the host makes, and those only the a2a rule was held to.
    assert_eq!((checked, beyond), (9111, 9114));
}

/// The units a removing cancel leaves, as the planes that remove left them (never marked).
fn strip(m: Table) -> Table {
    m.into_iter()
        .map(|(k, u)| (k, Unit { over: false, ..u }))
        .collect()
}

#[test]
fn the_cancel_reads_its_ticket_and_unit_and_answers_partial_or_aborted() {
    let mut input: PlaneCancelIn = unsafe { std::mem::zeroed() };
    input.cancel.ticket = ticket(7);
    input.unit = 9;
    // SAFETY: a zeroed `in` with its two scalars set; no buffer is read.
    let lent = unsafe { Lent::new(&input) };
    assert_eq!(
        UnitCancel::of(&lent),
        UnitCancel {
            ticket: ticket(7),
            unit: 9
        }
    );
    assert_eq!(cancel_disposition(true), CANCEL_OK_PARTIAL);
    assert_eq!(cancel_disposition(false), CANCEL_ABORTED);
}
