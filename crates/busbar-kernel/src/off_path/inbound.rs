// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Off-path code for the request-path `inbound` tree: a listener generation's install (its line
//! index, its ordered auth chains, its door refusals, its request-point auths), the retirement of
//! the generations it replaces, a listener's removal, and the line specs a published listener
//! lends its transport. Each runs once per listener generation or lifecycle event, never per
//! request; the request path only reads the installed [`Table`].

use std::sync::{Arc, PoisonError};

use busbar_contract::kept::Text;
use busbar_contract::route::{AuthPoint, POINT_HEAD_BODY};
use foldhash::HashMap;

use crate::guest::LineAuth;
use crate::inbound::{is_line_id, Inbound, LineSpec, Listener, Table, IDS_REFUSED};

impl Listener {
    /// The lines as the transport is lent them, listed when the listener is published.
    #[must_use]
    pub fn specs(&self) -> Vec<LineSpec> {
        (0u32..)
            .zip(self.guests.lines().iter().zip(&self.ids))
            .map(|(i, (l, id))| {
                let points = l.auth.points().bits();
                LineSpec {
                    line: i,
                    auth: *id,
                    points,
                    body_limit: if points & POINT_HEAD_BODY != 0 {
                        self.body_limit
                    } else {
                        0
                    },
                }
            })
            .collect()
    }
}

impl Inbound {
    /// Install a listener generation: its tables are built once here, and the generations it
    /// replaces are retired.
    pub fn install_at(
        &self,
        owner: u64,
        listener_id: u64,
        generation: u64,
        listener: Listener,
    ) -> Result<(), &'static str> {
        let lines_by_id = checked_line_ids(&listener.ids, listener.guests.lines().len())?;
        let providers: Vec<Arc<[Text]>> = listener
            .guests
            .lines()
            .iter()
            .map(|line| match &line.auth {
                LineAuth::Chain(names, _) => ordered(names),
                LineAuth::None => Arc::default(),
            })
            .collect();
        let doors = crate::core_routes::CoreRouteTable::default()
            .with_door_refusals(listener.door_refusals.clone());
        let request_auths = listener
            .auths
            .iter()
            .filter(|(_, auth)| {
                let points = auth.inbound_points();
                points.has(AuthPoint::Head) || points.has(AuthPoint::HeadBody)
            })
            .map(|(name, _)| name.clone())
            .chain(std::iter::once(crate::config::KEYS_MODULE.to_owned()))
            .collect();
        let mut tables = self.tables.write().unwrap_or_else(PoisonError::into_inner);
        let mut retired = Vec::new();
        let replaced = tables.insert(
            (owner, listener_id, generation),
            Arc::new(Table {
                listener,
                doors,
                providers,
                lines_by_id,
                request_auths,
            }),
        );
        retired.extend(replaced);
        tables.retain(|(o, listener, g), table| {
            let keep = *o != owner || *listener != listener_id || g.saturating_add(1) >= generation;
            if !keep {
                retired.push(Arc::clone(table));
            }
            keep
        });
        drop(tables);
        drop(retired);
        Ok(())
    }
}

/// A listener's line ids, indexed once when it is installed.
pub(crate) fn checked_line_ids(
    ids: &[u64],
    lines: usize,
) -> Result<HashMap<u64, u32>, &'static str> {
    let lines_by_id: HashMap<u64, u32> = ids.iter().copied().zip(0u32..).collect();
    if ids.len() != lines || lines_by_id.len() != lines || !ids.iter().all(|id| is_line_id(*id)) {
        return Err(IDS_REFUSED);
    }
    Ok(lines_by_id)
}

/// A line's auth chain in walk order (the keys module last), ordered once at install.
/// A line's provider names in walk order, each made shared text once, when the table is built: a
/// request that names one afterwards shares it.
fn ordered(names: &[String]) -> Arc<[Text]> {
    let keys = crate::config::KEYS_MODULE;
    names
        .iter()
        .filter(|n| *n != keys)
        .chain(names.iter().filter(|n| *n == keys).take(1))
        .map(|n| Text::from(Arc::<str>::from(n.as_str())))
        .collect()
}
