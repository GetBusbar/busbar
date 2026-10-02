// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! M6-COLD-DELETE (TRANSITIONAL, with `crate::export`): the recorder snapshot as the COLD export
//! lane's `ExportRequest::Scrape` carries it. The host reads its recorder through the contract's one
//! reader (`busbar_contract::export_calls::parse_families`); a memory-ABI sink is handed that
//! snapshot by `crate::export_door`, and a cold sink by [`DynExport::scrape`] over the cold shape
//! [`cold_families`] lowers it to.

use crate::DynExport;
use busbar_contract::abi::cold::export::{
    ExportRequest, ExportResponse, MetricFamily, MetricSample,
};
use busbar_contract::export_calls::{type_word, Family};

/// The snapshot's families in the cold lane's shape, in order.
#[must_use]
pub fn cold_families(families: &[Family]) -> Vec<MetricFamily> {
    families
        .iter()
        .map(|f| MetricFamily {
            name: f.name.clone(),
            kind: type_word(f.kind).unwrap_or("untyped").to_string(),
            help: f.help.clone(),
            samples: f
                .samples
                .iter()
                .map(|s| MetricSample {
                    name: s.name.clone(),
                    labels: s.labels.clone(),
                    value: s.value.clone(),
                })
                .collect(),
        })
        .collect()
}

impl DynExport {
    /// Hand the sink the recorder snapshot and take back the exposition it rendered:
    /// `(content_type, body)`. A sink that cannot decode the op says so out of band — it renders
    /// nothing, and the host keeps rendering its own.
    pub fn scrape(&self, families: Vec<MetricFamily>) -> Result<(String, String), String> {
        let req = ExportRequest::Scrape { families };
        match self
            .raw
            .transport_call::<ExportRequest, ExportResponse>(&req)?
        {
            ExportResponse::Exposition { content_type, body } => Ok((content_type, body)),
            other => Err(format!(
                "export plugin '{}' returned an unexpected response to scrape: {other:?}",
                self.raw.path
            )),
        }
    }
}
