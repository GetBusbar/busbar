// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth door's off-path code (`crate::auth_door`): what an instance's OPEN, a REFRESH (config
//! reload, secret rotation) and a row's LOAD build, once per instance lifecycle, never per request.
//! Every fn here is reached only from `AuthInstance::open`, `AuthInstance::refresh_lent` (called by
//! `refresh` and `relend`) and `AuthSink::new` (called by `AuthRows::load`); no verify, login or
//! outbound op reaches it.

use busbar_contract::abi::mechanism::call::Blob;
use busbar_contract::plugin::KernelSeal;

use crate::auth_door::{AuthSink, FlushSink, InstanceMetadata, KeptSecrets, ReplyExtensions};
use crate::cold::auth_door as cold;
use crate::dispatch::kinds::auth::AuthFacts;

impl AuthSink {
    /// The sink an auth row binds with, made as the row loads.
    #[must_use]
    pub fn new(plugin: &str) -> Self {
        Self(std::sync::Arc::new(FlushSink {
            plugin: cold::sink_plugin(plugin),
            family: std::sync::Mutex::new(None),
            flushed: std::sync::atomic::AtomicU64::new(0),
        }))
    }
}

impl KeptSecrets {
    /// One secret blob per kept secret, lent to an OPEN or a REFRESH.
    pub(crate) fn blobs(
        &self,
        seal: Option<&(dyn KernelSeal + Send + Sync)>,
    ) -> Result<Vec<Blob>, String> {
        if self.0.is_empty() {
            return Ok(Vec::new());
        }
        let seal = seal.ok_or("credential lending requires the host settings seal")?;
        Ok(cold::lent_blobs(self, seal))
    }
}

pub(crate) fn instance_carriers(
    ext: Option<ReplyExtensions<'_>>,
    previous: &[String],
    facts: &AuthFacts,
) -> Result<Vec<String>, String> {
    use busbar_contract::auth_calls::codes::{EXT_CARRIERS, FACT_DEFAULT_INBOUND_STYLE};
    use busbar_contract::kinds::codes::extensions;

    let invalid = cold::invalid_carriers;
    let bytes = match ext {
        None => return Err(invalid()),
        Some(ReplyExtensions::Absent) => return Ok(cold::kept_carriers(previous)),
        Some(ReplyExtensions::Bytes(bytes)) => bytes,
    };
    let mut consumed = 0;
    let mut selection = None;
    for (key, value) in extensions::entries(bytes) {
        consumed += 2 + key.len() + 4 + value.len();
        if key != EXT_CARRIERS.as_bytes() {
            continue;
        }
        if selection.is_some() {
            return Err(invalid());
        }
        // The selection is the stated names themselves, lowered and deduplicated in place
        // (first occurrence kept, in order).
        let mut selected: Vec<String> =
            busbar_contract::json::parse(value).map_err(|_| invalid())?;
        for name in &mut selected {
            if !facts
                .carriers
                .iter()
                .any(|declared| declared.eq_ignore_ascii_case(name.as_str()))
            {
                return Err(invalid());
            }
            name.make_ascii_lowercase();
        }
        let mut kept = 0;
        for at in 0..selected.len() {
            if !selected[..kept].contains(&selected[at]) {
                selected.swap(kept, at);
                kept += 1;
            }
        }
        selected.truncate(kept);
        if selected.is_empty() && facts.facts & FACT_DEFAULT_INBOUND_STYLE != 0 {
            return Err(invalid());
        }
        selection = Some(selected);
    }
    if consumed != bytes.len() {
        return Err(invalid());
    }
    Ok(selection.unwrap_or_else(|| cold::kept_carriers(previous)))
}

pub(crate) fn instance_metadata(
    ext: Option<ReplyExtensions<'_>>,
    previous: &[String],
    facts: &AuthFacts,
    generation: u64,
) -> Result<InstanceMetadata, String> {
    let carriers = instance_carriers(ext, previous, facts)?;
    let bytes = match ext {
        Some(ReplyExtensions::Bytes(bytes)) => bytes,
        _ => &[][..],
    };
    let presentation = busbar_contract::auth_calls::presentation::login_presentation(bytes)
        .map_err(cold::presentation_refused)?;
    if presentation.is_some() && facts.caps & busbar_contract::auth_calls::codes::CAP_LOGIN == 0 {
        return Err("auth login presentation requires the login capability".into());
    }
    Ok(InstanceMetadata {
        carriers: cold::shared_carriers(carriers),
        presentation,
        generation,
        attempted_generation: generation,
    })
}
