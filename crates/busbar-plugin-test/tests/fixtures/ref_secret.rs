// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REFERENCE SECRET (secret 3.0): the smallest image that uses every element the secret contract keeps.
//! `resolve` crosses by the one call shape (no numbers, no texts, `blobs[0]` = the reference's settings) and
//! answers VALUE and, when its source states a lease, the one fact `F_LEASE_S`: the element the engine reads at
//! `plugin-loader/src/adapters/secret.rs` and that `busbar-secret-vault` sets. The boundary test
//! (`c_boundary_fleet.rs`) drives it through the engine's real secret adapter, so a disagreement between the
//! contract's layout and the adapter shows here, on one kind, before any shipped plugin is involved.
//!
//! Config: an object of name to text value. The reserved name `lease_s`, when present, is the lease in whole
//! seconds every value is served with (a text that is no positive whole number is refused at open).
//! Reference: `{"name": "<key>"}`. Unknown name: REFUSED R_NOT_FOUND. Malformed: REFUSED R_INVALID.

use std::collections::HashMap;

use busbar_plugin_abi::fail::refused::{R_CONFIG, R_INVALID, R_NOT_FOUND};
use busbar_plugin_abi::fail::Fail;
use busbar_plugin_abi::host::Host;
use busbar_plugin_abi::need::ChainBytes;
use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
use busbar_plugin_abi::records::{tag, Records, Reply, Writer};
use busbar_plugin_abi::{secret, Secret};

/// The reserved config name that states the lease.
pub const LEASE_NAME: &str = "lease_s";

type Entries = HashMap<String, String>;

/// The reference secret source: its values and the lease it states for each.
pub struct RefSecret {
    entries: Entries,
    lease_s: Option<u64>,
}

fn read(config: &[u8]) -> Result<(Entries, Option<u64>), Fail> {
    let mut entries = busbar_contract::json::parse::<Entries>(config).map_err(|_| {
        Fail::refused_because(R_CONFIG, "config must be an object of name to text value")
    })?;
    let lease_s = match entries.remove(LEASE_NAME) {
        None => None,
        Some(text) => match text.parse::<u64>() {
            Ok(seconds) if seconds > 0 => Some(seconds),
            _ => {
                return Err(Fail::refused_because(
                    R_CONFIG,
                    "`lease_s` must be a positive whole number of seconds",
                ))
            }
        },
    };
    Ok((entries, lease_s))
}

/// The reference's settings object: one CONFIG record whose body is the object (the loader's
/// `encode_reference`); bytes that are not a record stream are the object itself.
fn settings(bytes: &[u8]) -> &[u8] {
    Records::new(bytes)
        .next()
        .and_then(Result::ok)
        .filter(|rec| rec.tag == tag::CONFIG)
        .map_or(bytes, |rec| rec.body)
}

impl Open for RefSecret {
    async fn open(_h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
        let (entries, lease_s) = config.with(read)?;
        Ok(RefSecret { entries, lease_s })
    }

    fn check(_h: &Host, config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
        read(config).map(|_| ())
    }

    fn describe(d: &mut Describe<'_>) {
        d.schema(r#"{"type":"object","additionalProperties":{"type":"string"}}"#);
        d.item_text(
            secret::tag::D_REF_SCHEMA,
            r#"{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}"#,
        );
    }
}

impl Secret for RefSecret {
    async fn resolve(&self, _h: &'static Host, reference: ChainBytes) -> Result<Reply, Fail> {
        let name = reference
            .with(|bytes| busbar_contract::json::parse::<Entries>(settings(bytes)))
            .ok()
            .and_then(|mut object| object.remove("name"))
            .ok_or_else(|| {
                Fail::refused_because(R_INVALID, "reference must be {\"name\": text}")
            })?;
        let value = self
            .entries
            .get(&name)
            .ok_or_else(|| Fail::refused_because(R_NOT_FOUND, "no such secret"))?;
        // VALUE first, then the backend's one fact. One FACT record is 24 bytes with its head.
        let mut reply = Reply::with_capacity(value.len() + 16 + 24);
        reply
            .put(secret::tag::VALUE, value.as_bytes())
            .map_err(Fail::from)?;
        if let Some(seconds) = self.lease_s {
            reply
                .put_fact(secret::F_LEASE_S, seconds)
                .map_err(Fail::from)?;
        }
        Ok(reply)
    }
}

busbar_plugin_abi::plugin!(Secret, RefSecret, name: "reference-secret");
