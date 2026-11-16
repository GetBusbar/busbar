// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A MIN-3 secret fixture written the real way (ABI-MIN3-INTERFACE §7.7): the `Secret` trait, `Open` and one
//! `plugin!` line, no hand wiring. Its config is the secret store itself, an object of name to value, held in
//! memory; a reference is `{"name": "<key>"}`. It answers a known name with its value, an unknown name with
//! REFUSED R_NOT_FOUND and a malformed reference with REFUSED R_INVALID, and it never logs or echoes a value.
//! No `unsafe`: the glue is `plugin!`'s output only.

use std::collections::HashMap;

use busbar_plugin_abi::fail::refused::{R_CONFIG, R_INVALID, R_NOT_FOUND};
use busbar_plugin_abi::fail::Fail;
use busbar_plugin_abi::host::Host;
use busbar_plugin_abi::need::ChainBytes;
use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
use busbar_plugin_abi::records::{tag, Records, Reply, Writer};
use busbar_plugin_abi::Secret;

type Entries = HashMap<String, String>;

/// The in-memory secret source.
pub struct MemSecret {
    entries: Entries,
}

fn entries(config: &[u8]) -> Result<Entries, Fail> {
    busbar_contract::json::parse::<Entries>(config).map_err(|_| {
        Fail::refused_because(R_CONFIG, "config must be an object of name to text value")
    })
}

/// The reference's settings object: the request is one CONFIG record whose body is the object (IF 8.2, the
/// loader's `encode_reference`); bytes that are not a record stream are the object itself.
fn settings(bytes: &[u8]) -> &[u8] {
    Records::new(bytes)
        .next()
        .and_then(Result::ok)
        .filter(|rec| rec.tag == tag::CONFIG)
        .map_or(bytes, |rec| rec.body)
}

impl Open for MemSecret {
    async fn open(_h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
        let entries = config.with(entries)?;
        Ok(MemSecret { entries })
    }

    fn check(_h: &Host, config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
        entries(config).map(|_| ())
    }

    fn describe(d: &mut Describe<'_>) {
        d.schema(r#"{"type":"object","additionalProperties":{"type":"string"}}"#);
        d.item_text(
            busbar_plugin_abi::secret::tag::D_REF_SCHEMA,
            r#"{"type":"object","properties":{"name":{"type":"string"}}}"#,
        );
    }
}

impl Secret for MemSecret {
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
        let mut reply = Reply::new();
        reply
            .put(busbar_plugin_abi::secret::tag::VALUE, value.as_bytes())
            .map_err(Fail::from)?;
        Ok(reply)
    }
}

busbar_plugin_abi::plugin!(Secret, MemSecret, name: "fixture-secret-a");
