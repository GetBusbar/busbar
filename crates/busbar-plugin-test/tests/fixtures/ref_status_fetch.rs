// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REFERENCE CALLER OF THE STATUS-ONLY FETCH (core 3.0, `net1::FETCH_STATUS_ONLY`): the smallest image
//! that makes one FETCH per call, status-only or full, and answers what the host handed back. A secret
//! plugin, because a secret's `resolve` is the plainest async method that may FETCH.
//!
//! The reference is `{"url": text, "mode": "status" | "full"}`. The value answered is
//! `<status> <number of headers> <body length>`, so a test reads off it whether the host kept a body.
//! `busbar-export-webhook` makes the status-only call the same way: a `Fetch` with `max_body: 0` handed to
//! `need::fetch_status`.

use std::collections::HashMap;

use busbar_plugin_abi::fail::refused::R_INVALID;
use busbar_plugin_abi::fail::Fail;
use busbar_plugin_abi::host::Host;
use busbar_plugin_abi::need::need::{self, Fetch};
use busbar_plugin_abi::need::{egress, ChainBytes, TrustHandle};
use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
use busbar_plugin_abi::records::{tag, Records, Reply, Writer};
use busbar_plugin_abi::{secret, Secret};

/// The reference caller: no state.
pub struct RefStatusFetch;

/// The reference's settings object: one CONFIG record whose body is the object (the loader's
/// `encode_reference`); bytes that are not a record stream are the object itself.
fn settings(bytes: &[u8]) -> &[u8] {
    Records::new(bytes)
        .next()
        .and_then(Result::ok)
        .filter(|rec| rec.tag == tag::CONFIG)
        .map_or(bytes, |rec| rec.body)
}

impl Open for RefStatusFetch {
    async fn open(_h: &'static Host, _config: ChainBytes) -> Result<Self, Fail> {
        Ok(RefStatusFetch)
    }

    fn check(_h: &Host, _config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
        Ok(())
    }

    fn describe(d: &mut Describe<'_>) {
        d.schema(r#"{"type":"object"}"#);
        d.item_text(
            secret::tag::D_REF_SCHEMA,
            r#"{"type":"object","required":["url","mode"],"properties":{"url":{"type":"string"},"mode":{"type":"string"}}}"#,
        );
    }
}

impl Secret for RefStatusFetch {
    async fn resolve(&self, _h: &'static Host, reference: ChainBytes) -> Result<Reply, Fail> {
        let mut object = reference
            .with(|bytes| busbar_contract::json::parse::<HashMap<String, String>>(settings(bytes)))
            .map_err(|_| Fail::refused_because(R_INVALID, "reference must be {url, mode}"))?;
        let (Some(url), Some(mode)) = (object.remove("url"), object.remove("mode")) else {
            return Err(Fail::refused_because(
                R_INVALID,
                "reference must be {url, mode}",
            ));
        };
        let status_only = match mode.as_str() {
            "status" => true,
            "full" => false,
            _ => return Err(Fail::refused_because(R_INVALID, "mode is status or full")),
        };
        let headers: [(&str, &[u8]); 1] = [("content-type", b"application/json")];
        let request = Fetch {
            method: "POST",
            url: &url,
            headers: &headers,
            body: b"{\"line\":1}",
            // A status-only FETCH states no cap of its own.
            max_body: if status_only { 0 } else { 4096 },
            trust: TrustHandle::NONE,
            cert: None,
            egress: egress::OPEN_WEB,
        };
        let answer = if status_only {
            need::fetch_status(&request).await
        } else {
            need::fetch(&request).await
        }
        .map_err(Fail::from)?;
        let value = format!(
            "{} {} {}",
            answer.status,
            answer.headers.len(),
            answer.body.len()
        );
        let mut reply = Reply::with_capacity(value.len() + 16);
        reply
            .put(secret::tag::VALUE, value.as_bytes())
            .map_err(Fail::from)?;
        Ok(reply)
    }
}

busbar_plugin_abi::plugin!(Secret, RefStatusFetch, name: "reference-status-fetch");
