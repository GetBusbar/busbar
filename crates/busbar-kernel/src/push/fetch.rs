// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Delivery of validated queue records through the root-owned guarded fetch bridge.

use std::sync::Arc;

use busbar_plugin_abi::fail::{failed::F_UPSTREAM, refused::R_INVALID};
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::need::egress;
use busbar_plugin_abi::plane::tag as plane;
use busbar_plugin_abi::records::{tag, Records, Reply, Writer};

use crate::plane_driver::port_fetch::{PlaneFetch, PlaneFetchRequest};
use crate::retry::PortError;

/// A queue sink that delegates network, deadline and destination authority to the root's connector bridge.
pub struct ConnectorPushSink {
    fetch: Arc<dyn PlaneFetch>,
}
impl ConnectorPushSink {
    pub fn new(fetch: Arc<dyn PlaneFetch>) -> Self {
        Self { fetch }
    }
}
fn invalid() -> PortError {
    PortError::Refused {
        code: R_INVALID,
        text: "invalid queued delivery records".into(),
        error: None,
    }
}
impl ConnectorPushSink {
    /// One delivery attempt: the connector's fetch under the live instance's Caller and the connector's
    /// guard (arch lints section 3.1: the one sink is this concrete type).
    pub fn deliver<'a>(
        &'a self,
        who: &'a Caller<'_>,
        recs: &'a [u8],
    ) -> BoxFut<'a, Result<(), PortError>> {
        Box::pin(async move {
            let mut records = Records::new(recs);
            let method = records.next().ok_or_else(invalid)?.map_err(|_| invalid())?;
            if method.tag != tag::H_METHOD {
                return Err(invalid());
            }
            let method = method.text().map_err(|_| invalid())?;
            let url = records.next().ok_or_else(invalid)?.map_err(|_| invalid())?;
            if url.tag != plane::PUSH_URL {
                return Err(invalid());
            }
            let url = url.text().map_err(|_| invalid())?;
            if method.is_empty() || url.is_empty() {
                return Err(invalid());
            }
            // Reply wipes its buffer on drop, including copied credential headers.
            let mut headers = Reply::new();
            let mut body = None;
            for rec in records {
                let rec = rec.map_err(|_| invalid())?;
                if body.is_some() {
                    return Err(invalid());
                }
                match rec.tag {
                    tag::PAIR => {
                        let (name, value) = rec.pair().map_err(|_| invalid())?;
                        headers
                            .put_pair(tag::PAIR, name, value)
                            .map_err(|_| invalid())?;
                    }
                    plane::BODY => body = Some(rec.body),
                    _ => return Err(invalid()),
                }
            }
            let body = body.ok_or_else(invalid)?;
            let answer = self
                .fetch
                .fetch(
                    who,
                    PlaneFetchRequest {
                        method,
                        url,
                        headers: Records::new(headers.as_bytes()),
                        body,
                        // The body is discarded after a bounded fetch; callback responses may contain
                        // a receipt, so an otherwise successful response is not limited to one byte.
                        max_body: super::MAX_PUSH as u64,
                        egress: egress::OPEN_WEB,
                    },
                )
                .await?;
            if (200..300).contains(&answer.status) {
                Ok(())
            } else {
                Err(PortError::Failed {
                    code: F_UPSTREAM,
                    text: "callback did not accept the delivery".into(),
                    retry_after_s: None,
                    backend_status: Some(u64::from(answer.status)),
                    error: None,
                })
            }
        })
    }
}
