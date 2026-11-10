// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Deterministic SDK crossing witness: opaque batches, supplied fields and a modeled connector.
//! No exporter format, product configuration or external output is implemented here.
use busbar_contract::abi::export::{self, CheckIn, CheckOut, DeliverIn, ExportStream, Tail};
use busbar_contract::abi::host::conn::connector::{Need, DIRECTION_OUTBOUND, EGRESS_OPEN_WEB};
use busbar_contract::abi::mechanism::call::{OutHead, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::exchange::{exchange, Exchange, Request};
use busbar_contract::abi::sdk::export::{NoScrape, NoServe, Quiet};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::plugin::markers::ExportKind;
use std::sync::RwLock;
use std::task::Poll;

pub const NAME: &str = "neutral-export-witness";
pub const STREAMS: &[u8] = &[ExportStream::Logs as u8, ExportStream::Traces as u8];
const TAIL: Tail = busbar_contract::abi::sdk::export::tail(STREAMS, &[]);
const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: EGRESS_OPEN_WEB,
    transport: abi_str("http"),
    target_from: abi_str("settings.target"),
    ..Need::EMPTY
}];
const DIAGS: &[busbar_contract::abi::mechanism::call::AbiStr] = &[abi_str("BUSBAR-9901")];
const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),
    diag_ids: DIAGS.as_ptr(),
    diag_ids_len: DIAGS.len(),
    ..statement(NAME, "1.6.0", u32::MAX)
};

fn settings(bytes: &[u8]) -> Result<serde_json::Value, Refusal> {
    let value = busbar_contract::abi::sdk::life::settings_value(bytes)?;
    if value.get("bogus").is_some() || value.get("value").is_some_and(|v| !v.is_string()) {
        return Err(Refusal::refused("settings: witness refused"));
    }
    Ok(value)
}
pub struct Witness(RwLock<serde_json::Value>);
impl Life for Witness {
    type Kind = ExportKind;
    const CANCEL: u32 = export::cancel::ABORTED;
    fn validate(bytes: &[u8]) -> Result<(), Refusal> {
        settings(bytes).map(|_| ())
    }
    fn open(bytes: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self(RwLock::new(settings(bytes)?)))
    }
    fn refresh(&self, bytes: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        *self.0.write().unwrap() = settings(bytes)?;
        Ok(Refreshed::default())
    }
}
struct Pending {
    settings: serde_json::Value,
    offset: usize,
    issued: u32,
    exchange: Option<Exchange>,
}
pub struct Deliver;
impl SafeSlot for Deliver {
    type Kind = ExportKind;
    type In = DeliverIn;
    type Out = OutHead;
    type State = Held<Witness>;
    fn call(
        instance: Instance<'_, Self::State, ExportKind>,
        input: Lent<'_, DeliverIn>,
        mut out: Out<'_, OutHead>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        let Some(host) = held.host() else {
            return Outcome::Refused;
        };
        let mut at = instance
            .resume::<Pending>()
            .map(|p| *p)
            .unwrap_or_else(|| Pending {
                settings: held.life().0.read().unwrap().clone(),
                offset: 0,
                issued: 0,
                exchange: None,
            });
        let batch = input.field(|i| &i.batch).bytes();
        while at.offset < batch.len() {
            let end = batch[at.offset..]
                .iter()
                .position(|b| *b == b'\n')
                .map_or(batch.len(), |n| at.offset + n);
            if end == at.offset {
                at.offset += 1;
                continue;
            }
            let mut connector = host.connector_from(instance.ticket(), at.issued);
            let mut ex = at.exchange.take().unwrap_or_else(|| {
                let fields = at.settings["fields"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .enumerate()
                    .map(|(index, v)| {
                        let mut value = v[1].clone();
                        let credential = busbar_contract::abi::sdk::cred::Cred::take(&mut value)
                            .unwrap()
                            .require_secure_if(true);
                        (
                            index,
                            v[0].as_str().unwrap().as_bytes().to_vec(),
                            credential.field(),
                        )
                    })
                    .collect();
                let target = at.settings["target"].as_str().unwrap_or("");
                let path = target.split_once("://").map_or(target, |(_, rest)| rest);
                let path = path.find('/').map_or("/", |start| &path[start..]);
                Exchange::request_sealed(
                    Request {
                        method: b"POST".to_vec(),
                        target: path.as_bytes().to_vec(),
                        fields: vec![],
                        body: batch[at.offset..end].to_vec(),
                        timeout_ms: 600_000,
                    },
                    fields,
                )
                .unwrap()
                .head_only()
            });
            match exchange(&mut connector, &mut ex, 0, None) {
                Poll::Pending => {
                    at.exchange = Some(ex);
                    instance.park(at);
                    return Outcome::Pending;
                }
                Poll::Ready(result) => {
                    at.issued = connector.issued();
                    if result.is_err() {
                        out.diag(0, 1, "BUSBAR-9901 witness crossing refused");
                    }
                }
            }
            at.offset = end + 1;
        }
        Outcome::Ready
    }
}
pub struct Check;
impl SafeSlot for Check {
    type Kind = ExportKind;
    type In = CheckIn;
    type Out = CheckOut;
    type State = Held<Witness>;
    fn call(
        instance: Instance<'_, Self::State, ExportKind>,
        input: Lent<'_, CheckIn>,
        mut out: Out<'_, CheckOut>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        let mut findings = Vec::new();
        for item in input.instances().iter() {
            let settings: serde_json::Value =
                serde_json::from_slice(item.field(|i| &i.settings).bytes()).unwrap_or_default();
            let name = String::from_utf8_lossy(item.field(|i| &i.name).bytes()).into_owned();
            if let Some(case) = settings["case"].as_str() {
                findings.push(format!(
                    "export.{name}: witness {case} phase {}",
                    input.phase
                ));
            }
        }
        if !findings.is_empty() {
            out.lease(
                |o| &o.findings,
                held.leases(),
                serde_json::to_vec(&findings).unwrap(),
                BLOB_JSON,
            );
        }
        Outcome::Ready
    }
}
busbar_contract::plugin_door! {
    ops: busbar_contract::abi::export::Ops, statement: STATEMENT,
    lifecycle: life(Witness),
    kind_ops: { deliver: Safe<Deliver>, scrape: Safe<NoScrape<Witness>>, status: Safe<Quiet<Witness>>, check: Safe<Check>, serve: Safe<NoServe<Witness>> },
}
