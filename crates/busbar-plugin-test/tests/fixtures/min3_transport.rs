// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A MIN-3 transport fixture written the real way (ABI-MIN3-INTERFACE §8.7): the `Transport` trait, `Open` and
//! one `plugin!` line. A client-only framer shaped like transport-ws's dial: `begin` writes nothing, and the only
//! way a stream opens is core's `emit(E_HEAD)` on stream 0, answered with STREAM_OPENED(1) and the request bytes.
//! Bytes read before or after the head open nothing. It refuses an E_HEAD that carries no H_AUTHORITY, as a
//! dialled framer does, so the suite must hand it a real head. No `unsafe`: the glue is `plugin!`'s output only.

use busbar_plugin_abi::fail::{failed, refused, Fail};
use busbar_plugin_abi::host::Host;
use busbar_plugin_abi::need::ChainBytes;
use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
use busbar_plugin_abi::records::{tag as head_tag, Out, Records, Writer};
use busbar_plugin_abi::transport::{self as tp, tag, ConnInfo, StreamFlow};
use busbar_plugin_abi::types::Bytes;
use busbar_plugin_abi::Transport;

/// The dial framer: no settings.
pub struct Dial;

/// One dialled conn: whether its one stream is open.
pub struct DialSession {
    opened: bool,
}

impl Open for Dial {
    async fn open(_h: &'static Host, _config: ChainBytes) -> Result<Self, Fail> {
        Ok(Dial)
    }

    fn check(_h: &Host, _config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
        Ok(())
    }

    fn describe(d: &mut Describe<'_>) {
        d.methods(tp::M_BEGIN | tp::M_INGEST | tp::M_EMIT | tp::M_OFFER)
            .facts(tp::FB_CLIENT)
            .schema(r#"{"type":"object"}"#);
    }
}

fn full<T>(_: T) -> Fail {
    Fail::failed(failed::F_LIMIT)
}

impl Transport for Dial {
    type Session = DialSession;

    fn begin(
        &self,
        _h: &Host,
        conn: &ConnInfo<'_>,
        _out: &mut Out<'_>,
    ) -> Result<DialSession, Fail> {
        if conn.role != tp::ROLE_CLIENT {
            return Err(Fail::refused_because(
                refused::R_UNSUPPORTED,
                "fixture: a dial framer begins client conns only",
            ));
        }
        Ok(DialSession { opened: false })
    }

    fn ingest(
        &self,
        _h: &Host,
        _s: &mut DialSession,
        _bytes: Bytes<'_>,
        _out: &mut Out<'_>,
    ) -> Result<(), Fail> {
        Ok(())
    }

    fn emit(
        &self,
        _h: &Host,
        s: &mut DialSession,
        stream: u64,
        piece: u32,
        _arg: u32,
        bytes: Bytes<'_>,
        out: &mut Out<'_>,
    ) -> Result<(), Fail> {
        if piece != tp::E_HEAD || stream != 0 {
            return Ok(());
        }
        if s.opened {
            return Err(Fail::refused_because(
                refused::R_INVALID,
                "fixture: a dialled conn opens one stream",
            ));
        }
        let authority = Records::new(bytes.get())
            .filter_map(Result::ok)
            .find(|rec| rec.tag == head_tag::H_AUTHORITY)
            .and_then(|rec| rec.text().ok())
            .filter(|text| !text.is_empty())
            .ok_or_else(|| {
                Fail::refused_because(refused::R_INVALID, "fixture: the head names no authority")
            })?;
        s.opened = true;
        out.put_pod(tag::STREAM_OPENED, &StreamFlow { stream: 1 })
            .map_err(full)?;
        let request = format!("GET / HTTP/1.1\r\nhost: {authority}\r\n\r\n");
        out.put(tag::WRITE, request.as_bytes()).map_err(full)
    }

    fn offer(&self, _h: &Host, role: u32, out: &mut Out<'_>) -> Result<(), Fail> {
        match role {
            tp::ROLE_CLIENT => out.put_text(tag::ALPN, "http/1.1").map_err(full),
            tp::ROLE_SERVER => Ok(()),
            _ => Err(Fail::refused(refused::R_UNSUPPORTED)),
        }
    }
}

busbar_plugin_abi::plugin!(Transport, Dial, name: "fixture-transport-dial");
