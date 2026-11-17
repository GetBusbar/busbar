// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Post-handler HTTP output enters the native session through funded canonical records.

use std::pin::Pin;
use std::sync::Arc;

use axum::body::Body;
use axum::http::HeaderMap;
use axum::response::Response;
use busbar_contract::storage::StorageSource;
use busbar_core_connector::framed_stream::session::{Payload, Piece};
use busbar_kernel::inbound::native::PhysicalAdminExecution;
use busbar_plugin_abi::records::{record_size, tag, PairRec, U32Rec, Writer};
use busbar_plugin_abi::transport::{E_BODY, E_HEAD, E_TRAILERS};
use bytes::{Buf, Bytes};
use http_body::Body as _;

use super::{add, InputError, PLAINTEXT_WINDOW};

fn quote_records(status: Option<u16>, fields: &HeaderMap) -> Result<usize, InputError> {
    let mut extent = if status.is_some() {
        record_size(std::mem::size_of::<U32Rec>()).ok_or(InputError::Capacity)?
    } else {
        0
    };
    for (name, value) in fields {
        let size = add(
            add(std::mem::size_of::<PairRec>(), name.as_str().len())?,
            value.as_bytes().len(),
        )?;
        // The canonical wire length is u32, independent of host usize width.
        u32::try_from(size).map_err(|_| InputError::Capacity)?;
        extent = add(extent, record_size(size).ok_or(InputError::Capacity)?)?;
    }
    if extent > PLAINTEXT_WINDOW {
        return Err(InputError::Capacity);
    }
    Ok(extent)
}

fn encode_records(
    source: &StorageSource,
    status: Option<u16>,
    fields: &HeaderMap,
) -> Result<Payload, InputError> {
    let extent = quote_records(status, fields)?;
    Payload::encode(source, extent, |writer| {
        if let Some(status) = status {
            writer.put_pod(
                tag::H_STATUS,
                &U32Rec {
                    value: u32::from(status),
                },
            )?;
        }
        for (name, value) in fields {
            writer.put_pair(tag::PAIR, name.as_str(), value.as_bytes())?;
        }
        Ok(())
    })
    .map_err(|_| InputError::Capacity)
}

/// This producer yields only actual final head/body/trailers. Its caller records each submitted
/// piece in the admission-bound final plan. Only observed body EOF permits freezing that plan;
/// E_END/E_REFUSE and audit release belong to the supervised finalizer, never to Body::Drop.
pub(super) struct ResponsePieces {
    head: Option<Payload>,
    body: Body,
    pending: Bytes,
    source: StorageSource,
    admin: Option<Arc<PhysicalAdminExecution>>,
    status: u16,
    trailers_seen: bool,
    eof: bool,
    failed: bool,
}

impl ResponsePieces {
    pub(super) fn new(response: Response, source: StorageSource) -> Result<Self, InputError> {
        let (mut parts, body) = response.into_parts();
        let status = parts.status.as_u16();
        let head = encode_records(&source, Some(status), &parts.headers)?;
        let admin = parts.extensions.remove::<Arc<PhysicalAdminExecution>>();
        Ok(Self {
            head: Some(head),
            body,
            pending: Bytes::new(),
            source,
            admin,
            status,
            trailers_seen: false,
            eof: false,
            failed: false,
        })
    }

    pub(super) fn status(&self) -> u16 {
        self.status
    }
    pub(super) fn eof(&self) -> bool {
        self.eof
    }

    /// Transfer the actual handler's final physical authority to the response's terminal owner.
    pub(super) fn take_admin(&mut self) -> Option<Arc<PhysicalAdminExecution>> {
        self.admin.take()
    }

    pub(super) async fn next(&mut self) -> Result<Option<Piece>, InputError> {
        if self.failed {
            return Err(InputError::Invalid);
        }
        let result = self.next_inner().await;
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    async fn next_inner(&mut self) -> Result<Option<Piece>, InputError> {
        if let Some(bytes) = self.head.take() {
            return Ok(Some(Piece {
                piece: E_HEAD,
                arg: 0,
                bytes,
            }));
        }
        loop {
            if !self.pending.is_empty() {
                let count = self.pending.len().min(PLAINTEXT_WINDOW);
                let bytes = Payload::copy(&self.source, &self.pending[..count])
                    .map_err(|_| InputError::Capacity)?;
                self.pending.advance(count);
                return Ok(Some(Piece {
                    piece: E_BODY,
                    arg: 0,
                    bytes,
                }));
            }
            if self.eof {
                return Ok(None);
            }
            let Some(frame) =
                std::future::poll_fn(|cx| Pin::new(&mut self.body).poll_frame(cx)).await
            else {
                self.eof = true;
                return Ok(None);
            };
            let frame = frame.map_err(InputError::Body)?;
            match frame.into_data() {
                Ok(bytes) => {
                    if self.trailers_seen {
                        return Err(InputError::Invalid);
                    }
                    self.pending = bytes;
                }
                Err(frame) => {
                    let fields = frame.into_trailers().map_err(|_| InputError::Invalid)?;
                    if self.trailers_seen {
                        return Err(InputError::Invalid);
                    }
                    self.trailers_seen = true;
                    let bytes = encode_records(&self.source, None, &fields)?;
                    return Ok(Some(Piece {
                        piece: E_TRAILERS,
                        arg: 0,
                        bytes,
                    }));
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/listener_native_response.rs"]
mod tests;
