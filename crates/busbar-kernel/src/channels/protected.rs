// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Guarded storage for an authorized protected inspection. These owners enforce capacity and
//! destruction order; the native session still checks admission, whole-answer grammar and lease
//! incarnation before committing. Constructing storage does not establish those authorities.

use std::io;
use std::ops::Range;

use busbar_contract::secure::SecureVec;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::budget::{
    CapacityDenied, Charge, Claim, InstanceBudget, LinkBudget, UnitBudget, REPLY_BYTES,
};
use super::frame::{Framing, MAX_MESSAGE};

pub const OUTPUT_BYTES: usize = MAX_MESSAGE + 24;

pub struct ReplyStorage {
    // Rust drops fields in declaration order: storage is wiped/freed before its charge.
    output: SecureVec,
    charge: Charge,
    unit: UnitBudget,
}

impl ReplyStorage {
    pub fn new(unit: &UnitBudget) -> Result<Self, CapacityDenied> {
        let charge = unit.reserve_reply(
            Claim {
                bytes: REPLY_BYTES,
                completions: 1,
                ..Claim::default()
            },
            None,
        )?;
        Ok(Self {
            output: SecureVec::zeroed(OUTPUT_BYTES),
            charge,
            unit: unit.clone(),
        })
    }

    pub fn output(&self) -> &[u8] {
        self.output.as_slice()
    }

    /// Lend to the FFI fixed output loan. The caller cannot grow or replace this backing.
    pub fn output_mut(&mut self) -> &mut [u8] {
        &mut self.output
    }

    /// A fully validated general answer keeps its entire fixed backing charged while the caller
    /// admits every effect. Reclassification failure consumes/discards it without publication.
    pub fn into_general(mut self) -> Result<GeneralStorage, CapacityDenied> {
        // The maximum writer-copy allowance is unused on this path. Retire only that unused
        // entitlement, never the live output allocation or callback completion cell.
        let unused = self.charge.claim().bytes - self.output.len();
        drop(self.charge.split(Claim {
            bytes: unused,
            ..Claim::default()
        })?);
        self.charge.reclassify_general()?;
        Ok(GeneralStorage {
            output: self.output,
            _charge: self.charge,
        })
    }

    /// Consume the validated single reply's payload range. No backing escapes before its full
    /// writer capacity is reserved. The session must check the actual target lease beforehand.
    pub fn into_write(
        mut self,
        payload: Range<usize>,
        link: &LinkBudget,
    ) -> Result<GuardedWrite, CapacityDenied> {
        let bytes = self.output.as_slice().get(payload).ok_or(CapacityDenied)?;
        if bytes.len() > MAX_MESSAGE {
            return Err(CapacityDenied);
        }
        let retained = bytes.len().checked_add(1).ok_or(CapacityDenied)?;
        let outbound = self.unit.reserve_reply(
            Claim {
                outbound_bytes: retained,
                messages: 1,
                ..Claim::default()
            },
            Some(link),
        )?;
        let charge = self.charge.split(Claim {
            bytes: retained,
            ..Claim::default()
        })?;
        let mut writer = SecureVec::zeroed(bytes.len());
        writer.copy_from_slice(bytes);
        // `self` then destroys fixed output before returning its remaining staging/completion share.
        Ok(GuardedWrite {
            bytes: writer,
            _payload: charge,
            _outbound: outbound,
            ask: None,
            link: link.clone(),
            framing: Framing::Ndjson,
        })
    }
}

/// Validated general callback storage. Capacity is not permission to apply any of its effects.
pub struct GeneralStorage {
    output: SecureVec,
    _charge: Charge,
}

impl GeneralStorage {
    pub fn output(&self) -> &[u8] {
        self.output.as_slice()
    }
}

/// One owned native reply, moved into the bounded writer. Never cloned into an encoded frame.
pub struct GuardedWrite {
    bytes: SecureVec,
    _payload: Charge,
    _outbound: Charge,
    ask: Option<Charge>,
    link: LinkBudget,
    framing: Framing,
}

impl GuardedWrite {
    /// The already validated sessionless DEMUX fallback, bounded by its source-owned 4096-byte limit.
    /// This private control path cannot be selected by ordinary sends or protected replies.
    pub(super) fn fallback(
        instance: &InstanceBudget,
        link: &LinkBudget,
        framing: Framing,
        bytes: &[u8],
    ) -> Result<Self, CapacityDenied> {
        let wire = Self::wire_len(framing, bytes)?;
        let (payload, outbound) = instance.reserve_fallback(link, bytes.len(), wire)?;
        let mut owned = SecureVec::zeroed(bytes.len());
        owned.copy_from_slice(bytes);
        Ok(Self {
            bytes: owned,
            _payload: payload,
            _outbound: outbound,
            ask: None,
            link: link.clone(),
            framing,
        })
    }

    fn wire_len(framing: Framing, bytes: &[u8]) -> Result<usize, CapacityDenied> {
        match framing {
            Framing::None => Ok(bytes.len()),
            Framing::Ndjson => bytes.len().checked_add(1).ok_or(CapacityDenied),
            Framing::Sse => bytes
                .split(|b| *b == b'\n')
                .try_fold(1usize, |len, line| {
                    len.checked_add(line.len())?.checked_add(7)
                })
                .ok_or(CapacityDenied),
        }
    }
    /// Admit a general message before its only payload copy. The ask cell is separate from the
    /// writer payload so write completion cannot prematurely release an outstanding ask.
    pub fn new(
        unit: &UnitBudget,
        link: &LinkBudget,
        framing: Framing,
        bytes: &[u8],
        ask: bool,
    ) -> Result<Self, CapacityDenied> {
        if bytes.len() > MAX_MESSAGE {
            return Err(CapacityDenied);
        }
        let wire_bytes = Self::wire_len(framing, bytes)?;
        let payload = unit.reserve(
            Claim {
                bytes: bytes.len().checked_add(1).ok_or(CapacityDenied)?,
                ..Claim::default()
            },
            None,
        )?;
        let outbound = unit.reserve(
            Claim {
                outbound_bytes: wire_bytes,
                messages: 1,
                ..Claim::default()
            },
            Some(link),
        )?;
        let ask = if ask {
            Some(unit.reserve(
                Claim {
                    asks: 1,
                    ..Claim::default()
                },
                Some(link),
            )?)
        } else {
            None
        };
        let mut owned = SecureVec::zeroed(bytes.len());
        owned.copy_from_slice(bytes);
        Ok(Self {
            bytes: owned,
            _payload: payload,
            _outbound: outbound,
            ask,
            link: link.clone(),
            framing,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub(super) fn destination(&self, link: &LinkBudget, framing: Framing) -> bool {
        self.link.same_link(link) && self.framing == framing
    }

    pub(super) fn take_ask(&mut self) -> Option<Charge> {
        self.ask.take()
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Retains byte/message custody while blocked, through payload, delimiter and flush. Dropping
    /// an interrupted future wipes its backing before its account shares are returned.
    pub async fn write_ndjson<W: AsyncWrite + Unpin>(self, writer: &mut W) -> io::Result<()> {
        if self.framing != Framing::Ndjson {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "channel framing mismatch",
            ));
        }
        self.write(writer).await
    }

    /// Writes every supported framing directly from the charged backing, without an encoded copy.
    pub async fn write<W: AsyncWrite + Unpin>(self, writer: &mut W) -> io::Result<()> {
        match self.framing {
            Framing::None => writer.write_all(self.bytes.as_slice()).await?,
            Framing::Ndjson => {
                writer.write_all(self.bytes.as_slice()).await?;
                writer.write_all(b"\n").await?;
            }
            Framing::Sse => {
                for line in self.bytes.as_slice().split(|b| *b == b'\n') {
                    writer.write_all(b"data: ").await?;
                    writer.write_all(line).await?;
                    writer.write_all(b"\n").await?;
                }
                writer.write_all(b"\n").await?;
            }
        }
        writer.flush().await
    }
}
