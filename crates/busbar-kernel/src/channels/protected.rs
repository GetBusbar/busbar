// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Guarded storage for an authorized protected inspection. These owners enforce capacity and
//! destruction order; the native session still checks admission, whole-answer grammar and lease
//! incarnation before committing. Constructing storage does not establish those authorities.

use std::io;
use std::ops::Range;

use busbar_contract::secure::SecureVec;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::budget::{CapacityDenied, Charge, Claim, LinkBudget, UnitBudget, REPLY_BYTES};
use super::frame::MAX_MESSAGE;

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
        })
    }
}

/// One owned native reply, moved into the bounded writer. Never cloned into an encoded frame.
pub struct GuardedWrite {
    bytes: SecureVec,
    _payload: Charge,
    _outbound: Charge,
}

impl GuardedWrite {
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Retains byte/message custody while blocked, through payload, delimiter and flush. Dropping
    /// an interrupted future wipes its backing before its account shares are returned.
    pub async fn write_ndjson<W: AsyncWrite + Unpin>(self, writer: &mut W) -> io::Result<()> {
        writer.write_all(self.bytes.as_slice()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await
    }
}
