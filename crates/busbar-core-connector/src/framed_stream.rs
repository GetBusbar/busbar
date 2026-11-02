// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE STREAM, FRAMED BY ITS CLAIM'S FRAMER.

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::transport::{StatusRow, SIDE_ACCEPT_STREAM};

use crate::compose::HeadWords;
use crate::framer::{AuthBinding, Established, FramerDoor, Framing, Refused, Yielded};

/// The one stream a [`SIDE_ACCEPT_STREAM`] framing carries.
pub const STREAM: u64 = 1;

/// One accepted stream, framed by the framer that answers its claim.
pub struct FramedStream {
    framing: Framing,
    claim: u32,
    rows: Vec<StatusRow>,
    partial: Vec<u8>,
    opening: Vec<HeadWords>,
}

impl std::fmt::Debug for FramedStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FramedStream")
            .field("claim", &self.claim)
            .finish_non_exhaustive()
    }
}

fn fault(error: impl Into<String>) -> Refused {
    Refused {
        outcome: Outcome::Fault,
        error: error.into(),
    }
}

impl FramedStream {
    /// Open the stream that arrived at `target` with `head` (its head fields, as the caller sent

    pub fn open(
        door: Arc<dyn FramerDoor>,
        claim: &str,
        target: &str,
        head: &[(String, Vec<u8>)],
        scheme: u8,
    ) -> Result<Self, Refused> {
        Self::open_bound(door, claim, target, head, &AuthBinding::NONE, scheme)
    }

    /// [`FramedStream::open`] over `binding`. A stream is framed TICKET-LESS, so a binding with

    pub fn open_bound(
        door: Arc<dyn FramerDoor>,
        claim: &str,
        target: &str,
        head: &[(String, Vec<u8>)],
        binding: &AuthBinding,
        scheme: u8,
    ) -> Result<Self, Refused> {
        binding.ticket_less()?;
        let facts = door.facts();
        let index = facts
            .claims
            .iter()
            .position(|c| *c == claim)
            .and_then(|i| u32::try_from(i).ok())
            .ok_or_else(|| fault(format!("`{}` does not answer `{claim}`", facts.name)))?;
        let rows = facts
            .status_rows
            .iter()
            .map(|&(claim, lo, hi)| StatusRow {
                claim,
                lo,
                hi,
                class: 0,
            })
            .collect();
        let established = Established {
            claim: Some(claim.to_string()),
            scheme,
            ..Established::default()
        };
        let (framing, opened) = Framing::begin_ticketless(
            door,
            SIDE_ACCEPT_STREAM,
            target,
            &established,
            head,
            binding,
        )?;
        let opening = opening_fields(&opened.wire)?;
        Ok(Self {
            framing,
            claim: index,
            rows,
            partial: Vec::new(),
            opening,
        })
    }

    /// Initial response fields supplied by the stream's framer at Begin, before any body or

    #[must_use]
    pub fn opening_fields(&self) -> &[HeadWords] {
        &self.opening
    }

    /// The stream's body bytes (`end` = its last); the messages they complete, in order.

    pub fn ingest(&mut self, body: &[u8], end: bool) -> Result<Vec<Vec<u8>>, Refused> {
        let mut y = self.framing.ingest(body, end)?;
        let mut messages = Vec::new();
        for piece in std::mem::take(&mut y.pieces) {
            if piece.failed {
                return Err(Refused {
                    outcome: Outcome::Failed,
                    error: String::from_utf8_lossy(&piece.bytes).into_owned(),
                });
            }
            if piece.fields {
                continue;
            }
            self.partial.extend_from_slice(&piece.bytes);
            if piece.end_of_frame {
                messages.push(std::mem::take(&mut self.partial));
            }
        }
        Ok(messages)
    }

    /// One reply message's bytes (`ends` = they complete it); the stream's body bytes.

    pub fn emit(&mut self, message: &[u8], ends: bool) -> Result<Vec<u8>, Refused> {
        self.framing
            .emit(STREAM, message, ends, false)
            .map(|mut y| std::mem::take(&mut y.wire))
    }

    /// End the stream refused: `bytes` and the refusal's neutral `status`; the closing field block.

    pub fn refuse(
        &mut self,
        bytes: &[u8],
        status: u32,
        head_sent: bool,
    ) -> Result<Vec<HeadWords>, Refused> {
        let y = self
            .framing
            .refuse(Some(STREAM), bytes, status, head_sent)?;
        closing(&y)
    }

    /// End the stream with the final status the unit stated (`status` in the claim's numbering,

    pub fn finish(
        &mut self,
        status: u32,
        message: &[u8],
        details: &[u8],
    ) -> Result<Vec<HeadWords>, Refused> {
        let y = self
            .framing
            .finish_final(status, message, details, &self.rows, self.claim)?;
        closing(&y)
    }
}

/// An initial field block must be wholly parsed and carry only valid ordinary field names and

fn opening_fields(block: &[u8]) -> Result<Vec<HeadWords>, Refused> {
    use busbar_contract::abi::transport::fields;
    let mut read = 0;
    let mut out = Vec::new();
    for (name, value) in fields::lines(block) {
        if name.is_empty()
            || !name
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
            || value.iter().any(|b| *b < b' ' && *b != b'\t' || *b == 0x7f)
        {
            return Err(fault(
                "the opening field block has an invalid name or value",
            ));
        }
        read += name.len() + fields::SEPARATOR.len() + value.len() + fields::LINE_END.len();
        out.push((name.to_vec(), value.to_vec()));
    }
    if read != block.len() {
        return Err(fault(
            "the opening field block has an incomplete or malformed line",
        ));
    }
    Ok(out)
}

/// The closing field block an answer wrote, read as field lines.
fn closing(y: &Yielded) -> Result<Vec<HeadWords>, Refused> {
    field_lines(&y.wire)
}

/// FIELD LINES (`name: value` CRLF each, a blank line or the end closing them), read in order. A

pub fn field_lines(block: &[u8]) -> Result<Vec<HeadWords>, Refused> {
    let mut out = Vec::new();
    for line in block.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let pseudo = usize::from(line.first() == Some(&b':'));
        let colon = line[pseudo..]
            .iter()
            .position(|b| *b == b':')
            .map(|c| c + pseudo)
            .ok_or_else(|| fault("the closing field block has a line with no `:`"))?;
        let (name, value) = line.split_at(colon);
        if name.len() == pseudo || name.iter().any(|b| b.is_ascii_whitespace()) {
            return Err(fault("the closing field block has a line with no name"));
        }
        let value = &value[1..];
        let start = value
            .iter()
            .position(|b| *b != b' ' && *b != b'\t')
            .unwrap_or(value.len());
        let end = value
            .iter()
            .rposition(|b| *b != b' ' && *b != b'\t')
            .map_or(start, |e| e + 1);
        out.push((name.to_vec(), value[start..end.max(start)].to_vec()));
    }
    Ok(out)
}

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/framed_stream_tests.rs"]
mod tests;
