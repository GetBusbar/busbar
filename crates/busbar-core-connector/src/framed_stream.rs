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

/// A stream framer's closing head. Status is producer metadata, never a parsed field.
#[derive(Debug, Default)]
pub struct Closing {
    /// The producer's numeric code, when a closing head carries one.
    pub status: Option<u32>,
    /// The exact declared numbering of the producer's code.
    pub status_namespace: Option<Arc<str>>,
    /// Opaque closing fields in producer order.
    pub fields: Vec<HeadWords>,
}

/// One accepted stream, framed by the framer that answers its claim.
pub struct FramedStream {
    framing: Framing,
    claim: u32,
    rows: Vec<StatusRow>,
    partial: Vec<u8>,
    opening: Vec<HeadWords>,
    deadline_ns: Option<u64>,
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
        Self::open_bound_kind(door, claim, target, head, binding, scheme, false)
    }

    /// Open a stream over the transport field grammar without interpreting field names as HTTP.
    pub fn open_neutral(
        door: Arc<dyn FramerDoor>,
        claim: &str,
        target: &str,
        head: &[(String, Vec<u8>)],
        scheme: u8,
    ) -> Result<Self, Refused> {
        Self::open_bound_kind(door, claim, target, head, &AuthBinding::NONE, scheme, true)
    }

    #[allow(clippy::too_many_arguments)]
    fn open_bound_kind(
        door: Arc<dyn FramerDoor>,
        claim: &str,
        target: &str,
        head: &[(String, Vec<u8>)],
        binding: &AuthBinding,
        scheme: u8,
        neutral: bool,
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
        let opening = if neutral {
            neutral_opening_fields(&opened.wire)?
        } else {
            opening_fields(&opened.wire)?
        };
        let mut stream = Self {
            framing,
            claim: index,
            rows,
            partial: Vec::new(),
            opening,
            deadline_ns: opened.deadline_ns,
        };
        stream.observe(&opened)?;
        Ok(stream)
    }

    /// Initial response fields supplied by the stream's framer at Begin, before any body or
    #[must_use]
    pub fn opening_fields(&self) -> &[HeadWords] {
        &self.opening
    }

    /// The next host-clock instant at which this stream's framer must be called.
    #[must_use]
    pub fn deadline(&self) -> Option<std::time::Instant> {
        self.deadline_ns.map(crate::framer::instant_of)
    }

    /// Drive the requested timer, retaining its next deadline and terminal stream failure.
    pub fn timer(&mut self) -> Result<(), Refused> {
        let yielded = self.framing.timer()?;
        self.observe(&yielded)
    }

    fn observe(&mut self, yielded: &Yielded) -> Result<(), Refused> {
        self.deadline_ns = yielded.deadline_ns;
        if let Some(piece) = yielded.pieces.iter().find(|piece| piece.failed) {
            return Err(Refused {
                outcome: Outcome::Failed,
                error: String::from_utf8_lossy(&piece.bytes).into_owned(),
            });
        }
        Ok(())
    }

    /// The stream's body bytes (`end` = its last); the messages they complete, in order.
    pub fn ingest(&mut self, body: &[u8], end: bool) -> Result<Vec<Vec<u8>>, Refused> {
        let mut y = self.framing.ingest(body, end)?;
        self.observe(&y)?;
        let mut messages = Vec::new();
        for piece in std::mem::take(&mut y.pieces) {
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
        let mut yielded = self.framing.emit(STREAM, message, ends, false)?;
        self.observe(&yielded)?;
        Ok(std::mem::take(&mut yielded.wire))
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

    /// Close normally when no final claim code was stated; the producer owns its normal ending.
    pub fn close_response(self) -> Result<Closing, Refused> {
        closing_response(
            &self
                .framing
                .finish(busbar_contract::abi::transport::CLOSE_NORMAL),
        )
    }

    /// Refuse the stream, retaining the producer's code and numbering separately from fields.
    pub fn refuse_response(
        &mut self,
        bytes: &[u8],
        status: u32,
        head_sent: bool,
    ) -> Result<Closing, Refused> {
        let yielded = self
            .framing
            .refuse(Some(STREAM), bytes, status, head_sent)?;
        closing_response(&yielded)
    }

    /// Finish the stream with a claim-native final code and retain its closing metadata.
    pub fn finish_response(
        &mut self,
        status: u32,
        message: &[u8],
        details: &[u8],
    ) -> Result<Closing, Refused> {
        let yielded = self
            .framing
            .finish_final(status, message, details, &self.rows, self.claim)?;
        closing_response(&yielded)
    }
}

fn closing_response(yielded: &Yielded) -> Result<Closing, Refused> {
    let mut closing = Closing {
        fields: neutral_opening_fields(&yielded.wire)?,
        ..Closing::default()
    };
    for piece in &yielded.pieces {
        if piece.fields {
            if let Some(status) = piece.status_code {
                if closing.status.replace(status).is_some() {
                    return Err(fault("the closing head states its status more than once"));
                }
                closing.status_namespace.clone_from(&piece.status_namespace);
            }
        }
    }
    Ok(closing)
}

/// The compatibility operator adapter validates ordinary HTTP field names and values.
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

/// A transport field block must be complete; field names and values belong to its producer.
fn neutral_opening_fields(block: &[u8]) -> Result<Vec<HeadWords>, Refused> {
    use busbar_contract::abi::transport::fields;
    let mut read = 0;
    let mut out = Vec::new();
    for (name, value) in fields::lines(block) {
        if name.is_empty() {
            return Err(fault("the opening field block has an empty name"));
        }
        read += name.len() + fields::SEPARATOR.len() + value.len() + fields::LINE_END.len();
        out.push((name.to_vec(), value.to_vec()));
    }
    if read != block.len() {
        return Err(fault("the opening field block is incomplete"));
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
