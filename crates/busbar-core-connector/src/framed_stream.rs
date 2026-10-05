// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE STREAM, FRAMED BY ITS CLAIM'S FRAMER (ARCHITECT 4l, 2026-10-05).
//!
//! One listener port carries the streams of every claim, so the host's own framer keeps the
//! connection and each stream's head, and a stream whose claim another framer answers is framed
//! by that framer alone, stream by stream ([`SIDE_ACCEPT_STREAM`]): its body bytes go in and come
//! back as messages, the unit's messages go in and come back as body bytes, and its close (a
//! refusal, or the final status the unit stated) comes back as the stream's closing field block,
//! which the host sends verbatim. The host renders nothing of the claim's wire and names no
//! transport: which framer frames a stream is the claim the stream resolved to.

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::transport::{StatusRow, SIDE_ACCEPT_STREAM};

use crate::framer::{Established, FramerDoor, Framing, Refused, Yielded};

/// The one stream a [`SIDE_ACCEPT_STREAM`] framing carries.
pub const STREAM: u64 = 1;

/// Field lines: `(name, value)`, in order.
pub type FieldLines = Vec<(Vec<u8>, Vec<u8>)>;

/// One accepted stream, framed by the framer that answers its claim.
pub struct FramedStream {
    framing: Framing,
    claim: u32,
    rows: Vec<StatusRow>,
    partial: Vec<u8>,
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
    /// them) on `claim`, a claim `door` answers.
    ///
    /// # Errors
    ///
    /// `door` does not answer `claim`, or its framer refused the stream.
    pub fn open(
        door: Arc<dyn FramerDoor>,
        claim: &str,
        target: &str,
        head: &[(String, Vec<u8>)],
    ) -> Result<Self, Refused> {
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
            ..Established::default()
        };
        let (framing, _) =
            Framing::begin_with(door, SIDE_ACCEPT_STREAM, target, &established, head)?;
        Ok(Self {
            framing,
            claim: index,
            rows,
            partial: Vec::new(),
        })
    }

    /// The stream's body bytes (`end` = its last); the messages they complete, in order.
    ///
    /// # Errors
    ///
    /// The framer failed the stream (its bytes are no message of the claim's).
    pub fn ingest(&mut self, body: &[u8], end: bool) -> Result<Vec<Vec<u8>>, Refused> {
        let y = self.framing.ingest(body, end)?;
        let mut messages = Vec::new();
        for piece in y.pieces {
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
    ///
    /// # Errors
    ///
    /// The framer refused them.
    pub fn emit(&mut self, message: &[u8], ends: bool) -> Result<Vec<u8>, Refused> {
        self.framing
            .emit(STREAM, message, ends, false)
            .map(|y| y.wire)
    }

    /// End the stream refused: `bytes` and the refusal's neutral `status`; the closing field block.
    ///
    /// # Errors
    ///
    /// The framer refused to render it, or its block is no field lines.
    pub fn refuse(&mut self, bytes: &[u8], status: u32) -> Result<FieldLines, Refused> {
        let y = self.framing.refuse(Some(STREAM), bytes, status)?;
        closing(&y)
    }

    /// End the stream with the final status the unit stated (`status` in the claim's numbering,
    /// its message and details, each empty where none); the closing field block.
    ///
    /// # Errors
    ///
    /// The status is not the claim's ([`Framing::finish_final`]: nothing crossed), or the framer
    /// refused it.
    pub fn finish(
        &mut self,
        status: u32,
        message: &[u8],
        details: &[u8],
    ) -> Result<FieldLines, Refused> {
        let y = self
            .framing
            .finish_final(status, message, details, &self.rows, self.claim)?;
        closing(&y)
    }
}

/// The closing field block an answer wrote, read as field lines.
fn closing(y: &Yielded) -> Result<FieldLines, Refused> {
    field_lines(&y.wire)
}

/// FIELD LINES (`name: value` CRLF each, a blank line or the end closing them), read in order. A
/// name may be a pseudo-field's (`:status`), as the data listener's own wire states its head's.
///
/// # Errors
///
/// A line with no name, or no `:`.
pub fn field_lines(block: &[u8]) -> Result<FieldLines, Refused> {
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
