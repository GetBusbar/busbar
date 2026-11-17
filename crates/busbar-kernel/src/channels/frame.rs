// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Framing of a channel's byte stream (IF §8.6 `CH_FRAME_*`, §12.19): core splits what a child writes (or a held
//! request streams) into messages before the plane's `demux` sees them, and frames what core writes the same way.
//!
//! * `CH_FRAME_NONE`: each read is one message; a write is the message as it is.
//! * `CH_FRAME_NDJSON`: one message per `\n`-terminated line (a trailing `\r` is dropped, a blank line is nothing); a
//!   write is the message and one `\n`.
//! * `CH_FRAME_SSE`: one message per Server-Sent Event (WHATWG: `data:` lines joined by `\n`, a blank line ends the
//!   event, `:` comments, `id:` and `retry:` ignored). An event with no `event:` name, or the name `message`, is its
//!   data; any other named event is `event: <name>\ndata: <data>` so the plane can tell it apart (the legacy MCP
//!   `endpoint` event). A write is `data:` lines and a blank line.

use busbar_plugin_abi::plane::{CH_FRAME_NDJSON, CH_FRAME_NONE, CH_FRAME_SSE};

/// The longest message core buffers before it gives the channel up: a stream that never ends a line or an event is
/// not a protocol this driver can serve.
pub const MAX_MESSAGE: usize = 4 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    None,
    Ndjson,
    Sse,
}

impl Framing {
    /// The framing a `CH_FRAME_*` code names; `None` for a code this core does not know.
    #[must_use]
    pub fn of(code: u32) -> Option<Self> {
        match code {
            CH_FRAME_NONE => Some(Self::None),
            CH_FRAME_NDJSON => Some(Self::Ndjson),
            CH_FRAME_SSE => Some(Self::Sse),
            _ => None,
        }
    }
}

/// A message exceeded its bound or its original account could not fund framing storage.
#[derive(Debug, PartialEq, Eq)]
pub struct Overlong;

/// Splits a byte stream while retaining the original general storage owner through every frame.
pub struct Framer {
    framing: Framing,
    source: busbar_contract::storage::StorageSource,
    line: crate::limits::output::OutputBuffer,
    name: crate::limits::output::OutputBuffer,
    data: crate::limits::output::OutputBuffer,
    has_data: bool,
}

impl Framer {
    pub fn new(
        framing: Framing,
        source: busbar_contract::storage::StorageSource,
    ) -> Result<Self, Overlong> {
        use crate::limits::output::OutputBuffer;
        Ok(Self {
            framing,
            line: OutputBuffer::with_source(&source, 0).map_err(|_| Overlong)?,
            name: OutputBuffer::with_source(&source, 0).map_err(|_| Overlong)?,
            data: OutputBuffer::with_source(&source, 0).map_err(|_| Overlong)?,
            source,
            has_data: false,
        })
    }

    /// Consume at most one completed message. The caller retains the charged read backing while
    /// delivering it; there is no uncharged intermediate vector of completed frame descriptors.
    pub fn feed(&mut self, bytes: &mut &[u8]) -> Result<Option<bytes::Bytes>, Overlong> {
        use crate::limits::output::OutputBuffer;
        if self.framing == Framing::None {
            if bytes.len() > MAX_MESSAGE {
                return Err(Overlong);
            }
            if bytes.is_empty() {
                return Ok(None);
            }
            let mut out =
                OutputBuffer::with_source(&self.source, bytes.len()).map_err(|_| Overlong)?;
            out.write_bytes(bytes).map_err(|_| Overlong)?;
            *bytes = &[];
            return out.into_bytes().map(Some).map_err(|_| Overlong);
        }
        while !bytes.is_empty() {
            let end = bytes
                .iter()
                .position(|byte| *byte == b'\n')
                .unwrap_or(bytes.len());
            if self
                .line
                .as_ref()
                .len()
                .checked_add(end)
                .is_none_or(|len| len > MAX_MESSAGE)
            {
                return Err(Overlong);
            }
            self.line.write_bytes(&bytes[..end]).map_err(|_| Overlong)?;
            *bytes = &bytes[end..];
            if bytes.is_empty() {
                return Ok(None);
            }
            *bytes = &bytes[1..];
            let fresh = OutputBuffer::with_source(&self.source, 0).map_err(|_| Overlong)?;
            let mut line = std::mem::replace(&mut self.line, fresh);
            if line.as_ref().last() == Some(&b'\r') {
                line.truncate(line.as_ref().len() - 1);
            }
            if self.framing == Framing::Ndjson {
                if !line.as_ref().iter().all(u8::is_ascii_whitespace) {
                    return line.into_bytes().map(Some).map_err(|_| Overlong);
                }
            } else if let Some(message) = self.sse_line(line.as_ref())? {
                return Ok(Some(message));
            }
        }
        Ok(None)
    }

    /// Test convenience over the same streaming parser; production never collects uncharged frames.
    #[cfg(test)]
    pub fn push(&mut self, mut bytes: &[u8]) -> Result<Vec<bytes::Bytes>, Overlong> {
        let mut out = Vec::new();
        while let Some(message) = self.feed(&mut bytes)? {
            out.push(message);
        }
        Ok(out)
    }

    /// An unterminated NDJSON line is a final message; an incomplete SSE event is not.
    pub fn finish(&mut self) -> Result<Option<bytes::Bytes>, Overlong> {
        use crate::limits::output::OutputBuffer;
        let fresh = OutputBuffer::with_source(&self.source, 0).map_err(|_| Overlong)?;
        let line = std::mem::replace(&mut self.line, fresh);
        if self.framing == Framing::Ndjson && !line.as_ref().iter().all(u8::is_ascii_whitespace) {
            line.into_bytes().map(Some).map_err(|_| Overlong)
        } else {
            Ok(None)
        }
    }

    fn sse_line(&mut self, line: &[u8]) -> Result<Option<bytes::Bytes>, Overlong> {
        if line.is_empty() {
            return self.dispatch();
        }
        if line[0] == b':' {
            return Ok(None);
        }
        let (field, value) = match line.iter().position(|byte| *byte == b':') {
            Some(at) => {
                let value = &line[at + 1..];
                (&line[..at], value.strip_prefix(b" ").unwrap_or(value))
            }
            None => (line, &[][..]),
        };
        match field {
            b"data" => {
                let needed = self
                    .data
                    .as_ref()
                    .len()
                    .checked_add(usize::from(self.has_data))
                    .and_then(|len| len.checked_add(value.len()))
                    .ok_or(Overlong)?;
                if needed > MAX_MESSAGE {
                    return Err(Overlong);
                }
                if self.has_data {
                    self.data.write_bytes(b"\n").map_err(|_| Overlong)?;
                }
                self.has_data = true;
                self.data.write_bytes(value).map_err(|_| Overlong)?;
            }
            b"event" => {
                self.name.clear();
                self.name.write_bytes(value).map_err(|_| Overlong)?;
            }
            _ => {}
        }
        Ok(None)
    }

    fn dispatch(&mut self) -> Result<Option<bytes::Bytes>, Overlong> {
        use crate::limits::output::OutputBuffer;
        let name = std::mem::replace(
            &mut self.name,
            OutputBuffer::with_source(&self.source, 0).map_err(|_| Overlong)?,
        );
        let data = std::mem::replace(
            &mut self.data,
            OutputBuffer::with_source(&self.source, 0).map_err(|_| Overlong)?,
        );
        if !std::mem::take(&mut self.has_data) {
            return Ok(None);
        }
        if name.as_ref().is_empty() || name.as_ref() == b"message" {
            return data.into_bytes().map(Some).map_err(|_| Overlong);
        }
        let len = name
            .as_ref()
            .len()
            .checked_add(data.as_ref().len())
            .and_then(|len| len.checked_add(14))
            .ok_or(Overlong)?;
        if len > MAX_MESSAGE {
            return Err(Overlong);
        }
        let mut message = OutputBuffer::with_source(&self.source, len).map_err(|_| Overlong)?;
        for bytes in [
            b"event: ".as_slice(),
            name.as_ref(),
            b"\ndata: ".as_slice(),
            data.as_ref(),
        ] {
            message.write_bytes(bytes).map_err(|_| Overlong)?;
        }
        message.into_bytes().map(Some).map_err(|_| Overlong)
    }
}

/// `message` as the bytes core writes to the channel.
#[must_use]
pub fn frame(framing: Framing, message: &[u8]) -> Vec<u8> {
    match framing {
        Framing::None => message.to_vec(),
        Framing::Ndjson => {
            let mut out = Vec::with_capacity(message.len() + 1);
            out.extend_from_slice(message);
            out.push(b'\n');
            out
        }
        Framing::Sse => {
            let mut out = Vec::with_capacity(message.len() + 8);
            for line in message.split(|b| *b == b'\n') {
                out.extend_from_slice(b"data: ");
                out.extend_from_slice(line);
                out.push(b'\n');
            }
            out.push(b'\n');
            out
        }
    }
}
