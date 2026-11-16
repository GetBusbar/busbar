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

/// A message grew past [`MAX_MESSAGE`] before it ended.
#[derive(Debug, PartialEq, Eq)]
pub struct Overlong;

/// Splits a byte stream into messages.
#[derive(Debug)]
pub struct Framer {
    framing: Framing,
    /// Bytes of the line in progress.
    line: Vec<u8>,
    /// SSE: the event in progress.
    name: Vec<u8>,
    data: Vec<u8>,
    has_data: bool,
}

impl Framer {
    #[must_use]
    pub fn new(framing: Framing) -> Self {
        Self {
            framing,
            line: Vec::new(),
            name: Vec::new(),
            data: Vec::new(),
            has_data: false,
        }
    }

    /// The messages `bytes` completes, in order.
    ///
    /// # Errors
    /// A message is longer than [`MAX_MESSAGE`].
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Box<[u8]>>, Overlong> {
        let mut out = Vec::new();
        match self.framing {
            Framing::None => {
                if bytes.len() > MAX_MESSAGE {
                    return Err(Overlong);
                }
                if !bytes.is_empty() {
                    out.push(bytes.into());
                }
            }
            Framing::Ndjson | Framing::Sse => {
                for &byte in bytes {
                    if byte != b'\n' {
                        self.line.push(byte);
                        if self.line.len() > MAX_MESSAGE {
                            return Err(Overlong);
                        }
                        continue;
                    }
                    let mut line = std::mem::take(&mut self.line);
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    match self.framing {
                        Framing::Ndjson => {
                            if !line.iter().all(u8::is_ascii_whitespace) {
                                out.push(line.into());
                            }
                        }
                        _ => {
                            if let Some(message) = self.sse_line(&line)? {
                                out.push(message);
                            }
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    /// The stream ended: the last NDJSON line that had no terminator is a message; an event that was not ended by a
    /// blank line is not.
    #[must_use]
    pub fn finish(&mut self) -> Option<Box<[u8]>> {
        let line = std::mem::take(&mut self.line);
        match self.framing {
            Framing::Ndjson if !line.iter().all(u8::is_ascii_whitespace) => Some(line.into()),
            _ => None,
        }
    }

    fn sse_line(&mut self, line: &[u8]) -> Result<Option<Box<[u8]>>, Overlong> {
        if line.is_empty() {
            return Ok(self.dispatch());
        }
        if line[0] == b':' {
            return Ok(None);
        }
        let (field, value) = match line.iter().position(|b| *b == b':') {
            Some(at) => {
                let value = &line[at + 1..];
                (&line[..at], value.strip_prefix(b" ").unwrap_or(value))
            }
            None => (line, &[][..]),
        };
        match field {
            b"data" => {
                if self.has_data {
                    self.data.push(b'\n');
                }
                self.has_data = true;
                self.data.extend_from_slice(value);
                if self.data.len() > MAX_MESSAGE {
                    return Err(Overlong);
                }
            }
            b"event" => {
                self.name.clear();
                self.name.extend_from_slice(value);
            }
            _ => {}
        }
        Ok(None)
    }

    fn dispatch(&mut self) -> Option<Box<[u8]>> {
        let name = std::mem::take(&mut self.name);
        let data = std::mem::take(&mut self.data);
        let had = std::mem::take(&mut self.has_data);
        if !had {
            return None;
        }
        if name.is_empty() || name == b"message" {
            return Some(data.into());
        }
        let mut message = b"event: ".to_vec();
        message.extend_from_slice(&name);
        message.extend_from_slice(b"\ndata: ");
        message.extend_from_slice(&data);
        Some(message.into())
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
