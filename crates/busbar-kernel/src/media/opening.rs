// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A dial's opening (IF §12.13, round 27): nested PAIR* records, `media` = <kind> lines then `channel` =
//! <label> lines, ≥ 1. `mirror`, `media` and `channel` are core vocabulary (§15.8).

use busbar_plugin_abi::records::{tag, Records, Reply, Writer};

use crate::plugin_records::RecordsDenied;

const MEDIA: &str = "media";
const CHANNEL: &str = "channel";
const MIRROR: &str = "mirror";

/// A leg's lines: media kinds in line order, then channel labels in the order they were opened.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Lines {
    pub media: Vec<Box<str>>,
    pub channels: Vec<Box<str>>,
}

/// What an UP_NEW(CARRIER_RTC) PAIR* names: the RV_ACCEPT bridge of client exchange `n` in this session
/// (its `opening()` is the dial's), or explicit lines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DialOpening {
    Mirror(u64),
    Lines(Lines),
}

impl Lines {
    /// No line and no channel.
    pub fn is_empty(&self) -> bool {
        self.media.is_empty() && self.channels.is_empty()
    }

    /// Read an opening. Anything but PAIR records named `media` then `channel`, ≥ 1, each value a non-empty
    /// line with no control character (a `media` kind also no space) = `Invalid`.
    pub fn read(opening: &[u8]) -> Result<Lines, RecordsDenied> {
        let mut lines = Lines::default();
        for rec in Records::new(opening) {
            let rec = rec.map_err(|_| RecordsDenied::Invalid)?;
            if rec.tag != tag::PAIR {
                return Err(RecordsDenied::Invalid);
            }
            let (name, value) = rec.pair().map_err(|_| RecordsDenied::Invalid)?;
            lines.push(name, value)?;
        }
        lines.stated()
    }

    /// The opening these lines state, as `dial` and `ConnInfo.head` carry it.
    pub fn write(&self) -> Result<Box<[u8]>, RecordsDenied> {
        let mut out = Reply::new();
        let named = self.media.iter().map(|m| (MEDIA, m));
        for (name, value) in named.chain(self.channels.iter().map(|c| (CHANNEL, c))) {
            out.put_pair(tag::PAIR, name, value.as_bytes())
                .map_err(|_| RecordsDenied::TooLarge)?;
        }
        Ok(out.as_bytes().into())
    }

    /// Whether `answered` mirrors these (offered) lines: the same count of media lines, the same kind at every
    /// position, and every offered channel. `Err` is the refusal text (today's `Bridge::mirrored`).
    pub fn mirrored_by(&self, answered: &Lines) -> Result<(), Box<str>> {
        if self.media.len() != answered.media.len() {
            return Err(lines_differ_in_count(
                answered.media.len(),
                self.media.len(),
            ));
        }
        let mut pairs = self.media.iter().zip(&answered.media).enumerate();
        if let Some((i, (offered, got))) = pairs.find(|(_, (a, b))| a != b) {
            return Err(line_kinds_differ(i, offered, got));
        }
        match self
            .channels
            .iter()
            .find(|c| !answered.channels.contains(c))
        {
            Some(label) => Err(channel_missing(label)),
            None => Ok(()),
        }
    }

    /// One PAIR line: `media` only before any `channel`, each a value [`line_value`] keeps.
    fn push(&mut self, name: &str, value: &[u8]) -> Result<(), RecordsDenied> {
        match name {
            MEDIA if self.channels.is_empty() => {
                let kind = line_value(value)?;
                if kind.contains(' ') {
                    return Err(RecordsDenied::Invalid);
                }
                self.media.push(kind.into());
            }
            CHANNEL => self.channels.push(line_value(value)?.into()),
            _ => return Err(RecordsDenied::Invalid),
        }
        Ok(())
    }

    /// ≥ 1 line or channel, else `Invalid`.
    fn stated(self) -> Result<Lines, RecordsDenied> {
        if self.is_empty() {
            return Err(RecordsDenied::Invalid);
        }
        Ok(self)
    }
}

/// A non-empty UTF-8 value with no control character: the transport writes it into its description, so a
/// line break here could state a line nobody asked for.
fn line_value(value: &[u8]) -> Result<&str, RecordsDenied> {
    match core::str::from_utf8(value) {
        Ok(text) if !text.is_empty() && !text.chars().any(char::is_control) => Ok(text),
        _ => Err(RecordsDenied::Invalid),
    }
}

/// The UP_NEW(CARRIER_RTC) opening resolution (§12.13): exactly one `mirror` = <decimal n> and nothing else, or
/// lines that [`Lines::read`] would keep. Anything else = `Invalid` (the plane task's FAULT; nothing is dialled).
pub fn resolve<'a>(
    pairs: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> Result<DialOpening, RecordsDenied> {
    let mut pairs = pairs.into_iter().peekable();
    if let Some(&(MIRROR, value)) = pairs.peek() {
        pairs.next();
        if pairs.next().is_some() || value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
            return Err(RecordsDenied::Invalid);
        }
        let n = core::str::from_utf8(value)
            .ok()
            .and_then(|n| n.parse().ok())
            .ok_or(RecordsDenied::Invalid)?;
        return Ok(DialOpening::Mirror(n));
    }
    let mut lines = Lines::default();
    for (name, value) in pairs {
        lines.push(name, value)?;
    }
    lines.stated().map(DialOpening::Lines)
}

/// `remote`'s refusal when the legs carry different counts of media lines (connector's text, kept).
#[cold]
fn lines_differ_in_count(upstream: usize, caller: usize) -> Box<str> {
    format!("the upstream leg carries {upstream} line(s), the caller's {caller}").into()
}

/// `remote`'s refusal when media line `i` is of a different kind on each leg (connector's text, kept).
#[cold]
fn line_kinds_differ(i: usize, caller: &str, upstream: &str) -> Box<str> {
    format!("line {i} is `{caller}` on the caller's leg and `{upstream}` upstream").into()
}

/// `remote`'s refusal when the answered leg lacks a channel the opening offered.
#[cold]
fn channel_missing(label: &str) -> Box<str> {
    format!("the upstream leg carries no channel `{label}`").into()
}
