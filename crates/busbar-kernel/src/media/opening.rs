// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A dial's opening (IF §12.13, round 27): nested PAIR* records, `media` = <kind> lines then `channel` =
//! <label> lines, ≥ 1. `mirror`, `media` and `channel` are core vocabulary (§15.8).

use crate::plugin_records::RecordsDenied;

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
        todo!()
    }

    /// Read an opening. Anything but PAIR records named `media` then `channel`, ≥ 1, each value a non-empty
    /// line with no control character (a `media` kind also no space) = `Invalid`.
    pub fn read(opening: &[u8]) -> Result<Lines, RecordsDenied> {
        let _ = opening;
        todo!()
    }

    /// The opening these lines state, as `dial` and `ConnInfo.head` carry it.
    pub fn write(&self) -> Result<Box<[u8]>, RecordsDenied> {
        todo!()
    }

    /// Whether `answered` mirrors these (offered) lines: the same count of media lines, the same kind at every
    /// position, and every offered channel. `Err` is the refusal text (today's `Bridge::mirrored`).
    pub fn mirrored_by(&self, answered: &Lines) -> Result<(), Box<str>> {
        let _ = answered;
        todo!()
    }
}

/// The UP_NEW(CARRIER_RTC) opening resolution (§12.13): exactly one `mirror` = <decimal n> and nothing else, or
/// lines that [`Lines::read`] would keep. Anything else = `Invalid` (the plane task's FAULT; nothing is dialled).
pub fn resolve<'a>(
    pairs: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> Result<DialOpening, RecordsDenied> {
    let _ = pairs.into_iter();
    todo!()
}
