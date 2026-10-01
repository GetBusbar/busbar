// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OPENAI RESPONSES' FLAT FIELDS, AS DATA. Each row is one wire member and the IR slot it carries;
//! `codec::carry` is the only code that walks them. No logic lives here.

use crate::codec::carry::{Codec, Dir, Field, Slot, Table, Word};

/// The Responses-only rows: `text.verbosity` (IR-07), beside the `text.format` the dialect writes
/// from `response_format`.
const RESPONSES: &[Field] = &[(&["text", "verbosity"], Slot::Verbosity, Codec::Plain)];

/// Every Responses flat request field: the members Chat spells alike, then its own.
pub(super) const FIELDS: Table = &[crate::codec::openai_chat::fields::OPENAI_FAMILY, RESPONSES];

/// The response `service_tier` (the tier that SERVED the answer, RSP-17) ↔ the IR attribution word
/// (the Anthropic vocabulary). Only `default` (IS `standard`) and `priority` are read: `flex` /
/// `scale` have no word in that vocabulary and `auto` is a request instruction, not a served tier.
/// The OpenAI-family words are written as-is so a tier that arrived in that vocabulary is not lost.
pub(super) const SERVED_TIER: &[Word] = &[
    ("default", "standard", Dir::Both),
    ("default", "default", Dir::Write),
    ("priority", "priority", Dir::Both),
    ("flex", "flex", Dir::Write),
    ("scale", "scale", Dir::Write),
];
