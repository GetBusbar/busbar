// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OPENAI CHAT'S FLAT FIELDS, AS DATA. Each row is one wire member and the IR slot it carries;
//! `codec::carry` is the only code that walks them. No logic lives here.

use crate::codec::carry::{Codec, Dir, Field, Slot, Table, Word};

/// The Q57 request members Chat and Responses spell alike (ir-slots-landed.md IR-03..06).
pub(crate) const OPENAI_FAMILY: &[Field] = &[
    (&["metadata"], Slot::Metadata, Codec::Plain),
    (&["service_tier"], Slot::ServiceTier, Codec::Plain),
    (&["store"], Slot::Store, Codec::Plain),
    (&["safety_identifier"], Slot::SafetyIdentifier, Codec::Plain),
    (&["prompt_cache_key"], Slot::PromptCacheKey, Codec::Plain),
];

/// The Chat-only rows: `verbosity` (IR-07), `modalities` (IR-19: `audio` needs the `audio` member,
/// a named hook) and `web_search_options` (IR-11: one hosted search, a named hook).
const CHAT: &[Field] = &[
    (&["verbosity"], Slot::Verbosity, Codec::Plain),
    (
        &["modalities"],
        Slot::OutputModalities,
        Codec::Hook(super::slots::read_modalities, super::slots::write_modalities),
    ),
    (
        &["web_search_options"],
        Slot::WebSearch,
        Codec::Hook(super::slots::read_web_search, super::slots::write_web_search),
    ),
];

/// Every Chat flat request field.
pub(super) const FIELDS: Table = &[OPENAI_FAMILY, CHAT];

/// The response `service_tier` (the tier that SERVED the answer, OAI-03) ↔ the IR attribution word
/// (the Anthropic vocabulary: `default` IS `standard`). `flex` / `scale` keep the IR tier word.
pub(crate) const SERVED_TIER: &[Word] = &[
    ("default", "standard", Dir::Both),
    ("default", "default", Dir::Write),
    ("priority", "priority", Dir::Both),
    ("flex", "flex", Dir::Both),
    ("scale", "scale", Dir::Both),
];
