// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The sealing of an opening's credential values (`crate::seal`), done once as an opening is sealed
//! (the seal lifecycle event), never per request byte: the sealed names and query pairs taken out
//! of an opening, the streams that wait on a seal, a stream's seals dropped and the spliced seals
//! let go of.

use busbar_contract::secure::SecureVec;
use foldhash::HashMap;

use crate::seal::Seal;

/// One seal on `stream` is no longer pending: its count drops, and a stream with none left is
/// forgotten.
fn released(counts: &mut HashMap<u64, usize>, stream: u64) {
    if let std::collections::hash_map::Entry::Occupied(mut held) = counts.entry(stream) {
        *held.get_mut() -= 1;
        if *held.get() == 0 {
            held.remove();
        }
    }
}

/// The names the opener's [`busbar_contract::conn::SEALED_FIELDS_FIELD`] states, taken out of
/// `fields` (the field itself is removed).
pub(crate) fn take_sealed_names(fields: &mut Vec<(String, Vec<u8>)>) -> Vec<String> {
    let mut names = Vec::new();
    fields.retain(|(n, v)| {
        if busbar_contract::conn::is_sealed_fields_field(n.as_bytes()) {
            names.extend(
                String::from_utf8_lossy(v)
                    .split(',')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty()),
            );
            false
        } else {
            true
        }
    });
    names
}

/// The host's query metadata fields taken out of `fields`, their values moved into secure buffers.
pub(crate) fn take_query_pairs(fields: &mut Vec<(String, Vec<u8>)>) -> Vec<SecureVec> {
    let mut pairs = Vec::new();
    fields.retain_mut(|(name, value)| {
        if busbar_contract::conn::is_sealed_query_field(name.as_bytes()) {
            pairs.push(SecureVec::from(std::mem::take(value)));
            false
        } else {
            true
        }
    });
    pairs
}

/// The streams `seals` has a seal waiting on, each once, in the order their first seal was held.
pub(crate) fn pending_streams(seals: &[Seal]) -> Vec<u64> {
    let mut streams = Vec::new();
    for seal in seals {
        if !streams.contains(&seal.stream) {
            streams.push(seal.stream);
        }
    }
    streams
}

/// Drop every seal held on `stream`.
pub(crate) fn drop_stream(seals: &mut Vec<Seal>, stream: u64) {
    seals.retain(|seal| seal.stream != stream);
}

/// Splice into `wire` every seal whose filler stood at a position in `positions` (one per seal, in
/// order), and let those seals go; a seal whose filler was not found stays.
pub(crate) fn splice_found(
    seals: &mut Vec<Seal>,
    positions: &[Option<usize>],
    wire: &mut [u8],
    counts: &mut HashMap<u64, usize>,
) {
    let mut at = positions.iter();
    seals.retain(|s| match at.next().copied().flatten() {
        Some(i) => {
            wire[i..i + s.filler.len()].copy_from_slice(&s.value);
            released(counts, s.stream);
            false
        }
        None => true,
    });
}
