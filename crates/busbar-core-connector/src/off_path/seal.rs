// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The sealing of an opening's credential values (`crate::seal`), done once as an opening is sealed
//! (the seal lifecycle event), never per request byte: the sealed names and query pairs taken out
//! of an opening and the streams that wait on a seal. Dropping a stream's seals and splicing are
//! `crate::seal`'s own: they empty slots the connection keeps.

use busbar_contract::secure::SecureVec;

use crate::seal::Seal;

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
