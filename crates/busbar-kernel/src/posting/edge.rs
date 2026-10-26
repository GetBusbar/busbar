// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! VALIDATION AT THE EDGE (MONEY-DESIGN §3b, §7 item 4): every id that becomes a store row key is
//! checked where it is minted or configured, never when it is posted, so a cell that could poison a
//! batch is refused by name and never queued.
//!
//! - a composed bucket id (`group:<name>@<window>#<kind>:<value>`, or a key id) is at most
//!   [`MAX_BUCKET_ID`] ASCII bytes, the narrowest store column (mysql `VARCHAR(128)`), and never
//!   begins `e:`, the sibling era row's namespace;
//! - a model (lane) name is at most [`MAX_MODEL`] bytes, so the sibling row's pseudo-model
//!   `"<24hex>\u{1f}<model>"` fits `VARCHAR(256)`;
//! - a provider name is at most [`MAX_PROVIDER`] bytes, so the metering row's prefixed provider
//!   `"<24hex>\u{1f}<provider>"` fits `VARCHAR(128)`.

/// The longest bucket id a store column holds.
pub const MAX_BUCKET_ID: usize = 128;

/// The longest model (lane) name: 256 less the 25-byte entry-id prefix and its separator.
pub const MAX_MODEL: usize = 230;

/// The longest provider name: 128 less the 25-byte entry-id prefix and its separator.
pub const MAX_PROVIDER: usize = 103;

/// The sibling era rows' namespace: no key or group bucket may begin with it.
pub const SIBLING_PREFIX: &str = "e:";

/// The longest window word a bucket id carries (`minute`).
pub const LONGEST_WINDOW: &str = "minute";

/// Why `id` cannot be a bucket id, or `None` when it can.
#[must_use]
pub fn bucket_id_refusal(id: &str) -> Option<String> {
    if !id.is_ascii() {
        return Some(format!(
            "bucket id `{id}` is not ASCII; store bucket columns hold ASCII only"
        ));
    }
    if id.len() > MAX_BUCKET_ID {
        return Some(format!(
            "bucket id `{id}` is {} bytes; the store's bucket column holds at most {MAX_BUCKET_ID}",
            id.len()
        ));
    }
    if id.starts_with(SIBLING_PREFIX) {
        return Some(format!(
            "bucket id `{id}` begins `{SIBLING_PREFIX}`, the namespace of the per-entry era rows"
        ));
    }
    None
}

/// Why `model` cannot be priced and recorded, or `None` when it can.
#[must_use]
pub fn model_refusal(model: &str) -> Option<String> {
    (model.len() > MAX_MODEL).then(|| {
        format!(
            "model `{model}` is {} bytes; at most {MAX_MODEL} fit the store's model column with \
             the card-entry prefix",
            model.len()
        )
    })
}

/// Why `provider` cannot be metered, or `None` when it can.
#[must_use]
pub fn provider_refusal(provider: &str) -> Option<String> {
    (provider.len() > MAX_PROVIDER).then(|| {
        format!(
            "provider `{provider}` is {} bytes; at most {MAX_PROVIDER} fit the store's provider \
             column with the card-entry prefix",
            provider.len()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_edge_refuses_by_name_what_a_store_column_cannot_hold() {
        assert!(bucket_id_refusal("group:team@day").is_none());
        // `group:` (6) + name + `@minute` (7): 115 bytes of name is exactly 128.
        assert!(bucket_id_refusal(&format!("group:{}@minute", "a".repeat(116))).is_some());
        assert!(bucket_id_refusal(&format!("group:{}@minute", "a".repeat(115))).is_none());
        assert!(bucket_id_refusal("group:é@day").is_some());
        assert!(bucket_id_refusal("e:abc").is_some());
        assert!(model_refusal(&"m".repeat(MAX_MODEL)).is_none());
        assert!(model_refusal(&"m".repeat(MAX_MODEL + 1)).is_some());
        assert!(provider_refusal(&"p".repeat(MAX_PROVIDER)).is_none());
        assert!(provider_refusal(&"p".repeat(MAX_PROVIDER + 1)).is_some());
    }
}
