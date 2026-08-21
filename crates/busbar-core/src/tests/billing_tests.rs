// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/billing.rs`.

use super::*;

#[test]
fn billing_variants_are_distinct() {
    assert_ne!(Billing::Flat, Billing::Characters { count: 0 });
    assert_ne!(
        Billing::Duration { seconds: 1.0 },
        Billing::Duration { seconds: 2.0 }
    );
}

/// A DEFAULT `TokenUsage` is the empty invoice: every countable tier is 0 and every optional
/// (cache / per-modality) field is absent. `tier_tokens` maps a `None` cache field to a 0 charge, so
/// a default that silently carried `Some(_)` or a non-zero `input` would bill a request that
/// consumed nothing. Pins the zero-origin the accounting path starts every accrual from.
#[test]
fn token_usage_default_is_the_empty_invoice() {
    let u = TokenUsage::default();
    assert_eq!((u.input, u.output), (0, 0));
    assert_eq!(u.cache_read, None);
    assert_eq!(u.cache_creation, None);
    assert_eq!(u.input_text, None);
    assert_eq!(u.input_audio, None);
    assert_eq!(u.input_image, None);
}

/// `Billing::Tokens` equality is sensitive to EACH separately-priced tier: two token bills that
/// differ only in `cache_creation` (the rate card's most expensive tier) are NOT equal, and neither
/// are ones differing only in `cache_read` or `output`. Guards against a future change that would
/// let two differently-priced usages compare equal (e.g. a hand-written `PartialEq` that dropped a
/// field), which would let one usage record stand in for another at a different price.
#[test]
fn tokens_equality_distinguishes_each_priced_tier() {
    let base = TokenUsage {
        input: 100,
        output: 200,
        cache_read: Some(10),
        cache_creation: Some(20),
        ..Default::default()
    };
    let mut diff_creation = base.clone();
    diff_creation.cache_creation = Some(21);
    assert_ne!(
        Billing::Tokens(base.clone()),
        Billing::Tokens(diff_creation),
        "a different cache_creation (cache_write tier) is a different bill"
    );
    let mut diff_read = base.clone();
    diff_read.cache_read = Some(11);
    assert_ne!(Billing::Tokens(base.clone()), Billing::Tokens(diff_read));
    let mut diff_output = base.clone();
    diff_output.output = 201;
    assert_ne!(Billing::Tokens(base), Billing::Tokens(diff_output));
}

/// `Billing::Images` equality tracks size AND quality, not just count — the tiers dall-e/Titan price
/// by. Two 1-image bills at different sizes (or qualities) are different bills; equal fields compare
/// equal. Pins that the price-determining attributes participate in identity.
#[test]
fn images_equality_tracks_size_and_quality() {
    let mk = |size: Option<&str>, quality: Option<&str>| Billing::Images {
        count: 1,
        size: size.map(str::to_string),
        quality: quality.map(str::to_string),
    };
    assert_eq!(
        mk(Some("1024x1024"), Some("hd")),
        mk(Some("1024x1024"), Some("hd"))
    );
    assert_ne!(
        mk(Some("1024x1024"), Some("hd")),
        mk(Some("512x512"), Some("hd")),
        "a different size is a different (tiered) price"
    );
    assert_ne!(
        mk(Some("1024x1024"), Some("hd")),
        mk(Some("1024x1024"), Some("standard")),
        "a different quality is a different price"
    );
}
