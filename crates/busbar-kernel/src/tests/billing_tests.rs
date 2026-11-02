// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::billing::{Billing, TokenUsage};

#[test]
fn billing_variants_are_distinct() {
    assert_ne!(Billing::Flat, Billing::Characters { count: 0 });
    assert_ne!(
        Billing::Duration {
            seconds: busbar_contract::Count::parse("1").expect("exact")
        },
        Billing::Duration {
            seconds: busbar_contract::Count::parse("2").expect("exact")
        }
    );
}

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
