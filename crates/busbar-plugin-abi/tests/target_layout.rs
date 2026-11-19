// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! #408 appends the selected descriptor admission bytes to the existing Target prefix.
//!
//! Since the one call shape (core 3.0, interface revision C.3) a view crosses field by field through the
//! positional codec, not as a C struct: the prefix is the view's wire order (`call.rs`), so an image built
//! before #408 reads every field it knows from the front of each call field and never sees `admission`.

#![forbid(unsafe_code)]

use busbar_plugin_abi::call::{Packer, Put};
use busbar_plugin_abi::plane::Target;
use busbar_plugin_abi::types::{Bytes, Slice, Str};

#[test]
fn target_keeps_its_prefix_and_appends_one_admission_view() {
    let target = Target {
        attempt: 7,
        flags: 9,
        dialect: Str::new("dialect"),
        model: Str::new("model"),
        base_path: Str::new("/base"),
        upstream: Str::new("upstream"),
        provider: Str::new("{}"),
        params: Slice::EMPTY,
        admission: Bytes::new(b"admission"),
    };
    let mut packer = Packer::new();
    (&target).put(&mut packer);
    assert!(packer.fits());
    // attempt and flags in head; five texts; params, then admission appended last in blobs.
    assert_eq!(packer.counts(), (8, 5, 2));
    packer.with(0, |call| {
        assert_eq!(&call.head()[..4], &7u32.to_le_bytes());
        assert_eq!(&call.head()[4..8], &9u32.to_le_bytes());
        let texts: Vec<&str> = call.texts().iter().map(|text| text.get()).collect();
        assert_eq!(texts, ["dialect", "model", "/base", "upstream", "{}"]);
        assert_eq!(call.blobs()[0].len(), 0, "params: no pairs");
        assert_eq!(call.blobs()[1].get(), b"admission");
    });
}
