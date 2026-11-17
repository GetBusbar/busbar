// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! #408 appends the selected descriptor admission bytes to the existing Target prefix.

#![forbid(unsafe_code)]

use core::mem::{align_of, offset_of, size_of};

use busbar_plugin_abi::plane::Target;
use busbar_plugin_abi::types::{Bytes, Pair, Slice, Str};

#[test]
fn target_keeps_its_prefix_and_appends_one_admission_view() {
    let text = size_of::<Str<'static>>();
    let pairs = size_of::<Slice<'static, Pair<'static>>>();
    let bytes = size_of::<Bytes<'static>>();

    assert_eq!(offset_of!(Target<'static>, attempt), 0);
    assert_eq!(offset_of!(Target<'static>, flags), 4);
    assert_eq!(offset_of!(Target<'static>, dialect), 8);
    assert_eq!(offset_of!(Target<'static>, model), 8 + text);
    assert_eq!(offset_of!(Target<'static>, base_path), 8 + 2 * text);
    assert_eq!(offset_of!(Target<'static>, upstream), 8 + 3 * text);
    assert_eq!(offset_of!(Target<'static>, provider), 8 + 4 * text);
    assert_eq!(offset_of!(Target<'static>, params), 8 + 5 * text);
    assert_eq!(offset_of!(Target<'static>, admission), 8 + 5 * text + pairs);
    assert_eq!(size_of::<Target<'static>>(), 8 + 5 * text + pairs + bytes);
    assert_eq!(align_of::<Target<'static>>(), align_of::<Bytes<'static>>());
}
