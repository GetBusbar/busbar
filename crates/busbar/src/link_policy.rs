// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[must_use]
pub fn arguments(target: &str) -> &'static [&'static str] {
    if target.ends_with("-apple-darwin") {
        // Apple ld may only warn about duplicate definitions under dead stripping.
        // The kernel's root seal requires a duplicate definition to refuse the image.
        &["-Wl,-duplicate_symbols,error"]
    } else {
        &[]
    }
}
