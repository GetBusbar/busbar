// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// A valid shared object with no memory-ABI door. The loader must name the missing symbol.
#[unsafe(no_mangle)]
pub extern "C" fn unrelated_symbol() {}
