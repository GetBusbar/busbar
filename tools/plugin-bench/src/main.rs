// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `busbar-plugin-bench --plugin target/release/libX.so --kind store`: a dropped-in cdylib.
//! A plugin repo that links its door uses `busbar_plugin_bench::bench_main!(its_crate::door)`.

busbar_plugin_bench::bench_main!();
