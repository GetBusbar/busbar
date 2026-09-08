// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CONFIG VALUE SHAPES that sit BELOW the neutral substrate — the serde grammar for blocks whose
//! CONSUMER is not the substrate but a crate the substrate does not depend on.
//!
//! `busbar_substrate::config` is where the config grammar's pure shapes live, and it is the right
//! home for every block the engine itself reads. The `plugins:` block is the exception: its
//! consumers are `busbar-plugin-sign` (the trust policy) and `busbar-plugin-loader` (the fetch
//! list), and neither is in the substrate's dependency closure — nor should the substrate be in
//! theirs. Declaring the shapes HERE, in the PURE half, lets the loader read them without an edge
//! to the whole engine substrate, while `busbar_substrate::config::plugins` re-exports them so the
//! grammar still has ONE address to an operator and to `cargo xtask gate config-schema`.

pub mod plugins;
