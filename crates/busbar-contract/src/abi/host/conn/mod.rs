// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTION TABLE: the connector table ([`connector`], `HostTables.conns`), the one table
//! through which a plugin of any kind establishes, reads and writes the streams its declared needs
//! allow. Its every `in` and `out` has exactly one size (owner ruling 21).

pub mod connector;
