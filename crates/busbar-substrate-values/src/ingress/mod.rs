// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The PURE half of the arrival doors: the values that cross them.
//!
//! A door binds, and a crate whose whole transitive closure is scanned may not name what binds.
//! What a door HANDS OVER, though, is plain data, and that half belongs on this side of the split.
//! `busbar-substrate` re-exports every module below at the path it has always had, so no reader
//! changes a spelling.

pub mod close_slot;
