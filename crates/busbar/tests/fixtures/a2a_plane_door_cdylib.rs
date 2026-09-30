// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The a2a plane's door as a dropped-in `cdylib`: the one export, over the same function the
//! linked door is.

busbar_contract::export_door!(busbar_plane_a2a::plane_door::door);
