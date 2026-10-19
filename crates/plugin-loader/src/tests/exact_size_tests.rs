// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE SIZE PER STRUCT, AT THE HOST (owner ruling 21 and THE DESIGN's R9): the loader and the
//! dispatcher accept exactly one v1 size for every struct a plugin hands them, and refuse any other
//! size, shorter or longer, with a declared code. A field a short struct lacks never reads as
//! "none". Each item of the sweep keeps its own REDs here.
