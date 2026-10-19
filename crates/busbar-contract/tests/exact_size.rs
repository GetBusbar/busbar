// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE SIZE PER STRUCT (owner ruling 21 and THE DESIGN's R9): every ABI struct has exactly one v1
//! size, and any other size, shorter or longer, is refused with a declared code. No older or
//! shorter size is published or accepted, and a field a short struct lacks never reads as "none".
//! Each item of the sweep keeps its own REDs here: a short size (and a long one) refused.
