// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-MSG-FLAGS (ABI-MIN3-INTERFACE §14): Transport STREAM_BODY / `emit(E_BODY)` carry MSG_TEXT/MSG_BINARY/MSG_FIN
//! through a fragmented message.
//!
//! The arm runs in plugin-loader, beside the transport adapter's private answer decode (not pub to this crate,
//! and not widened for a test, SDK-SAFE-TEST-HOST), so it moved to the owner's crate (WBS rule 10):
//!
//! - TEST-VALUE `message_flags_cross_a_fragmented_message`:
//!   `busbar_plugin_loader::adapters::transport::tests::message_flags_cross_a_fragmented_message` (three
//!   MSG_TEXT pieces ending MSG_FIN, then a MSG_BINARY|MSG_FIN one, cross `emit(E_BODY)` with their flags
//!   whole; MSG_FIN alone, TEXT|BINARY and an unknown bit are GRAMMAR).
