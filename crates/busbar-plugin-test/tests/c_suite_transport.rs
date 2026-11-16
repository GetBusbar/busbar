// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `suites::transport` end to end (ABI-MIN3-INTERFACE §14): a `plugin!`-built client framer admitted through
//! `admit_header` and driven through the registry. A ROLE_CLIENT stream opens only on core's `emit(E_HEAD)` on
//! stream 0 (IF §8.7), so a client case's scripted input counts streams only after the suite sends that head.

use busbar_plugin_abi::transport::ROLE_CLIENT;
use busbar_plugin_test::suites::{self, TransportCase};

use crate::min3_transport::PLUGIN;

/// The answer a dial reads: the head of the response, no body.
const ANSWER: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";

#[test]
fn a_client_case_opens_its_stream_through_e_head() {
    suites::transport(
        PLUGIN.plugin(),
        b"{}",
        &[TransportCase {
            role: ROLE_CLIENT,
            alpn: "http/1.1",
            input: &[ANSWER],
            expect_streams: 1,
        }],
    );
}
