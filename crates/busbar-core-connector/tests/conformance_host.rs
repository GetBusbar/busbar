// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The test kit's suite host connector (`busbar_test_kit::conformance_host!`), as a plugin repo
//! states it, over the stub tcp carrier: the host's TLS upgrade trusts the suite's test anchors,
//! and is refused with them withheld (RED).

busbar_test_kit::conformance_host! {
    far_end: "localhost:47391",
    doors: [("tcp", busbar_stub_transport_plugin::door::MACRO_DOOR)],
}
