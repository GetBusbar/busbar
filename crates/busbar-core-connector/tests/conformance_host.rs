// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The test kit's suite host connector in its framed form (`busbar_test_kit::conformance_host!`

busbar_test_kit::conformance_host! {
    far_end: "localhost:47391",
    doors: [("tcp", busbar_stub_transport_plugin::door::MACRO_DOOR)],
}
