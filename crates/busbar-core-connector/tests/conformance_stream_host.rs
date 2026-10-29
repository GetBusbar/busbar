// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The test kit's suite host in its stream form (`busbar_test_kit::conformance_host!` with no
//! doors), as a plugin whose needs are plain streams states it: the stream table's TLS upgrade, the
//! connector's own client TLS, trusts the suite's test anchors, and is refused with them withheld
//! (RED).

busbar_test_kit::conformance_host! { far_end: "localhost:47392" }
