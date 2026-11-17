// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{configured_framer, DataFramer, FramerFor};

pub const DATA_SCHEME: &str = "http";

pub fn data_framer(framer_for: FramerFor) -> Option<DataFramer> {
    // The fixture listener owns an unlimited process admission, as boot shares one in production.
    configured_framer(framer_for, DATA_SCHEME, None).map(|framer| {
        framer.with_process_admission(
            busbar_kernel::limits::process_admission::ProcessAdmission::new(0),
        )
    })
}
