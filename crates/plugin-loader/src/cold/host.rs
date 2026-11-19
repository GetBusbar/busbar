// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold code of `crate::host`: the log-file rotation, run when a log file reaches its size cap.

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::path::Path;

use crate::host::FailedStep;


