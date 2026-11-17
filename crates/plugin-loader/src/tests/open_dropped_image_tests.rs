// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `open_dropped_image`: a test that drives a dropped image's raw tables opens it through the
//! loader's one `dlopen`, never its own (LINT-RULES LR-123), and gets the validated door held open.

use crate::dispatch::load::{open_dropped_image, LoadError};

#[test]
fn a_path_that_is_no_library_is_refused_as_an_open_error() {
    let path = std::env::temp_dir().join(format!(
        "busbar-open-dropped-image-{}-not-a-library",
        std::process::id()
    ));
    std::fs::write(&path, b"not a shared library").expect("the scratch file writes");
    let got = open_dropped_image(&path);
    let _ = std::fs::remove_file(&path);
    assert!(matches!(got, Err(LoadError::Open(_))), "{:?}", got.err());
}
