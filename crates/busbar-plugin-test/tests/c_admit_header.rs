// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ADMIT-HEADER (UNSAFE-MIN §2.2 A1; IF §14): the suite harness admits from the `&'static Plugin` the frozen
//! suite signatures take, with no `LinkedPlugin` conversion (and so no `unsafe` cast in busbar-ffi). The header
//! path runs the same null and stamp checks as `admit_linked` and lands on the same header.

use busbar_ffi::image::Admitted;
use busbar_plugin_loader::admit::{admit_header, admit_linked};

use crate::bridge_fixture::{header, linked};

/// `Admitted::from_header` names the very header `Admitted::linked` names for the same image.
#[test]
fn a_static_header_admits_to_the_header_the_linked_static_admits_to() {
    let by_header = Admitted::from_header(header()).expect("the fixture header admits");
    let by_linked = Admitted::linked(linked()).expect("the fixture image admits");
    assert!(
        std::ptr::eq(by_header.header(), by_linked.header()),
        "one image, one header"
    );
    assert!(by_header.null_field().is_none());
}

/// The loader's header path agrees with its linked path: admitted together, or refused together.
#[test]
fn the_loader_admits_a_static_header_exactly_as_it_admits_the_linked_static() {
    let by_header = admit_header(header());
    let by_linked = admit_linked(linked());
    assert_eq!(by_header.is_ok(), by_linked.is_ok());
    if let (Ok(h), Ok(l)) = (by_header, by_linked) {
        assert!(std::ptr::eq(h.plugin().header(), l.plugin().header()));
    }
}
