// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ADMIT-UNLOAD (ABI-MIN3-INTERFACE §14; defined by FU5 (b), MIN3-BLOCKER-RULINGS B25, from §11.1's two exits
//! and I13): an image admitted and then refused, and an image admitted and then dropped, each leave by exit (a):
//! the library stays in the loader's image table, is never `dlclose`d, and no runtime thread unloads it.
//!
//! Each arm runs the refusal or the drop on a spawned thread that has run plugin code inline (describe at
//! `Registry::add`, or the instance's entries) and then exits, the shape of the TLS-destructor crash
//! (ffi_thread.rs). It holds only a `Weak<Image>` across it, then asserts: the `Weak` still upgrades (the image
//! table holds the image: nothing unloaded it), a re-admit of the same bytes returns the same `Arc<Image>`
//! (`Arc::ptr_eq`: resident, not loaded again), and a call through a fresh instance of the re-admitted image
//! answers (its code is still mapped). A planted unload site (exit (b) taken after admission, e.g. a
//! `stage::dlclose_on_worker` on `Registry::add`'s NameConflict branch, or a `Drop for Image` that unloads)
//! fails the first two assertions; IF §15 rule 13 (`busbar-ci-checks rule-13`) finds the same site in source.
//!
//! Exit (b) (refused before admission, unloaded once on the permanent ffi worker) is asserted where the
//! routing is observable, in plugin-loader's own admit tests through its `UNLOADS_ON_WORKER` count (W1-L1).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green). Both arms need a dropped-in MIN-3
//! fixture image, so by STAGE23-DISPATCH Δ4 they run in the QA integration suite (#217), over W1-L1's `admit`
//! and W1-L2's `Registry::new`/`add`/`remove` and image table.

/// NameConflict at `Registry::add` (a second fixture whose identity is already admitted): a refusal after
/// admission never unloads.
#[test]
#[ignore = "owner: #217 (Δ4: dropped-in MIN-3 image; needs W1-L1 admit, W1-L2 Registry)"]
fn admitted_then_refused_stays_resident_and_readmits_the_same_image() {
    todo!("owner: #217 (C-ADMIT-UNLOAD)")
}

/// The last instance closed and the `Admitted` and registry entry dropped: the image table keeps the image.
#[test]
#[ignore = "owner: #217 (Δ4: dropped-in MIN-3 image; needs W1-L1 admit, W1-L2 Registry)"]
fn admitted_then_dropped_stays_resident_and_readmits_the_same_image() {
    todo!("owner: #217 (C-ADMIT-UNLOAD)")
}

/// DES-443 r3 §6: an image inspected (described, never admitted) is closed on a permanent worker and unmapped: it
/// is neither resident nor reopened by a later inspection. Asserted today in plugin-loader's
/// `inspect::tests::an_image_is_opened_once_unloaded_and_then_answered_from_the_cache`; this arm runs it over a
/// dropped-in image in the QA integration suite.
#[test]
#[ignore = "owner: #217 (Δ4: dropped-in MIN-3 image; loader cover: inspect_tests an_image_is_opened_once_unloaded_and_then_answered_from_the_cache)"]
fn inspected_then_unloaded_is_neither_resident_nor_reopened() {
    todo!("owner: #217 (C-ADMIT-UNLOAD, inspected and unloaded)")
}

/// DES-443 r3 §6: an inspected image that pins itself (it stays mapped after close) is counted as pinned, gets no
/// resident entry, and is never reopened. Asserted today in plugin-loader's
/// `inspect::tests::an_image_that_pins_itself_is_counted_and_never_reopened`.
#[test]
#[ignore = "owner: #217 (Δ4: dropped-in MIN-3 image; loader cover: inspect_tests an_image_that_pins_itself_is_counted_and_never_reopened)"]
fn inspected_then_pinned_has_no_resident_entry() {
    todo!("owner: #217 (C-ADMIT-UNLOAD, inspected and pinned)")
}
