// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `install_crypto_provider` actually installs a process-wide provider, and says so from a process
//! where nothing else could have installed one first.
//!
//! This has to be its own integration target, and holds only one test on purpose. The thing under
//! test is a PROCESS-WIDE, once-only side effect: any other test in the same binary that builds a
//! `rustls` config installs the crate-feature provider as the process default on its way past, so a
//! test sharing a binary with one of those would pass whether `install_crypto_provider` did
//! anything or not. Alone in its own process, the assertion is real.

/// Before the call there is no process default; after it there is one, and calling it again is
/// harmless rather than a panic on a second listener's provisioning.
#[test]
fn installing_the_provider_sets_the_process_default_and_is_idempotent() {
    assert!(
        rustls::crypto::CryptoProvider::get_default().is_none(),
        "this target must be alone in its process for the assertion below to mean anything"
    );

    busbar_unit_transport_key::install_crypto_provider();
    let installed = rustls::crypto::CryptoProvider::get_default()
        .expect("install_crypto_provider installed the process-wide default")
        .clone();

    // A second listener provisioning on the same node calls this again; a "provider already
    // installed" error is expected and swallowed, and the provider already in place stays.
    busbar_unit_transport_key::install_crypto_provider();
    let after = rustls::crypto::CryptoProvider::get_default()
        .expect("the default is still installed")
        .clone();
    assert!(std::sync::Arc::ptr_eq(&installed, &after));
}
