// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kind's ONE entry: `impl Unit for TransportKeyUnit`, in the exemplar's file position.

use busbar_caps::{TransportKeyHandle, TransportKeyToken, Unit, UnitToken, Verify};

use crate::{provision_server, AccessJournal, SecretSource, Slot, TlsConfigSink, TlsLocations};

/// Everything the loop hands this unit when it provisions a listener's key material.
pub struct ProvisionInput<'a> {
    /// The secret plugin, read here and nowhere else.
    pub source: &'a dyn SecretSource,
    /// Where the access entry for every secret actually read is written.
    pub journal: &'a dyn AccessJournal,
    /// The transport's slot table. The transport only ever sees a slot number.
    pub sink: &'a dyn TlsConfigSink,
    /// The token that mints a key handle. Only this unit is lent it.
    pub keys: &'a TransportKeyToken,
    /// Which slot the config is registered under.
    pub slot: Slot,
    /// Where the material is resolved from.
    pub at: &'a TlsLocations<'a>,
    /// The ALPN protocols to offer.
    pub alpn: &'a [&'a [u8]],
}

/// The transport-key unit, as the thing the loop is handed.
///
/// A zero-sized type because provisioning is a function of its inputs and the sinks it is handed;
/// the crate had no unit struct before, and the kind's shape is one type per crate implementing one
/// trait.
pub struct TransportKeyUnit;

/// The transport-key unit SERVES the verify step: it hands back a handle, never a decision.
///
/// Two honest caveats, both named rather than smoothed over. First, the root's table says this unit
/// "runs at listen, dial and upgrade, outside the loop entirely"; `PLUGIN-TREE.md` §2's step table
/// places it at **Verify** ("plane (`verify`), transport-key unit -> secret"), and the spec is what
/// the kind gate reads, so Verify is the step declared here. Second, this is the ONE `decide` in
/// the tree that performs I/O — it reads a secret and writes a journal entry — which is exactly why
/// it is not on the request path: it runs at listener provisioning, before any unit exists.
impl Unit for TransportKeyUnit {
    type Step = Verify;
    type Input<'a> = ProvisionInput<'a>;
    type Answer<'a> = Result<TransportKeyHandle, String>;
    const OWNS_ITS_STEP: bool = false;

    fn decide<'a>(
        &'a mut self,
        _token: &'a UnitToken<Verify>,
        input: ProvisionInput<'a>,
    ) -> Result<TransportKeyHandle, String> {
        provision_server(
            input.source,
            input.journal,
            input.sink,
            input.keys,
            input.slot,
            input.at,
            input.alpn,
        )
    }
}
