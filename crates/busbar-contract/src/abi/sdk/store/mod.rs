// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Primitive Store adapter and shared native connection mechanics.

pub mod cells;
pub mod v4;
pub mod wire;

mod op;
pub use op::{Checkout, Op, Services, Step};

/// THE RECOVERABLE GATE, the store's side (MIGRATE-ON-BOOT §4, §5). A store's data step counts,
/// read-only and in its own encoding, the 1.5.5 credential rows whose secret is recoverable (stored
/// in the clear), and calls this with that count before its first data, DDL or marker write. `Ok`
/// when the boot can seal them (core's at-rest key resolves). Otherwise the REFUSED the store
/// returns from its `open` unchanged, with core's text: how to add the key. `n == 0` asks nothing.
///
/// A host that does not offer `migrate.admit` cannot seal, so the gate refuses (never open by
/// default): the store hands core no plaintext it cannot seal.
///
/// # Errors
/// The host's refusal, its text verbatim; or a CONFIG refusal when the host gave no answer.
#[cold]
#[inline(never)]
pub fn admit_recoverable(
    host: &crate::abi::sdk::conn::Host<crate::plugin::markers::StoreKind>,
    n: u64,
) -> Result<(), crate::abi::sdk::life::Refusal> {
    use crate::abi::mechanism::ticket::Ticket;
    use crate::abi::sdk::conn::ConnFailure;
    use crate::abi::sdk::life::Refusal;
    if n == 0 {
        return Ok(());
    }
    match host.connector(Ticket::NONE).migrate_admit(n) {
        Ok(()) => Ok(()),
        Err(ConnFailure::Refused(text)) if !text.is_empty() => Err(Refusal::refused(text)),
        Err(other) => Err(Refusal::refused(format!(
            "CONFIG: this store holds {n} recoverable credentials (SigV4 secret keys) stored in \
             the clear, and the host did not admit them for sealing ({other}); nothing was written"
        ))),
    }
}
