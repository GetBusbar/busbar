// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[cfg(not(test))]
struct Held(busbar_contract::caps::MigrationSeal);

#[cfg(not(test))]
fn acquire() -> busbar_contract::caps::MigrationSeal {
    match busbar_contract::caps::MigrationSeal::deliver().downcast::<Held>() {
        Ok(held) => {
            let Held(seal) = *held;
            seal
        }
        Err(_) => unreachable!("migration root returned a foreign holder"),
    }
}

#[cfg(not(test))]
#[allow(unsafe_code)]
#[no_mangle]
pub fn __busbar_migrations_root(
    seal: busbar_contract::caps::MigrationSeal,
) -> Box<dyn std::any::Any + Send + Sync> {
    // This is the matching root signature declared by busbar-contract. The
    // private holder prevents any other linked crate from extracting the seal.
    Box::new(Held(seal))
}

#[cfg(test)]
fn acquire() -> busbar_contract::caps::MigrationSeal {
    busbar_contract::caps::MigrationSeal::acquire_for_migrations()
}

pub(crate) fn lend() -> busbar_contract::caps::MigrationGrant {
    acquire().grant()
}
