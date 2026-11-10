// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Trusted logical grouping for a streaming physical archive. The external
//! index owns protected group keys and charges their bytes plus each member
//! index before allocation. Payloads are lent one row at a time, never retained.
use super::Error;

pub struct LogicalGroup {
    pub family: [u8; 16],
    pub key: busbar_contract::Secret<Vec<u8>>,
}
fn framed(parts: &[&[u8]]) -> Result<Vec<u8>, Error> {
    busbar_kernel::persistence::import_target::records::keys::framed(b'G', parts)
        .map_err(|_| Error::Range)
}

pub fn index_charge(group_key: &[u8], member_count: usize) -> Result<usize, Error> {
    group_key
        .len()
        .checked_add(16)
        .and_then(|v| {
            member_count
                .checked_mul(std::mem::size_of::<usize>())
                .and_then(|members| v.checked_add(members))
        })
        .ok_or(Error::Range)
}

/// Group every original journal frame part under its node and sequence.
pub fn journal_group_key(key: &[u8]) -> Result<busbar_contract::Secret<Vec<u8>>, Error> {
    if key.len() != 18 || key[..8] == [0; 8] || key[8..16] == [0; 8] {
        return Err(Error::Invalid);
    }
    Ok(busbar_contract::Secret::new(framed(&[
        b"J",
        &key[..8],
        &key[8..16],
    ])?))
}
