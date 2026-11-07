// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core key components are byte strings, never delimiter-escaped text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    Length,
    Allocation,
    Malformed,
}

pub fn framed(tag: u8, parts: &[&[u8]]) -> Result<Vec<u8>, KeyError> {
    let mut size = 1usize;
    for part in parts {
        u32::try_from(part.len()).map_err(|_| KeyError::Length)?;
        size = size
            .checked_add(4)
            .and_then(|n| n.checked_add(part.len()))
            .ok_or(KeyError::Length)?;
    }
    let mut key = Vec::new();
    key.try_reserve_exact(size)
        .map_err(|_| KeyError::Allocation)?;
    key.push(tag);
    for part in parts {
        key.extend_from_slice(&(part.len() as u32).to_be_bytes());
        key.extend_from_slice(part);
    }
    Ok(key)
}

pub fn components(key: &[u8], tag: u8) -> Result<Vec<&[u8]>, KeyError> {
    if key.first() != Some(&tag) {
        return Err(KeyError::Malformed);
    }
    let mut tail = &key[1..];
    let mut result = Vec::new();
    while !tail.is_empty() {
        let n = u32::from_be_bytes(
            tail.get(..4)
                .ok_or(KeyError::Malformed)?
                .try_into()
                .map_err(|_| KeyError::Malformed)?,
        ) as usize;
        tail = &tail[4..];
        result.try_reserve(1).map_err(|_| KeyError::Allocation)?;
        result.push(tail.get(..n).ok_or(KeyError::Malformed)?);
        tail = &tail[n..];
    }
    Ok(result)
}
