// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native listener ownership over the selected TransportPort and canonical physical routes.

use std::sync::Arc;

use busbar_contract::secure::SecureVec;
use busbar_kernel::inbound::Head;
use busbar_kernel::limits::process_admission::{
    AdmissionClass, ByteCredit, ProcessAdmission, RequestLease,
};
use busbar_plugin_abi::records::{tag, Records};

// Root-adopted finite shape; exact private allocation quotes are charged separately.
const PENDING_SPANS: usize = 4096;
const LIVE_RESPONSES: usize = 200;
const PLAINTEXT_WINDOW: usize = 256 * 1024;

#[derive(Debug)]
enum InputError {
    Invalid,
    Capacity,
    TooLarge,
}

struct DecodedHead {
    head: Head,
    // Retain the provisional full allocation until PhysicalConnection::head reserves its owner.
    credit: ByteCredit,
}

fn add(left: usize, right: usize) -> Result<usize, InputError> {
    left.checked_add(right).ok_or(InputError::Capacity)
}

fn text_copy(text: &str) -> Result<String, InputError> {
    let mut copied = String::new();
    copied
        .try_reserve_exact(text.len())
        .map_err(|_| InputError::Capacity)?;
    if copied.capacity() > text.len() {
        return Err(InputError::Capacity);
    }
    copied.push_str(text);
    Ok(copied)
}

fn value_copy(value: &[u8]) -> Result<Vec<u8>, InputError> {
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(value.len())
        .map_err(|_| InputError::Capacity)?;
    if copied.capacity() > value.len() {
        return Err(InputError::Capacity);
    }
    copied.extend_from_slice(value);
    Ok(copied)
}

/// Validate borrowed records and quote every destination allocation before copying any field.
fn decode_head(bytes: &[u8], request: &RequestLease) -> Result<DecodedHead, InputError> {
    let (mut method, mut path, mut authority, mut scheme) = (None, None, None, None);
    let mut fields = 0usize;
    let mut field_bytes = 0usize;
    for record in Records::new(bytes) {
        let record = record.map_err(|_| InputError::Invalid)?;
        match record.tag {
            tag::H_METHOD | tag::H_PATH | tag::H_AUTHORITY | tag::H_SCHEME => {
                let text = record.text().map_err(|_| InputError::Invalid)?;
                let destination = match record.tag {
                    tag::H_METHOD => &mut method,
                    tag::H_PATH => &mut path,
                    tag::H_AUTHORITY => &mut authority,
                    _ => &mut scheme,
                };
                if destination.replace(text).is_some() {
                    return Err(InputError::Invalid);
                }
            }
            tag::PAIR => {
                let (name, value) = record.pair().map_err(|_| InputError::Invalid)?;
                fields = add(fields, 1)?;
                field_bytes = add(add(field_bytes, name.len())?, value.len())?;
            }
            _ => return Err(InputError::Invalid),
        }
    }
    let method = method
        .filter(|method| !method.is_empty())
        .ok_or(InputError::Invalid)?;
    let path = path
        .filter(|path| !path.is_empty())
        .ok_or(InputError::Invalid)?;
    let (path, query) = path
        .split_once('?')
        .map_or((path, None), |(path, query)| (path, Some(query)));
    let authority = authority.unwrap_or_default();
    let descriptors = fields
        .checked_mul(std::mem::size_of::<(String, Vec<u8>)>())
        .ok_or(InputError::Capacity)?;
    let extent = add(
        add(
            add(
                add(add(method.len(), path.len())?, query.map_or(0, str::len))?,
                authority.len(),
            )?,
            field_bytes,
        )?,
        descriptors,
    )?;
    let credit = request
        .try_reserve(extent)
        .map_err(|_| InputError::Capacity)?;
    let mut head = Head::default();
    head.method = text_copy(method)?;
    head.target = text_copy(path)?;
    head.query = query.map(text_copy).transpose()?;
    head.authority = text_copy(authority)?;
    head.fields
        .try_reserve_exact(fields)
        .map_err(|_| InputError::Capacity)?;
    if head.fields.capacity() > fields {
        return Err(InputError::Capacity);
    }
    for record in Records::new(bytes) {
        let record = record.map_err(|_| InputError::Invalid)?;
        if record.tag == tag::PAIR {
            let (name, value) = record.pair().map_err(|_| InputError::Invalid)?;
            head.fields.push((text_copy(name)?, value_copy(value)?));
        }
    }
    // H_SCHEME is validated text only; physical security comes from the accepted socket.
    Ok(DecodedHead { head, credit })
}

struct InputBody {
    bytes: SecureVec,
    credit: ByteCredit,
}
impl InputBody {
    fn new(request: &RequestLease) -> Result<Self, InputError> {
        let credit = request.try_reserve(0).map_err(|_| InputError::Capacity)?;
        Ok(Self {
            bytes: SecureVec::new(),
            credit,
        })
    }
    fn append(
        &mut self,
        request: &RequestLease,
        bytes: &[u8],
        max: usize,
    ) -> Result<(), InputError> {
        if !self.credit.request().same_request(request) {
            return Err(InputError::Invalid);
        }
        let length = add(self.bytes.len(), bytes.len())?;
        if length > max {
            return Err(InputError::TooLarge);
        }
        if bytes.is_empty() {
            return Ok(());
        }
        // Full replacement overlaps the old request allocation and the original callback owner.
        let credit = request
            .try_reserve(length)
            .map_err(|_| InputError::Capacity)?;
        let mut replacement = SecureVec::with_capacity(length).map_err(|_| InputError::Capacity)?;
        if replacement.capacity() > length {
            return Err(InputError::Capacity);
        }
        replacement
            .extend(self.bytes.as_slice())
            .map_err(|_| InputError::Capacity)?;
        replacement
            .extend(bytes)
            .map_err(|_| InputError::Capacity)?;
        let old_bytes = std::mem::replace(&mut self.bytes, replacement);
        let old_credit = std::mem::replace(&mut self.credit, credit);
        drop(old_bytes);
        drop(old_credit);
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/listener_native.rs"]
mod tests;
