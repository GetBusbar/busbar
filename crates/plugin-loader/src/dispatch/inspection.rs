// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Generic host inspection through existing MAIN extension bytes. The host supplies authority;
//! no principal, pointer, or completion handle in a plugin's request can establish it.

use std::sync::Arc;

use busbar_contract::abi::mechanism::{
    call::{Blob, InHead, OutHead, Outcome, BLOB_OCTETS},
    extensions,
    inspection::{self, InspectionReceipt},
    lifecycle::slot,
    ticket::Ticket,
};

use super::ticket::{InstanceWake, Waking};

fn caller_key(wake: &'static InstanceWake) -> usize {
    std::ptr::from_ref(wake) as usize
}

/// A per-crossing input loan. Blob::from_raw_parts adopts AbiStr's call-only lifetime:
/// plugins copy facts before returning. The epoch owns the receipt, not historical input blobs;
/// RESUME, DRIVE and short recall each receive a fresh loan of that same receipt.
pub(crate) struct Input {
    input: *mut InHead,
    original: Blob,
    _bytes: Arc<zeroize::Zeroizing<Vec<u8>>>,
}

impl Drop for Input {
    fn drop(&mut self) {
        // SAFETY: this guard is scoped inside the crossing owning the input frame.
        unsafe {
            (*self.input).extensions = self.original;
        }
    }
}

/// # Safety
/// `input` is the host's current live frame. Its original extension blob belongs to that frame.
pub(crate) unsafe fn prepare(
    wake: &'static InstanceWake,
    operation: u32,
    input: *mut InHead,
    unit: Option<u64>,
) -> Result<Option<Input>, ()> {
    if matches!(
        operation,
        slot::CANCEL | slot::RELEASE | slot::CLOSE | slot::VALIDATE
    ) {
        return Ok(None);
    }
    // SAFETY: the host's current input frame.
    let head = unsafe { &mut *input };
    if head.ticket.is_none() {
        return Ok(None);
    }
    let Some(route) = Waking::of(wake).and_then(|w| w.route.upgrade()) else {
        return Ok(None);
    };
    let Some(served) = route.services() else {
        return Ok(None);
    };
    if wake.caller.get().is_none() {
        return Ok(None);
    }
    let caller = caller_key(wake);
    let (epoch, receipt) = served.store.inspection_input(caller, head.ticket, unit)?;
    let original = head.extensions;
    if original.len > inspection::MAX_BYTES {
        return if served.store.inspection_active(caller, head.ticket) {
            Err(())
        } else {
            Ok(None)
        };
    }
    // SAFETY: the host retains this original blob for the frame's lifetime.
    let prior = unsafe { super::validate::lent(original.ptr, original.len) }.ok_or(())?;
    // Inspection is optional. Old callers keep their original format, truncated trailing
    // unknown entries and full byte budget when no inspection feature is involved.
    let negotiated = feature_present(prior);
    if !prior.is_empty() && original.fmt != BLOB_OCTETS {
        return if negotiated || receipt.is_some() {
            Err(())
        } else {
            Ok(None)
        };
    }
    let complete = extensions::entries(prior)
        .map(|(key, value)| 2 + key.len() + 4 + value.len())
        .sum::<usize>()
        == prior.len();
    if !complete {
        return if negotiated || receipt.is_some() {
            Err(())
        } else {
            Ok(None)
        };
    }
    let capability = inspection::read_capability(prior).map_err(|_| ())?;
    if capability.as_ref().is_some_and(|c| c.epoch != epoch)
        || extensions::get(prior, inspection::EXT_REQUEST).is_some()
    {
        return Err(());
    }
    // Strict inspection-key validation does not change unrelated keys' first-entry semantics.
    let replies = extensions::entries(prior)
        .filter(|(key, _)| *key == inspection::EXT_REPLY.as_bytes())
        .count();
    let existing_reply = extensions::get(prior, inspection::EXT_REPLY);
    if replies > 1
        || existing_reply.is_some_and(|value| {
            receipt
                .as_ref()
                .and_then(|bytes| extensions::get(bytes, inspection::EXT_REPLY))
                != Some(value)
        })
    {
        return Err(());
    }
    let capability_bytes = if capability.is_none() {
        inspection::append_capability(&[], epoch).map_err(|_| ())?
    } else {
        Vec::new()
    };
    let receipt_bytes = if existing_reply.is_none() {
        receipt.as_deref().unwrap_or(&[])
    } else {
        &[]
    };
    let Some(len) = prior
        .len()
        .checked_add(capability_bytes.len())
        .and_then(|n| n.checked_add(receipt_bytes.len()))
        .filter(|n| *n <= inspection::MAX_BYTES)
    else {
        return if negotiated || receipt.is_some() {
            Err(())
        } else {
            Ok(None)
        };
    };
    // Allocate the complete size before copying any secret. No append helper or Arc<[u8]>
    // conversion can leave an ordinary temporary or reallocated buffer containing the secret.
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(len));
    bytes.extend_from_slice(prior);
    bytes.extend_from_slice(&capability_bytes);
    bytes.extend_from_slice(receipt_bytes);
    let bytes = Arc::new(bytes);
    head.extensions = Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: original.flags,
    };
    Ok(Some(Input {
        input,
        original,
        _bytes: bytes,
    }))
}

/// Detect an inspection key even when its value is cut short. Unknown malformed tails retain
/// the ordinary extensions iterator's behavior; malformed inspection entries are fail-closed.
fn feature_present(mut bytes: &[u8]) -> bool {
    while bytes.len() >= 2 {
        let key_len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        let Some(key) = bytes.get(2..2 + key_len) else {
            return false;
        };
        if [
            inspection::EXT_CAPABILITY,
            inspection::EXT_REQUEST,
            inspection::EXT_REPLY,
        ]
        .iter()
        .any(|name| key == name.as_bytes())
        {
            return true;
        }
        let Some(value_len) = bytes.get(2 + key_len..6 + key_len) else {
            return false;
        };
        let value_len = u32::from_le_bytes(value_len.try_into().expect("four bytes")) as usize;
        let Some(next) = (6 + key_len)
            .checked_add(value_len)
            .and_then(|at| bytes.get(at..))
        else {
            return false;
        };
        bytes = next;
    }
    false
}

/// Copy and serve a validated answer's request before its lease can be released. The provider
/// runs outside all custody locks; only a receipt committed to the original epoch causes a wake.
///
/// # Safety
/// `head` is a plugin answer whose extension ranges are still live under its answer lease.
pub(crate) unsafe fn answer(
    wake: &'static InstanceWake,
    operation: u32,
    ticket: Ticket,
    unit: Option<u64>,
    outcome: Outcome,
    head: &OutHead,
) -> Result<bool, ()> {
    let Some(waking) = Waking::of(wake) else {
        return Ok(false);
    };
    let Some(route) = waking.route.upgrade() else {
        return Ok(false);
    };
    let Some(served) = route.services() else {
        return Ok(false);
    };
    let caller = caller_key(wake);
    if operation == slot::CANCEL {
        served.store.inspection_cancel(caller, ticket);
        return Ok(false);
    }
    if head.extensions.len > inspection::MAX_BYTES {
        return if served.store.inspection_active(caller, ticket) {
            Err(())
        } else {
            Ok(false)
        };
    }
    // SAFETY: the raw length is bounded above and the answer is still leased; decoding copies
    // every request byte before returning.
    let bytes =
        unsafe { super::validate::lent(head.extensions.ptr, head.extensions.len) }.ok_or(())?;
    if bytes.is_empty() {
        return Ok(false);
    }
    if !feature_present(bytes) {
        return Ok(false);
    }
    if head.extensions.fmt != BLOB_OCTETS {
        return Err(());
    }
    let Some(request) = inspection::read_request(bytes).map_err(|_| ())? else {
        return Ok(false);
    };
    if outcome != Outcome::Pending || ticket.is_none() || request.ticket != ticket {
        return Err(());
    }
    let authority = wake.caller.get().ok_or(())?;
    if !served.store.inspection_begin(caller, unit, &request)? {
        return Ok(true);
    }
    let result = served.provider.inspect(authority, unit, &request.query);
    let receipt = InspectionReceipt {
        request: request.clone(),
        result,
    };
    let bytes = match inspection::append_receipt(&[], &receipt) {
        Ok(bytes) => bytes,
        Err(_) => {
            served.store.inspection_cancel(caller, ticket);
            return Err(());
        }
    };
    if !served
        .store
        .inspection_complete(caller, unit, &request, Arc::from(bytes))
    {
        return Err(());
    }
    waking.wake(ticket);
    Ok(true)
}

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "inspection_tests.rs"]
mod tests;
