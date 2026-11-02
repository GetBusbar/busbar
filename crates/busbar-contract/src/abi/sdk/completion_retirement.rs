// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Explicit consumption of terminal host-service results on a long-lived driver ticket.
//! This uses MAIN extensions; completion handles and every C layout remain unchanged.

use crate::abi::mechanism::{
    extensions,
    ticket::{HostCtx, Ticket},
};

pub const CAPABILITY: &str = "busbar.completion-retirement.capability";
pub const ACK: &str = "busbar.completion-retirement.ack";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Domain {
    Host,
    Connector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Handle {
    pub domain: Domain,
    pub seq: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    pub owner: HostCtx,
    pub ticket: Ticket,
    pub epoch: u64,
    pub nonce: u64,
    pub acknowledged: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acknowledgement {
    pub capability: Capability,
    pub handles: Vec<Handle>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
}

/// One feature entry, with complete framing and no duplicate known keys.
pub fn entry<'a>(bytes: &'a [u8], key: &str) -> Result<Option<&'a [u8]>, Error> {
    let mut found = None;
    let mut read = 0usize;
    for (name, value) in extensions::entries(bytes) {
        read = read
            .checked_add(6 + name.len() + value.len())
            .ok_or(Error::Invalid)?;
        if name == key.as_bytes() && found.replace(value).is_some() {
            return Err(Error::Invalid);
        }
    }
    if read != bytes.len() {
        return Err(Error::Invalid);
    }
    Ok(found)
}

fn capability(bytes: &[u8]) -> Result<Capability, Error> {
    if bytes.len() != 65 || bytes[0] != 1 {
        return Err(Error::Invalid);
    }
    let value = Capability {
        owner: HostCtx {
            handle: u64::from_le_bytes(bytes[25..33].try_into().map_err(|_| Error::Invalid)?),
        },
        ticket: Ticket {
            slot: u32::from_le_bytes(bytes[1..5].try_into().map_err(|_| Error::Invalid)?),
            generation: u32::from_le_bytes(bytes[5..9].try_into().map_err(|_| Error::Invalid)?),
        },
        epoch: u64::from_le_bytes(bytes[9..17].try_into().map_err(|_| Error::Invalid)?),
        nonce: u64::from_le_bytes(bytes[17..25].try_into().map_err(|_| Error::Invalid)?),
        acknowledged: bytes[33..65].try_into().map_err(|_| Error::Invalid)?,
    };
    if value.owner.is_none() || value.ticket.is_none() || value.epoch == 0 || value.nonce == 0 {
        return Err(Error::Invalid);
    }
    Ok(value)
}

fn encoded_capability(value: Capability) -> Vec<u8> {
    let mut bytes = vec![1];
    bytes.extend_from_slice(&value.ticket.slot.to_le_bytes());
    bytes.extend_from_slice(&value.ticket.generation.to_le_bytes());
    bytes.extend_from_slice(&value.epoch.to_le_bytes());
    bytes.extend_from_slice(&value.nonce.to_le_bytes());
    bytes.extend_from_slice(&value.owner.handle.to_le_bytes());
    bytes.extend_from_slice(&value.acknowledged);
    bytes
}

fn append(prior: &[u8], key: &str, value: &[u8]) -> Result<Vec<u8>, Error> {
    let length = prior
        .len()
        .checked_add(6 + key.len() + value.len())
        .filter(|&n| n <= crate::abi::mechanism::check::HARD_MAX_BYTES as usize)
        .ok_or(Error::Invalid)?;
    if entry(prior, key)?.is_some() {
        return Err(Error::Invalid);
    }
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(prior);
    bytes.extend_from_slice(&extensions::encode(&[(key, value)]));
    Ok(bytes)
}

/// Detect the actual key even if its value is truncated, without matching bytes inside values.
pub fn present(mut bytes: &[u8], name: &str) -> bool {
    while bytes.len() >= 2 {
        let len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        let Some(key) = bytes.get(2..2 + len) else {
            return false;
        };
        if key == name.as_bytes() {
            return true;
        }
        let Some(size) = bytes.get(2 + len..6 + len) else {
            return false;
        };
        let size = u32::from_le_bytes(size.try_into().expect("four bytes")) as usize;
        let Some(rest) = (6 + len).checked_add(size).and_then(|end| bytes.get(end..)) else {
            return false;
        };
        bytes = rest;
    }
    false
}

pub fn read_capability(bytes: &[u8]) -> Result<Option<Capability>, Error> {
    entry(bytes, CAPABILITY)?.map(capability).transpose()
}

pub fn append_capability(prior: &[u8], value: Capability) -> Result<Vec<u8>, Error> {
    let encoded = encoded_capability(value);
    capability(&encoded)?;
    append(prior, CAPABILITY, &encoded)
}

pub fn read_ack(bytes: &[u8]) -> Result<Option<Acknowledgement>, Error> {
    let Some(value) = entry(bytes, ACK)? else {
        return Ok(None);
    };
    let header = value.get(..65).ok_or(Error::Invalid)?;
    let capability = capability(header)?;
    let count = u32::from_le_bytes(
        value
            .get(65..69)
            .ok_or(Error::Invalid)?
            .try_into()
            .map_err(|_| Error::Invalid)?,
    ) as usize;
    if count == 0 || count.checked_mul(5).and_then(|n| n.checked_add(69)) != Some(value.len()) {
        return Err(Error::Invalid);
    }
    let mut handles = Vec::with_capacity(count);
    let mut seen = std::collections::HashSet::with_capacity(count);
    for record in value[69..].as_chunks::<5>().0 {
        let handle = Handle {
            domain: match record[0] {
                0 => Domain::Host,
                1 => Domain::Connector,
                _ => return Err(Error::Invalid),
            },
            seq: u32::from_le_bytes(record[1..].try_into().map_err(|_| Error::Invalid)?),
        };
        // Host services and connector calls share one issue-number namespace.
        if !seen.insert(handle.seq) {
            return Err(Error::Invalid);
        }
        handles.push(handle);
    }
    Ok(Some(Acknowledgement {
        capability,
        handles,
    }))
}

pub fn append_ack(prior: &[u8], ack: &Acknowledgement) -> Result<Vec<u8>, Error> {
    let mut value = encoded_capability(ack.capability);
    let count = u32::try_from(ack.handles.len()).map_err(|_| Error::Invalid)?;
    value.extend_from_slice(&count.to_le_bytes());
    for handle in &ack.handles {
        value.push(match handle.domain {
            Domain::Host => 0,
            Domain::Connector => 1,
        });
        value.extend_from_slice(&handle.seq.to_le_bytes());
    }
    let encoded = append(&[], ACK, &value)?;
    read_ack(&encoded)?.ok_or(Error::Invalid)?;
    append(prior, ACK, &value)
}

/// Exact accepted-batch identity; a different coordinator's acknowledgement grants no reuse.
pub fn ack_digest(ack: &Acknowledgement) -> Result<[u8; 32], Error> {
    Ok(crate::abi::sdk::digest::sha256(&append_ack(&[], ack)?))
}

/// Guest-owned consumption state. The caller explicitly marks a result consumed only after
/// copying all borrowed data and ending its use of the result. Merely seeing READY is insufficient.
/// A handle is reusable only after `begin` returns it following host confirmation.
#[derive(Debug, Default)]
pub struct Retirement {
    capability: Option<Capability>,
    consumed: Vec<Handle>,
    waiting: Option<Acknowledgement>,
}

impl Retirement {
    pub fn begin(
        &mut self,
        owner: HostCtx,
        ticket: Ticket,
        bytes: &[u8],
    ) -> Result<Vec<Handle>, Error> {
        let next = read_capability(bytes)?.ok_or(Error::Unsupported)?;
        if next.owner != owner
            || next.ticket != ticket
            || self
                .capability
                .is_some_and(|prior| prior.owner != owner || prior.ticket != ticket)
        {
            return Err(Error::Invalid);
        }
        let mut reusable = Vec::new();
        if let Some(waiting) = &self.waiting {
            if waiting.capability != next {
                if waiting.capability.epoch == next.epoch
                    && next.acknowledged != ack_digest(waiting)?
                {
                    return Err(Error::Invalid);
                }
                reusable = self
                    .waiting
                    .take()
                    .expect("the pending acknowledgement")
                    .handles;
            }
        }
        if self
            .capability
            .is_some_and(|prior| prior.epoch != next.epoch)
        {
            reusable.append(&mut self.consumed);
        }
        self.capability = Some(next);
        Ok(reusable)
    }

    pub fn consumed(&mut self, handle: Handle) -> Result<(), Error> {
        if self.capability.is_none() {
            return Err(Error::Unsupported);
        }
        if self
            .consumed
            .iter()
            .chain(self.waiting.iter().flat_map(|a| a.handles.iter()))
            .any(|h| h.seq == handle.seq)
        {
            return Err(Error::Invalid);
        }
        self.consumed.push(handle);
        Ok(())
    }

    pub fn queued(&self) -> bool {
        !self.consumed.is_empty() || self.waiting.is_some()
    }

    /// Stop issuing or polling work when false, retaining any pending operation's buffers.
    pub fn can_consume(&self, prior_extension_bytes: usize) -> bool {
        self.capability.is_some()
            && self.consumed.len() + self.waiting.as_ref().map_or(0, |a| a.handles.len())
                < Self::capacity(prior_extension_bytes)
    }

    fn capacity(prior: usize) -> usize {
        (crate::abi::mechanism::check::HARD_MAX_BYTES as usize)
            .saturating_sub(prior.saturating_add(6 + ACK.len() + 69))
            / 5
    }

    pub fn acknowledgement(
        &mut self,
        prior_extension_bytes: usize,
    ) -> Result<Option<Acknowledgement>, Error> {
        let count = Self::capacity(prior_extension_bytes);
        if self
            .waiting
            .as_ref()
            .is_some_and(|a| a.handles.len() > count)
        {
            return Err(Error::Invalid);
        }
        if self.waiting.is_none() && !self.consumed.is_empty() {
            if count == 0 {
                return Err(Error::Invalid);
            }
            let count = count.min(self.consumed.len());
            self.waiting = Some(Acknowledgement {
                capability: self.capability.ok_or(Error::Unsupported)?,
                handles: self.consumed.drain(..count).collect(),
            });
        }
        Ok(self.waiting.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability() -> Capability {
        Capability {
            owner: HostCtx { handle: 71 },
            ticket: Ticket {
                slot: 3,
                generation: 5,
            },
            epoch: 11,
            nonce: 13,
            acknowledged: [0; 32],
        }
    }

    #[test]
    fn consumption_waits_for_confirmation_and_refuses_another_owner() {
        let cap = capability();
        let input = append_capability(&[], cap).unwrap();
        let mut guest = Retirement::default();
        assert_eq!(
            guest.begin(cap.owner, cap.ticket, &[]),
            Err(Error::Unsupported)
        );
        assert!(guest
            .begin(cap.owner, cap.ticket, &input)
            .unwrap()
            .is_empty());
        let handle = Handle {
            domain: Domain::Connector,
            seq: 9,
        };
        guest.consumed(handle).unwrap();
        let ack = guest.acknowledgement(0).unwrap().unwrap();
        assert_eq!(
            read_ack(&append_ack(&[], &ack).unwrap()).unwrap(),
            Some(ack.clone())
        );
        assert!(guest
            .begin(cap.owner, cap.ticket, &input)
            .unwrap()
            .is_empty());
        assert_eq!(guest.acknowledgement(0).unwrap(), Some(ack.clone()));
        let wrong = Capability {
            owner: HostCtx { handle: 72 },
            nonce: 14,
            ..cap
        };
        assert_eq!(
            guest.begin(
                wrong.owner,
                wrong.ticket,
                &append_capability(&[], wrong).unwrap()
            ),
            Err(Error::Invalid)
        );
        assert_eq!(
            guest.begin(
                cap.owner,
                cap.ticket,
                &append_capability(&[], Capability { nonce: 14, ..cap }).unwrap()
            ),
            Err(Error::Invalid)
        );
        let confirmed = Capability {
            nonce: 14,
            acknowledged: ack_digest(&ack).unwrap(),
            ..cap
        };
        assert_eq!(
            guest
                .begin(
                    cap.owner,
                    cap.ticket,
                    &append_capability(&[], confirmed).unwrap()
                )
                .unwrap(),
            vec![handle]
        );
        assert!(!guest.queued());
        guest.consumed(handle).unwrap();
        guest.acknowledgement(0).unwrap().unwrap();
        let next_cycle = Capability {
            epoch: 15,
            nonce: 16,
            acknowledged: [0; 32],
            ..confirmed
        };
        assert_eq!(
            guest
                .begin(
                    cap.owner,
                    cap.ticket,
                    &append_capability(&[], next_cycle).unwrap()
                )
                .unwrap(),
            vec![handle]
        );
    }

    #[test]
    fn batches_fit_actual_existing_extension_space_and_never_silently_stall() {
        let cap = capability();
        let mut guest = Retirement::default();
        guest
            .begin(cap.owner, cap.ticket, &append_capability(&[], cap).unwrap())
            .unwrap();
        let one = Handle {
            domain: Domain::Host,
            seq: 1,
        };
        let two = Handle {
            domain: Domain::Connector,
            seq: 2,
        };
        guest.consumed(one).unwrap();
        guest.consumed(two).unwrap();
        let occupied =
            crate::abi::mechanism::check::HARD_MAX_BYTES as usize - (6 + ACK.len() + 69 + 5);
        assert!(!guest.can_consume(occupied));
        assert_eq!(guest.acknowledgement(occupied + 5), Err(Error::Invalid));
        let ack = guest.acknowledgement(occupied).unwrap().unwrap();
        assert_eq!(ack.handles, vec![one]);
        let next = Capability {
            nonce: 14,
            acknowledged: ack_digest(&ack).unwrap(),
            ..cap
        };
        assert_eq!(
            guest
                .begin(
                    cap.owner,
                    cap.ticket,
                    &append_capability(&[], next).unwrap()
                )
                .unwrap(),
            vec![one]
        );
        assert_eq!(
            guest.acknowledgement(occupied).unwrap().unwrap().handles,
            vec![two]
        );
    }

    #[test]
    fn malformed_or_duplicate_ack_does_not_describe_consumption() {
        let cap = capability();
        let handle = Handle {
            domain: Domain::Host,
            seq: 1,
        };
        let ack = Acknowledgement {
            capability: cap,
            handles: vec![handle],
        };
        let bytes = append_ack(&[], &ack).unwrap();
        for end in (2 + ACK.len())..bytes.len() {
            assert!(present(&bytes[..end], ACK));
            assert!(read_ack(&bytes[..end]).is_err());
        }
        let mut duplicate = bytes.clone();
        duplicate.extend_from_slice(&bytes);
        assert!(read_ack(&duplicate).is_err());
        assert!(append_ack(
            &[],
            &Acknowledgement {
                handles: vec![
                    handle,
                    Handle {
                        domain: Domain::Connector,
                        ..handle
                    }
                ],
                ..ack
            }
        )
        .is_err());
    }
}
