use std::sync::Arc;

use busbar_contract::abi::sdk::store::conditional::{Expected, Mutation, Predicate, Request};
use busbar_contract::bounded::MAX_RECORD_BYTES;
use oauth_as::store::StorageError;

const MAGIC: &[u8] = b"\0oauth-cell\x01";

pub(super) const MAX_CELL_BYTES: usize =
    busbar_contract::abi::mechanism::check::HARD_MAX_BYTES as usize;

pub(super) struct Descriptor {
    len: usize,
    hash: [u8; 32],
}

fn invalid() -> StorageError {
    StorageError::new("oauth_as store: invalid chunked authoritative record")
}

impl Descriptor {
    pub(super) fn decode(bytes: &[u8]) -> Result<Option<Self>, StorageError> {
        if !bytes.starts_with(MAGIC) {
            return Ok(None);
        }
        if bytes.len() != MAGIC.len() + 8 + 32 {
            return Err(invalid());
        }
        let len = u64::from_le_bytes(bytes[MAGIC.len()..MAGIC.len() + 8].try_into().unwrap());
        let len = usize::try_from(len).map_err(|_| invalid())?;
        if !(MAX_RECORD_BYTES + 1..=MAX_CELL_BYTES).contains(&len) {
            return Err(invalid());
        }
        Ok(Some(Self {
            len,
            hash: bytes[MAGIC.len() + 8..].try_into().unwrap(),
        }))
    }

    fn of(bytes: &[u8]) -> Result<Self, StorageError> {
        if bytes.len() > MAX_CELL_BYTES {
            return Err(StorageError::new(
                "oauth_as store: logical cell exceeds byte bound",
            ));
        }
        Ok(Self {
            len: bytes.len(),
            hash: ring::digest::digest(&ring::digest::SHA256, bytes)
                .as_ref()
                .try_into()
                .unwrap(),
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&(self.len as u64).to_le_bytes());
        bytes.extend_from_slice(&self.hash);
        bytes
    }

    pub(super) fn parts(&self) -> usize {
        self.len.div_ceil(MAX_RECORD_BYTES)
    }

    fn prefix(&self, key: &[u8]) -> Vec<u8> {
        let mut prefix = key.to_vec();
        prefix.push(0);
        prefix.extend_from_slice(&self.hash);
        prefix
    }

    pub(super) fn key(&self, key: &[u8], part: usize) -> Vec<u8> {
        let mut key = self.prefix(key);
        key.extend_from_slice(&(part as u64).to_le_bytes());
        key
    }

    pub(super) fn check(&self, bytes: &[u8]) -> bool {
        bytes.len() == self.len
            && ring::digest::digest(&ring::digest::SHA256, bytes).as_ref() == self.hash
    }
}

pub(super) fn parts_schema(schema: &str) -> String {
    format!("{schema}.parts")
}

pub(super) fn physical(
    request: Arc<Request>,
    observed: &[Predicate],
) -> Result<Arc<Request>, StorageError> {
    let mut physical = (*request).clone();
    let mut chunks = Vec::new();
    for mutation in &mut physical.mutations {
        let (schema, key) = match mutation {
            Mutation::Put { schema, key, value } if value.len() > MAX_RECORD_BYTES => {
                let descriptor = Descriptor::of(value)?;
                for (part, bytes) in value.chunks(MAX_RECORD_BYTES).enumerate() {
                    chunks.push(Mutation::Put {
                        schema: parts_schema(schema),
                        key: descriptor.key(key, part),
                        value: bytes.to_vec(),
                    });
                }
                *value = descriptor.encode();
                continue;
            }
            Mutation::Put { schema, key, .. } | Mutation::Delete { schema, key } => (schema, key),
            Mutation::DeleteRange { .. } => continue,
        };

        let mut prefix = key.clone();
        prefix.push(0);
        chunks.push(Mutation::DeleteRange {
            schema: parts_schema(schema),
            exact_key_length: (prefix.len() + 32 + 8) as u64,
            prefix,
        });
    }
    for old in request.predicates.iter().chain(observed) {
        let Expected::Bytes(bytes) = &old.expected else {
            continue;
        };
        let descriptor = if bytes.len() > MAX_RECORD_BYTES {
            Some(Descriptor::of(bytes)?)
        } else {
            Descriptor::decode(bytes)?
        };
        let Some(descriptor) = descriptor else {
            continue;
        };
        let header = descriptor.encode();

        if physical.mutations.iter().any(|m| {
            matches!(m,
            Mutation::Put { schema, key, value }
                if schema == &old.schema && key == &old.key
                    && Descriptor::decode(value).ok().flatten().is_some() && value != &header)
        }) {
            let prefix = descriptor.prefix(&old.key);
            chunks.push(Mutation::DeleteRange {
                schema: parts_schema(&old.schema),
                exact_key_length: (prefix.len() + 8) as u64,
                prefix,
            });
        }
    }
    for predicate in &mut physical.predicates {
        if let Expected::Bytes(bytes) = &mut predicate.expected {
            if bytes.len() > MAX_RECORD_BYTES {
                *bytes = Descriptor::of(bytes)?.encode();
            }
        }
    }
    physical.mutations.extend(chunks);
    Ok(Arc::new(physical))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_content_keeps_its_generation_without_overlapping_cleanup() {
        let bytes = vec![b'x'; MAX_RECORD_BYTES + 1];
        let schema = "cell.atomic.v1";
        let logical = crate::shared::Shared::candidate(schema, "id", Some(bytes.clone()), bytes);
        let physical = physical(logical, &[]).unwrap();
        physical.encode().unwrap();
        assert!(!physical
            .mutations
            .iter()
            .any(|m| matches!(m, Mutation::DeleteRange { .. })));
        assert!(physical
            .mutations
            .iter()
            .all(|m| !matches!(m, Mutation::Put { value, .. } if value.len() > MAX_RECORD_BYTES)));
    }

    #[test]
    fn logical_length_and_complete_physical_wire_are_bounded() {
        let oversized = crate::shared::Shared::candidate(
            "cell.atomic.v1",
            "id",
            None,
            vec![b'x'; MAX_CELL_BYTES + 1],
        );
        assert!(physical(oversized, &[]).is_err());

        let maximal = crate::shared::Shared::candidate(
            "cell.atomic.v1",
            "id",
            None,
            vec![b'x'; MAX_CELL_BYTES],
        );
        assert!(physical(maximal, &[]).unwrap().encode().is_err());
    }
}
