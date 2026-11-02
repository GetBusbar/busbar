// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Credential header classification retained outside the serialized request bytes.

use crate::abi::mechanism::extensions;

/// An opening Emit input's credential field names; never a wire field.
pub const EXT_SENSITIVE_FIELDS: &str = "fields.sensitive";

/// The request-target pseudo-field classified by the sensitive-field extension.
pub const REQUEST_TARGET_FIELD: &str = ":path";

/// The immutable field-name classification of one outbound request head. `:path` identifies an
/// auth query credential in the target; every other name is an ordinary header. No values cross here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SensitiveFields(Vec<String>);

impl SensitiveFields {
    /// Normalize the host's credential field names, independently of whether sealing is offered.
    pub fn new(names: Vec<String>) -> Result<Self, &'static str> {
        let mut normalized = Vec::new();
        for name in names {
            if name != REQUEST_TARGET_FIELD && !crate::header::is_header_name_token(name.as_bytes())
            {
                return Err("a sensitive field name is not a header token");
            }
            let name = name.to_ascii_lowercase();
            if !normalized.contains(&name) {
                normalized.push(name);
            }
        }
        Ok(Self(normalized))
    }

    /// Whether this header's value must carry the encoder's sensitive flag.
    #[must_use]
    pub fn contains(&self, name: &[u8]) -> bool {
        self.0
            .iter()
            .any(|field| field.as_bytes().eq_ignore_ascii_case(name))
    }

    /// Decode the complete known entry; absent metadata preserves the legacy unmarked request.
    pub fn from_extensions(bytes: &[u8]) -> Result<Option<Self>, &'static str> {
        extensions::get(bytes, EXT_SENSITIVE_FIELDS)
            .map(Self::decode)
            .transpose()
    }

    /// Encode a host input extension. An unmarked request needs no entry.
    pub fn extensions(&self) -> Result<Vec<u8>, &'static str> {
        if self.0.is_empty() {
            return Ok(Vec::new());
        }
        let mut value = 1_u32.to_le_bytes().to_vec();
        let count = u32::try_from(self.0.len()).map_err(|_| "too many sensitive field names")?;
        value.extend_from_slice(&count.to_le_bytes());
        for name in &self.0 {
            let len =
                u32::try_from(name.len()).map_err(|_| "a sensitive field name is too long")?;
            value.extend_from_slice(&len.to_le_bytes());
            value.extend_from_slice(name.as_bytes());
        }
        Ok(extensions::encode(&[(EXT_SENSITIVE_FIELDS, &value)]))
    }

    fn decode(mut bytes: &[u8]) -> Result<Self, &'static str> {
        fn word(bytes: &mut &[u8]) -> Result<u32, &'static str> {
            let value = bytes
                .get(..4)
                .ok_or("the sensitive field entry is truncated")?;
            let mut raw = [0; 4];
            raw.copy_from_slice(value);
            *bytes = &bytes[4..];
            Ok(u32::from_le_bytes(raw))
        }
        if word(&mut bytes)? != 1 {
            return Err("unknown sensitive field version");
        }
        let count = word(&mut bytes)? as usize;
        if count > bytes.len() / 4 {
            return Err("the sensitive field list is truncated");
        }
        let mut names = Vec::new();
        for _ in 0..count {
            let len = word(&mut bytes)? as usize;
            let value = bytes
                .get(..len)
                .ok_or("a sensitive field name is truncated")?;
            names.push(
                std::str::from_utf8(value)
                    .map_err(|_| "a sensitive field name is not UTF-8")?
                    .to_owned(),
            );
            bytes = &bytes[len..];
        }
        if !bytes.is_empty() {
            return Err("the sensitive field entry has trailing bytes");
        }
        Self::new(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_survive_the_input_loan_without_values_or_case_dependence() {
        let fields = SensitiveFields::new(vec!["X-Api-Key".into(), "x-api-key".into()]).unwrap();
        let input = fields.extensions().unwrap();
        let copied = SensitiveFields::from_extensions(&input).unwrap().unwrap();
        drop(input);
        assert_eq!(copied, fields);
        assert!(copied.contains(b"X-API-KEY"));
        assert!(!copied.contains(b"x-public"));
        assert!(SensitiveFields::default().extensions().unwrap().is_empty());
        assert!(SensitiveFields::from_extensions(&[]).unwrap().is_none());
    }

    #[test]
    fn malformed_present_classification_is_never_silently_unmarked() {
        let ext = SensitiveFields::new(vec!["x-key".into()])
            .unwrap()
            .extensions()
            .unwrap();
        let value = extensions::get(&ext, EXT_SENSITIVE_FIELDS).unwrap();
        for end in 0..value.len() {
            assert!(SensitiveFields::decode(&value[..end]).is_err());
        }
        let mut unknown = value.to_vec();
        unknown[0] = 2;
        assert!(SensitiveFields::decode(&unknown).is_err());
        let mut trailing = value.to_vec();
        trailing.push(0);
        assert!(SensitiveFields::decode(&trailing).is_err());
        assert!(SensitiveFields::new(vec!["bad:name".into()]).is_err());
    }

    #[test]
    fn only_the_target_pseudo_field_can_be_classified_sensitive() {
        let fields = SensitiveFields::new(vec![":path".into(), "x-key".into()]).unwrap();
        assert_eq!(
            SensitiveFields::from_extensions(&fields.extensions().unwrap()).unwrap(),
            Some(fields)
        );
        for other in [":authority", ":method", ":scheme", ":status"] {
            assert!(SensitiveFields::new(vec![other.into()]).is_err());
        }
    }
}
