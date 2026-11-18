// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Opt-in autonomous polling through existing durable work custody. The host captures the
//! authenticated principal; this record contains no identity or credential. Polls are fresh
//! governed GET units and cannot repeat the paid creation request. Settle the work only after
//! the final result and its accounting receipt are durable.

const PREFIX: &[u8] = b"BBPOLL01";

/// Present with value `[1]` on `OnPiece` only when the host owns a live recovery scheduler
/// and durable private work custody. Require this before opening work or paid dispatch.
pub const CAPABILITY: &str = "work_recovery_v1";

pub fn supported(extensions: &[u8]) -> bool {
    matches!(
        crate::abi::mechanism::extensions::unique(extensions, CAPABILITY),
        Ok(Some([1]))
    )
}

/// Encode the local GET target for `Services::work_open`.
pub fn poll_record(target: &str) -> Result<Vec<u8>, &'static str> {
    if !valid_target(target)
        || PREFIX.len() + target.len() > crate::abi::host::service::MAX_WORK_RECORD
    {
        return Err("invalid or overlong recovery poll target");
    }
    let mut record = PREFIX.to_vec();
    record.extend_from_slice(target.as_bytes());
    Ok(record)
}

/// Decode an opt-in polling record. Ordinary opaque work records return `Ok(None)`.
pub fn poll_target(record: &[u8]) -> Result<Option<&str>, &'static str> {
    let Some(target) = record.strip_prefix(PREFIX) else {
        return Ok(None);
    };
    let target = std::str::from_utf8(target).map_err(|_| "invalid recovery poll target")?;
    if record.len() > crate::abi::host::service::MAX_WORK_RECORD || !valid_target(target) {
        return Err("invalid recovery poll target");
    }
    Ok(Some(target))
}

fn valid_target(target: &str) -> bool {
    target.starts_with('/')
        && !target.starts_with("//")
        && target.len() > 1
        && target
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'#' | b'\\'))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_poll_codec_is_local_bounded_and_opt_in() {
        let record = poll_record("/jobs/42?cursor=7").unwrap();
        assert_eq!(poll_target(&record), Ok(Some("/jobs/42?cursor=7")));
        assert_eq!(poll_target(b"ordinary work"), Ok(None));
        for target in [
            "https://example.test/job",
            "//example.test/job",
            "/a\nb",
            "/a#b",
            "/a\\b",
        ] {
            assert!(poll_record(target).is_err());
        }
        assert!(poll_record(&format!("/{}", "x".repeat(256))).is_err());
        assert!(poll_target(b"BBPOLL01bad").is_err());
        assert!(!supported(&[]));
        let enabled = crate::abi::mechanism::extensions::encode(&[(CAPABILITY, &[1])]);
        assert!(supported(&enabled));
        assert!(!supported(&enabled[..enabled.len() - 1]));
        assert!(!supported(&crate::abi::mechanism::extensions::encode(&[(
            CAPABILITY,
            &[0]
        )])));
    }
}
