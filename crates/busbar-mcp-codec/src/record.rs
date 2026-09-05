// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP PLANE'S OWN DURABLE RECORD TYPES — relocated here from `busbar-api` (1.7.0 plane
//! extraction). The neutral `busbar_api::Store` contract speaks ONLY the opaque
//! `busbar_api::PlaneRecord` envelope; a plane owns its concrete row schema and serializes it into
//! (and back out of) that envelope's opaque `body` with `serde_json` — byte-for-byte the same the
//! store plugins persist it with. The neutral crates name none of these types.

use busbar_api::{PlaneDisposition, PlaneRecord, PlaneSelector, StoreError, StoreResult};

/// The `call` kind — the MCP per-call log record's neutral `PlaneRecord.kind` tag.
pub const KIND_CALL: &str = "call";
/// The `demotion` kind — the MCP upstream-demotion record's neutral `PlaneRecord.kind` tag.
pub const KIND_DEMOTION: &str = "demotion";

/// One MCP TOOL-CALL record, as it crosses the store seam for DURABLE persistence — the per-call
/// evidence the audit claim rests on. The chain is scoped to the PRINCIPAL. A store persists these
/// verbatim and returns them verbatim: the digest is computed and verified engine-side, and a backend
/// never interprets or recomputes it. Plain data, never a credential — arguments and results are
/// deliberately ABSENT.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct McpCallRecord {
    /// The authenticated caller this chain belongs to. THE CHAIN SCOPE.
    pub principal: String,
    /// Monotonic sequence number, 1-based WITHIN `principal`.
    pub seq: u64,
    /// Unix seconds the call was attempted.
    pub ts: u64,
    /// The registered MCP server id the call resolved to, or empty when it resolved to none.
    pub server: String,
    /// `{server}_{tool}` — the namespaced routing key exactly as the call named it.
    pub tool: String,
    /// Stable outcome token: `dispatched` (the call went out) | `refused` (it did not).
    pub outcome: String,
    /// The reason token for this outcome, or empty. Never free text.
    pub reason: String,
    /// The tool digest the call was admitted against, or empty on a refusal that never reached one.
    pub tool_digest: String,
    /// The catalogue pin generation the call was resolved under.
    pub pin_generation: u64,
    /// The request-spine join key. EXCLUDED from the digest.
    pub request_id: String,
    /// The preceding record's `hash` for this principal (empty for the first of a chain).
    pub prev_hash: String,
    /// The tamper-evidence digest over this record's chained fields (computed + verified engine-side).
    pub hash: String,
}

impl McpCallRecord {
    // NB: there is deliberately NO plane-side `to_plane_record` WRITER for the call record. The
    // engine owns the append: a `call` chain is persisted ONLY as the neutral `{seq, prev_hash, hash,
    // content}` journal body (see [`Self::from_journal_body`]), NOT as a serde-serialized
    // `McpCallRecord`. A writer that serialized this struct into a `PlaneRecord` body would emit a
    // shape the actual reader (`from_journal_body`) cannot parse — a footgun, so it does not exist.
    // The plane owns only the READ-BACK of what the engine wrote.

    /// The list selector that reads one principal's `call` chain back, oldest-first.
    pub fn parent_selector(principal: &str) -> PlaneSelector {
        PlaneSelector::Parent(principal.to_string())
    }

    /// Reconstruct a record from an opaque serde `call` body — the inverse of a plain `serde_json`
    /// serialization of this struct. NOT the engine's persisted shape (that is the neutral journal
    /// body — see [`Self::from_journal_body`]); this decodes a bare `McpCallRecord` where one is held.
    pub fn from_body(body: &[u8]) -> StoreResult<Self> {
        decode(body)
    }

    /// Reconstruct a record from the NEUTRAL durable-journal body the engine's call-log seam persists
    /// — `{seq, prev_hash, hash, content}`, where `content` is the pre-framed LengthPrefixed field
    /// SUFFIX the record's digest was sealed over. This is the shape core's store-backed call journal
    /// writes (it carries no plane type), so a plane reading its own call chain back out of the store
    /// owns the decode; the field framing is the plane's (it travels with the record). `principal` is
    /// the chain SCOPE — the store parent — supplied by the caller and never carried in the body.
    /// `request_id` is a join key: never in the digest, so never in the neutral content, and it comes
    /// back EMPTY. The rebuilt fields feed the same digest byte stream the stored `hash` sealed, so a
    /// chain read back through this verifies byte-identically.
    pub fn from_journal_body(principal: &str, body: &[u8]) -> StoreResult<Self> {
        // The neutral envelope, decoded structurally (matching field names) so this names no core type.
        #[derive(serde::Deserialize)]
        struct NeutralJournalBody {
            seq: u64,
            prev_hash: String,
            hash: String,
            content: Vec<u8>,
        }
        let nb: NeutralJournalBody = decode(body)?;
        let (ts, server, tool, outcome, reason, tool_digest, pin_generation) =
            parse_call_suffix(&nb.content)?;
        Ok(McpCallRecord {
            principal: principal.to_string(),
            seq: nb.seq,
            ts,
            server,
            tool,
            outcome,
            reason,
            tool_digest,
            pin_generation,
            request_id: String::new(),
            prev_hash: nb.prev_hash,
            hash: nb.hash,
        })
    }
}

/// Parse the LengthPrefixed call SUFFIX (`ts, server, tool, outcome, reason, tool_digest,
/// pin_generation`) the neutral journal body carries — the inverse of the seam's write framing. Every
/// field is `len:u64-be ⧺ bytes`; a numeric field is its eight big-endian bytes carried as one such
/// length-prefixed field. Fails closed on a truncated/oversized field rather than reading past the
/// buffer.
fn parse_call_suffix(
    content: &[u8],
) -> StoreResult<(u64, String, String, String, String, String, u64)> {
    fn take<'a>(content: &'a [u8], off: &mut usize) -> StoreResult<&'a [u8]> {
        if *off + 8 > content.len() {
            return Err(StoreError(
                "truncated call suffix length prefix".to_string(),
            ));
        }
        let len = u64::from_be_bytes(content[*off..*off + 8].try_into().unwrap()) as usize;
        *off += 8;
        if *off + len > content.len() {
            return Err(StoreError("truncated call suffix field".to_string()));
        }
        let s = &content[*off..*off + len];
        *off += len;
        Ok(s)
    }
    fn take_num(content: &[u8], off: &mut usize) -> StoreResult<u64> {
        let arr: [u8; 8] = take(content, off)?
            .try_into()
            .map_err(|_| StoreError("call suffix num field is not 8 bytes".to_string()))?;
        Ok(u64::from_be_bytes(arr))
    }
    fn take_text(content: &[u8], off: &mut usize) -> StoreResult<String> {
        Ok(String::from_utf8_lossy(take(content, off)?).into_owned())
    }
    let mut off = 0usize;
    let ts = take_num(content, &mut off)?;
    let server = take_text(content, &mut off)?;
    let tool = take_text(content, &mut off)?;
    let outcome = take_text(content, &mut off)?;
    let reason = take_text(content, &mut off)?;
    let tool_digest = take_text(content, &mut off)?;
    let pin_generation = take_num(content, &mut off)?;
    Ok((
        ts,
        server,
        tool,
        outcome,
        reason,
        tool_digest,
        pin_generation,
    ))
}

/// ONE RECORDED DEMOTION of an upstream MCP server, as it crosses the store seam. Written when a
/// server is demoted, cleared when a later observation agrees with the approval again, and read back
/// at boot so the demotion is in force before the first request is served. Keyed by `server`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct McpDemotionRow {
    /// The registered upstream's local id — the row's primary key.
    pub server: String,
    /// The operator-facing word for why it was demoted. Never free-form caller text.
    pub reason: String,
    /// Unix seconds the demotion was recorded.
    pub recorded_at: u64,
}

impl McpDemotionRow {
    /// Serialize this row into the opaque `demotion` [`PlaneRecord`] envelope (kind `demotion`),
    /// keyed by its server. Demotions are never purged by age, so the disposition is left `Active`.
    pub fn to_plane_record(&self) -> StoreResult<PlaneRecord> {
        Ok(PlaneRecord {
            kind: KIND_DEMOTION.to_string(),
            id: self.server.clone(),
            parent: None,
            seq: 0,
            ts: self.recorded_at,
            disposition: PlaneDisposition::Active,
            body: encode(self)?,
        })
    }

    /// Reconstruct a row from an opaque `demotion` body — the inverse of [`Self::to_plane_record`].
    pub fn from_body(body: &[u8]) -> StoreResult<Self> {
        decode(body)
    }
}

/// Serialize a typed plane row into an opaque `PlaneRecord::body`. `serde_json`.
fn encode<T: serde::Serialize>(row: &T) -> StoreResult<Vec<u8>> {
    serde_json::to_vec(row).map_err(|e| StoreError(format!("plane body encode: {e}")))
}

/// Decode an opaque `PlaneRecord::body` back into its typed plane row — the inverse of [`encode`].
fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> StoreResult<T> {
    serde_json::from_slice(body).map_err(|e| StoreError(format!("plane body decode: {e}")))
}

#[cfg(test)]
#[path = "tests/record_tests.rs"]
mod record_tests;
