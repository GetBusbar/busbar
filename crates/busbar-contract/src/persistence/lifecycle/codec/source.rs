// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Strict protected logical-source chunks over the existing SourcePage payload.
use super::super::source::*;
use super::*;
use serde::{de::DeserializeOwned, Serialize};

const SOURCE_MAGIC: &[u8; 8] = b"BBSRC001";
fn family_tag(family: HistoricalFamily) -> u8 {
    match family {
        HistoricalFamily::Identity => 0,
        HistoricalFamily::Accounting => 1,
        HistoricalFamily::Archival => 2,
        HistoricalFamily::Audit => 3,
        HistoricalFamily::Evidence => 4,
    }
}
fn role_tag(role: AccountingRole) -> u8 {
    match role {
        AccountingRole::Fragment => 0,
        AccountingRole::Exact => 1,
        AccountingRole::Signed64Projection => 2,
        AccountingRole::ExactWithSigned64Projection => 3,
    }
}
struct JsonWriter(Writer);
impl std::io::Write for JsonWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .put(bytes)
            .map_err(|_| std::io::Error::other("source JSON budget"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn json<T: Serialize>(value: &T, bounds: Bounds) -> Result<Secret<Vec<u8>>, Error> {
    let mut writer = JsonWriter(Writer {
        out: Secret::new(Vec::new()),
        budget: Budget::new(bounds),
    });
    serde_json::to_writer(&mut writer, value).map_err(|_| Error::Bounds)?;
    Ok(writer.0.out)
}
impl Writer {
    fn json<T: Serialize>(&mut self, value: &T) -> Result<(), Error> {
        let encoded = json(value, self.budget.bounds)?;
        self.blob(&encoded.0)
    }
    fn text_value(&mut self, value: &str) -> Result<(), Error> {
        self.blob(value.as_bytes())
    }
    fn opt_text(&mut self, value: &Option<String>) -> Result<(), Error> {
        self.byte(u8::from(value.is_some()))?;
        if let Some(value) = value {
            self.text_value(value)?;
        }
        Ok(())
    }
    fn opt_u64(&mut self, value: Option<u64>) -> Result<(), Error> {
        self.byte(u8::from(value.is_some()))?;
        if let Some(value) = value {
            self.u64(value)?;
        }
        Ok(())
    }
    fn fact<O>(&mut self, fact: &HistoricalFact<O>) -> Result<(), Error> {
        match fact {
            HistoricalFact::Key { value, updated_at } => {
                self.byte(0)?;
                self.json(value)?;
                self.opt_u64(*updated_at)
            }
            HistoricalFact::Credential { meta, envelope } => {
                self.byte(1)?;
                self.json(meta)?;
                self.secret(envelope)
            }
            HistoricalFact::Denial {
                subject,
                reason,
                created_at,
            } => {
                self.byte(2)?;
                self.text_value(subject)?;
                self.text_value(reason)?;
                self.u64(*created_at)
            }
            HistoricalFact::Revision(value) => {
                self.byte(3)?;
                self.u64(*value)
            }
            HistoricalFact::Usage {
                bucket,
                window,
                model,
                requests,
                ledger,
                role,
            } => {
                self.byte(4)?;
                self.text_value(bucket)?;
                self.u64(*window)?;
                self.text_value(model)?;
                self.byte(match requests {
                    RequestAggregation::Dedicated => 0,
                    RequestAggregation::Sum => 1,
                })?;
                self.json(ledger)?;
                self.byte(role_tag(*role))
            }
            HistoricalFact::UsageUnit {
                bucket,
                window,
                model,
                unit,
                count,
                role,
            } => {
                self.byte(5)?;
                self.text_value(bucket)?;
                self.u64(*window)?;
                self.text_value(model)?;
                self.text_value(unit)?;
                self.put(&count.to_le_bytes())?;
                self.byte(role_tag(*role))
            }
            HistoricalFact::Metering { bucket, row, role } => {
                self.byte(6)?;
                self.u64(*bucket)?;
                self.json(row)?;
                self.byte(role_tag(*role))
            }
            HistoricalFact::MeteringUnit {
                bucket,
                key_id,
                provider,
                model,
                priced_from_ms,
                key_group_at_use,
                pricing_version,
                unit,
                count,
                role,
            } => {
                self.byte(7)?;
                self.u64(*bucket)?;
                self.text_value(key_id)?;
                self.text_value(provider)?;
                self.text_value(model)?;
                self.u64(*priced_from_ms)?;
                self.opt_text(key_group_at_use)?;
                self.opt_text(pricing_version)?;
                self.text_value(unit)?;
                self.put(&count.to_le_bytes())?;
                self.byte(role_tag(*role))
            }
            HistoricalFact::Audit(record) => {
                self.byte(8)?;
                self.json(record)
            }
            HistoricalFact::Record { schema, key, value } => {
                self.byte(9)?;
                self.text_value(schema)?;
                self.secret(key)?;
                self.secret(value)
            }
            HistoricalFact::History {
                kind,
                id,
                parent,
                sequence,
                timestamp,
                disposition,
                body,
                append,
            } => {
                self.byte(10)?;
                self.text_value(kind)?;
                self.text_value(id)?;
                self.opt_text(parent)?;
                self.u64(*sequence)?;
                self.u64(*timestamp)?;
                self.json(disposition)?;
                self.secret(body)?;
                self.byte(match append {
                    None => 0,
                    Some(false) => 1,
                    Some(true) => 2,
                })
            }
            HistoricalFact::Token {
                kind,
                token,
                expires_at,
            } => {
                self.byte(11)?;
                self.text_value(kind)?;
                self.secret(token)?;
                self.u64(*expires_at)
            }
            HistoricalFact::Receipt {
                operation,
                body,
                answer,
                recorded_at,
                expires_at_ms,
                historical_digest,
                completed_shape,
            } => {
                self.byte(12)?;
                self.put(operation)?;
                self.secret(body)?;
                self.secret(answer)?;
                self.opt_u64(*recorded_at)?;
                self.byte(u8::from(expires_at_ms.is_some()))?;
                if let Some(expiry) = expires_at_ms {
                    self.put(&expiry.to_le_bytes())?;
                }
                self.byte(u8::from(historical_digest.is_some()))?;
                if let Some(digest) = historical_digest {
                    self.put(digest)?;
                }
                self.byte(u8::from(*completed_shape))
            }
            HistoricalFact::EvidenceOnly => self.byte(13),
        }
    }
}
impl Reader<'_> {
    fn json<T: DeserializeOwned + Serialize>(&mut self) -> Result<T, Error> {
        let bytes = self.blob()?;
        let allocation = bytes
            .len()
            .checked_mul(64)
            .and_then(|n| n.checked_add(1024))
            .ok_or(Error::Bounds)?;
        self.budget.charge(0, allocation)?;
        let value = serde_json::from_slice(bytes).map_err(|_| Error::Corrupt)?;
        // Canonical DTO framing rejects ignored fields and ambiguous encodings.
        let canonical = json(&value, self.budget.bounds)?;
        valid(canonical.0 == bytes)?;
        Ok(value)
    }
    fn text_value(&mut self) -> Result<String, Error> {
        let bytes = self.blob()?;
        let text = std::str::from_utf8(bytes).map_err(|_| Error::Corrupt)?;
        let mut owned = String::new();
        owned
            .try_reserve_exact(text.len())
            .map_err(|_| Error::Bounds)?;
        owned.push_str(text);
        Ok(owned)
    }
    fn opt_text(&mut self) -> Result<Option<String>, Error> {
        if self.presence()? {
            self.text_value().map(Some)
        } else {
            Ok(None)
        }
    }
    fn opt_u64(&mut self) -> Result<Option<u64>, Error> {
        if self.presence()? {
            self.u64().map(Some)
        } else {
            Ok(None)
        }
    }
    fn role(&mut self) -> Result<AccountingRole, Error> {
        match self.byte()? {
            0 => Ok(AccountingRole::Fragment),
            1 => Ok(AccountingRole::Exact),
            2 => Ok(AccountingRole::Signed64Projection),
            3 => Ok(AccountingRole::ExactWithSigned64Projection),
            _ => Err(Error::Corrupt),
        }
    }
    fn i128(&mut self) -> Result<i128, Error> {
        Ok(i128::from_le_bytes(
            self.take(16)?.try_into().map_err(|_| Error::Corrupt)?,
        ))
    }
    fn fact<O>(
        &mut self,
        make: fn(Vec<u8>) -> Secret<Vec<u8>, O>,
    ) -> Result<HistoricalFact<O>, Error> {
        Ok(match self.byte()? {
            0 => HistoricalFact::Key {
                value: self.json()?,
                updated_at: self.opt_u64()?,
            },
            1 => HistoricalFact::Credential {
                meta: self.json()?,
                envelope: self.secret(make)?,
            },
            2 => HistoricalFact::Denial {
                subject: self.text_value()?,
                reason: self.text_value()?,
                created_at: self.u64()?,
            },
            3 => HistoricalFact::Revision(self.u64()?),
            4 => HistoricalFact::Usage {
                bucket: self.text_value()?,
                window: self.u64()?,
                model: self.text_value()?,
                requests: match self.byte()? {
                    0 => RequestAggregation::Dedicated,
                    1 => RequestAggregation::Sum,
                    _ => return Err(Error::Corrupt),
                },
                ledger: self.json()?,
                role: self.role()?,
            },
            5 => HistoricalFact::UsageUnit {
                bucket: self.text_value()?,
                window: self.u64()?,
                model: self.text_value()?,
                unit: self.text_value()?,
                count: self.i128()?,
                role: self.role()?,
            },
            6 => HistoricalFact::Metering {
                bucket: self.u64()?,
                row: self.json()?,
                role: self.role()?,
            },
            7 => HistoricalFact::MeteringUnit {
                bucket: self.u64()?,
                key_id: self.text_value()?,
                provider: self.text_value()?,
                model: self.text_value()?,
                priced_from_ms: self.u64()?,
                key_group_at_use: self.opt_text()?,
                pricing_version: self.opt_text()?,
                unit: self.text_value()?,
                count: self.i128()?,
                role: self.role()?,
            },
            8 => HistoricalFact::Audit(self.json()?),
            9 => HistoricalFact::Record {
                schema: self.text_value()?,
                key: self.secret(make)?,
                value: self.secret(make)?,
            },
            10 => HistoricalFact::History {
                kind: self.text_value()?,
                id: self.text_value()?,
                parent: self.opt_text()?,
                sequence: self.u64()?,
                timestamp: self.u64()?,
                disposition: self.json()?,
                body: self.secret(make)?,
                append: match self.byte()? {
                    0 => None,
                    1 => Some(false),
                    2 => Some(true),
                    _ => return Err(Error::Corrupt),
                },
            },
            11 => HistoricalFact::Token {
                kind: self.text_value()?,
                token: self.secret(make)?,
                expires_at: self.u64()?,
            },
            12 => HistoricalFact::Receipt {
                operation: self.take(16)?.try_into().map_err(|_| Error::Corrupt)?,
                body: self.secret(make)?,
                answer: self.secret(make)?,
                recorded_at: self.opt_u64()?,
                expires_at_ms: if self.presence()? {
                    Some(i64::from_le_bytes(
                        self.take(8)?.try_into().map_err(|_| Error::Corrupt)?,
                    ))
                } else {
                    None
                },
                historical_digest: if self.presence()? {
                    Some(self.take(32)?.try_into().map_err(|_| Error::Corrupt)?)
                } else {
                    None
                },
                completed_shape: self.presence()?,
            },
            13 => HistoricalFact::EvidenceOnly,
            _ => return Err(Error::Corrupt),
        })
    }
}
/// Encode one protected, bounded interpretation chunk. This grants no target authority.
pub fn encode_source_chunk<O>(
    chunk: &SourceChunk<O>,
    bounds: Bounds,
) -> Result<Secret<Vec<u8>>, Error> {
    valid(!chunk.group.0.is_empty())?;
    valid(!chunk.evidence.is_empty() || !chunk.facts.is_empty())?;
    let mut w = Writer::with_magic(bounds, SOURCE_MAGIC, 5, 0)?;
    w.source_reader(chunk.reader)?;
    w.byte(family_tag(chunk.family))?;
    w.secret(&chunk.group)?;
    w.u64(chunk.sequence)?;
    w.byte(u8::from(chunk.complete))?;
    w.budget.vector::<SourceEvidence<O>>(chunk.evidence.len())?;
    w.count(chunk.evidence.len())?;
    for evidence in &chunk.evidence {
        w.u32(evidence.table)?;
        w.secret(&evidence.native_key)?;
        w.id(&evidence.value_digest)?;
    }
    w.budget.vector::<HistoricalFact<O>>(chunk.facts.len())?;
    w.count(chunk.facts.len())?;
    for fact in &chunk.facts {
        valid(fact.family() == chunk.family)?;
        w.fact(fact)?;
    }
    Ok(w.out)
}
fn decode<O>(
    bytes: &[u8],
    bounds: Bounds,
    make: fn(Vec<u8>) -> Secret<Vec<u8>, O>,
) -> Result<SourceChunk<O>, Error> {
    let (mut r, tag) = Reader::with_magic(bytes, bounds, SOURCE_MAGIC, 5)?;
    valid(tag == 0)?;
    let reader = r.source_reader()?;
    let family = match r.byte()? {
        0 => HistoricalFamily::Identity,
        1 => HistoricalFamily::Accounting,
        2 => HistoricalFamily::Archival,
        3 => HistoricalFamily::Audit,
        4 => HistoricalFamily::Evidence,
        _ => return Err(Error::Corrupt),
    };
    let group = r.secret(make)?;
    valid(!group.0.is_empty())?;
    let sequence = r.u64()?;
    let complete = r.presence()?;
    let (mut evidence, count) = r.vector::<SourceEvidence<O>>()?;
    for _ in 0..count {
        evidence.push(SourceEvidence {
            table: r.u32()?,
            native_key: r.secret(make)?,
            value_digest: r.id()?,
        });
    }
    let (mut facts, count) = r.vector::<HistoricalFact<O>>()?;
    for _ in 0..count {
        let fact = r.fact(make)?;
        valid(fact.family() == family)?;
        facts.push(fact);
    }
    valid(!evidence.is_empty() || !facts.is_empty())?;
    r.end()?;
    Ok(SourceChunk {
        reader,
        family,
        group,
        sequence,
        complete,
        evidence,
        facts,
    })
}
/// Decode a bounded chunk in host-owned protected custody.
pub fn decode_source_chunk(bytes: &[u8], bounds: Bounds) -> Result<SourceChunk, Error> {
    decode(bytes, bounds, Secret::new)
}
/// Decode a bounded chunk in the receiving plugin owner's protected custody.
pub fn decode_source_chunk_owned<O: OwnerSeal>(
    bytes: &[u8],
    bounds: Bounds,
) -> Result<SourceChunk<O>, Error> {
    decode(bytes, bounds, Secret::held)
}

/// Encode a chunk while retaining the originating plugin owner's protected custody.
pub fn encode_source_chunk_owned<O: OwnerSeal>(
    chunk: &SourceChunk<O>,
    bounds: Bounds,
) -> Result<Secret<Vec<u8>, O>, Error> {
    let mut encoded = encode_source_chunk(chunk, bounds)?;
    Ok(Secret::held(std::mem::take(&mut encoded.0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    crate::own_seal!(Own);
    fn reader() -> SourceReader {
        SourceReader::new(
            SourceCodec::HistoricalV1,
            DocumentSemantics::Current,
            [4; 32],
        )
        .unwrap()
    }
    fn bounds() -> Bounds {
        Bounds {
            items: 32,
            bytes: 1024 * 1024,
        }
    }
    #[test]
    fn logical_facts_preserve_wide_quantities_and_exact_protected_receipts() {
        for fact in [
            HistoricalFact::UsageUnit {
                bucket: "test".into(),
                window: u64::MAX,
                model: "model".into(),
                unit: "unit".into(),
                count: i128::MAX,
                role: AccountingRole::Exact,
            },
            HistoricalFact::Receipt {
                operation: [8; 16],
                body: Secret::new(vec![0, 255, 1]),
                answer: Secret::new(vec![255, 0, 2]),
                recorded_at: Some(7),
                expires_at_ms: Some(-4),
                historical_digest: Some([9; 32]),
                completed_shape: false,
            },
        ] {
            let chunk = SourceChunk {
                reader: reader(),
                family: fact.family(),
                group: Secret::new(vec![1, 0, 255]),
                sequence: 0,
                complete: true,
                evidence: vec![SourceEvidence {
                    table: 3,
                    native_key: Secret::new(vec![0, 255]),
                    value_digest: [7; 32],
                }],
                facts: vec![fact],
            };
            let encoded = encode_source_chunk(&chunk, bounds()).unwrap();
            let decoded = decode_source_chunk(&encoded.0, bounds()).unwrap();
            assert_eq!(
                encode_source_chunk(&decoded, bounds()).unwrap().0,
                encoded.0
            );
            let owned = decode_source_chunk_owned::<Own>(&encoded.0, bounds()).unwrap();
            assert_eq!(encode_source_chunk(&owned, bounds()).unwrap().0, encoded.0);
            for cut in 0..encoded.0.len() {
                assert!(decode_source_chunk(&encoded.0[..cut], bounds()).is_err());
            }
            let mut extra = encoded.0.clone();
            extra.push(0);
            assert!(decode_source_chunk(&extra, bounds()).is_err());
            assert!(decode_source_chunk(
                &encoded.0,
                Bounds {
                    items: 1,
                    bytes: 1024
                }
            )
            .is_err());
        }
    }
    #[test]
    fn logical_facts_reject_cross_domain_claims_and_unknown_codecs() {
        let mut chunk = SourceChunk {
            reader: reader(),
            family: HistoricalFamily::Identity,
            group: Secret::new(vec![1]),
            sequence: 0,
            complete: true,
            evidence: vec![],
            facts: vec![HistoricalFact::Revision(3)],
        };
        let encoded = encode_source_chunk(&chunk, bounds()).unwrap();
        let mut invalid = encoded.0.clone();
        invalid[16] = 255;
        assert!(matches!(
            decode_source_chunk(&invalid, bounds()),
            Err(Error::UnsupportedFormat)
        ));
        chunk.family = HistoricalFamily::Accounting;
        assert!(matches!(
            encode_source_chunk(&chunk, bounds()),
            Err(Error::Corrupt)
        ));
        let mut invalid = encoded.0.clone();
        invalid[50] = 1;
        assert!(matches!(
            decode_source_chunk(&invalid, bounds()),
            Err(Error::Corrupt)
        ));
    }
}
