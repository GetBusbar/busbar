// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exact historical SDK operation-body domains. Source: retained contract
//! dedupe.rs at 241065e0c1 (wide) and its parent (narrow/scale-aware). These are
//! comparison-only historical hashes, never current persistence receipts.
use crate::Error;
use busbar_contract::records::{MeteringDelta, UsageDelta};
use busbar_kernel::persistence::import_target::records::OriginalAccounting;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
enum Codec {
    Narrow,
    Wide,
}
struct Feed(Sha256);
impl Feed {
    fn u64(&mut self, v: u64) {
        self.0.update(v.to_le_bytes());
    }
    fn i64(&mut self, v: i64) {
        self.0.update(v.to_le_bytes());
    }
    fn i128(&mut self, v: i128) {
        self.0.update(v.to_le_bytes());
    }
    fn count(&mut self, v: usize) -> Result<(), Error> {
        self.u64(v.try_into().map_err(|_| Error::Bounds)?);
        Ok(())
    }
    fn bytes(&mut self, v: &[u8]) -> Result<(), Error> {
        self.count(v.len())?;
        self.0.update(v);
        Ok(())
    }
    fn text(&mut self, v: &str) -> Result<(), Error> {
        self.bytes(v.as_bytes())
    }
    fn usage(&mut self, d: &UsageDelta, codec: Codec, scaled: bool) -> Result<(), Error> {
        self.i64(d.requests);
        self.i64(d.billable_requests);
        self.count(d.models.len())?;
        for model in &d.models {
            if scaled {
                self.u64(u64::from(model.scale));
            }
            self.text(&model.model)?;
            self.count(model.usage_units.len())?;
            for (unit, count) in &model.usage_units {
                self.text(unit)?;
                match codec {
                    Codec::Wide => self.i128(*count),
                    Codec::Narrow => {
                        self.i64((*count).try_into().map_err(|_| Error::UnsupportedVersion)?)
                    }
                }
            }
        }
        Ok(())
    }
    fn metering(&mut self, d: &MeteringDelta, codec: Codec, scaled: bool) -> Result<(), Error> {
        if scaled {
            self.u64(u64::from(d.scale));
        }
        self.text(&d.key_id)?;
        self.u64(d.bucket);
        self.text(&d.model)?;
        self.text(&d.provider)?;
        for count in [
            d.tokens_input,
            d.tokens_output,
            d.tokens_cache_read,
            d.tokens_cache_write,
        ] {
            match codec {
                Codec::Wide => self.i128(count),
                Codec::Narrow => self.u64(count.try_into().map_err(|_| Error::UnsupportedVersion)?),
            }
        }
        self.u64(d.requests);
        self.u64(d.billable_requests);
        self.text(&d.key_group_at_use)?;
        self.text(&d.pricing_version)?;
        self.u64(d.priced_from_ms);
        self.count(d.usage_units.len())?;
        for (unit, count) in &d.usage_units {
            self.text(unit)?;
            match codec {
                Codec::Wide => self.i128(*count),
                Codec::Narrow => {
                    self.u64((*count).try_into().map_err(|_| Error::UnsupportedVersion)?)
                }
            }
        }
        Ok(())
    }
}
fn encode(values: &OriginalAccounting, codec: Codec) -> Result<[u8; 32], Error> {
    let quantities = !matches!(values, OriginalAccounting::CorrectionFingerprint(_));
    let scaled = match values {
        OriginalAccounting::Usage(cells) => cells
            .iter()
            .any(|(_, _, d)| d.models.iter().any(|m| m.scale != 0)),
        OriginalAccounting::Metering(rows) => rows.iter().any(|d| d.scale != 0),
        OriginalAccounting::CorrectionFingerprint(_) => false,
    };
    let mut feed = Feed(Sha256::new());
    let wide = matches!(codec, Codec::Wide) && quantities;
    feed.text(if wide {
        "busbar.store.op/3"
    } else if scaled {
        "busbar.store.op/2"
    } else {
        "busbar.store.op/1"
    })?;
    match values {
        OriginalAccounting::Usage(cells) => {
            feed.text("add_usage_batch")?;
            feed.count(cells.len())?;
            for (bucket, window, delta) in cells {
                feed.text(bucket)?;
                feed.u64(*window);
                feed.usage(delta, codec, wide || scaled)?;
            }
        }
        OriginalAccounting::Metering(rows) => {
            feed.text("add_metering_batch")?;
            feed.count(rows.len())?;
            for row in rows {
                feed.metering(row, codec, wide || scaled)?;
            }
        }
        OriginalAccounting::CorrectionFingerprint(digest) => {
            feed.text("busbar.store.usage-correction")?;
            feed.bytes(digest)?;
        }
    }
    Ok(feed.0.finalize().into())
}
#[cfg(test)]
fn matches(values: &OriginalAccounting, actual: &[u8; 32]) -> Result<bool, Error> {
    let wide = encode(values, Codec::Wide)?;
    if &wide == actual {
        return Ok(true);
    }
    match encode(values, Codec::Narrow) {
        Ok(narrow) => Ok(&narrow == actual),
        Err(Error::UnsupportedVersion) => Ok(false),
        Err(error) => Err(error),
    }
}
pub fn recognized_digests(values: &OriginalAccounting) -> Result<Vec<[u8; 32]>, Error> {
    let wide = encode(values, Codec::Wide)?;
    let mut digests = vec![wide];
    match encode(values, Codec::Narrow) {
        Ok(narrow) if narrow != wide => digests.push(narrow),
        Ok(_) | Err(Error::UnsupportedVersion) => {}
        Err(error) => return Err(error),
    }
    Ok(digests)
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_contract::records::ModelTokensDelta;
    #[test]
    fn synthetic_historical_domains_are_distinct_and_never_native_receipts() {
        let original = OriginalAccounting::Usage(vec![(
            "b".into(),
            60,
            UsageDelta {
                requests: 1,
                billable_requests: 1,
                models: vec![ModelTokensDelta {
                    scale: 0,
                    model: "m".into(),
                    usage_units: std::collections::BTreeMap::from([("input".into(), 7)]),
                }],
            },
        )]);
        let narrow = encode(&original, Codec::Narrow).unwrap();
        let wide = encode(&original, Codec::Wide).unwrap();
        assert_ne!(narrow, wide);
        assert!(matches(&original, &narrow).unwrap());
        assert!(matches(&original, &wide).unwrap());
        assert!(!matches(&original, &[0; 32]).unwrap());
        let huge = OriginalAccounting::Usage(vec![(
            "b".into(),
            60,
            UsageDelta {
                requests: 1,
                billable_requests: 1,
                models: vec![ModelTokensDelta {
                    scale: 6,
                    model: "m".into(),
                    usage_units: std::collections::BTreeMap::from([("input".into(), i128::MAX)]),
                }],
            },
        )]);
        assert!(matches!(
            encode(&huge, Codec::Narrow),
            Err(Error::UnsupportedVersion)
        ));
        assert!(matches(&huge, &encode(&huge, Codec::Wide).unwrap()).unwrap());
    }
}
