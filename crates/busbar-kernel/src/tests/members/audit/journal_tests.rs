// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::Pass;
use busbar_contract::caps::{Audit as AuditStep, MeterClassId};

use busbar_kernel_audit::journal::{from_journal_body, journal_body, JOURNAL_TAG};
use busbar_kernel_audit::record::{AuditBreakKind, AuditChain};
use busbar_kernel_audit::sign::AuditSigningKey;

fn declared(name: &str) -> Option<MeterClassId> {
    ["tokens_in", "tokens_out"]
        .into_iter()
        .find(|c| *c == name)
        .map(MeterClassId::new)
}

const SEALING_NODE: u64 = 13;

fn sealed(n: u64) -> Vec<busbar_kernel_audit::record::AuditRecord> {
    let key = AuditSigningKey::from_hex_seed(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    )
    .expect("the test seed is 64 lowercase hex");
    let mut chain = AuditChain::new().signing_with(key).sealing_as(SEALING_NODE);
    (1..=n)
        .map(|unit| {
            let mut inputs = super::sign_tests::rich_inputs(unit);
            inputs.what.incarnation = 3;
            busbar_kernel_audit::record::Audit::seal(
                &mut chain,
                inputs,
                &Pass::<AuditStep>::mint(&crate::seal::acquire()),
            )
        })
        .collect()
}

#[test]
fn a_signed_record_round_trips_through_its_journal_body() {
    for record in sealed(3) {
        let back = from_journal_body(&journal_body(&record).expect("the body fits"), &declared)
            .expect("the body decodes")
            .expect("the body is an audit record");
        assert_eq!(back, record, "the journal lost or changed a field");
        assert_eq!(back.node, SEALING_NODE, "the journal lost the sealing node");
        assert_eq!(AuditChain::digest_of(&back), record.hash);
    }
    let back: Vec<_> = sealed(3)
        .iter()
        .map(|r| {
            from_journal_body(&journal_body(r).expect("the body fits"), &declared)
                .unwrap()
                .unwrap()
        })
        .collect();
    assert!(
        AuditChain::verify_chain(&back).is_ok(),
        "the decoded run walks from genesis"
    );
}

#[test]
fn whole_fractional_whole_chain_keeps_v5_bytes_and_verifies_v6() {
    use busbar_kernel_audit::{Audit, AuditVerifyingKey, Recipe};
    let signer = AuditSigningKey::from_seed(&[73; 32]);
    let verify = AuditVerifyingKey::from_hex(&signer.public_key_hex()).unwrap();
    let mut chain = AuditChain::new()
        .signing_with(signer)
        .sealing_as(SEALING_NODE);
    let counts = ["120", "27.5", "121"];
    let records: Vec<_> = counts
        .iter()
        .enumerate()
        .map(|(index, count)| {
            let mut inputs = super::sign_tests::rich_inputs(index as u64 + 1);
            inputs.usage.lines[0].quantity = busbar_contract::Count::parse(count).unwrap();
            Audit::seal(
                &mut chain,
                inputs,
                &Pass::<AuditStep>::mint(&crate::seal::acquire()),
            )
        })
        .collect();
    assert_eq!(
        records.iter().map(|r| r.recipe.clone()).collect::<Vec<_>>(),
        vec![Recipe::V5, Recipe::V6, Recipe::V5]
    );
    let mut decoded = Vec::new();
    for (index, record) in records.iter().enumerate() {
        let bytes = journal_body(record).unwrap();
        if index != 1 {
            let whole = record.usage.lines[0]
                .quantity
                .whole_u64()
                .unwrap()
                .to_be_bytes();
            assert!(bytes.windows(8).any(|window| window == whole));
            assert!(bytes
                .windows(JOURNAL_TAG.len())
                .any(|window| window == JOURNAL_TAG.as_bytes()));
        }
        let back = from_journal_body(&bytes, &declared).unwrap().unwrap();
        assert_eq!(&back, record);
        assert_eq!(journal_body(&back).unwrap(), bytes);
        AuditChain::verify_signature(&back, &verify).unwrap();
        decoded.push(back);
    }
    AuditChain::verify_chain(&decoded).unwrap();
    let mut forged = journal_body(&records[1]).unwrap();
    let at = forged.windows(8).position(|b| b == b"audit.v6").unwrap();
    forged[at + 7] = b'5';
    assert!(
        from_journal_body(&forged, &declared).is_err(),
        "a tag never selects another recipe's quantity framing"
    );
}

#[test]
fn a_body_that_is_not_an_audit_record_is_none_and_a_torn_one_is_an_error() {
    assert_eq!(from_journal_body(b"posting/counts", &declared), Ok(None));
    let body = journal_body(&sealed(1)[0]).expect("the body fits");
    assert!(body.starts_with(&(JOURNAL_TAG.len() as u32).to_be_bytes()));
    assert!(from_journal_body(&body[..body.len() - 1], &declared).is_err());
    let mut longer = body.clone();
    longer.push(0);
    assert!(from_journal_body(&longer, &declared).is_err());
}

#[test]
fn a_class_nobody_declares_here_is_an_error_naming_it() {
    let body = journal_body(&sealed(1)[0]).expect("the body fits");
    let err = from_journal_body(&body, &|_| None).expect_err("no class resolves");
    assert!(err.contains("tokens_out"), "{err}");
}

#[test]
fn an_edited_journal_body_decodes_to_a_record_the_chain_walk_refuses() {
    let records = sealed(1);
    let mut body = journal_body(&records[0]).expect("the body fits");

    let needle = 120u64.to_be_bytes();
    let at = body
        .windows(8)
        .position(|w| w == needle)
        .expect("the quantity is in the body");
    body[at + 7] = 121;
    let tampered = from_journal_body(&body, &declared).unwrap().unwrap();
    assert_eq!(tampered.usage.lines[0].quantity, 121);
    assert_eq!(
        AuditChain::verify_chain(std::slice::from_ref(&tampered)).map_err(|b| b.kind),
        Err(AuditBreakKind::DigestMismatch)
    );
}

#[test]
fn an_outcome_tag_that_does_not_re_render_is_refused_never_remapped_in_a_sealed_body() {
    let body = journal_body(&sealed(1)[0]).expect("the body fits");
    let tag = b"Refused(Admit, OverBudget)";
    let at = body
        .windows(tag.len())
        .position(|w| w == tag)
        .expect("the outcome tag is in the body");
    let mut forged = body.clone();
    forged[at + tag.len() - 2] = b'T';
    assert!(
        from_journal_body(&forged, &declared).is_err(),
        "a body carrying a tag that does not re-render decoded"
    );
}

/// RECIPE V7 FRAMES WHOLE AND FRACTIONAL QUANTITIES ALIKE (ADMIN-API-1.6 §3.2): every new seal is
/// `v7`, whatever its quantities; each quantity is exact decimal text in the digest and in the
/// journal; and the unit facts `v7` adds are digested, kept by the journal and published by the
/// range read under their recipe names.
#[test]
fn v7_frames_whole_and_fractional_quantities() {
    use busbar_kernel_audit::recipe::DigestValue;
    use busbar_kernel_audit::record::{Attempt, AttemptOutcome, UnitFacts};
    use busbar_kernel_audit::{Audit, AuditVerifyingKey, Recipe};
    let signer = AuditSigningKey::from_seed(&[73; 32]);
    let verify = AuditVerifyingKey::from_hex(&signer.public_key_hex()).unwrap();
    let mut chain = AuditChain::new()
        .signing_with(signer)
        .sealing_as(SEALING_NODE);
    let counts = ["120", "27.5", "121"];
    let records: Vec<_> = counts
        .iter()
        .enumerate()
        .map(|(index, count)| {
            let mut inputs = super::sign_tests::rich_inputs(index as u64 + 1);
            inputs.usage.lines[0].quantity = busbar_contract::Count::parse(count).unwrap();
            inputs.unit = UnitFacts {
                wall_ms: 1_700_000_000_123 + index as u64,
                attribution: busbar_kernel_audit::attribution("team-a", "default", "acme"),
                boot_nonce: [0x5f; 16],
                status: 200,
                ttft_us: 0,
                total_us: 0,
                attempts: [
                    Some(Attempt {
                        outcome: AttemptOutcome::Failover,
                        target: "lane-a".into(),
                        reason: "upstream_5xx".into(),
                        us: 0,
                    }),
                    Some(Attempt {
                        outcome: AttemptOutcome::Ok,
                        target: "lane-b".into(),
                        reason: String::new(),
                        us: 7,
                    }),
                    None,
                    None,
                ],
                attempts_total: 2,
            };
            Audit::seal(
                &mut chain,
                inputs,
                &Pass::<AuditStep>::mint(&crate::seal::acquire()),
            )
        })
        .collect();
    assert!(
        records.iter().all(|r| r.recipe == Recipe::V7),
        "every new seal is v7, whole or fractional"
    );
    for (record, count) in records.iter().zip(counts) {
        let fields = super::digest_fields(record);
        let quantity = fields
            .iter()
            .find(|f| f.name == "lines[].quantity")
            .expect("a quantity is framed");
        assert_eq!(
            quantity.value,
            DigestValue::Text(count.to_string()),
            "the quantity is its exact decimal text"
        );
        let bytes = journal_body(record).unwrap();
        assert!(bytes.windows(8).any(|window| window == b"audit.v7"));
        let back = from_journal_body(&bytes, &declared).unwrap().unwrap();
        assert_eq!(&back, record, "the journal keeps every v7 fact");
        assert_eq!(journal_body(&back).unwrap(), bytes);
        AuditChain::verify_signature(&back, &verify).unwrap();
        assert_eq!(
            back.unit.attributed(),
            [Some("team-a"), Some("default"), Some("acme")]
        );
    }
    AuditChain::verify_chain(&records).unwrap();

    let mut forged = records[0].clone();
    forged.unit.wall_ms += 1;
    assert_ne!(AuditChain::digest_of(&forged), records[0].hash, "wall_ms");
    let mut forged = records[0].clone();
    forged.unit.attempts[1] = None;
    assert_ne!(AuditChain::digest_of(&forged), records[0].hash, "attempts");
    let mut forged = records[0].clone();
    forged.unit.attribution = busbar_kernel_audit::attribution("team-b", "default", "acme");
    assert_ne!(
        AuditChain::digest_of(&forged),
        records[0].hash,
        "attribution"
    );

    let mut torn = journal_body(&records[0]).unwrap();
    torn.pop();
    assert!(
        from_journal_body(&torn, &declared).is_err(),
        "a torn v7 tail"
    );

    let body: serde_json::Value = serde_json::from_str(&busbar_kernel_audit::expose::range_body(
        &chain, &records, 1, 3,
    ))
    .unwrap();
    assert_eq!(body["recipe"], "busbar.audit.digest.v7");
    let first = &body["records"][0];
    assert_eq!(first["recipe"], "busbar.audit.digest.v7");
    assert_eq!(first["lines"][0]["quantity"], "120");
    assert_eq!(first["wall_ms"], "1700000000123");
    assert_eq!(first["boot_nonce"], "5f".repeat(16));
    assert_eq!(first["status"], "200");
    assert_eq!(first["attempts_count"], "2");
    assert_eq!(first["attempts"][0]["outcome"], "failover");
    assert_eq!(first["attempts"][0]["reason"], "upstream_5xx");
    assert_eq!(first["attempts"][1]["us"], "7");
    assert_eq!(first["attempts_total"], "2");
    assert_eq!(body["records"][1]["lines"][0]["quantity"], "27.5");
}

/// THE UNIT ID (ADMIN-API-1.6 §3.4): `node_<16 hex>.<32 hex nonce>.<unit key>`, one formatter;
/// no id at all when the boot nonce is unavailable, or for a record sealed before `v7`.
#[test]
fn unit_id_null_without_boot_nonce() {
    use busbar_kernel_audit::record::UnitId;
    assert_eq!(UnitId::of(0x0123_4567_89ab_cdef, [0; 16], 42), None);
    let id = UnitId::of(0x0123_4567_89ab_cdef, [0x5f; 16], 42).unwrap();
    assert_eq!(
        id.to_string(),
        format!("node_0123456789abcdef.{}.42", "5f".repeat(16))
    );
    let mut record = sealed(1).remove(0);
    assert_eq!(record.unit_id(), None, "a seal with no nonce names no unit");
    record.unit.boot_nonce = [0x5f; 16];
    assert_eq!(
        record.unit_id().map(|id| id.to_string()),
        Some(format!(
            "node_{SEALING_NODE:016x}.{}.{}",
            "5f".repeat(16),
            record.what.unit_key.get()
        ))
    );
    record.recipe = busbar_kernel_audit::Recipe::V6;
    assert_eq!(record.unit_id(), None, "a record sealed before v7");
}
