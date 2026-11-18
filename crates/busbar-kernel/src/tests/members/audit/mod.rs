// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod amend_tests;
mod digest_framing_tests;
mod journal_tests;
mod link_tests;
mod published_recipe_tests;
mod record_tests;
mod restart_walk_tests;
mod sign_tests;
mod stamp_tests;
mod subject_decoder_tests;

/// The published link recipe (SEALING-FIX §3, `busbar.audit.link.v1`/`v2`), recomputed from the
/// record's published field list alone: SHA-256 over every field but the last, each framed by its
/// big-endian eight-byte length, then the predecessor's 32 raw fingerprint bytes framed the same
/// way. Since SF-4 part 2 (4bc8cfec86) every sealed line is a link line.
pub(super) fn published_link_digest(record: &busbar_kernel_audit::record::AuditRecord) -> String {
    use busbar_kernel_audit::digest::{Digest, Framing};
    use busbar_kernel_audit::recipe::DigestValue;
    let fields = digest_fields(record);
    let (last, content) = fields.split_last().expect("a line has fields");
    assert_eq!(
        last.name, "prev_hash",
        "a link line ends with its predecessor"
    );
    let mut framed = Digest::new(Framing::LengthPrefixed);
    for field in content {
        match &field.value {
            DigestValue::Text(text) => framed.text(text),
            DigestValue::Num(n) => framed.num(*n),
        };
    }
    let prev = busbar_kernel_audit::Fingerprint::from_hex(&record.prev_hash)
        .expect("a fingerprint or the genesis");
    framed.raw(&32u64.to_be_bytes()).raw(&prev.0);
    busbar_kernel_audit::Fingerprint(busbar_contract::crypto::sha256(&framed.into_framed()))
        .to_string()
}

/// Every field of one record's digest, in order, as owned values a test can index and compare.
pub(super) fn digest_fields(
    record: &busbar_kernel_audit::record::AuditRecord,
) -> Vec<busbar_kernel_audit::recipe::DigestField> {
    use busbar_kernel_audit::recipe::{visit_fields, DigestField, DigestValue, FieldSink};
    struct Fields(Vec<DigestField>);
    impl FieldSink for Fields {
        fn text(&mut self, name: &'static str, value: &str) {
            self.0.push(DigestField {
                name,
                value: DigestValue::Text(value.to_owned()),
            });
        }
        fn text_fmt(&mut self, name: &'static str, value: std::fmt::Arguments<'_>) {
            self.0.push(DigestField {
                name,
                value: DigestValue::Text(value.to_string()),
            });
        }
        fn num(&mut self, name: &'static str, value: u64) {
            self.0.push(DigestField {
                name,
                value: DigestValue::Num(value),
            });
        }
    }
    let mut fields = Fields(Vec::new());
    visit_fields(record, &mut fields);
    fields.0
}
