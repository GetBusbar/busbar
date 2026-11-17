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
