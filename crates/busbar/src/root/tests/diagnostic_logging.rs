// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

fn catalogue() -> busbar_kernel::diagnostics::Catalogue {
    use busbar_contract::diagnostic::{Class, Diagnostic, Severity};
    static FIXTURE: Diagnostic = Diagnostic {
        code: 4998,
        class: Class::Auth,
        slug: "fixture-declared",
        title: "Fixture diagnostic",
        severity: Severity::Actionable,
        summary: "A neutral fixture operation failed.",
        action: "Inspect the fixture.",
        since: "1.6.0",
        retired: false,
    };
    busbar_kernel::diagnostics::Catalogue::lent(&[&FIXTURE])
}

fn capture_log(max_level: tracing::Level, f: impl FnOnce()) -> Vec<String> {
    use tracing_subscriber::layer::SubscriberExt as _;
    struct Events {
        max_level: tracing::Level,
        messages: Arc<std::sync::Mutex<Vec<String>>>,
    }
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Events {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() > self.max_level {
                return;
            }
            #[derive(Default)]
            struct Fields {
                message: String,
                fields: Vec<String>,
            }
            impl Fields {
                fn record(&mut self, field: &tracing::field::Field, text: String) {
                    if field.name() == "message" {
                        self.message = text;
                    } else {
                        self.fields.push(format!("{}={text}", field.name()));
                    }
                }
            }
            impl tracing::field::Visit for Fields {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.record(field, format!("{value:?}"));
                }
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    self.record(field, value.to_string());
                }
            }
            let mut fields = Fields::default();
            event.record(&mut fields);
            self.messages.lock().unwrap().push(
                format!("{} {}", fields.message, fields.fields.join(" "))
                    .trim_end()
                    .to_owned(),
            );
        }
    }
    let messages = Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(Events {
        max_level,
        messages: messages.clone(),
    });
    tracing::subscriber::with_default(subscriber, f);
    let captured = messages.lock().unwrap().clone();
    captured
}

fn main_log(f: impl FnOnce()) -> Vec<String> {
    capture_log(tracing::Level::DEBUG, f)
}

#[test]
fn the_main_log_sink_writes_a_declared_diagnostic_in_its_one_five_five_shape() {
    use crate::root::loader::dispatch::{Diagnostic, EnvelopeSink, NoSink};
    let sink = crate::root::door_steps::MainLogSink(Arc::new(NoSink), catalogue());
    let got = main_log(|| {
        sink.diag(Diagnostic {
            id: 2,
            name: b"BUSBAR-4998",
            severity: 1,
            text: b"Fixture operation failed; will retry error=connect: refused (os error 111)",
        });
        sink.diag(Diagnostic {
            id: busbar_contract::abi::mechanism::call::DIAG_LOG,
            name: b"",
            severity: 1,
            text: b"the plugin's own record",
        });
    });
    assert_eq!(
        got,
        vec![
            "Fixture operation failed; will retry diag=BUSBAR-4998 error=connect: refused (os \
             error 111)"
                .to_string()
        ]
    );
}

#[test]
fn a_declared_line_raised_at_warn_is_written_at_warn_under_a_live_actionable_entry() {
    use crate::root::loader::dispatch::{Diagnostic, EnvelopeSink, NoSink};
    use busbar_contract::diagnostic::Severity;
    let sink = crate::root::door_steps::MainLogSink(Arc::new(NoSink), catalogue());
    for code in [4998u16] {
        let entry = catalogue()
            .by_code(code)
            .unwrap_or_else(|| panic!("BUSBAR-{code:04} is in the catalogue"));
        assert!(
            !entry.retired,
            "BUSBAR-{code:04} is raised by the fixture, so its entry is not retired"
        );
        assert_eq!(
            entry.severity,
            Severity::Actionable,
            "BUSBAR-{code:04} is raised at warn, so its entry is actionable"
        );
        let name = format!("BUSBAR-{code:04}");

        let messages = capture_log(tracing::Level::WARN, || {
            sink.diag(Diagnostic {
                id: 0,
                name: name.as_bytes(),
                severity: 1,
                text: b"a raised fixture line",
            });
        });
        assert_eq!(
            messages,
            vec![format!("a raised fixture line diag={name}")],
            "the main log writes {name} at the warn it was raised at"
        );
    }
}
