// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::framer::{Call, Crossed, DoorFacts, FramerDoor};
use std::sync::Mutex;

struct Observed {
    inner: Arc<crate::support::PendingDoor>,
    emits: Mutex<Vec<(u64, bool, Vec<u8>)>>,
}

impl Observed {
    fn note(&self, resume: bool, call: &Call<'_>) {
        if let Call::Emit(input, _) = call {
            let extension = input.head.extensions;
            let bytes = if extension.len == 0 {
                Vec::new()
            } else {
                // SAFETY: the connector lends the complete extension for this crossing.
                unsafe { std::slice::from_raw_parts(extension.ptr, extension.len) }.to_vec()
            };
            self.emits
                .lock()
                .unwrap()
                .push((input.stream, resume, bytes));
        }
    }
}

impl FramerDoor for Observed {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        self.note(false, &call);
        self.inner.cross(call)
    }
    fn framing_side(&self) -> Option<Box<dyn crate::carrier::Side>> {
        self.inner.framing_side()
    }
    fn cross_on(&self, side: &dyn crate::carrier::Side, resume: bool, call: Call<'_>) -> Crossed {
        self.note(resume, &call);
        self.inner.cross_on(side, resume, call)
    }
}

fn named(fields: &[u8], name: &str) -> bool {
    let Some(value) = busbar_contract::abi::mechanism::extensions::get(fields, "fields.sensitive")
    else {
        return false;
    };
    let mut expected = 1_u32.to_le_bytes().to_vec();
    expected.extend_from_slice(&1_u32.to_le_bytes());
    expected.extend_from_slice(&(name.len() as u32).to_le_bytes());
    expected.extend_from_slice(name.as_bytes());
    value == expected
}

#[test]
fn trusted_names_survive_unsealed_encoding_early_writes_and_a_pending_opening_emit() {
    worker().block_on(async {
        let far = echo().await;
        let inner = Arc::new(crate::support::PendingDoor::new(
            TestDoor::new(
                "bytes",
                &["bytes"],
                &[],
                Knobs {
                    render_fields: true,
                    ..Knobs::default()
                },
            ),
            EXCHANGE_STREAM,
        ));
        let door = Arc::new(Observed {
            inner: inner.clone(),
            emits: Mutex::new(Vec::new()),
        });
        let mut d = dial(&far);
        d.opening = Some((
            vec![
                ("x-api-key".into(), b"dummy-first".to_vec()),
                (
                    busbar_contract::conn::SEALED_FIELDS_FIELD.into(),
                    b"X-Api-Key".to_vec(),
                ),
            ],
            b"first".to_vec().into(),
        ));
        let mut c = Connection::dial(door.clone(), &crate::support::via(), d).unwrap();
        c.open_exchange(
            3,
            Some((
                vec![
                    ("x-second".into(), b"dummy-second".to_vec()),
                    (
                        busbar_contract::conn::SEALED_FIELDS_FIELD.into(),
                        b"x-second".to_vec(),
                    ),
                ],
                b"second".to_vec().into(),
            )),
            HeadWords::default(),
            &mut std::task::Context::from_waker(std::task::Waker::noop()),
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), next(&mut c))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        {
            let emits = door.emits.lock().unwrap();
            assert!(emits.iter().any(|(stream, resume, fields)| *stream == 1
                && !resume
                && named(fields, "x-api-key")));
            assert!(emits
                .iter()
                .any(|(stream, _, fields)| *stream == 3 && named(fields, "x-second")));
            assert!(!emits
                .iter()
                .any(|(stream, _, fields)| *stream == 3 && named(fields, "x-api-key")));
        }
        inner.host.complete(1);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if door
                    .emits
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(stream, resume, fields)| {
                        *stream == 1 && *resume && named(fields, "x-api-key")
                    })
                {
                    break;
                }
                next(&mut c).await.unwrap().unwrap();
            }
        })
        .await
        .unwrap();
    });
}
