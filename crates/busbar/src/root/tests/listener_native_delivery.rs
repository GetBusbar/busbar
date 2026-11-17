// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[tokio::test]
async fn abandoned_delivered_registration_ack_cancels_original_cell_without_eof() {
    let (_fixture, service, mut ledger) = crate::root::durability::response_intent_tests::rig().await;
    let connection = service.connection().unwrap();
    let key = connection.key(1, None).unwrap();
    let handles = ledger.admit(key).unwrap();
    let watch = handles.watch.clone();
    let (send, receiver) = oneshot::channel();
    assert!(send.send(Ok(handles)).is_ok());
    drop(RegistrationAck { receiver });
    assert_eq!(watch.key(), key);
    assert_eq!(watch.cancellation(), Some(ResponseStop::Cancelled));
    assert!(watch.snapshot().terminal.is_none(), "cancellation cannot manufacture delivery or EOF");
}
