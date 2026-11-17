// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::governance::unit_checkpoint::partitions::Disposition;
use crate::plane_driver::usage::Ending;
use busbar_contract::response_delivery::{DeliverySnapshot, DeliveryTerminal, ResponseStop};

#[test]
fn selected_work_end_is_distinct_from_late_transport_cut() {
    let facts = delivery_facts(
        Ending::End,
        DeliverySnapshot {
            first_payload_written: true,
            terminal: Some(DeliveryTerminal::Failed(ResponseStop::Cancelled)),
        },
    )
    .unwrap();
    assert_eq!(facts, (Disposition::End, true, true));
}

#[test]
fn selected_cancel_uses_actual_payload_and_requires_frozen_terminal() {
    let ending = Ending::Cancel {
        cause: busbar_contract::caps::ReasonCode::ClientGone,
        far_end_answered: true,
        streamed: true,
    };
    assert!(delivery_facts(
        ending,
        DeliverySnapshot {
            first_payload_written: true,
            terminal: None
        }
    )
    .is_err());
    let (_, written, cut) = delivery_facts(
        ending,
        DeliverySnapshot {
            first_payload_written: false,
            terminal: Some(DeliveryTerminal::Failed(ResponseStop::Cancelled)),
        },
    )
    .unwrap();
    assert!(
        !written,
        "legacy streamed/queue observation cannot create a payload write"
    );
    assert!(cut);
}
