// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SINGLE-PATH SP-AU6: the caller's verified secret is copied into kernel custody once, at
//! `CallerCredential::verified`; the unit's transport-custody `Secret<String>` moves into the
//! claimed request instead of being copied, and every later holder shares the one zeroising
//! buffer. Counted by the dev-only stage probe (`Derive::SecretCopy`) on the actual inbound host.

use super::*;
use busbar_contract::stage_probe::{Derive, Scope};

#[tokio::test(flavor = "current_thread")]
async fn caller_secret_has_one_plaintext_buffer() {
    let scope = Scope::open();
    let (k, unit, admission, _script) = transfer_request();
    let _ = crate::auth::admitted_context(&admission).await;

    assert_eq!(
        scope.count(Derive::SecretCopy),
        1,
        "from the claim to the host context the caller secret is copied once, into the kernel's \
         one zeroising buffer"
    );
    assert!(
        k.inbound.with_credential(unit.id, |_| ()).is_none(),
        "the claim takes the unit's credential into the claimed request; no copy stays behind"
    );
}
