// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SERDE FENCE for [`Secret`](crate::Secret) — a compile-time pin that a secret VALUE can

use super::*;

use core::marker::PhantomData;

/// A `Probe<T>` used to detect, at compile time, whether `T` implements a serde trait. The inherent
struct Probe<T>(PhantomData<T>);

trait ViaSerDefault {
    /// Trait default: reports NO `Serialize` impl. Shadowed by the inherent `ser()` when `T: Serialize`.
    fn ser(&self) -> bool {
        false
    }
}
impl<T> ViaSerDefault for Probe<T> {}
impl<T: serde::Serialize> Probe<T> {
    fn ser(&self) -> bool {
        true
    }
}

trait ViaDeDefault {
    /// Trait default: reports NO `Deserialize` impl. Shadowed by the inherent `de()` when
    fn de(&self) -> bool {
        false
    }
}
impl<T> ViaDeDefault for Probe<T> {}
impl<T: serde::de::DeserializeOwned> Probe<T> {
    fn de(&self) -> bool {
        true
    }
}

/// THE FENCE: `Secret<String>` implements neither `Serialize` nor `Deserialize`. Either half going
#[test]
fn redacted_implements_neither_serialize_nor_deserialize() {
    let secret_probe = Probe::<Secret<String>>(PhantomData);
    assert!(
        !secret_probe.ser(),
        "FENCE BREACH: Secret<T> must NOT implement serde::Serialize — a secret VALUE could now be \
         written into an audit record / wire payload / config dump / log line. Remove the impl."
    );
    assert!(
        !secret_probe.de(),
        "FENCE BREACH: Secret<T> must NOT implement serde::Deserialize — a secret VALUE could now be \
         reconstructed from untrusted wire/disk input. Remove the impl."
    );

    let control = Probe::<String>(PhantomData);
    assert!(
        control.ser(),
        "probe self-check: must detect a real Serialize impl (String is Serialize)"
    );
    assert!(
        control.de(),
        "probe self-check: must detect a real Deserialize impl (String is Deserialize)"
    );
}
