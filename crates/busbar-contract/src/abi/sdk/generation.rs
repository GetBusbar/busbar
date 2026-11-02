// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GENERATION BORROW follows the shared memory rule: plugin-owned returned memory remains

use std::marker::PhantomData;

/// THE GENERATION BORROW one op is lent: what is borrowed for `'g` lives at least until the
/// instance's next refresh generation. Only the SDK makes one, and it is INVARIANT in `'g`, so it
/// can be neither shortened to a local's lifetime nor stretched past the instance's.
///
/// RED: a string of the call's own does not outlive the op's generation borrow.
///
/// ```compile_fail,E0597
/// use busbar_contract::abi::mechanism::call::AbiStr;
/// use busbar_contract::abi::sdk::Instance;
/// fn body(instance: Instance<'_, String>) {
///     let gen = instance.generation();
///     let local = String::from("echo");
///     let _named = AbiStr::lent(&local, &gen);
/// }
/// ```
///
/// GREEN, its twin: the instance state's string does.
///
/// ```
/// use busbar_contract::abi::mechanism::call::AbiStr;
/// use busbar_contract::abi::sdk::Instance;
/// fn body(instance: Instance<'_, String>) {
///     let gen = instance.generation();
///     let state = instance.get().map_or("", String::as_str);
///     let _named = AbiStr::lent(state, &gen);
/// }
/// ```
///
/// RED: nor does a string the host lent the call.
///
/// ```compile_fail
/// use busbar_contract::abi::auth::BeginLoginIn;
/// use busbar_contract::abi::mechanism::call::AbiStr;
/// use busbar_contract::abi::sdk::{Instance, Lent};
/// fn body(instance: Instance<'_, String>, input: Lent<'_, BeginLoginIn>) {
///     let gen = instance.generation();
///     let lent = input.state().as_str().unwrap_or("");
///     let _named = AbiStr::lent(lent, &gen);
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Gen<'g> {
    /// `fn(&'g ()) -> &'g ()`: invariant in `'g`.
    _g: PhantomData<fn(&'g ()) -> &'g ()>,
}

impl<'g> Gen<'g> {
    /// The borrow for `'g`.
    ///
    /// # Safety
    ///
    /// Every value safe code can hold borrowed for `'g` lives at least until the next refresh
    /// generation of the instance the op serves: the instance's own state, or the program's
    /// memory.
    pub(crate) const unsafe fn assume() -> Self {
        Gen { _g: PhantomData }
    }
}
