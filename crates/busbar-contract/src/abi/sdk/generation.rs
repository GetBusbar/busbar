// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GENERATION BORROW (status row 194; `BUSBAR-1.6.0.md` THE DESIGN, the shared mechanism's
//! memory rule: memory a plugin returns is plugin-owned and valid until that plugin's next refresh
//! generation). The SDK lends every op a [`Gen<'g>`]: a proof, which only the SDK can make, that
//! what is borrowed for `'g` lives at least until the instance's next refresh generation. The
//! runtime writers of the ABI's strings and payloads take one beside the memory they name
//! ([`AbiStr::lent`](crate::abi::mechanism::call::AbiStr::lent),
//! [`Blob::lent`](crate::abi::mechanism::call::Blob::lent),
//! [`Out::lent_str`](super::Out::lent_str)),
//! so the borrow checker, not a reviewer, holds an `out`'s contents to memory that outlives every
//! read the host makes of it.
//!
//! A slot body reaches its op's borrow through its instance
//! ([`Instance::generation`](super::Instance::generation)): `'g` is the instance's own lifetime,
//! which the instance state (`Instance::get`) lives for and nothing of the call's does. A string the
//! state owns is accepted; a local, or a string the host lent the call, is refused at compile time.
//! A plugin crate stays `#![forbid(unsafe_code)]`: none of this asks it for `unsafe`.

use std::marker::PhantomData;

/// THE GENERATION BORROW one op is lent: what is borrowed for `'g` lives at least until the
/// instance's next refresh generation. Only the SDK makes one, and it is INVARIANT in `'g`, so it
/// can be neither shortened to a local's lifetime nor stretched past the instance's.
///
/// RED (status row 194): a string of the call's own does not outlive the op's generation borrow.
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
