// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core's side of the interface (IF §10, feature `host`), reached as `busbar_plugin_abi::host::*`.

pub mod answer;
pub mod caller;
pub mod driver;
pub mod entry;
pub mod host_vt;
pub mod needs;
pub mod pool;
pub mod proxy;
pub mod scrub;
pub mod watch;

/// The shared permanent native lifecycle owner, including scoped Send borrowing.
///
/// The public SDK path preserves both callback and result Send requirements.
///
/// ```
/// let mut value = String::from("borrowed");
/// busbar_plugin_abi::host_side::lifecycle::run(|| value.push_str(" result")).unwrap();
/// assert_eq!(
///     busbar_plugin_abi::host_side::lifecycle::run(|| value.as_str()).unwrap(),
///     "borrowed result",
/// );
/// ```
///
/// ```compile_fail,E0277
/// let value = std::rc::Rc::new(1);
/// busbar_plugin_abi::host_side::lifecycle::run(move || drop(value));
/// ```
///
/// ```compile_fail,E0277
/// busbar_plugin_abi::host_side::lifecycle::run(|| std::rc::Rc::new(1));
/// ```
///
/// ```compile_fail,E0277
/// let lock = std::sync::Mutex::new(());
/// let guard = lock.lock().unwrap();
/// busbar_plugin_abi::host_side::lifecycle::run(move || drop(guard));
/// ```
pub use busbar_ffi::lifecycle;

pub use answer::*;
pub use caller::*;
pub use driver::*;
pub use host_vt::*;
pub use needs::*;
pub use pool::*;
pub use scrub::*;
pub use watch::*;
