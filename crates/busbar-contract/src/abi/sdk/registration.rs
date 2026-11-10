// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Static operation completeness for SDK-authored doors. The loader independently validates
//! foreign tables and all declarations that become known only when an instance opens.

//! Compiler witnesses exercise the actual public door macro. Each complete example has a
//! negative twin missing exactly one mandatory operation; unrelated compile failures do not
//! count as a refusal in the trusted architecture witness runner.
//!
//! ```
//! // SDK_REGISTRATION_WITNESS store complete
//! use busbar_contract::abi::{mechanism::call::Outcome, sdk::door::{KindOps, KindSlot, RawSlot, statement}};
//! use busbar_contract::abi::store::v4::{Ops, slot};
//! struct Operation<T, const N: u32>(std::marker::PhantomData<T>);
//! impl<T: KindSlot<N>, const N: u32> RawSlot for Operation<T, N> {
//!     type Kind = <Ops as KindOps>::Marker;
//!     type In = <T as KindSlot<N>>::In;
//!     type Out = <T as KindSlot<N>>::Out;
//!     unsafe fn call(_: *mut std::ffi::c_void, _: &Self::In, _: &mut Self::Out) -> Outcome { Outcome::Refused }
//! }
//! type Life = <Ops as KindOps>::Lifecycle;
//! busbar_contract::plugin_door! {
//!     ops: Ops,
//!     statement: statement("registration-store", "1", 1),
//!     lifecycle: {
//!         validate: Operation<Life, 0>,
//!         open: Operation<Life, 1>,
//!         refresh: Operation<Life, 2>,
//!         retire: Operation<Life, 3>,
//!         tick: Operation<Life, 4>,
//!         drive: Operation<Life, 5>,
//!         cancel: Operation<Life, 6>,
//!         release: Operation<Life, 7>,
//!         close: Operation<Life, 8>,
//!     },
//!     kind_ops: {
//!         read: Operation<Ops, {slot::READ}>,
//!         scan: Operation<Ops, {slot::SCAN}>,
//!         commit: Operation<Ops, {slot::COMMIT}>,
//!         clock: Operation<Ops, {slot::CLOCK}>,
//!         bootstrap: Operation<Ops, {slot::BOOTSTRAP}>,
//!     },
//! }
//! fn main() { let _ = door(); }
//! ```
//!
//! ```compile_fail,E0080
//! // SDK_REGISTRATION_WITNESS store missing
//! use busbar_contract::abi::{mechanism::call::Outcome, sdk::door::{KindOps, KindSlot, RawSlot, statement}};
//! use busbar_contract::abi::store::v4::{Ops, slot};
//! struct Operation<T, const N: u32>(std::marker::PhantomData<T>);
//! impl<T: KindSlot<N>, const N: u32> RawSlot for Operation<T, N> {
//!     type Kind = <Ops as KindOps>::Marker;
//!     type In = <T as KindSlot<N>>::In;
//!     type Out = <T as KindSlot<N>>::Out;
//!     unsafe fn call(_: *mut std::ffi::c_void, _: &Self::In, _: &mut Self::Out) -> Outcome { Outcome::Refused }
//! }
//! type Life = <Ops as KindOps>::Lifecycle;
//! busbar_contract::plugin_door! {
//!     ops: Ops,
//!     statement: statement("registration-store", "1", 1),
//!     lifecycle: {
//!         validate: Operation<Life, 0>,
//!         open: Operation<Life, 1>,
//!         refresh: Operation<Life, 2>,
//!         retire: Operation<Life, 3>,
//!         tick: Operation<Life, 4>,
//!         drive: Operation<Life, 5>,
//!         cancel: Operation<Life, 6>,
//!         release: Operation<Life, 7>,
//!         close: Operation<Life, 8>,
//!     },
//!     kind_ops: {
//!         scan: Operation<Ops, {slot::SCAN}>,
//!         commit: Operation<Ops, {slot::COMMIT}>,
//!         clock: Operation<Ops, {slot::CLOCK}>,
//!         bootstrap: Operation<Ops, {slot::BOOTSTRAP}>,
//!     },
//! }
//! fn main() { let _ = door(); }
//! ```
//!
//! ```
//! // SDK_REGISTRATION_WITNESS secret complete
//! use busbar_contract::abi::{mechanism::call::Outcome, sdk::door::{KindOps, KindSlot, RawSlot, statement}};
//! use busbar_contract::abi::secret::{Ops, slot};
//! struct Operation<T, const N: u32>(std::marker::PhantomData<T>);
//! impl<T: KindSlot<N>, const N: u32> RawSlot for Operation<T, N> {
//!     type Kind = <Ops as KindOps>::Marker;
//!     type In = <T as KindSlot<N>>::In;
//!     type Out = <T as KindSlot<N>>::Out;
//!     unsafe fn call(_: *mut std::ffi::c_void, _: &Self::In, _: &mut Self::Out) -> Outcome { Outcome::Refused }
//! }
//! type Life = <Ops as KindOps>::Lifecycle;
//! busbar_contract::plugin_door! {
//!     ops: Ops,
//!     statement: statement("registration-secret", "1", 1),
//!     lifecycle: {
//!         validate: Operation<Life, 0>,
//!         open: Operation<Life, 1>,
//!         refresh: Operation<Life, 2>,
//!         retire: Operation<Life, 3>,
//!         tick: Operation<Life, 4>,
//!         drive: Operation<Life, 5>,
//!         cancel: Operation<Life, 6>,
//!         release: Operation<Life, 7>,
//!         close: Operation<Life, 8>,
//!     },
//!     kind_ops: {
//!         resolve: Operation<Ops, {slot::RESOLVE}>,
//!     },
//! }
//! fn main() { let _ = door(); }
//! ```
//!
//! ```compile_fail,E0080
//! // SDK_REGISTRATION_WITNESS secret missing
//! use busbar_contract::abi::{mechanism::call::Outcome, sdk::door::{KindOps, KindSlot, RawSlot, statement}};
//! use busbar_contract::abi::secret::{Ops, slot};
//! struct Operation<T, const N: u32>(std::marker::PhantomData<T>);
//! impl<T: KindSlot<N>, const N: u32> RawSlot for Operation<T, N> {
//!     type Kind = <Ops as KindOps>::Marker;
//!     type In = <T as KindSlot<N>>::In;
//!     type Out = <T as KindSlot<N>>::Out;
//!     unsafe fn call(_: *mut std::ffi::c_void, _: &Self::In, _: &mut Self::Out) -> Outcome { Outcome::Refused }
//! }
//! type Life = <Ops as KindOps>::Lifecycle;
//! busbar_contract::plugin_door! {
//!     ops: Ops,
//!     statement: statement("registration-secret", "1", 1),
//!     lifecycle: {
//!         validate: Operation<Life, 0>,
//!         open: Operation<Life, 1>,
//!         refresh: Operation<Life, 2>,
//!         retire: Operation<Life, 3>,
//!         tick: Operation<Life, 4>,
//!         drive: Operation<Life, 5>,
//!         cancel: Operation<Life, 6>,
//!         release: Operation<Life, 7>,
//!         close: Operation<Life, 8>,
//!     },
//!     kind_ops: {
//!     },
//! }
//! fn main() { let _ = door(); }
//! ```
//!
//! ```
//! // SDK_REGISTRATION_WITNESS auth complete
//! use busbar_contract::abi::{mechanism::call::Outcome, sdk::door::{KindOps, KindSlot, RawSlot, statement}};
//! use busbar_contract::abi::auth::{Ops, slot};
//! struct Operation<T, const N: u32>(std::marker::PhantomData<T>);
//! impl<T: KindSlot<N>, const N: u32> RawSlot for Operation<T, N> {
//!     type Kind = <Ops as KindOps>::Marker;
//!     type In = <T as KindSlot<N>>::In;
//!     type Out = <T as KindSlot<N>>::Out;
//!     unsafe fn call(_: *mut std::ffi::c_void, _: &Self::In, _: &mut Self::Out) -> Outcome { Outcome::Refused }
//! }
//! type Life = <Ops as KindOps>::Lifecycle;
//! busbar_contract::plugin_door! {
//!     ops: Ops,
//!     statement: statement("registration-auth", "1", 1),
//!     lifecycle: {
//!         validate: Operation<Life, 0>,
//!         open: Operation<Life, 1>,
//!         refresh: Operation<Life, 2>,
//!         retire: Operation<Life, 3>,
//!         tick: Operation<Life, 4>,
//!         drive: Operation<Life, 5>,
//!         cancel: Operation<Life, 6>,
//!         release: Operation<Life, 7>,
//!         close: Operation<Life, 8>,
//!     },
//!     kind_ops: {
//!         verify: Operation<Ops, {slot::VERIFY}>,
//!         begin_login: Operation<Ops, {slot::BEGIN_LOGIN}>,
//!         complete_login: Operation<Ops, {slot::COMPLETE_LOGIN}>,
//!         open_outbound: Operation<Ops, {slot::OPEN_OUTBOUND}>,
//!         outbound_ready: Operation<Ops, {slot::OUTBOUND_READY}>,
//!         fields: Operation<Ops, {slot::FIELDS}>,
//!     },
//! }
//! fn main() { let _ = door(); }
//! ```
//!
//! ```compile_fail,E0080
//! // SDK_REGISTRATION_WITNESS auth missing
//! use busbar_contract::abi::{mechanism::call::Outcome, sdk::door::{KindOps, KindSlot, RawSlot, statement}};
//! use busbar_contract::abi::auth::{Ops, slot};
//! struct Operation<T, const N: u32>(std::marker::PhantomData<T>);
//! impl<T: KindSlot<N>, const N: u32> RawSlot for Operation<T, N> {
//!     type Kind = <Ops as KindOps>::Marker;
//!     type In = <T as KindSlot<N>>::In;
//!     type Out = <T as KindSlot<N>>::Out;
//!     unsafe fn call(_: *mut std::ffi::c_void, _: &Self::In, _: &mut Self::Out) -> Outcome { Outcome::Refused }
//! }
//! type Life = <Ops as KindOps>::Lifecycle;
//! busbar_contract::plugin_door! {
//!     ops: Ops,
//!     statement: statement("registration-auth", "1", 1),
//!     lifecycle: {
//!         validate: Operation<Life, 0>,
//!         open: Operation<Life, 1>,
//!         refresh: Operation<Life, 2>,
//!         retire: Operation<Life, 3>,
//!         tick: Operation<Life, 4>,
//!         drive: Operation<Life, 5>,
//!         cancel: Operation<Life, 6>,
//!         release: Operation<Life, 7>,
//!         close: Operation<Life, 8>,
//!     },
//!     kind_ops: {
//!         begin_login: Operation<Ops, {slot::BEGIN_LOGIN}>,
//!         complete_login: Operation<Ops, {slot::COMPLETE_LOGIN}>,
//!         open_outbound: Operation<Ops, {slot::OPEN_OUTBOUND}>,
//!         outbound_ready: Operation<Ops, {slot::OUTBOUND_READY}>,
//!         fields: Operation<Ops, {slot::FIELDS}>,
//!     },
//! }
//! fn main() { let _ = door(); }
//! ```
//!
//! ```
//! // SDK_REGISTRATION_WITNESS hook complete
//! use busbar_contract::abi::{mechanism::call::Outcome, sdk::door::{KindOps, KindSlot, RawSlot, statement}};
//! use busbar_contract::abi::hook::{Ops, slot};
//! struct Operation<T, const N: u32>(std::marker::PhantomData<T>);
//! impl<T: KindSlot<N>, const N: u32> RawSlot for Operation<T, N> {
//!     type Kind = <Ops as KindOps>::Marker;
//!     type In = <T as KindSlot<N>>::In;
//!     type Out = <T as KindSlot<N>>::Out;
//!     unsafe fn call(_: *mut std::ffi::c_void, _: &Self::In, _: &mut Self::Out) -> Outcome { Outcome::Refused }
//! }
//! type Life = <Ops as KindOps>::Lifecycle;
//! busbar_contract::plugin_door! {
//!     ops: Ops,
//!     statement: busbar_contract::abi::sdk::hook::statement_with_tail(statement("registration-hook", "1", 1), &busbar_contract::abi::sdk::hook::tail(busbar_contract::abi::hook::CLASS_GATE, 0, 0)),
//!     lifecycle: {
//!         validate: Operation<Life, 0>,
//!         open: Operation<Life, 1>,
//!         refresh: Operation<Life, 2>,
//!         retire: Operation<Life, 3>,
//!         tick: Operation<Life, 4>,
//!         drive: Operation<Life, 5>,
//!         cancel: Operation<Life, 6>,
//!         release: Operation<Life, 7>,
//!         close: Operation<Life, 8>,
//!     },
//!     kind_ops: {
//!         decide: Operation<Ops, {slot::DECIDE}>,
//!         transform: Operation<Ops, {slot::TRANSFORM}>,
//!         notify: Operation<Ops, {slot::NOTIFY}>,
//!         configure: Operation<Ops, {slot::CONFIGURE}>,
//!         status: Operation<Ops, {slot::STATUS}>,
//!         describe: Operation<Ops, {slot::DESCRIBE}>,
//!     },
//! }
//! fn main() { let _ = door(); }
//! ```
//!
//! ```compile_fail,E0080
//! // SDK_REGISTRATION_WITNESS hook missing
//! use busbar_contract::abi::{mechanism::call::Outcome, sdk::door::{KindOps, KindSlot, RawSlot, statement}};
//! use busbar_contract::abi::hook::{Ops, slot};
//! struct Operation<T, const N: u32>(std::marker::PhantomData<T>);
//! impl<T: KindSlot<N>, const N: u32> RawSlot for Operation<T, N> {
//!     type Kind = <Ops as KindOps>::Marker;
//!     type In = <T as KindSlot<N>>::In;
//!     type Out = <T as KindSlot<N>>::Out;
//!     unsafe fn call(_: *mut std::ffi::c_void, _: &Self::In, _: &mut Self::Out) -> Outcome { Outcome::Refused }
//! }
//! type Life = <Ops as KindOps>::Lifecycle;
//! busbar_contract::plugin_door! {
//!     ops: Ops,
//!     statement: busbar_contract::abi::sdk::hook::statement_with_tail(statement("registration-hook", "1", 1), &busbar_contract::abi::sdk::hook::tail(busbar_contract::abi::hook::CLASS_GATE, 0, 0)),
//!     lifecycle: {
//!         validate: Operation<Life, 0>,
//!         open: Operation<Life, 1>,
//!         refresh: Operation<Life, 2>,
//!         retire: Operation<Life, 3>,
//!         tick: Operation<Life, 4>,
//!         drive: Operation<Life, 5>,
//!         cancel: Operation<Life, 6>,
//!         release: Operation<Life, 7>,
//!         close: Operation<Life, 8>,
//!     },
//!     kind_ops: {
//!         transform: Operation<Ops, {slot::TRANSFORM}>,
//!         notify: Operation<Ops, {slot::NOTIFY}>,
//!         configure: Operation<Ops, {slot::CONFIGURE}>,
//!         status: Operation<Ops, {slot::STATUS}>,
//!         describe: Operation<Ops, {slot::DESCRIBE}>,
//!     },
//! }
//! fn main() { let _ = door(); }
//! ```
//!
//! ```
//! // SDK_REGISTRATION_WITNESS export complete
//! use busbar_contract::abi::{mechanism::call::Outcome, sdk::door::{KindOps, KindSlot, RawSlot, statement}};
//! use busbar_contract::abi::export::{Ops, slot};
//! struct Operation<T, const N: u32>(std::marker::PhantomData<T>);
//! impl<T: KindSlot<N>, const N: u32> RawSlot for Operation<T, N> {
//!     type Kind = <Ops as KindOps>::Marker;
//!     type In = <T as KindSlot<N>>::In;
//!     type Out = <T as KindSlot<N>>::Out;
//!     unsafe fn call(_: *mut std::ffi::c_void, _: &Self::In, _: &mut Self::Out) -> Outcome { Outcome::Refused }
//! }
//! type Life = <Ops as KindOps>::Lifecycle;
//! busbar_contract::plugin_door! {
//!     ops: Ops,
//!     statement: busbar_contract::abi::mechanism::door::Statement { kind_tail: std::ptr::from_ref(&busbar_contract::abi::sdk::export::tail(&[], &[])).cast(), ..statement("registration-export", "1", 1) },
//!     lifecycle: {
//!         validate: Operation<Life, 0>,
//!         open: Operation<Life, 1>,
//!         refresh: Operation<Life, 2>,
//!         retire: Operation<Life, 3>,
//!         tick: Operation<Life, 4>,
//!         drive: Operation<Life, 5>,
//!         cancel: Operation<Life, 6>,
//!         release: Operation<Life, 7>,
//!         close: Operation<Life, 8>,
//!     },
//!     kind_ops: {
//!         status: Operation<Ops, {slot::STATUS}>,
//!         check: Operation<Ops, {slot::CHECK}>,
//!     },
//! }
//! fn main() { let _ = door(); }
//! ```
//!
//! ```compile_fail,E0080
//! // SDK_REGISTRATION_WITNESS export missing
//! use busbar_contract::abi::{mechanism::call::Outcome, sdk::door::{KindOps, KindSlot, RawSlot, statement}};
//! use busbar_contract::abi::export::{Ops, slot};
//! struct Operation<T, const N: u32>(std::marker::PhantomData<T>);
//! impl<T: KindSlot<N>, const N: u32> RawSlot for Operation<T, N> {
//!     type Kind = <Ops as KindOps>::Marker;
//!     type In = <T as KindSlot<N>>::In;
//!     type Out = <T as KindSlot<N>>::Out;
//!     unsafe fn call(_: *mut std::ffi::c_void, _: &Self::In, _: &mut Self::Out) -> Outcome { Outcome::Refused }
//! }
//! type Life = <Ops as KindOps>::Lifecycle;
//! busbar_contract::plugin_door! {
//!     ops: Ops,
//!     statement: busbar_contract::abi::mechanism::door::Statement { kind_tail: std::ptr::from_ref(&busbar_contract::abi::sdk::export::tail(&[], &[])).cast(), ..statement("registration-export", "1", 1) },
//!     lifecycle: {
//!         validate: Operation<Life, 0>,
//!         open: Operation<Life, 1>,
//!         refresh: Operation<Life, 2>,
//!         retire: Operation<Life, 3>,
//!         tick: Operation<Life, 4>,
//!         drive: Operation<Life, 5>,
//!         cancel: Operation<Life, 6>,
//!         release: Operation<Life, 7>,
//!         close: Operation<Life, 8>,
//!     },
//!     kind_ops: {
//!         check: Operation<Ops, {slot::CHECK}>,
//!     },
//! }
//! fn main() { let _ = door(); }
//! ```
//!
//! ```
//! // SDK_REGISTRATION_WITNESS plane complete
//! use busbar_contract::abi::{mechanism::call::Outcome, sdk::door::{KindOps, KindSlot, RawSlot, statement}};
//! use busbar_contract::abi::plane::{Ops, slot};
//! struct Operation<T, const N: u32>(std::marker::PhantomData<T>);
//! impl<T: KindSlot<N>, const N: u32> RawSlot for Operation<T, N> {
//!     type Kind = <Ops as KindOps>::Marker;
//!     type In = <T as KindSlot<N>>::In;
//!     type Out = <T as KindSlot<N>>::Out;
//!     unsafe fn call(_: *mut std::ffi::c_void, _: &Self::In, _: &mut Self::Out) -> Outcome { Outcome::Refused }
//! }
//! type Life = <Ops as KindOps>::Lifecycle;
//! busbar_contract::plugin_door! {
//!     ops: Ops,
//!     statement: busbar_contract::abi::mechanism::door::Statement { kind_tail: std::ptr::from_ref(&busbar_contract::abi::plane::PlaneTail::EMPTY).cast(), ..statement("registration-plane", "1", 1) },
//!     lifecycle: {
//!         validate: Operation<Life, 0>,
//!         open: Operation<Life, 1>,
//!         refresh: Operation<Life, 2>,
//!         retire: Operation<Life, 3>,
//!         tick: Operation<Life, 4>,
//!         drive: Operation<Life, 5>,
//!         cancel: Operation<Life, 6>,
//!         release: Operation<Life, 7>,
//!         close: Operation<Life, 8>,
//!     },
//!     kind_ops: {
//!         arrive: Operation<Ops, {slot::ARRIVE}>,
//!         on_piece: Operation<Ops, {slot::ON_PIECE}>,
//!         refusal: Operation<Ops, {slot::REFUSAL}>,
//!         hydrate: Operation<Ops, {slot::HYDRATE}>,
//!         start: Operation<Ops, {slot::START}>,
//!         project: Operation<Ops, {slot::PROJECT}>,
//!     },
//! }
//! fn main() { let _ = door(); }
//! ```
//!
//! ```compile_fail,E0080
//! // SDK_REGISTRATION_WITNESS plane missing
//! use busbar_contract::abi::{mechanism::call::Outcome, sdk::door::{KindOps, KindSlot, RawSlot, statement}};
//! use busbar_contract::abi::plane::{Ops, slot};
//! struct Operation<T, const N: u32>(std::marker::PhantomData<T>);
//! impl<T: KindSlot<N>, const N: u32> RawSlot for Operation<T, N> {
//!     type Kind = <Ops as KindOps>::Marker;
//!     type In = <T as KindSlot<N>>::In;
//!     type Out = <T as KindSlot<N>>::Out;
//!     unsafe fn call(_: *mut std::ffi::c_void, _: &Self::In, _: &mut Self::Out) -> Outcome { Outcome::Refused }
//! }
//! type Life = <Ops as KindOps>::Lifecycle;
//! busbar_contract::plugin_door! {
//!     ops: Ops,
//!     statement: busbar_contract::abi::mechanism::door::Statement { kind_tail: std::ptr::from_ref(&busbar_contract::abi::plane::PlaneTail::EMPTY).cast(), ..statement("registration-plane", "1", 1) },
//!     lifecycle: {
//!         validate: Operation<Life, 0>,
//!         open: Operation<Life, 1>,
//!         refresh: Operation<Life, 2>,
//!         retire: Operation<Life, 3>,
//!         tick: Operation<Life, 4>,
//!         drive: Operation<Life, 5>,
//!         cancel: Operation<Life, 6>,
//!         release: Operation<Life, 7>,
//!         close: Operation<Life, 8>,
//!     },
//!     kind_ops: {
//!         on_piece: Operation<Ops, {slot::ON_PIECE}>,
//!         refusal: Operation<Ops, {slot::REFUSAL}>,
//!         hydrate: Operation<Ops, {slot::HYDRATE}>,
//!         start: Operation<Ops, {slot::START}>,
//!         project: Operation<Ops, {slot::PROJECT}>,
//!     },
//! }
//! fn main() { let _ = door(); }
//! ```
//!
//! ```
//! // SDK_REGISTRATION_WITNESS transport complete
//! use busbar_contract::abi::{mechanism::call::Outcome, sdk::door::{KindOps, KindSlot, RawSlot, statement}};
//! use busbar_contract::abi::transport::{Ops, slot};
//! struct Operation<T, const N: u32>(std::marker::PhantomData<T>);
//! impl<T: KindSlot<N>, const N: u32> RawSlot for Operation<T, N> {
//!     type Kind = <Ops as KindOps>::Marker;
//!     type In = <T as KindSlot<N>>::In;
//!     type Out = <T as KindSlot<N>>::Out;
//!     unsafe fn call(_: *mut std::ffi::c_void, _: &Self::In, _: &mut Self::Out) -> Outcome { Outcome::Refused }
//! }
//! type Life = <Ops as KindOps>::Lifecycle;
//! busbar_contract::plugin_door! {
//!     ops: Ops,
//!     statement: busbar_contract::abi::mechanism::door::Statement { kind_tail: std::ptr::from_ref(&busbar_contract::abi::transport::TransportTail::EMPTY).cast(), ..statement("registration-transport", "1", 1) },
//!     lifecycle: {
//!         validate: Operation<Life, 0>,
//!         open: Operation<Life, 1>,
//!         refresh: Operation<Life, 2>,
//!         retire: Operation<Life, 3>,
//!         tick: Operation<Life, 4>,
//!         drive: Operation<Life, 5>,
//!         cancel: Operation<Life, 6>,
//!         release: Operation<Life, 7>,
//!         close: Operation<Life, 8>,
//!     },
//!     kind_ops: {
//!         listen: Operation<Ops, {slot::LISTEN}>,
//!         accept: Operation<Ops, {slot::ACCEPT}>,
//!         dial: Operation<Ops, {slot::DIAL}>,
//!         read: Operation<Ops, {slot::READ}>,
//!         write: Operation<Ops, {slot::WRITE}>,
//!         flush: Operation<Ops, {slot::FLUSH}>,
//!         shut: Operation<Ops, {slot::SHUT}>,
//!         arrival: Operation<Ops, {slot::ARRIVAL}>,
//!         locate: Operation<Ops, {slot::LOCATE}>,
//!         begin: Operation<Ops, {slot::BEGIN}>,
//!         ingest: Operation<Ops, {slot::INGEST}>,
//!         emit: Operation<Ops, {slot::EMIT}>,
//!         encode: Operation<Ops, {slot::ENCODE}>,
//!         refuse: Operation<Ops, {slot::REFUSE}>,
//!         finish: Operation<Ops, {slot::FINISH}>,
//!         detach: Operation<Ops, {slot::DETACH}>,
//!         adopt: Operation<Ops, {slot::ADOPT}>,
//!         timer: Operation<Ops, {slot::TIMER}>,
//!     },
//! }
//! fn main() { let _ = door(); }
//! ```
//!
//! ```compile_fail,E0080
//! // SDK_REGISTRATION_WITNESS transport missing
//! use busbar_contract::abi::{mechanism::call::Outcome, sdk::door::{KindOps, KindSlot, RawSlot, statement}};
//! use busbar_contract::abi::transport::{Ops, slot};
//! struct Operation<T, const N: u32>(std::marker::PhantomData<T>);
//! impl<T: KindSlot<N>, const N: u32> RawSlot for Operation<T, N> {
//!     type Kind = <Ops as KindOps>::Marker;
//!     type In = <T as KindSlot<N>>::In;
//!     type Out = <T as KindSlot<N>>::Out;
//!     unsafe fn call(_: *mut std::ffi::c_void, _: &Self::In, _: &mut Self::Out) -> Outcome { Outcome::Refused }
//! }
//! type Life = <Ops as KindOps>::Lifecycle;
//! busbar_contract::plugin_door! {
//!     ops: Ops,
//!     statement: busbar_contract::abi::mechanism::door::Statement { kind_tail: std::ptr::from_ref(&busbar_contract::abi::transport::TransportTail::EMPTY).cast(), ..statement("registration-transport", "1", 1) },
//!     lifecycle: {
//!         validate: Operation<Life, 0>,
//!         open: Operation<Life, 1>,
//!         refresh: Operation<Life, 2>,
//!         retire: Operation<Life, 3>,
//!         tick: Operation<Life, 4>,
//!         drive: Operation<Life, 5>,
//!         cancel: Operation<Life, 6>,
//!         release: Operation<Life, 7>,
//!         close: Operation<Life, 8>,
//!     },
//!     kind_ops: {
//!         accept: Operation<Ops, {slot::ACCEPT}>,
//!         dial: Operation<Ops, {slot::DIAL}>,
//!         read: Operation<Ops, {slot::READ}>,
//!         write: Operation<Ops, {slot::WRITE}>,
//!         flush: Operation<Ops, {slot::FLUSH}>,
//!         shut: Operation<Ops, {slot::SHUT}>,
//!         arrival: Operation<Ops, {slot::ARRIVAL}>,
//!         locate: Operation<Ops, {slot::LOCATE}>,
//!         begin: Operation<Ops, {slot::BEGIN}>,
//!         ingest: Operation<Ops, {slot::INGEST}>,
//!         emit: Operation<Ops, {slot::EMIT}>,
//!         encode: Operation<Ops, {slot::ENCODE}>,
//!         refuse: Operation<Ops, {slot::REFUSE}>,
//!         finish: Operation<Ops, {slot::FINISH}>,
//!         detach: Operation<Ops, {slot::DETACH}>,
//!         adopt: Operation<Ops, {slot::ADOPT}>,
//!         timer: Operation<Ops, {slot::TIMER}>,
//!     },
//! }
//! fn main() { let _ = door(); }
//! ```
//!
//! ```compile_fail,E0080
//! // SDK_REGISTRATION_WITNESS hook null-tail
//! use busbar_contract::abi::{mechanism::call::Outcome, sdk::door::{KindOps, KindSlot, RawSlot, statement}};
//! use busbar_contract::abi::hook::{Ops, slot};
//! struct Operation<T, const N: u32>(std::marker::PhantomData<T>);
//! impl<T: KindSlot<N>, const N: u32> RawSlot for Operation<T, N> {
//!     type Kind = <Ops as KindOps>::Marker;
//!     type In = <T as KindSlot<N>>::In;
//!     type Out = <T as KindSlot<N>>::Out;
//!     unsafe fn call(_: *mut std::ffi::c_void, _: &Self::In, _: &mut Self::Out) -> Outcome { Outcome::Refused }
//! }
//! type Life = <Ops as KindOps>::Lifecycle;
//! busbar_contract::plugin_door! {
//!     ops: Ops,
//!     statement: statement("registration-hook", "1", 1),
//!     lifecycle: {
//!         validate: Operation<Life, 0>,
//!         open: Operation<Life, 1>,
//!         refresh: Operation<Life, 2>,
//!         retire: Operation<Life, 3>,
//!         tick: Operation<Life, 4>,
//!         drive: Operation<Life, 5>,
//!         cancel: Operation<Life, 6>,
//!         release: Operation<Life, 7>,
//!         close: Operation<Life, 8>,
//!     },
//!     kind_ops: {
//!         decide: Operation<Ops, {slot::DECIDE}>,
//!         transform: Operation<Ops, {slot::TRANSFORM}>,
//!         notify: Operation<Ops, {slot::NOTIFY}>,
//!         configure: Operation<Ops, {slot::CONFIGURE}>,
//!         status: Operation<Ops, {slot::STATUS}>,
//!         describe: Operation<Ops, {slot::DESCRIBE}>,
//!     },
//! }
//! fn main() { let _ = door(); }
//! ```
//!
//! ```compile_fail,E0080
//! // SDK_REGISTRATION_WITNESS plane null-tail
//! use busbar_contract::abi::{mechanism::call::Outcome, sdk::door::{KindOps, KindSlot, RawSlot, statement}};
//! use busbar_contract::abi::plane::{Ops, slot};
//! struct Operation<T, const N: u32>(std::marker::PhantomData<T>);
//! impl<T: KindSlot<N>, const N: u32> RawSlot for Operation<T, N> {
//!     type Kind = <Ops as KindOps>::Marker;
//!     type In = <T as KindSlot<N>>::In;
//!     type Out = <T as KindSlot<N>>::Out;
//!     unsafe fn call(_: *mut std::ffi::c_void, _: &Self::In, _: &mut Self::Out) -> Outcome { Outcome::Refused }
//! }
//! type Life = <Ops as KindOps>::Lifecycle;
//! busbar_contract::plugin_door! {
//!     ops: Ops,
//!     statement: statement("registration-plane", "1", 1),
//!     lifecycle: {
//!         validate: Operation<Life, 0>,
//!         open: Operation<Life, 1>,
//!         refresh: Operation<Life, 2>,
//!         retire: Operation<Life, 3>,
//!         tick: Operation<Life, 4>,
//!         drive: Operation<Life, 5>,
//!         cancel: Operation<Life, 6>,
//!         release: Operation<Life, 7>,
//!         close: Operation<Life, 8>,
//!     },
//!     kind_ops: {
//!         arrive: Operation<Ops, {slot::ARRIVE}>,
//!         on_piece: Operation<Ops, {slot::ON_PIECE}>,
//!         refusal: Operation<Ops, {slot::REFUSAL}>,
//!         hydrate: Operation<Ops, {slot::HYDRATE}>,
//!         start: Operation<Ops, {slot::START}>,
//!         project: Operation<Ops, {slot::PROJECT}>,
//!     },
//! }
//! fn main() { let _ = door(); }
//! ```
//!
//! ```compile_fail,E0080
//! // SDK_REGISTRATION_WITNESS transport null-tail
//! use busbar_contract::abi::{mechanism::call::Outcome, sdk::door::{KindOps, KindSlot, RawSlot, statement}};
//! use busbar_contract::abi::transport::{Ops, slot};
//! struct Operation<T, const N: u32>(std::marker::PhantomData<T>);
//! impl<T: KindSlot<N>, const N: u32> RawSlot for Operation<T, N> {
//!     type Kind = <Ops as KindOps>::Marker;
//!     type In = <T as KindSlot<N>>::In;
//!     type Out = <T as KindSlot<N>>::Out;
//!     unsafe fn call(_: *mut std::ffi::c_void, _: &Self::In, _: &mut Self::Out) -> Outcome { Outcome::Refused }
//! }
//! type Life = <Ops as KindOps>::Lifecycle;
//! busbar_contract::plugin_door! {
//!     ops: Ops,
//!     statement: statement("registration-transport", "1", 1),
//!     lifecycle: {
//!         validate: Operation<Life, 0>,
//!         open: Operation<Life, 1>,
//!         refresh: Operation<Life, 2>,
//!         retire: Operation<Life, 3>,
//!         tick: Operation<Life, 4>,
//!         drive: Operation<Life, 5>,
//!         cancel: Operation<Life, 6>,
//!         release: Operation<Life, 7>,
//!         close: Operation<Life, 8>,
//!     },
//!     kind_ops: {
//!         listen: Operation<Ops, {slot::LISTEN}>,
//!         accept: Operation<Ops, {slot::ACCEPT}>,
//!         dial: Operation<Ops, {slot::DIAL}>,
//!         read: Operation<Ops, {slot::READ}>,
//!         write: Operation<Ops, {slot::WRITE}>,
//!         flush: Operation<Ops, {slot::FLUSH}>,
//!         shut: Operation<Ops, {slot::SHUT}>,
//!         arrival: Operation<Ops, {slot::ARRIVAL}>,
//!         locate: Operation<Ops, {slot::LOCATE}>,
//!         begin: Operation<Ops, {slot::BEGIN}>,
//!         ingest: Operation<Ops, {slot::INGEST}>,
//!         emit: Operation<Ops, {slot::EMIT}>,
//!         encode: Operation<Ops, {slot::ENCODE}>,
//!         refuse: Operation<Ops, {slot::REFUSE}>,
//!         finish: Operation<Ops, {slot::FINISH}>,
//!         detach: Operation<Ops, {slot::DETACH}>,
//!         adopt: Operation<Ops, {slot::ADOPT}>,
//!         timer: Operation<Ops, {slot::TIMER}>,
//!     },
//! }
//! fn main() { let _ = door(); }
//! ```
//!

//!
//! ```
//! // Authenticated route: complete opt-in.
//! use busbar_contract::abi::{mechanism::call::Outcome, sdk::door::{KindOps, KindSlot, RawSlot, statement}};
//! use busbar_contract::abi::plane::{Ops, slot};
//! struct Operation<T, const N: u32>(std::marker::PhantomData<T>);
//! impl<T: KindSlot<N>, const N: u32> RawSlot for Operation<T, N> {
//!     type Kind = <Ops as KindOps>::Marker;
//!     type In = <T as KindSlot<N>>::In;
//!     type Out = <T as KindSlot<N>>::Out;
//!     unsafe fn call(_: *mut std::ffi::c_void, _: &Self::In, _: &mut Self::Out) -> Outcome { Outcome::Refused }
//! }
//! const TAIL: busbar_contract::abi::plane::PlaneTail = busbar_contract::abi::plane::PlaneTail { flags: busbar_contract::abi::plane::TAIL_AUTHENTICATED_ROUTE, ..busbar_contract::abi::plane::PlaneTail::EMPTY };
//! type Life = <Ops as KindOps>::Lifecycle;
//! busbar_contract::plugin_door! {
//!     ops: Ops,
//!     statement: busbar_contract::abi::mechanism::door::Statement { kind_tail: std::ptr::from_ref(&TAIL).cast(), ..statement("registration-plane", "1", 1) },
//!     lifecycle: {
//!         validate: Operation<Life, 0>,
//!         open: Operation<Life, 1>,
//!         refresh: Operation<Life, 2>,
//!         retire: Operation<Life, 3>,
//!         tick: Operation<Life, 4>,
//!         drive: Operation<Life, 5>,
//!         cancel: Operation<Life, 6>,
//!         release: Operation<Life, 7>,
//!         close: Operation<Life, 8>,
//!     },
//!     kind_ops: {
//!         arrive: Operation<Ops, {slot::ARRIVE}>,
//!         on_piece: Operation<Ops, {slot::ON_PIECE}>,
//!         refusal: Operation<Ops, {slot::REFUSAL}>,
//!         hydrate: Operation<Ops, {slot::HYDRATE}>,
//!         start: Operation<Ops, {slot::START}>,
//!         project: Operation<Ops, {slot::PROJECT}>,
//!         authenticated_route: Operation<Ops, {slot::AUTHENTICATED_ROUTE}>,
//!     },
//! }
//! fn main() { let _ = door(); }
//! ```
//!
//! ```compile_fail,E0080
//! // Authenticated route: a declaration without its operation fails at compile time.
//! use busbar_contract::abi::{mechanism::call::Outcome, sdk::door::{KindOps, KindSlot, RawSlot, statement}};
//! use busbar_contract::abi::plane::{Ops, slot};
//! struct Operation<T, const N: u32>(std::marker::PhantomData<T>);
//! impl<T: KindSlot<N>, const N: u32> RawSlot for Operation<T, N> {
//!     type Kind = <Ops as KindOps>::Marker;
//!     type In = <T as KindSlot<N>>::In;
//!     type Out = <T as KindSlot<N>>::Out;
//!     unsafe fn call(_: *mut std::ffi::c_void, _: &Self::In, _: &mut Self::Out) -> Outcome { Outcome::Refused }
//! }
//! const TAIL: busbar_contract::abi::plane::PlaneTail = busbar_contract::abi::plane::PlaneTail { flags: busbar_contract::abi::plane::TAIL_AUTHENTICATED_ROUTE, ..busbar_contract::abi::plane::PlaneTail::EMPTY };
//! type Life = <Ops as KindOps>::Lifecycle;
//! busbar_contract::plugin_door! {
//!     ops: Ops,
//!     statement: busbar_contract::abi::mechanism::door::Statement { kind_tail: std::ptr::from_ref(&TAIL).cast(), ..statement("registration-plane", "1", 1) },
//!     lifecycle: {
//!         validate: Operation<Life, 0>,
//!         open: Operation<Life, 1>,
//!         refresh: Operation<Life, 2>,
//!         retire: Operation<Life, 3>,
//!         tick: Operation<Life, 4>,
//!         drive: Operation<Life, 5>,
//!         cancel: Operation<Life, 6>,
//!         release: Operation<Life, 7>,
//!         close: Operation<Life, 8>,
//!     },
//!     kind_ops: {
//!         arrive: Operation<Ops, {slot::ARRIVE}>,
//!         on_piece: Operation<Ops, {slot::ON_PIECE}>,
//!         refusal: Operation<Ops, {slot::REFUSAL}>,
//!         hydrate: Operation<Ops, {slot::HYDRATE}>,
//!         start: Operation<Ops, {slot::START}>,
//!         project: Operation<Ops, {slot::PROJECT}>,
//!     },
//! }
//! fn main() { let _ = door(); }
//! ```

use super::door::KindOps;
use crate::abi::mechanism::{door::Statement, KindCode};

/// Assert a complete operation table during the door macro's constant evaluation.
///
/// # Safety
/// The statement's pointers name their declared immutable, live data. `T` is sealed to the
/// seven SDK tables, each of which begins with the common lifecycle header.
#[doc(hidden)]
pub const unsafe fn check<T: KindOps>(st: &Statement, ops: &T) {
    let p = std::ptr::from_ref(ops);
    // SAFETY: every sealed KindOps table begins with OpsHead.
    let h = unsafe { &*p.cast::<crate::abi::mechanism::lifecycle::OpsHead>() };
    assert!(h.validate.is_some(), "SDK registration requires validate");
    assert!(h.open.is_some(), "SDK registration requires open");
    assert!(h.refresh.is_some(), "SDK registration requires refresh");
    assert!(h.retire.is_some(), "SDK registration requires retire");
    assert!(h.tick.is_some(), "SDK registration requires tick");
    assert!(h.drive.is_some(), "SDK registration requires drive");
    assert!(h.cancel.is_some(), "SDK registration requires cancel");
    assert!(h.release.is_some(), "SDK registration requires release");
    assert!(h.close.is_some(), "SDK registration requires close");
    macro_rules! require {
        ($o:ident; $($f:ident),+ $(,)?) => { $(
            assert!($o.$f.is_some(), concat!("SDK registration requires ", stringify!($f)));
        )+ };
    }
    // SAFETY: KindOps is sealed and its KIND identifies the exact table type.
    unsafe {
        match T::KIND {
            KindCode::Store => {
                assert!(
                    std::mem::size_of::<T>() == std::mem::size_of::<crate::abi::store::v4::Ops>(),
                    "SDK table must match its declared kind"
                );
                let o = &*p.cast::<crate::abi::store::v4::Ops>();
                require!(o; read, scan, commit, clock, bootstrap);
            }
            KindCode::Secret => {
                assert!(
                    std::mem::size_of::<T>() == std::mem::size_of::<crate::abi::secret::Ops>(),
                    "SDK table must match its declared kind"
                );
                let o = &*p.cast::<crate::abi::secret::Ops>();
                require!(o; resolve);
            }
            KindCode::Auth => {
                assert!(
                    std::mem::size_of::<T>() == std::mem::size_of::<crate::abi::auth::Ops>(),
                    "SDK table must match its declared kind"
                );
                let o = &*p.cast::<crate::abi::auth::Ops>();
                require!(o; verify, begin_login, complete_login, open_outbound, outbound_ready, fields);
            }
            KindCode::Hook => {
                assert!(
                    std::mem::size_of::<T>() == std::mem::size_of::<crate::abi::hook::Ops>(),
                    "SDK table must match its declared kind"
                );
                let o = &*p.cast::<crate::abi::hook::Ops>();
                require!(o; decide, transform, notify, configure, status, describe);
                assert!(
                    !st.kind_tail.is_null(),
                    "hook registration requires its class and access declarations"
                );
                assert!(
                    (*st.kind_tail).size as usize >= std::mem::size_of::<crate::abi::hook::Tail>(),
                    "hook registration tail is incomplete"
                );
                let t = &*st.kind_tail.cast::<crate::abi::hook::Tail>();
                assert!(
                    t.routes_len == 0 || o.serve.is_some(),
                    "hook routes require a serve implementation"
                );
            }
            KindCode::Export => {
                assert!(
                    std::mem::size_of::<T>() == std::mem::size_of::<crate::abi::export::Ops>(),
                    "SDK table must match its declared kind"
                );
                let o = &*p.cast::<crate::abi::export::Ops>();
                require!(o; status, check);
                assert!(
                    !st.kind_tail.is_null(),
                    "export registration requires its streams and routes"
                );
                assert!(
                    (*st.kind_tail).size as usize
                        >= std::mem::size_of::<crate::abi::export::Tail>(),
                    "export registration tail is incomplete"
                );
                let t = &*st.kind_tail.cast::<crate::abi::export::Tail>();
                assert!(
                    t.routes_len == 0 || o.serve.is_some(),
                    "export routes require a serve implementation"
                );
                assert!(
                    t.streams_len == 0 || !t.streams.is_null(),
                    "export streams require a non-null list"
                );
                let mut i = 0;
                while i < t.streams_len {
                    let stream = *t.streams.add(i);
                    assert!(
                        stream <= crate::abi::export::ExportStream::Completions as u8,
                        "export stream code is invalid"
                    );
                    if stream == crate::abi::export::ExportStream::Metrics as u8 {
                        assert!(o.scrape.is_some(), "metrics export requires scrape");
                    } else {
                        assert!(o.deliver.is_some(), "record export requires deliver");
                    }
                    i += 1;
                }
            }
            KindCode::Plane => {
                assert!(
                    std::mem::size_of::<T>() == std::mem::size_of::<crate::abi::plane::Ops>(),
                    "SDK table must match its declared kind"
                );
                let o = &*p.cast::<crate::abi::plane::Ops>();
                require!(o; arrive, on_piece, refusal, hydrate, start, project);
                assert!(
                    !st.kind_tail.is_null(),
                    "plane registration requires its kind tail"
                );
                assert!(
                    (*st.kind_tail).size as usize
                        >= std::mem::size_of::<crate::abi::plane::PlaneTail>(),
                    "plane registration tail is incomplete"
                );
                let t = &*st.kind_tail.cast::<crate::abi::plane::PlaneTail>();
                assert!(
                    t.flags & crate::abi::plane::TAIL_AUTHENTICATED_ROUTE == 0
                        || o.authenticated_route.is_some(),
                    "authenticated routing requires an authenticated_route implementation"
                );
                assert!(
                    t.admin_routes_len == 0 || o.serve.is_some(),
                    "plane admin routes require a serve implementation"
                );
            }
            KindCode::Transport => {
                assert!(
                    std::mem::size_of::<T>() == std::mem::size_of::<crate::abi::transport::Ops>(),
                    "SDK table must match its declared kind"
                );
                let o = &*p.cast::<crate::abi::transport::Ops>();
                require!(o; listen, accept, dial, read, write, flush, shut, arrival, locate,
                    begin, ingest, emit, encode, refuse, finish, detach, adopt, timer);
                assert!(
                    !st.kind_tail.is_null(),
                    "transport registration requires its kind tail"
                );
                assert!(
                    (*st.kind_tail).size as usize
                        >= std::mem::size_of::<crate::abi::transport::TransportTail>(),
                    "transport registration tail is incomplete"
                );
            }
        }
    }
}
