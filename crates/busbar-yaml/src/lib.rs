//! Busbar's YAML library: the serde YAML API (`Value`, `Mapping`, `from_str`, `to_string`, ...)
//! of `serde_yaml_ng` 0.10.0, on a memory-safe, pure-Rust port of libyaml.
//!
//! Busbar reads YAML through the `serde_yaml` name (the workspace aliases this package), and its
//! operators' files were parsed by libyaml through `serde_yaml_ng` 0.10 in 1.5.5. That parser
//! sat on `unsafe-libyaml`, an unmaintained C-to-Rust translation (RUSTSEC-2024-0449). This crate
//! keeps every behaviour the product depends on and drops the unsafe code:
//!
//! - The serde layer (`de`, `ser`, `value`, `mapping`, `number`, `path`, `error`, `loader`) is
//!   serde_yaml_ng 0.10.0's, unchanged except where it touched raw pointers (now safe code) and the
//!   unused `with` helpers (dropped). Values, scalar resolution, merge keys, error texts, error
//!   paths and marks are therefore the same.
//! - The private `libyaml` module is a safe port of libyaml 0.2.5's reader, scanner, parser and
//!   emitter (through unsafe-libyaml 0.2.11, the code serde_yaml_ng ran), so the same input gives
//!   the same events, marks and errors, and the same values serialize to the same bytes. The
//!   port is checked against libyaml event for event (see `tests/`).
//!
//! The whole crate is `#![forbid(unsafe_code)]`. It follows the YAML 1.1 specification, as
//! libyaml does.
//!
//! Licenses of the work this derives from (all MIT): see `NOTICE` in this crate.
//!
//! # Examples
//!
//! ```
//! use std::collections::BTreeMap;
//!
//! fn main() -> Result<(), busbar_yaml::Error> {
//!     // You have some type.
//!     let mut map = BTreeMap::new();
//!     map.insert("x".to_string(), 1.0);
//!     map.insert("y".to_string(), 2.0);
//!
//!     // Serialize it to a YAML string.
//!     let yaml = busbar_yaml::to_string(&map)?;
//!     assert_eq!(yaml, "x: 1.0\ny: 2.0\n");
//!
//!     // Deserialize it back to a Rust type.
//!     let deserialized_map: BTreeMap<String, f64> = busbar_yaml::from_str(&yaml)?;
//!     assert_eq!(map, deserialized_map);
//!     Ok(())
//! }
//! ```
//!
//! ## Using Serde derive
//!
//! It can also be used with Serde's derive macros to handle structs and enums
//! defined in your program.
//!
//! Structs serialize in the obvious way:
//!
//! ```
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Serialize, Deserialize, PartialEq, Debug)]
//! struct Point {
//!     x: f64,
//!     y: f64,
//! }
//!
//! fn main() -> Result<(), busbar_yaml::Error> {
//!     let point = Point { x: 1.0, y: 2.0 };
//!
//!     let yaml = busbar_yaml::to_string(&point)?;
//!     assert_eq!(yaml, "x: 1.0\ny: 2.0\n");
//!
//!     let deserialized_point: Point = busbar_yaml::from_str(&yaml)?;
//!     assert_eq!(point, deserialized_point);
//!     Ok(())
//! }
//! ```
//!
//! Enums serialize using YAML's `!tag` syntax to identify the variant name.
//!
//! ```
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Serialize, Deserialize, PartialEq, Debug)]
//! enum Enum {
//!     Unit,
//!     Newtype(usize),
//!     Tuple(usize, usize, usize),
//!     Struct { x: f64, y: f64 },
//! }
//!
//! fn main() -> Result<(), busbar_yaml::Error> {
//!     let yaml = "
//!         - !Newtype 1
//!         - !Tuple [0, 0, 0]
//!         - !Struct {x: 1.0, y: 2.0}
//!     ";
//!     let values: Vec<Enum> = busbar_yaml::from_str(yaml).unwrap();
//!     assert_eq!(values[0], Enum::Newtype(1));
//!     assert_eq!(values[1], Enum::Tuple(0, 0, 0));
//!     assert_eq!(values[2], Enum::Struct { x: 1.0, y: 2.0 });
//!
//!     // The last two in YAML's block style instead:
//!     let yaml = "
//!         - !Tuple
//!           - 0
//!           - 0
//!           - 0
//!         - !Struct
//!           x: 1.0
//!           y: 2.0
//!     ";
//!     let values: Vec<Enum> = busbar_yaml::from_str(yaml).unwrap();
//!     assert_eq!(values[0], Enum::Tuple(0, 0, 0));
//!     assert_eq!(values[1], Enum::Struct { x: 1.0, y: 2.0 });
//!
//!     // Variants with no data can be written using !Tag or just the string name.
//!     let yaml = "
//!         - Unit  # serialization produces this one
//!         - !Unit
//!     ";
//!     let values: Vec<Enum> = busbar_yaml::from_str(yaml).unwrap();
//!     assert_eq!(values[0], Enum::Unit);
//!     assert_eq!(values[1], Enum::Unit);
//!
//!     Ok(())
//! }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Suppressed clippy_pedantic lints
#![allow(
    // buggy
    clippy::iter_not_returning_iterator, // https://github.com/rust-lang/rust-clippy/issues/8285
    clippy::ptr_arg, // https://github.com/rust-lang/rust-clippy/issues/9218
    clippy::question_mark, // https://github.com/rust-lang/rust-clippy/issues/7859
    // private Deserializer::next
    clippy::should_implement_trait,
    // things are often more readable this way
    clippy::cast_lossless,
    clippy::checked_conversions,
    clippy::if_not_else,
    clippy::manual_assert,
    clippy::match_like_matches_macro,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::redundant_else,
    clippy::single_match_else,
    // code is acceptable
    clippy::blocks_in_conditions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::derive_partial_eq_without_eq,
    clippy::derived_hash_with_manual_eq,
    clippy::doc_markdown,
    clippy::items_after_statements,
    clippy::let_underscore_untyped,
    clippy::manual_map,
    clippy::missing_panics_doc,
    clippy::never_loop,
    clippy::return_self_not_must_use,
    clippy::too_many_lines,
    clippy::uninlined_format_args,
    clippy::unsafe_removed_from_name,
    clippy::wildcard_in_or_patterns,
    // noisy
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
)]

pub use crate::de::{from_reader, from_slice, from_str, Deserializer};
pub use crate::error::{Error, Location, Result};
pub use crate::ser::{to_string, to_writer, Serializer};
#[doc(inline)]
pub use crate::value::{from_value, to_value, Index, Number, Sequence, Value};

#[doc(inline)]
pub use crate::mapping::Mapping;

mod de;
mod error;
mod libyaml;
mod loader;
pub mod mapping;
mod number;
mod path;
mod ser;
pub mod value;

// Prevent downstream code from implementing the Index trait.
mod private {
    pub trait Sealed {}
    impl Sealed for usize {}
    impl Sealed for str {}
    impl Sealed for String {}
    impl Sealed for crate::Value {}
    impl<T> Sealed for &T where T: ?Sized + Sealed {}
}
