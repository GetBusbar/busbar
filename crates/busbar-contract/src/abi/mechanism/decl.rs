// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE DECLARATION PER SHAPE AND PER OP: the macros a kind's `abi/<kind>/` states its shapes and
//! its answer checks with, so each is written once.
//!
//! - `abi_struct!` states `#[repr(C)]` structs as written (attributes, docs and fields pass
//!   through unchanged) and adds each one's `FIELDS` (name, type, offset, size, in declaration
//!   order) and `LAYOUT` (the words [`crate::layout_shape!`] folds into the kind's fingerprint).
//! - `abi_op!` states one op's answer validator as an ordered list of per-field rules
//!   (`blob`, `code`, `bits`, `zero`, `list`, `span`, `within`) and hand steps (`then`), and
//!   generates the straight-line `check_<op>` plus its RED table ([`RedCase`]): one case per
//!   (field, rule), each naming the [`Rule`] and the fault field the check answers.
//! - `abi_answers!` states a kind's answers by slot and generates `answer::<op>` and the kind's
//!   `check_answer`, the one call the loader makes per op answer (the `in`/`out` size checks
//!   included).
//!
//! The rules run in the order they are listed, so a fault's field is the one today's checks name
//! first. A rule that relates two fields (a contradiction) is a `then` step: explicit code.

use super::check::Rule;

/// One field of an `abi_struct!` struct: its name, its Rust type as written, its offset and its
/// size, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbiField {
    /// The field's name.
    pub name: &'static str,
    /// Its Rust type, as written.
    pub ty: &'static str,
    /// Its offset (`offset_of!`).
    pub offset: usize,
    /// Its size (`size_of`).
    pub size: usize,
}

/// One RED case of an `abi_op!` validator: `red` breaks exactly one declared rule of a GREEN
/// answer, and the validator then answers `Fault { rule, field }`.
pub struct RedCase<T> {
    /// The rule the broken answer faults under.
    pub rule: Rule,
    /// The field the fault names.
    pub field: &'static str,
    /// Breaks the rule on a GREEN answer.
    pub red: fn(&mut T),
}

impl<T> core::fmt::Debug for RedCase<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RedCase")
            .field("rule", &self.rule)
            .field("field", &self.field)
            .finish_non_exhaustive()
    }
}

/// An unsigned ABI integer, widened to `u64` for a rule (no `as` cast at the rule site).
pub trait Word: Copy {
    /// The value as a `u64`.
    fn word(self) -> u64;
}

impl Word for u8 {
    fn word(self) -> u64 {
        u64::from(self)
    }
}

impl Word for u16 {
    fn word(self) -> u64 {
        u64::from(self)
    }
}

impl Word for u32 {
    fn word(self) -> u64 {
        u64::from(self)
    }
}

impl Word for u64 {
    fn word(self) -> u64 {
        self
    }
}

impl Word for usize {
    fn word(self) -> u64 {
        self as u64
    }
}

/// `abi_struct! { <struct>... }`: each struct as written, plus its `FIELDS` and `LAYOUT`.
macro_rules! abi_struct {
    ($(
        $(#[$m:meta])*
        $v:vis struct $name:ident {
            $( $(#[$fm:meta])* $fv:vis $f:ident : $t:ty ),* $(,)?
        }
    )*) => {$(
        $(#[$m])*
        $v struct $name {
            $( $(#[$fm])* $fv $f : $t, )*
        }

        impl $name {
            /// Every field, in declaration order: name, type, offset and size.
            pub const FIELDS: &'static [$crate::abi::mechanism::decl::AbiField] = &[$(
                $crate::abi::mechanism::decl::AbiField {
                    name: stringify!($f),
                    ty: stringify!($t),
                    offset: ::core::mem::offset_of!($name, $f),
                    size: ::core::mem::size_of::<$t>(),
                },
            )*];

            /// The layout words the kind's fingerprint folds: size, alignment, then every field's
            /// offset, in declaration order ([`crate::layout_shape!`]).
            pub const LAYOUT: &'static [u64] = $crate::layout_shape!($name => $($f),*);
        }
    )*};
}
pub(crate) use abi_struct;

/// `abi_op! { <docs> pub fn check_<op>(<params>) as "<op>", <TABLE> for <out>: <Out> { <steps> } }`:
/// the validator over its params (in their order), running the steps in order, and `<TABLE>`, the
/// [`RedCase`]s of its unconditional field rules over `<out>` (one of the params, `&<Out>`).
///
/// Field steps (`<f>` is a field of `<out>`; a fault is named `"<op>.<f>"` unless `as "<name>"`
/// names it, which a nested path `<f>.<g>` must):
/// - `blob(<f>);` a [`Blob`](super::call::Blob): [`Rule::NullWithCount`] `"<op>.<f>"`,
///   [`Rule::OverMax`] `"<op>.<f>.len"` ([`check::blob`](super::check::blob)).
/// - `code(<f>, LO, HI);` [`Rule::UnknownCode`] outside `LO..=HI`.
/// - `bits(<f>, MASK);` [`Rule::UnknownCode`] for a bit outside `MASK`.
/// - `zero(<f>, <Rule>);` `<Rule>` when not `0`.
/// - `list(<ptr>, <len>, MAX);` [`Rule::NullWithCount`] `"<op>.<ptr>"` for a count with a NULL
///   pointer, [`Rule::OverMax`] `"<op>.<len>"` above `MAX`.
/// - `text(<f>);` an [`AbiStr`](super::call::AbiStr) never counted with a NULL pointer
///   ([`check::text`](super::check::text)); `named(<f>);` one that is also present
///   ([`check::named`](super::check::named)).
/// - `span(<f>, BOUND);` a [`Span`](super::call::Span) absent or inside the first `BOUND` bytes
///   ([`check::span`](super::check::span)).
/// - `index(<f>, LEN);` [`Rule::IndexOutOfRange`] at or past `LEN`.
/// - `within(<f>, CAP);` [`Rule::OverCap`] above `CAP`.
///
/// Explicit steps (plain Rust conditions, in place; not in the RED table):
/// - `deny(<cond>, <Rule>, "<name>");` is `if <cond> { return Err(fault(Rule::<Rule>, "<name>")) }`.
/// - `when(<cond>) { <steps> }` is `if <cond> { <steps> }`.
/// - `then <fn>(<args>);` a cross-field rule in a plain function, called with `?`.
macro_rules! abi_op {
    (
        $(#[$m:meta])*
        $v:vis fn $check:ident ($($p:ident : $pt:ty),* $(,)?)
            as $op:literal, $table:ident for $o:ident : $ot:ty { $($steps:tt)* }
    ) => {
        $(#[$m])*
        $v fn $check($($p: $pt),*) -> ::core::result::Result<(), $crate::abi::mechanism::check::Fault> {
            $crate::abi::mechanism::decl::abi_op!(@check $o, $op; $($steps)*);
            ::core::result::Result::Ok(())
        }

        #[doc = concat!("The RED table of `", stringify!($check), "`: one case per (field, rule) its declaration states unconditionally.")]
        #[allow(dead_code)]
        $v const $table: &[$crate::abi::mechanism::decl::RedCase<$ot>] =
            $crate::abi::mechanism::decl::abi_op!(@red $ot, $op, [] $($steps)*);
    };

    // ── the validator's steps, in order ──
    (@check $o:ident, $op:literal;) => {};
    // The explicit steps first: a `deny` or `list` must never read as a field step.
    (@check $o:ident, $op:literal; deny($cond:expr, $rule:ident, $n:expr); $($rest:tt)*) => {
        if $cond {
            return ::core::result::Result::Err($crate::abi::mechanism::check::fault(
                $crate::abi::mechanism::check::Rule::$rule,
                $n,
            ));
        }
        $crate::abi::mechanism::decl::abi_op!(@check $o, $op; $($rest)*);
    };
    (@check $o:ident, $op:literal; when($cond:expr) { $($inner:tt)* } $($rest:tt)*) => {
        if $cond {
            $crate::abi::mechanism::decl::abi_op!(@check $o, $op; $($inner)*);
        }
        $crate::abi::mechanism::decl::abi_op!(@check $o, $op; $($rest)*);
    };
    (@check $o:ident, $op:literal; then $hand:ident ($($a:expr),* $(,)?); $($rest:tt)*) => {
        $hand($($a),*)?;
        $crate::abi::mechanism::decl::abi_op!(@check $o, $op; $($rest)*);
    };
    (@check $o:ident, $op:literal; list($ptr:ident, $len:ident, $max:expr); $($rest:tt)*) => {
        $crate::abi::mechanism::check::listed($o.$ptr, $o.$len, concat!($op, ".", stringify!($ptr)))?;
        if $crate::abi::mechanism::decl::Word::word($o.$len) > $crate::abi::mechanism::decl::Word::word($max) {
            return ::core::result::Result::Err($crate::abi::mechanism::check::fault(
                $crate::abi::mechanism::check::Rule::OverMax,
                concat!($op, ".", stringify!($len)),
            ));
        }
        $crate::abi::mechanism::decl::abi_op!(@check $o, $op; $($rest)*);
    };
    (@check $o:ident, $op:literal; blob($f:ident); $($rest:tt)*) => {
        $crate::abi::mechanism::check::blob(
            &$o.$f,
            concat!($op, ".", stringify!($f)),
            concat!($op, ".", stringify!($f), ".len"),
        )?;
        $crate::abi::mechanism::decl::abi_op!(@check $o, $op; $($rest)*);
    };
    (@check $o:ident, $op:literal; blob($($f:ident).+) as $n:literal; $($rest:tt)*) => {
        $crate::abi::mechanism::check::blob(&$o.$($f).+, $n, concat!($n, ".len"))?;
        $crate::abi::mechanism::decl::abi_op!(@check $o, $op; $($rest)*);
    };
    // `zero`'s rule is an identifier, which an `expr` argument would hide.
    (@check $o:ident, $op:literal; zero($f:ident, $rule:ident); $($rest:tt)*) => {
        $crate::abi::mechanism::decl::abi_op!(@check $o, $op; zero($f, $rule) as concat!($op, ".", stringify!($f)); $($rest)*);
    };
    // A field step with no name: its name is "<op>.<f>".
    (@check $o:ident, $op:literal; $step:ident($f:ident $(, $arg:expr)*); $($rest:tt)*) => {
        $crate::abi::mechanism::decl::abi_op!(@check $o, $op; $step($f $(, $arg)*) as concat!($op, ".", stringify!($f)); $($rest)*);
    };
    (@check $o:ident, $op:literal; code($($f:ident).+, $lo:expr, $hi:expr) as $n:expr; $($rest:tt)*) => {
        $crate::abi::mechanism::check::code(
            $crate::abi::mechanism::decl::Word::word($o.$($f).+),
            $crate::abi::mechanism::decl::Word::word($lo),
            $crate::abi::mechanism::decl::Word::word($hi),
            $n,
        )?;
        $crate::abi::mechanism::decl::abi_op!(@check $o, $op; $($rest)*);
    };
    (@check $o:ident, $op:literal; bits($($f:ident).+, $mask:expr) as $n:expr; $($rest:tt)*) => {
        $crate::abi::mechanism::check::bits(
            $crate::abi::mechanism::decl::Word::word($o.$($f).+),
            $crate::abi::mechanism::decl::Word::word($mask),
            $n,
        )?;
        $crate::abi::mechanism::decl::abi_op!(@check $o, $op; $($rest)*);
    };
    (@check $o:ident, $op:literal; zero($($f:ident).+, $rule:ident) as $n:expr; $($rest:tt)*) => {
        if $crate::abi::mechanism::decl::Word::word($o.$($f).+) != 0 {
            return ::core::result::Result::Err($crate::abi::mechanism::check::fault(
                $crate::abi::mechanism::check::Rule::$rule,
                $n,
            ));
        }
        $crate::abi::mechanism::decl::abi_op!(@check $o, $op; $($rest)*);
    };
    (@check $o:ident, $op:literal; text($($f:ident).+) as $n:expr; $($rest:tt)*) => {
        $crate::abi::mechanism::check::text($o.$($f).+, $n)?;
        $crate::abi::mechanism::decl::abi_op!(@check $o, $op; $($rest)*);
    };
    (@check $o:ident, $op:literal; named($($f:ident).+) as $n:expr; $($rest:tt)*) => {
        $crate::abi::mechanism::check::named($o.$($f).+, $n)?;
        $crate::abi::mechanism::decl::abi_op!(@check $o, $op; $($rest)*);
    };
    (@check $o:ident, $op:literal; span($($f:ident).+, $bound:expr) as $n:expr; $($rest:tt)*) => {
        $crate::abi::mechanism::check::span($o.$($f).+.offset, $o.$($f).+.len, $bound, $n)?;
        $crate::abi::mechanism::decl::abi_op!(@check $o, $op; $($rest)*);
    };
    (@check $o:ident, $op:literal; index($($f:ident).+, $len:expr) as $n:expr; $($rest:tt)*) => {
        $crate::abi::mechanism::check::index($o.$($f).+, $len, $n)?;
        $crate::abi::mechanism::decl::abi_op!(@check $o, $op; $($rest)*);
    };
    (@check $o:ident, $op:literal; within($($f:ident).+, $cap:expr) as $n:expr; $($rest:tt)*) => {
        $crate::abi::mechanism::check::within(
            $crate::abi::mechanism::decl::Word::word($o.$($f).+),
            $cap,
            $n,
        )?;
        $crate::abi::mechanism::decl::abi_op!(@check $o, $op; $($rest)*);
    };

    // ── the RED table: one case per unconditional (field, rule); explicit steps are tested by hand ──
    (@red $ot:ty, $op:literal, [$($acc:tt)*]) => { &[$($acc)*] };
    (@red $ot:ty, $op:literal, [$($acc:tt)*] deny($cond:expr, $rule:ident, $n:expr); $($rest:tt)*) => {
        $crate::abi::mechanism::decl::abi_op!(@red $ot, $op, [$($acc)*] $($rest)*)
    };
    (@red $ot:ty, $op:literal, [$($acc:tt)*] when($cond:expr) { $($inner:tt)* } $($rest:tt)*) => {
        $crate::abi::mechanism::decl::abi_op!(@red $ot, $op, [$($acc)*] $($rest)*)
    };
    (@red $ot:ty, $op:literal, [$($acc:tt)*] then $hand:ident ($($a:expr),* $(,)?); $($rest:tt)*) => {
        $crate::abi::mechanism::decl::abi_op!(@red $ot, $op, [$($acc)*] $($rest)*)
    };
    (@red $ot:ty, $op:literal, [$($acc:tt)*] list($ptr:ident, $len:ident, $max:expr); $($rest:tt)*) => {
        $crate::abi::mechanism::decl::abi_op!(@red $ot, $op, [$($acc)*
            $crate::abi::mechanism::decl::RedCase::<$ot> {
                rule: $crate::abi::mechanism::check::Rule::NullWithCount,
                field: concat!($op, ".", stringify!($ptr)),
                red: |o: &mut $ot| {
                    o.$ptr = ::core::ptr::null::<u8>() as _;
                    o.$len = 1;
                },
            },
            $crate::abi::mechanism::decl::RedCase::<$ot> {
                rule: $crate::abi::mechanism::check::Rule::OverMax,
                field: concat!($op, ".", stringify!($len)),
                red: |o: &mut $ot| {
                    o.$ptr = ::core::ptr::NonNull::<u8>::dangling().as_ptr() as _;
                    o.$len = ($max) as _;
                    o.$len += 1;
                },
            },
        ] $($rest)*)
    };
    (@red $ot:ty, $op:literal, [$($acc:tt)*] blob($f:ident); $($rest:tt)*) => {
        $crate::abi::mechanism::decl::abi_op!(@red $ot, $op, [$($acc)*] blob($f) names(
            concat!($op, ".", stringify!($f)),
            concat!($op, ".", stringify!($f), ".len")
        ); $($rest)*)
    };
    (@red $ot:ty, $op:literal, [$($acc:tt)*] blob($($f:ident).+) as $n:literal; $($rest:tt)*) => {
        $crate::abi::mechanism::decl::abi_op!(@red $ot, $op, [$($acc)*] blob($($f).+) names($n, concat!($n, ".len")); $($rest)*)
    };
    (@red $ot:ty, $op:literal, [$($acc:tt)*] blob($($f:ident).+) names($n:expr, $nl:expr); $($rest:tt)*) => {
        $crate::abi::mechanism::decl::abi_op!(@red $ot, $op, [$($acc)*
            $crate::abi::mechanism::decl::RedCase::<$ot> {
                rule: $crate::abi::mechanism::check::Rule::NullWithCount,
                field: $n,
                red: |o: &mut $ot| {
                    o.$($f).+.ptr = ::core::ptr::null();
                    o.$($f).+.len = 1;
                },
            },
            $crate::abi::mechanism::decl::RedCase::<$ot> {
                rule: $crate::abi::mechanism::check::Rule::OverMax,
                field: $nl,
                red: |o: &mut $ot| {
                    o.$($f).+.ptr = ::core::ptr::NonNull::<u8>::dangling().as_ptr();
                    o.$($f).+.len = $crate::abi::mechanism::check::HARD_MAX_BYTES as usize + 1;
                },
            },
        ] $($rest)*)
    };
    (@red $ot:ty, $op:literal, [$($acc:tt)*] zero($f:ident, $rule:ident); $($rest:tt)*) => {
        $crate::abi::mechanism::decl::abi_op!(@red $ot, $op, [$($acc)*] zero($f, $rule) as concat!($op, ".", stringify!($f)); $($rest)*)
    };
    // A field step with no name: its name is "<op>.<f>".
    (@red $ot:ty, $op:literal, [$($acc:tt)*] $step:ident($f:ident $(, $arg:expr)*); $($rest:tt)*) => {
        $crate::abi::mechanism::decl::abi_op!(@red $ot, $op, [$($acc)*] $step($f $(, $arg)*) as concat!($op, ".", stringify!($f)); $($rest)*)
    };
    (@red $ot:ty, $op:literal, [$($acc:tt)*] code($($f:ident).+, $lo:expr, $hi:expr) as $n:expr; $($rest:tt)*) => {
        $crate::abi::mechanism::decl::abi_op!(@red $ot, $op, [$($acc)*
            $crate::abi::mechanism::decl::RedCase::<$ot> {
                rule: $crate::abi::mechanism::check::Rule::UnknownCode,
                field: $n,
                red: |o: &mut $ot| o.$($f).+ = ($crate::abi::mechanism::decl::Word::word($hi) + 1) as _,
            },
        ] $($rest)*)
    };
    (@red $ot:ty, $op:literal, [$($acc:tt)*] bits($($f:ident).+, $mask:expr) as $n:expr; $($rest:tt)*) => {
        $crate::abi::mechanism::decl::abi_op!(@red $ot, $op, [$($acc)*
            $crate::abi::mechanism::decl::RedCase::<$ot> {
                rule: $crate::abi::mechanism::check::Rule::UnknownCode,
                field: $n,
                red: |o: &mut $ot| o.$($f).+ = !$crate::abi::mechanism::decl::Word::word($mask) as _,
            },
        ] $($rest)*)
    };
    (@red $ot:ty, $op:literal, [$($acc:tt)*] zero($($f:ident).+, $rule:ident) as $n:expr; $($rest:tt)*) => {
        $crate::abi::mechanism::decl::abi_op!(@red $ot, $op, [$($acc)*
            $crate::abi::mechanism::decl::RedCase::<$ot> {
                rule: $crate::abi::mechanism::check::Rule::$rule,
                field: $n,
                red: |o: &mut $ot| o.$($f).+ = 1,
            },
        ] $($rest)*)
    };
    (@red $ot:ty, $op:literal, [$($acc:tt)*] text($($f:ident).+) as $n:expr; $($rest:tt)*) => {
        $crate::abi::mechanism::decl::abi_op!(@red $ot, $op, [$($acc)*
            $crate::abi::mechanism::decl::RedCase::<$ot> {
                rule: $crate::abi::mechanism::check::Rule::NullWithCount,
                field: $n,
                red: |o: &mut $ot| {
                    o.$($f).+.ptr = ::core::ptr::null();
                    o.$($f).+.len = 1;
                },
            },
        ] $($rest)*)
    };
    (@red $ot:ty, $op:literal, [$($acc:tt)*] named($($f:ident).+) as $n:expr; $($rest:tt)*) => {
        $crate::abi::mechanism::decl::abi_op!(@red $ot, $op, [$($acc)*
            $crate::abi::mechanism::decl::RedCase::<$ot> {
                rule: $crate::abi::mechanism::check::Rule::Missing,
                field: $n,
                red: |o: &mut $ot| o.$($f).+.len = 0,
            },
            $crate::abi::mechanism::decl::RedCase::<$ot> {
                rule: $crate::abi::mechanism::check::Rule::NullWithCount,
                field: $n,
                red: |o: &mut $ot| {
                    o.$($f).+.ptr = ::core::ptr::null();
                    o.$($f).+.len = 1;
                },
            },
        ] $($rest)*)
    };
    (@red $ot:ty, $op:literal, [$($acc:tt)*] span($($f:ident).+, $bound:expr) as $n:expr; $($rest:tt)*) => {
        $crate::abi::mechanism::decl::abi_op!(@red $ot, $op, [$($acc)*
            $crate::abi::mechanism::decl::RedCase::<$ot> {
                rule: $crate::abi::mechanism::check::Rule::SpanNotAbsent,
                field: $n,
                red: |o: &mut $ot| {
                    o.$($f).+.offset = $crate::abi::mechanism::check::SPAN_ABSENT;
                    o.$($f).+.len = 1;
                },
            },
        ] $($rest)*)
    };
    (@red $ot:ty, $op:literal, [$($acc:tt)*] index($($f:ident).+, $len:expr) as $n:expr; $($rest:tt)*) => {
        $crate::abi::mechanism::decl::abi_op!(@red $ot, $op, [$($acc)*
            $crate::abi::mechanism::decl::RedCase::<$ot> {
                rule: $crate::abi::mechanism::check::Rule::IndexOutOfRange,
                field: $n,
                red: |o: &mut $ot| o.$($f).+ = u32::MAX,
            },
        ] $($rest)*)
    };
    (@red $ot:ty, $op:literal, [$($acc:tt)*] within($($f:ident).+, $cap:expr) as $n:expr; $($rest:tt)*) => {
        $crate::abi::mechanism::decl::abi_op!(@red $ot, $op, [$($acc)*] $($rest)*)
    };
}
pub(crate) use abi_op;

/// `abi_answers! { cx: <Cx>; <slots> => <op>(<frames>) |<outcome>, <in>, <out>, <cx>| <body> ... }`:
/// the kind's `answer::<op>` per listed slot pattern (`slot::A` or `slot::A | slot::B`) and its
/// `check_answer`, the loader's one call per op answer.
///
/// `<frames>` names what the op reads, in the order the loader reads it: `in In, out Out`,
/// `out Out, in In`, `out Out` or `in In` (an unnamed frame is the bare `InHead`/`OutHead` and is
/// not size-checked). A frame smaller than its struct is `Fault { Rule::Foreign, "in" | "out" }`,
/// in that order. A slot not listed answers `Ok(())`.
macro_rules! abi_answers {
    (
        cx: $cx:ty;
        $( $slot:pat => $op:ident ($($frames:tt)*)
            |$oc:pat_param, $i:pat_param, $o:pat_param, $c:pat_param| $body:block )*
    ) => {
        /// The kind's answer checks, one per op that has one ([`check_answer`] dispatches here).
        pub mod answer {
            #[allow(unused_imports)]
            use super::*;
            $(
                $crate::abi::mechanism::decl::abi_answers!(@op $op ($($frames)*) |$oc, $i, $o, $c| $body; $cx);
            )*
        }

        /// THE KIND'S ANSWER CHECK: the op's `in` and `out` read at their structs (each frame
        /// smaller than its struct faults [`Rule::Foreign`](crate::abi::mechanism::check::Rule::Foreign)
        /// `"in"`/`"out"`), then the op's `answer::<op>`. A slot with no answer check passes.
        ///
        /// # Errors
        /// The rule the answer breaks.
        ///
        /// # Safety
        /// `input` and `out` point at live host-owned buffers of at least `in_size`/`out_size`
        /// bytes (each at least its head), aligned for the op's structs, that nothing writes
        /// during the call; every buffer the `in` lends is the host's own, of its stated
        /// capacity, and every list a READY answer names under its lease is live plugin memory.
        pub unsafe fn check_answer(
            slot: u32,
            outcome: $crate::abi::mechanism::call::Outcome,
            input: *const $crate::abi::mechanism::call::InHead,
            in_size: usize,
            out: *const $crate::abi::mechanism::call::OutHead,
            out_size: usize,
            cx: &$cx,
        ) -> ::core::result::Result<(), $crate::abi::mechanism::check::Fault> {
            match slot {
                $(
                    $slot => {
                        $crate::abi::mechanism::decl::abi_answers!(@frames ($($frames)*) input, in_size, out, out_size; i, o);
                        // SAFETY: the caller's contract; both frames were read at their structs.
                        unsafe { answer::$op(outcome, i, o, cx) }
                    }
                )*
                _ => ::core::result::Result::Ok(()),
            }
        }
    };

    (@op $op:ident ($($frames:tt)*) |$oc:pat_param, $i:pat_param, $o:pat_param, $c:pat_param| $body:block; $cx:ty) => {
        $crate::abi::mechanism::decl::abi_answers!(@sig $op [$oc, $i, $o, $c] $body; $cx; $($frames)*);
    };
    (@sig $op:ident [$($b:tt)*] $body:block; $cx:ty; in $it:ty, out $ot:ty) => {
        $crate::abi::mechanism::decl::abi_answers!(@fn $op [$($b)*] $body; $cx; $it, $ot);
    };
    (@sig $op:ident [$($b:tt)*] $body:block; $cx:ty; out $ot:ty, in $it:ty) => {
        $crate::abi::mechanism::decl::abi_answers!(@fn $op [$($b)*] $body; $cx; $it, $ot);
    };
    (@sig $op:ident [$($b:tt)*] $body:block; $cx:ty; out $ot:ty) => {
        $crate::abi::mechanism::decl::abi_answers!(@fn $op [$($b)*] $body; $cx;
            $crate::abi::mechanism::call::InHead, $ot);
    };
    (@sig $op:ident [$($b:tt)*] $body:block; $cx:ty; in $it:ty) => {
        $crate::abi::mechanism::decl::abi_answers!(@fn $op [$($b)*] $body; $cx;
            $it, $crate::abi::mechanism::call::OutHead);
    };
    (@fn $op:ident [$oc:pat_param, $i:pat_param, $o:pat_param, $c:pat_param] $body:block; $cx:ty; $it:ty, $ot:ty) => {
        #[doc = concat!("`", stringify!($op), "`'s answer check, its `in` and `out` already read at their structs.")]
        ///
        /// # Errors
        /// The rule the answer breaks.
        ///
        /// # Safety
        /// As [`check_answer`](super::check_answer): the buffers `in`/`out` name are the host's,
        /// live, and unwritten during the call.
        pub unsafe fn $op(
            $oc: $crate::abi::mechanism::call::Outcome,
            $i: &$it,
            $o: &$ot,
            $c: &$cx,
        ) -> ::core::result::Result<(), $crate::abi::mechanism::check::Fault> $body
    };

    (@frames (in $it:ty, out $ot:ty) $ip:ident, $is:ident, $op_:ident, $os:ident; $i:ident, $o:ident) => {
        $crate::abi::mechanism::decl::abi_answers!(@read $ip, $is, "in", $it, $i);
        $crate::abi::mechanism::decl::abi_answers!(@read $op_, $os, "out", $ot, $o);
    };
    (@frames (out $ot:ty, in $it:ty) $ip:ident, $is:ident, $op_:ident, $os:ident; $i:ident, $o:ident) => {
        $crate::abi::mechanism::decl::abi_answers!(@read $op_, $os, "out", $ot, $o);
        $crate::abi::mechanism::decl::abi_answers!(@read $ip, $is, "in", $it, $i);
    };
    (@frames (out $ot:ty) $ip:ident, $is:ident, $op_:ident, $os:ident; $i:ident, $o:ident) => {
        // SAFETY: the caller's contract: every `in` is at least its head.
        let $i = unsafe { &*$ip };
        $crate::abi::mechanism::decl::abi_answers!(@read $op_, $os, "out", $ot, $o);
    };
    (@frames (in $it:ty) $ip:ident, $is:ident, $op_:ident, $os:ident; $i:ident, $o:ident) => {
        $crate::abi::mechanism::decl::abi_answers!(@read $ip, $is, "in", $it, $i);
        // SAFETY: the caller's contract: every `out` is at least its head.
        let $o = unsafe { &*$op_ };
    };
    (@read $p:ident, $size:ident, $which:literal, $t:ty, $bind:ident) => {
        if $size < ::core::mem::size_of::<$t>() {
            return ::core::result::Result::Err($crate::abi::mechanism::check::fault(
                $crate::abi::mechanism::check::Rule::Foreign,
                $which,
            ));
        }
        // SAFETY: the caller's contract; the frame holds a whole `$t`, which leads with its head.
        let $bind = unsafe { &*$p.cast::<$t>() };
    };
}
pub(crate) use abi_answers;
