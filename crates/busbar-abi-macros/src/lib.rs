// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `kind!`: ONE declaration per plugin kind. From the kind's op list it builds the kind's `slot`
//! constants, its `#[repr(C)]` ops table, the SDK's per-slot struct wiring, the op contracts and the
//! host's per-op answer checks and short-buffer rule, so none of them is written twice.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as Tokens;
use quote::{format_ident, quote};
use syn::{parse_macro_input, ExprClosure, Pat};

mod decl;

use decl::{KindDecl, OpDecl};

/// Declares a plugin kind's table and per-op glue. See `decl` for the grammar.
#[proc_macro]
pub fn kind(input: TokenStream) -> TokenStream {
    let decl = parse_macro_input!(input as KindDecl);
    match expand(&decl) {
        Ok(t) => t.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand(d: &KindDecl) -> syn::Result<Tokens> {
    let c = quote!(::busbar_contract::abi);
    let kind = &d.kind;
    let lifecycle = &d.lifecycle;
    let n = d.ops.len();
    let n32 = u32::try_from(n).map_err(|_| syn::Error::new(kind.span(), "too many ops"))?;

    let consts = d.ops.iter().enumerate().map(|(k, op)| {
        let docs = &op.docs;
        let konst = &op.konst;
        let k = u32::try_from(k).unwrap_or(u32::MAX);
        quote! {
            #(#docs)*
            pub const #konst: u32 = #c::mechanism::lifecycle::LIFECYCLE_SLOTS + #k;
        }
    });
    let fields = d.ops.iter().map(|op| {
        let docs = &op.docs;
        let field = &op.field;
        quote! {
            #(#docs)*
            pub #field: ::core::option::Option<#c::mechanism::call::Op>,
        }
    });
    let wiring = d.ops.iter().map(|op| {
        let konst = &op.konst;
        let (i, o) = (&op.input, &op.out);
        quote! {
            // SAFETY: the structs this declaration states for the slot.
            unsafe impl #c::sdk::door::KindSlot<{ slot::#konst }> for Ops {
                type In = #i;
                type Out = #o;
            }
        }
    });
    let names = d.ops.iter().map(|op| op.field.to_string());
    let contracts = d.ops.iter().map(|op| {
        let konst = &op.konst;
        let (i, o, class) = (&op.input, &op.out, &op.class);
        let (rp, pend) = (op.request, op.pend);
        quote! {
            #c::mechanism::check::OpContract {
                slot: slot::#konst,
                request_path: #rp,
                may_pend: #pend,
                max_in: ::core::mem::size_of::<#i>(),
                max_out: ::core::mem::size_of::<#o>(),
                deadline: #c::mechanism::call::DeadlineClass::#class,
            }
        }
    });
    let checks = d
        .ops
        .iter()
        .filter_map(|op| op.check.as_ref().map(|cl| check_arm(op, cl)))
        .collect::<syn::Result<Vec<_>>>()?;
    let shorts = d.ops.iter().filter(|op| !op.bufs.is_empty()).map(short_arm);
    let unused = d.ops.iter().filter(|op| op.unused).map(|op| {
        let konst = &op.konst;
        quote!(slot::#konst)
    });

    Ok(quote! {
        /// [`InHead::op`](#c::mechanism::call::InHead::op) of each kind op: `LIFECYCLE_SLOTS + k`,
        /// in table order.
        pub mod slot {
            #(#consts)*
        }

        /// How many kind slots the table holds after the lifecycle.
        pub const KIND_SLOTS: u32 = #n32;

        /// The kind's ops table: the shared [`OpsHead`](#c::mechanism::lifecycle::OpsHead), then
        /// one slot per kind op in [`slot`] order.
        #[repr(C)]
        #[derive(Debug, Clone, Copy)]
        pub struct Ops {
            /// The lifecycle.
            pub head: #c::mechanism::lifecycle::OpsHead,
            #(#fields)*
        }

        const _: () = ::core::assert!(
            ::core::mem::size_of::<Ops>()
                == ::core::mem::size_of::<#c::mechanism::lifecycle::OpsHead>()
                    + #n * ::core::mem::size_of::<::core::option::Option<#c::mechanism::call::Op>>()
        );

        // SAFETY: `Ops` is `#[repr(C)]`, leads with `head: OpsHead` and appends only
        // `Option<Op>` slots (above).
        unsafe impl #c::sdk::door::KindOps for Ops {
            const KIND: #c::mechanism::KindCode = #c::mechanism::KindCode::#kind;
            type Lifecycle = #lifecycle;
        }

        #(#wiring)*

        /// Every kind slot's name, as its table field, in table order.
        pub const NAMES: [&str; #n] = [#(#names,)*];

        /// Every kind slot's contract, in table order.
        pub const OPS: [#c::mechanism::check::OpContract; #n] = [#(#contracts,)*];

        // SAFETY: `check` and `short` read each frame only as the structs this declaration states
        // for its slot, through `Frames::get`, which checks the sizes.
        unsafe impl #c::mechanism::decl::KindDecl for Ops {
            const NAMES: &'static [&'static str] = &NAMES;
            const OPS: &'static [#c::mechanism::check::OpContract] = &OPS;
            const UNUSED: &'static [u32] = &[#(#unused,)*];

            unsafe fn check(
                slot: u32,
                outcome: #c::mechanism::call::Outcome,
                frames: #c::mechanism::decl::Frames,
            ) -> ::core::result::Result<(), #c::mechanism::check::Fault> {
                let _ = (outcome, frames);
                match slot {
                    #(#checks)*
                    _ => ::core::result::Result::Ok(()),
                }
            }

            unsafe fn short(
                slot: u32,
                outcome: #c::mechanism::call::Outcome,
                frames: #c::mechanism::decl::Frames,
            ) -> bool {
                if outcome != #c::mechanism::call::Outcome::Failed {
                    return false;
                }
                let _ = frames;
                match slot {
                    #(#shorts)*
                    _ => false,
                }
            }
        }
    })
}

/// `slot::X => { let (i, o) = frames.get::<In, Out>()?; <the closure's body over i, o> }`.
fn check_arm(op: &OpDecl, cl: &ExprClosure) -> syn::Result<Tokens> {
    let c = quote!(::busbar_contract::abi);
    let konst = &op.konst;
    let (i, o) = (&op.input, &op.out);
    let pats: Vec<&Pat> = cl.inputs.iter().collect();
    if !(2..=3).contains(&pats.len()) {
        return Err(syn::Error::new_spanned(
            cl,
            "a check closure takes `|in, out|` or `|in, out, outcome|`",
        ));
    }
    let (pi, po) = (pats[0], pats[1]);
    let outcome = pats.get(2).map(|p| quote!(let #p = outcome;));
    let body = &cl.body;
    let (gi, go) = (format_ident!("__in"), format_ident!("__out"));
    Ok(quote! {
        slot::#konst => {
            // SAFETY: the host's frames for this slot's crossing (the trait's contract).
            let (#gi, #go) = unsafe { frames.get::<#i, #o>() }?;
            #[allow(unused_variables)]
            let #pi: &#i = #gi;
            #[allow(unused_variables)]
            let #po: &#o = #go;
            #outcome
            let __checked: ::core::result::Result<(), #c::mechanism::check::Fault> = #body;
            __checked
        }
    })
}

/// `slot::X => out.<b>_needed != 0 || ..` (a FAILED answer naming a larger host buffer).
fn short_arm(op: &OpDecl) -> Tokens {
    let konst = &op.konst;
    let (i, o) = (&op.input, &op.out);
    let needed = op.bufs.iter().map(|b| {
        let f = format_ident!("{}_needed", b);
        quote!(o.#f != 0)
    });
    quote! {
        // SAFETY: as `check`.
        slot::#konst => unsafe { frames.get::<#i, #o>() }
            .is_ok_and(|(_, o)| false #(|| #needed)*),
    }
}
