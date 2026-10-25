// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The grammar of one kind declaration, `kind! { .. }`. The C header renderer reads the same
//! grammar through this file, so the table it prints and the table the macro builds are one reading.
//!
//! ```text
//! kind: Hook,
//! lifecycle: crate::abi::sdk::door::Lifecycle,
//! ops: {
//!     /// `decide`.
//!     DECIDE decide: DecideIn => DecideOut { class: Call, pend, request, check: |i, o| .., bufs: [order] },
//! }
//! ```

use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{braced, bracketed, Attribute, ExprClosure, Ident, Path, Token, Type};

/// One kind.
pub struct KindDecl {
    /// The `KindCode` variant.
    pub kind: Ident,
    /// The kind's lifecycle `in`/`out` index type.
    pub lifecycle: Path,
    /// The kind ops, in table order.
    pub ops: Vec<OpDecl>,
}

/// One kind op.
pub struct OpDecl {
    /// Its doc attributes (the slot constant and the table field carry them).
    pub docs: Vec<Attribute>,
    /// `slot::<CONST>`.
    pub konst: Ident,
    /// `Ops::<field>`.
    pub field: Ident,
    /// Its `in`.
    pub input: Type,
    /// Its `out`.
    pub out: Type,
    /// Its deadline class (`DeadlineClass::<class>`).
    pub class: Ident,
    /// It may answer PENDING.
    pub pend: bool,
    /// It is on the request path.
    pub request: bool,
    /// No host code calls it.
    pub unused: bool,
    /// The answer check: `|in, out| -> Result<(), Fault>` (an optional third parameter is the outcome).
    pub check: Option<ExprClosure>,
    /// The host buffers: `in.<b>_buf/_cap`, `out.<b>_written/_needed`.
    pub bufs: Vec<Ident>,
}

mod kw {
    syn::custom_keyword!(kind);
    syn::custom_keyword!(lifecycle);
    syn::custom_keyword!(ops);
    syn::custom_keyword!(class);
    syn::custom_keyword!(pend);
    syn::custom_keyword!(request);
    syn::custom_keyword!(unused);
    syn::custom_keyword!(check);
    syn::custom_keyword!(bufs);
}

impl Parse for KindDecl {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        input.parse::<kw::kind>()?;
        input.parse::<Token![:]>()?;
        let kind: Ident = input.parse()?;
        input.parse::<Token![,]>()?;
        input.parse::<kw::lifecycle>()?;
        input.parse::<Token![:]>()?;
        let lifecycle: Path = input.parse()?;
        input.parse::<Token![,]>()?;
        input.parse::<kw::ops>()?;
        input.parse::<Token![:]>()?;
        let body;
        braced!(body in input);
        let mut ops = Vec::new();
        while !body.is_empty() {
            ops.push(body.parse::<OpDecl>()?);
            if body.peek(Token![,]) {
                body.parse::<Token![,]>()?;
            }
        }
        if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
        }
        if !input.is_empty() {
            return Err(input.error("unexpected tokens after `ops`"));
        }
        Ok(KindDecl {
            kind,
            lifecycle,
            ops,
        })
    }
}

impl Parse for OpDecl {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let docs = input.call(Attribute::parse_outer)?;
        if let Some(a) = docs.iter().find(|a| !a.path().is_ident("doc")) {
            return Err(syn::Error::new_spanned(
                a,
                "only doc attributes are allowed on an op",
            ));
        }
        let konst: Ident = input.parse()?;
        let field: Ident = input.parse()?;
        input.parse::<Token![:]>()?;
        let input_ty: Type = input.parse()?;
        input.parse::<Token![=>]>()?;
        let out: Type = input.parse()?;
        let opts;
        braced!(opts in input);
        let mut op = OpDecl {
            docs,
            konst,
            field,
            input: input_ty,
            out,
            class: Ident::new("Call", proc_macro2::Span::call_site()),
            pend: false,
            request: false,
            unused: false,
            check: None,
            bufs: Vec::new(),
        };
        let mut class_seen = false;
        while !opts.is_empty() {
            let la = opts.lookahead1();
            if la.peek(kw::class) {
                opts.parse::<kw::class>()?;
                opts.parse::<Token![:]>()?;
                op.class = opts.parse()?;
                class_seen = true;
            } else if la.peek(kw::pend) {
                opts.parse::<kw::pend>()?;
                op.pend = true;
            } else if la.peek(kw::request) {
                opts.parse::<kw::request>()?;
                op.request = true;
            } else if la.peek(kw::unused) {
                opts.parse::<kw::unused>()?;
                op.unused = true;
            } else if la.peek(kw::check) {
                opts.parse::<kw::check>()?;
                opts.parse::<Token![:]>()?;
                op.check = Some(opts.parse()?);
            } else if la.peek(kw::bufs) {
                opts.parse::<kw::bufs>()?;
                opts.parse::<Token![:]>()?;
                let list;
                bracketed!(list in opts);
                op.bufs = Punctuated::<Ident, Token![,]>::parse_terminated(&list)?
                    .into_iter()
                    .collect();
            } else {
                return Err(la.error());
            }
            if opts.peek(Token![,]) {
                opts.parse::<Token![,]>()?;
            }
        }
        if !class_seen {
            return Err(syn::Error::new_spanned(
                &op.field,
                "an op states its deadline class (`class: Call|Stream|Connection|WriteBehind`)",
            ));
        }
        Ok(op)
    }
}
