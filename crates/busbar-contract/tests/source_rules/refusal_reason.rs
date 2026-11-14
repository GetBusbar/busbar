// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A HOST REFUSAL ALWAYS SAYS WHY (streams-mint, lint rule 2). A `Stored { .. }` literal whose
//! `outcome` is not `Ready` takes its base from `..Stored::refused(why)`, so the refusal carries
//! its reason to the plugin. No exceptions.

use syn::visit::Visit;

use crate::walk::{self, Source};

/// Every non-`Ready` `Stored` literal not based on `Stored::refused`, as `file:line`.
fn hits(sources: &[Source]) -> Vec<String> {
    struct Literals<'s> {
        rel: &'s str,
        out: Vec<String>,
    }
    impl<'ast> Visit<'ast> for Literals<'_> {
        fn visit_expr_struct(&mut self, s: &'ast syn::ExprStruct) {
            let named_stored = s
                .path
                .segments
                .last()
                .is_some_and(|seg| seg.ident == "Stored");
            let not_ready = s.fields.iter().any(|f| {
                matches!(&f.member, syn::Member::Named(m) if m == "outcome")
                    && matches!(&f.expr, syn::Expr::Path(p)
                        if p.path.segments.last().is_some_and(|seg| seg.ident != "Ready"))
            });
            let refused_base = s.rest.as_deref().is_some_and(|rest| {
                matches!(rest, syn::Expr::Call(c) if matches!(&*c.func, syn::Expr::Path(p) if {
                    let segs: Vec<String> =
                        p.path.segments.iter().map(|seg| seg.ident.to_string()).collect();
                    segs.ends_with(&["Stored".to_string(), "refused".to_string()])
                }))
            });
            if named_stored && not_ready && !refused_base {
                self.out
                    .push(format!("{}:{}", self.rel, walk::line_of(&s.path)));
            }
            syn::visit::visit_expr_struct(self, s);
        }
    }
    let mut out = Vec::new();
    for src in sources {
        let mut literals = Literals {
            rel: &src.rel,
            out: Vec::new(),
        };
        for item in walk::items(&src.file.items) {
            literals.visit_item(item);
        }
        out.extend(literals.out);
    }
    out
}

#[test]
fn every_host_refusal_carries_its_reason() {
    let roots = crate::count_gate::core_roots();
    let roots: Vec<&str> = roots.iter().map(String::as_str).collect();
    let hits = hits(&walk::production(&roots));
    assert!(
        hits.is_empty(),
        "a `Stored` that is not READY must take its base from `..Stored::refused(why)`:\n{}",
        hits.join("\n")
    );
}

#[test]
fn the_rule_reads_a_refusal_without_its_reason() {
    let planted = |text: &str| {
        vec![Source {
            rel: "planted.rs".into(),
            file: syn::parse_file(text).expect("the planted source parses"),
        }]
    };
    let bare = planted(
        "fn a() -> Stored { Stored { outcome: Outcome::Refused, value: 1, ..Stored::ready(0) } }",
    );
    assert_eq!(
        hits(&bare).len(),
        1,
        "a refusal based on READY names no reason"
    );
    let explained = planted(
        "fn a() -> Stored { Stored { outcome: Outcome::Failed, ..Stored::refused(WHY) } }
         fn b() -> Stored { Stored { value: 7, ..Stored::refused(WHY) } }
         fn c() -> Stored { Stored { outcome: Outcome::Ready, ..Stored::ready(0) } }",
    );
    assert!(hits(&explained).is_empty(), "{:?}", hits(&explained));
}
