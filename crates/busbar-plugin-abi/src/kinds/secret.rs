// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The secret kind: the `Secret` trait and the `secret` module (IF §8.2, §10.4). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-A6 fills it.

crate::kind::kind_stub! {
    /// A secret source. It resolves one reference to bytes. Core owns custody: caching, TTL, zeroizing, audit, cycles.
    pub trait Secret: Send + Sync + 'static {
        /// reference = the `settings` object of a SourceReference that custody routed to this instance
        /// (`{"name": "db"}`), verbatim. It never carries the `module` (custody strips it; I2).
        /// Answer: VALUE, FACT(F_LEASE_S)?. Unknown name: REFUSED R_NOT_FOUND. Malformed: REFUSED R_INVALID.
        fn resolve(
            &self,
            h: &'static crate::host::Host,
            reference: crate::need::ChainBytes,
        ) -> impl core::future::Future<Output = Result<crate::records::Reply, crate::fail::Fail>> + Send;
    }
}

pub mod secret {
    //! The secret kind's records, constants and method bits (IF §8.2), its typed describe helper, and its
    //! host-side `Proxy` (§10.4).

    /// Describe: one secret-reference shorthand this source answers to (round 6; replaces the 1.5.5
    /// Statement REWRITE_SUGAR/_SHOWN/_NAMES/_ROLE/ALIAS rewrites). Tail = exactly four nested TEXT records,
    /// in order: word (`[a-z][a-z0-9_-]{0,31}`; the operator writes `{<word>: X}`), settings key (core
    /// expands the shorthand to a SourceReference whose settings are `{<key>: X}`), shown placeholder (may
    /// be empty), names text (what a refusal calls the value). role = SUGAR_ROLE_*; flags = SUGAR_ALIAS?
    /// (the word is also accepted as a `module:` value naming this source).
    #[repr(C)]
    #[derive(
        Clone,
        Copy,
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
    )]
    pub struct SugarRec {
        pub role: u32,
        pub flags: u32,
    }

    pub mod tag {
        /// The secret value. Exactly one in an OK answer.
        pub const VALUE: u16 = 0x0100;
        /// describe: D_SUGAR* (SugarRec + 4 × TEXT), at most 4 per plugin.
        pub const D_SUGAR: u16 = 0x0180;
        /// Round 8, describe: the JSON Schema (UTF-8, draft 2020-12 subset core's D_SCHEMA validator already
        /// accepts) of one reference's `settings` object, exactly what `resolve` receives. At most one;
        /// required (DescribeInvalid without it). Replaces 1.5.x's pure, instance-free `check` slot: core's
        /// binder validates every reference routed to this plugin against it at `--validate`, boot and
        /// apply, before anything resolves (§12.7), with no plugin call. secret-env: `{"type":"object",
        /// "required":["key"],"additionalProperties":false,"properties":{"key":{"type":"string",
        /// "pattern":"^[^=\\u0000]*[^=\\u0000\\s][^=\\u0000]*$"}}}`; secret-file: `path` with
        /// `"pattern":"^/[^\\u0000]*$"` (absolute, no NUL), exactly today's `check` rules.
        pub const D_REF_SCHEMA: u16 = 0x0181;
    }

    pub const REQUIRED: u64 = 0b1;
    /// Fact: the backend's lease length in seconds (vault). Core decides the cache TTL.
    pub const F_LEASE_S: u32 = 0x100;
    /// SugarRec.role: none; FILL = the source `${NAME}` template placeholders are filled from (env);
    /// PATH = the source a bare file-path position reads from (file). Each role is declared by at most one
    /// admitted plugin (else config load refuses naming both words).
    pub const SUGAR_ROLE_NONE: u32 = 0;
    pub const SUGAR_ROLE_FILL: u32 = 1;
    pub const SUGAR_ROLE_PATH: u32 = 2;
    pub const SUGAR_ALIAS: u32 = 1;

    pub const KIND: crate::types::KindCode = crate::types::KindCode::Secret;
    pub const ABI: u32 = 2;
    pub const FP: u64 = 0; // W0-ABI stub value; kind! computes it (W1-A4).

    pub const M_RESOLVE: u64 = 1 << 0;
    pub const ALL: u64 = M_RESOLVE;

    // W0-ABI: `Vt` (field resolve is an unsafe extern "C" fn pointer) and the `vt::<T>()` shims are unsafe;
    // they land with W1-A4 (`kind!`) under an escapes.json admission.

    /// Declares one secret-reference shorthand (D_SUGAR: SugarRec + word, key, shown, names), over
    /// `Describe::item` (IF §8.2).
    pub fn sugar(
        d: &mut crate::plugin::Describe<'_>,
        role: u32,
        flags: u32,
        word: &str,
        key: &str,
        shown: &str,
        names: &str,
    ) {
        // A body that cannot be built (a text past the 16 MiB record cap) declares nothing; core's
        // `decode_sugars` bounds every real word, key and text far below that.
        if let Some(body) = sugar_body(role, flags, [word, key, shown, names]) {
            d.item(tag::D_SUGAR, &body);
        }
    }

    /// The D_SUGAR item body: the SugarRec, then exactly four TEXT records (word, key, shown, names).
    fn sugar_body(role: u32, flags: u32, texts: [&str; 4]) -> Option<Vec<u8>> {
        use crate::records::{Reply, Writer};
        use zerocopy::IntoBytes;

        let mut tail = Reply::new();
        for text in texts {
            tail.put_text(crate::records::tag::TEXT, text).ok()?;
        }
        let mut body = Vec::with_capacity(size_of::<SugarRec>() + tail.len());
        body.extend_from_slice(SugarRec { role, flags }.as_bytes());
        body.extend_from_slice(tail.as_bytes());
        Some(body)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::records::{Records, tag};

        #[test]
        fn a_sugar_body_is_the_rec_then_four_text_records_in_order() {
            let texts = ["env", "key", "VAR", "the variable"];
            let body = sugar_body(SUGAR_ROLE_FILL, SUGAR_ALIAS, texts).unwrap();
            assert_eq!(body[..4], SUGAR_ROLE_FILL.to_ne_bytes());
            assert_eq!(body[4..8], SUGAR_ALIAS.to_ne_bytes());
            let read: Vec<&str> = Records::new(&body[8..])
                .map(|r| {
                    let r = r.unwrap();
                    assert_eq!(r.tag, tag::TEXT);
                    r.text().unwrap()
                })
                .collect();
            assert_eq!(read, texts);
        }

        #[test]
        fn an_empty_shown_text_is_still_a_record() {
            let body = sugar_body(SUGAR_ROLE_PATH, 0, ["file", "path", "", "the file"]).unwrap();
            assert_eq!(Records::new(&body[8..]).count(), 4);
        }
    }

    /// `vt` points into the plugin image; it is valid because `inst` holds the image (I13), and it is never
    /// handed out with a lifetime longer than `&self`.
    #[cfg(feature = "host")]
    pub struct Proxy {
        // W0-ABI: fields `inst: Arc<Instance>` and `vt: NonNull<Vt>` land with W1-A4; `vt` needs the unsafe
        // `Vt`, and the `unsafe impl Send/Sync for Proxy` and `pub unsafe fn bind` land with it.
        _stub: core::marker::PhantomData<std::sync::Arc<crate::host_side::driver::Instance>>,
    }

    #[cfg(feature = "host")]
    impl Proxy {
        pub fn instance(&self) -> &std::sync::Arc<crate::host_side::driver::Instance> {
            let _ = &self._stub;
            todo!()
        }

        pub fn resolve<'a, N: crate::host_side::needs::Needs>(
            &'a self,
            drv: &'a mut crate::host_side::driver::Driver<'a, N>,
            req: crate::host_side::pool::PooledOut,
        ) -> impl core::future::Future<
            Output = Result<crate::host_side::answer::OwnedAnswer, crate::fail::CallError>,
        > + Send
        + 'a {
            let _ = (&self._stub, drv, req);
            async move { todo!() }
        }
    }
}
