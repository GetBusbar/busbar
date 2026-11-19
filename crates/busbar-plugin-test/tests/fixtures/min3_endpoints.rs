// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIN-3 endpoint-declaring fixtures (C-TRANSPORT booted arms, TRANSPORT-SECURITY-POLICY §2 and §8), written with
//! `plugin!` like a shipped plugin (SDK-SAFE-TEST-HOST §3.4 G). No `unsafe`.
//!
//! One image per kind (store, auth, secret, export, hook, transport), each with the same `Open::check`: it states
//! the endpoints its config names through `Endpoints`, exactly as a plugin states the endpoints its OPEN and FETCH
//! Needs will use, so the verdict is decided by the config, never by the kind. The config is an object of lists:
//!
//! ```text
//! {"open":  ["<tls> <egress> <dest>", ...],    tls = none | required | mutual | inband, egress = the class number
//!  "fetch": ["<egress> <url>", ...]}           `https://` = TLS, `http://` = none
//! ```
//!
//! `{}` declares nothing (an in-process instance). `open` checks the same grammar and builds the instance; every
//! kind method answers `unsupported`, because the arms these fixtures serve stop at `check` and `open`.
//!
//! [`raw`] is the one image `plugin!` cannot build: its `check` answer carries hand-written ENDPOINT records the SDK
//! writer refuses to emit (more than 16, an over-long dest, an unknown op, an egress class above 4, the retired bit
//! 0x200), so the loader's own decode (`decode_endpoints`, private to plugin-loader `instance.rs`) is reached through
//! a real CHECK answer. It is wired by hand over busbar-ffi's safe image API, as `tests/bridge_fixture.rs` is.

use std::collections::HashMap;

use busbar_plugin_abi::fail::refused::R_CONFIG;
use busbar_plugin_abi::fail::Fail;
use busbar_plugin_abi::need::need_flag::{TLS_INBAND, TLS_MUTUAL, TLS_NONE, TLS_REQUIRED};
use busbar_plugin_abi::need::ChainBytes;
use busbar_plugin_abi::plugin::{Describe, Endpoints};

/// The config: `open` and `fetch` lists of endpoint entries (module doc).
type Config = HashMap<String, Vec<String>>;

fn parse_config(bytes: &[u8]) -> Result<Config, Fail> {
    busbar_contract::json::parse::<Config>(bytes).map_err(|_| {
        Fail::refused_because(
            R_CONFIG,
            "config must be an object of lists of endpoint entries",
        )
    })
}

fn bad_entry() -> Fail {
    Fail::refused_because(
        R_CONFIG,
        "an endpoint entry is `<tls> <egress> <dest>` (open) or `<egress> <url>` (fetch)",
    )
}

fn tls_of(word: &str) -> Result<u32, Fail> {
    match word {
        "none" => Ok(TLS_NONE),
        "required" => Ok(TLS_REQUIRED),
        "mutual" => Ok(TLS_MUTUAL),
        "inband" => Ok(TLS_INBAND),
        _ => Err(bad_entry()),
    }
}

fn egress_of(word: &str) -> Result<u32, Fail> {
    word.parse::<u32>().map_err(|_| bad_entry())
}

/// `check`'s declarations: every `open` entry, then every `fetch` entry, in config order, as stated. Whether a
/// stated endpoint is admitted is core's verdict, never this fixture's.
fn declare(bytes: &[u8], ends: &mut Endpoints<'_>) -> Result<(), Fail> {
    let config = parse_config(bytes)?;
    for entry in config.get("open").into_iter().flatten() {
        let mut words = entry.splitn(3, ' ');
        let (Some(tls), Some(egress), Some(dest)) = (words.next(), words.next(), words.next())
        else {
            return Err(bad_entry());
        };
        ends.open(dest, tls_of(tls)?, egress_of(egress)?);
    }
    for entry in config.get("fetch").into_iter().flatten() {
        let (egress, url) = entry.split_once(' ').ok_or_else(bad_entry)?;
        ends.fetch(url, egress_of(egress)?);
    }
    Ok(())
}

/// `open`: the same grammar `check` reads, and nothing dialled.
fn opened(config: &ChainBytes) -> Result<(), Fail> {
    config.with(|bytes| parse_config(bytes).map(drop))
}

fn describe_object(d: &mut Describe<'_>) {
    d.schema(r#"{"type":"object"}"#);
}

/// `Open` for one endpoint-declaring fixture type, with the describe items its kind needs.
macro_rules! declaring {
    ($T:ident, $describe:path) => {
        impl busbar_plugin_abi::plugin::Open for $T {
            async fn open(_h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
                opened(&config)?;
                Ok($T)
            }

            fn check(_h: &Host, config: &[u8], ends: &mut Endpoints<'_>) -> Result<(), Fail> {
                declare(config, ends)
            }

            fn describe(d: &mut Describe<'_>) {
                $describe(d);
            }
        }
    };
}

pub mod store {
    use super::*;
    use busbar_plugin_abi::host::Host;
    use busbar_plugin_abi::records::{Out, Reply};

    /// A store that declares the endpoints its config names.
    pub struct EndpointStore;

    declaring!(EndpointStore, describe_object);

    impl busbar_plugin_abi::Store for EndpointStore {
        async fn read(&self, _h: &'static Host, _req: ChainBytes) -> Result<Reply, Fail> {
            Err(Fail::unsupported())
        }

        async fn scan(&self, _h: &'static Host, _req: ChainBytes) -> Result<Reply, Fail> {
            Err(Fail::unsupported())
        }

        async fn commit(&self, _h: &'static Host, _cand: ChainBytes) -> Result<Reply, Fail> {
            Err(Fail::unsupported())
        }

        async fn clock(&self, _h: &'static Host, _dataset: ChainBytes) -> Result<Reply, Fail> {
            Err(Fail::unsupported())
        }

        fn info(&self, _h: &Host, _out: &mut Out<'_>) -> Result<(), Fail> {
            Err(Fail::unsupported())
        }
    }

    busbar_plugin_abi::plugin!(Store, EndpointStore, name: "fixture-endpoint-store");
}

pub mod auth {
    use super::*;
    use busbar_plugin_abi::host::Host;

    /// An auth that declares the endpoints its config names.
    pub struct EndpointAuth;

    declaring!(EndpointAuth, describe_object);

    impl busbar_plugin_abi::Auth for EndpointAuth {}

    busbar_plugin_abi::plugin!(Auth, EndpointAuth, name: "fixture-endpoint-auth");
}

pub mod secret {
    use super::*;
    use busbar_plugin_abi::host::Host;
    use busbar_plugin_abi::records::Reply;

    /// A secret source that declares the endpoints its config names.
    pub struct EndpointSecret;

    fn describe_secret(d: &mut Describe<'_>) {
        describe_object(d);
        d.item_text(
            busbar_plugin_abi::secret::tag::D_REF_SCHEMA,
            r#"{"type":"object"}"#,
        );
    }

    declaring!(EndpointSecret, describe_secret);

    impl busbar_plugin_abi::Secret for EndpointSecret {
        async fn resolve(&self, _h: &'static Host, _reference: ChainBytes) -> Result<Reply, Fail> {
            Err(Fail::unsupported())
        }
    }

    busbar_plugin_abi::plugin!(Secret, EndpointSecret, name: "fixture-endpoint-secret");
}

pub mod export {
    use super::*;
    use busbar_plugin_abi::host::Host;

    /// An export sink that declares the endpoints its config names.
    pub struct EndpointExport;

    declaring!(EndpointExport, describe_object);

    impl busbar_plugin_abi::Export for EndpointExport {}

    busbar_plugin_abi::plugin!(Export, EndpointExport, name: "fixture-endpoint-export");
}

pub mod hook {
    use super::*;
    use busbar_plugin_abi::host::Host;

    /// A hook that declares the endpoints its config names.
    pub struct EndpointHook;

    declaring!(EndpointHook, describe_object);

    impl busbar_plugin_abi::Hook for EndpointHook {}

    busbar_plugin_abi::plugin!(Hook, EndpointHook, name: "fixture-endpoint-hook");
}

pub mod transport {
    use super::*;
    use busbar_plugin_abi::host::Host;
    use busbar_plugin_abi::records::Out;

    /// A transport that declares the endpoints its config names.
    pub struct EndpointTransport;

    declaring!(EndpointTransport, describe_object);

    impl busbar_plugin_abi::Transport for EndpointTransport {
        type Session = ();

        fn begin(
            &self,
            _h: &Host,
            _conn: &busbar_plugin_abi::transport::ConnInfo<'_>,
            _out: &mut Out<'_>,
        ) -> Result<Self::Session, Fail> {
            Err(Fail::unsupported())
        }
    }

    busbar_plugin_abi::plugin!(Transport, EndpointTransport, name: "fixture-endpoint-transport");
}

/// The hand-written CHECK answers (module doc). A secret-kind image: its `check` (the `open` entry under
/// `OPEN_DRY_RUN`) answers OK with the ENDPOINT records the config's `case` names; it never builds an instance and
/// its `resolve` refuses. Cases: `sixteen` (16 valid records), `seventeen` (17), `max-dest` (a 2,048-byte dest),
/// `long-dest` (2,049 bytes), `bad-op` (op SECRET), `egress-five` (egress class 5) and `bit-200` (TLS_REQUIRED with
/// the retired 0x200). Any other config answers no record.
pub mod raw {
    use busbar_ffi::shim::{ChainFut, Image, Opening, Starts, Step};
    use busbar_ffi::slots::{ChainBox, ChainRef, Slots};
    use busbar_ffi::vt::kind;
    use busbar_ffi::{plugin, Bytes, ChainBytes, LinkedPlugin, Out, Status, Str, Token};
    use busbar_ffi::{ChainArgs, Table};
    use busbar_plugin_abi::bridge::{self, Inbox};
    use busbar_plugin_abi::fail::{refused, Fail};
    use busbar_plugin_abi::host::Host;
    use busbar_plugin_abi::need::{egress, need_flag, op};
    use busbar_plugin_abi::plugin::OPEN_DRY_RUN;
    use busbar_plugin_abi::records::{tag, EndpointRec, MaskRec, Reply, Writer};

    /// A valid record's flags: verified TLS to operator infrastructure.
    const VALID: u32 =
        need_flag::TLS_REQUIRED | (egress::OPERATOR_INFRASTRUCTURE << need_flag::EGRESS_SHIFT);

    /// The plugin value (never built: this image answers `check` only).
    pub struct RawPlugin;

    /// The image type.
    pub struct RawImage;

    static GLOBAL: Slots<ChainBox<Result<Reply, Fail>, Inbox>> = Slots::new();

    fn endpoint(r: &mut Reply, code: u32, flags: u32, dest: &[u8]) -> Option<()> {
        r.put_pod_tail(tag::ENDPOINT, &EndpointRec { op: code, flags }, dest)
            .ok()
    }

    /// The ENDPOINT records of the case `config` names.
    fn answer(config: &[u8]) -> Option<Reply> {
        let names = |case: &str| config.windows(case.len()).any(|w| w == case.as_bytes());
        let mut r = Reply::new();
        if names("sixteen") || names("seventeen") {
            let n = if names("seventeen") { 17 } else { 16 };
            for i in 0..n {
                endpoint(
                    &mut r,
                    op::OPEN,
                    VALID,
                    format!("db{i}.internal:5432").as_bytes(),
                )?;
            }
        } else if names("max-dest") || names("long-dest") {
            let len = if names("long-dest") { 2_049 } else { 2_048 };
            let mut dest = vec![b'd'; len - ":5432".len()];
            dest.extend_from_slice(b":5432");
            endpoint(&mut r, op::OPEN, VALID, &dest)?;
        } else if names("bad-op") {
            endpoint(&mut r, op::SECRET, VALID, b"db.internal:5432")?;
        } else if names("egress-five") {
            let flags = need_flag::TLS_REQUIRED | (5 << need_flag::EGRESS_SHIFT);
            endpoint(&mut r, op::OPEN, flags, b"db.internal:5432")?;
        } else if names("bit-200") {
            endpoint(&mut r, op::OPEN, VALID | 0x200, b"db.internal:5432")?;
        }
        Some(r)
    }

    impl Image for RawImage {
        type Plugin = RawPlugin;
        type Session = ();
        type Reply = Result<Reply, Fail>;
        type Inbox = Inbox;

        fn global() -> &'static Slots<ChainBox<Self::Reply, Self::Inbox>> {
            &GLOBAL
        }

        fn describe(_h: &'static Host, out: &mut Out<'_>) -> Status {
            let mut items = Reply::new();
            let written = items
                .put_pod(
                    tag::D_METHODS,
                    &MaskRec {
                        mask: busbar_plugin_abi::secret::REQUIRED,
                    },
                )
                .and_then(|()| items.put_text(tag::D_SCHEMA, r#"{"type":"object"}"#))
                .and_then(|()| {
                    items.put_text(
                        busbar_plugin_abi::secret::tag::D_REF_SCHEMA,
                        r#"{"type":"object"}"#,
                    )
                });
            if written.is_ok() && out.append(items.as_bytes()) {
                Status::OK
            } else {
                Status::FAULT
            }
        }

        fn open(
            _h: &'static Host,
            config: Bytes<'_>,
            _chained: ChainBytes,
            flags: u32,
            out: &mut Out<'_>,
        ) -> Opening<Self::Reply, Self::Inbox> {
            if flags & OPEN_DRY_RUN == 0 {
                return Opening::Done(bridge::answer_sync(
                    out,
                    Err(Fail::refused_because(
                        refused::R_CONFIG,
                        "this fixture answers check only",
                    )),
                ));
            }
            Opening::Done(match answer(config.get()) {
                Some(records) if out.append(records.as_bytes()) => Status::OK,
                _ => Status::FAULT,
            })
        }

        fn poll(
            chain: ChainRef<'_, Self::Reply, Self::Inbox>,
            results: Option<ChainBytes>,
            out: &mut Out<'_>,
        ) -> Step {
            bridge::poll(chain, results, out)
        }

        fn parked(token: Token, out: &mut Out<'_>) -> Status {
            bridge::parked(token, out)
        }

        fn opened(token: Token, out: &mut Out<'_>) -> Status {
            bridge::opened(token, out)
        }
    }

    impl Starts<0> for RawImage {
        fn start<'i>(
            _p: &'i RawPlugin,
            _h: &'static Host,
            _args: ChainArgs<'_>,
        ) -> Option<(ChainFut<'i, Self::Reply>, Self::Inbox)> {
            Some((
                Box::pin(core::future::ready(Err::<Reply, Fail>(Fail::refused(
                    refused::R_INVALID,
                )))),
                Inbox::new(),
            ))
        }
    }

    static VT: Table<RawImage, 1> = Table::new([busbar_ffi::shim::starts::<RawImage, 0>()]);
    static STAMP: busbar_ffi::StampBytes =
        busbar_plugin_abi::stamp::emit(&busbar_plugin_abi::stamp::Spec {
            kind: busbar_plugin_abi::secret::KIND,
            kind_abi: busbar_plugin_abi::secret::ABI,
            kind_minor: busbar_plugin_abi::secret::MINOR,
            layout: busbar_plugin_abi::secret::FP,
            out_of_process: false,
            engine_min: None,
            engine_max: None,
            name: "fixture-endpoint-raw",
            version: env!("CARGO_PKG_VERSION"),
            build_id: None,
            crypto: "host",
        });

    /// This image's header (`PLUGIN.plugin()` is what `Harness::admit` takes).
    pub static PLUGIN: LinkedPlugin = plugin::<RawImage, kind::Secret, 1>(&VT, &STAMP, Str::EMPTY);
}
