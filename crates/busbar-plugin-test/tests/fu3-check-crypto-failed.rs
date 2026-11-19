// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FU3 (MIN3-BLOCKER-RULINGS B30): a Host crypto `Err` seen in a plugin's `check` answers FAILED, never REFUSED.
//! `check` judges a configuration, not a credential, so a crypto module that cannot run (INVALID, UNAVAILABLE,
//! LIMIT, RNG) is a backend failure the operator retries or reports, not a REFUSED config verdict that names a
//! setting. A signature that does not verify is not an `Err` (`Host::verify` answers `Ok(false)`), so a `check`
//! that propagates it with `?` still answers OK. Outside `check` the §4.1 map is unchanged: the same `Err`
//! stays the verdict `?` gives it today.
//!
//! The fixture is a secret-shaped plugin whose `check` verifies one signature and propagates the host's answer
//! with `?`; the host's `crypto` entry answers the status the case names (the config is that status's number).

use busbar_plugin_abi::fail::{failed, refused, Fail};
use busbar_plugin_abi::host::{
    crypto_status, CryptoErr, CryptoReq, CryptoRet, Ctx, Host, HostFns, RawLent,
};
use busbar_plugin_abi::plugin::__rt::host::{OpenAnswer, OutLease};
use busbar_plugin_abi::plugin::__rt::kind as marker;
use busbar_plugin_abi::plugin::OPEN_DRY_RUN;
use busbar_plugin_abi::types::Status;

mod fx {
    use busbar_plugin_abi::fail::Fail;
    use busbar_plugin_abi::host::{Host, HostExt, Key, Sig};
    use busbar_plugin_abi::need::ChainBytes;
    use busbar_plugin_abi::plugin::__rt::image::Admitted;
    use busbar_plugin_abi::plugin::{Endpoints, Open};
    use busbar_plugin_abi::records::Reply;

    busbar_plugin_abi::kind! {
        /// A secret-shaped kind for this case.
        pub trait Verifies: kind = 2, abi = 2 {
            views {}
            pods {}
            tags {}
            consts { REQUIRED: u64 = 0b1; }
            async fn resolve(&self, h: &'static Host, reference: ChainBytes) -> Result<Reply, Fail>;
        }
    }

    pub struct Fx;
    impl Verifies for Fx {
        async fn resolve(&self, _h: &'static Host, _reference: ChainBytes) -> Result<Reply, Fail> {
            Ok(Reply::new())
        }
    }
    impl Open for Fx {
        async fn open(_h: &'static Host, _config: ChainBytes) -> Result<Self, Fail> {
            Ok(Fx)
        }
        fn check(h: &Host, _config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
            h.verify(Sig::Es256, Key::Raw(&[1; 32]), b"message", b"signature")?;
            Ok(())
        }
    }

    busbar_plugin_abi::plugin!(@kind [secret] Fx);

    pub fn admitted() -> Admitted {
        match Admitted::linked(&PLUGIN) {
            Ok(admitted) => admitted,
            Err(e) => panic!("admit: {e:?}"),
        }
    }
}

/// A host whose `crypto` answers one fixed status with an empty output (every non-OK status has EMPTY out).
fn host(
    crypto: for<'e, 'a> extern "C" fn(Ctx<'e>, &CryptoReq<'a>) -> CryptoRet<'e>,
) -> &'static Host {
    Box::leak(Box::new(Host::new(
        0,
        HostFns {
            now: None,
            mono: None,
            random: None,
            crypto: Some(crypto),
            log: None,
            log_level: None,
            grow: None,
            deployment: None,
            service: None,
        },
    )))
}

fn answer<'e>(status: u32) -> CryptoRet<'e> {
    CryptoRet {
        status,
        _r: 0,
        out: RawLent::EMPTY,
    }
}

extern "C" fn invalid<'e, 'a>(_: Ctx<'e>, _: &CryptoReq<'a>) -> CryptoRet<'e> {
    answer(crypto_status::INVALID)
}
extern "C" fn unavailable<'e, 'a>(_: Ctx<'e>, _: &CryptoReq<'a>) -> CryptoRet<'e> {
    answer(crypto_status::UNAVAILABLE)
}
extern "C" fn limit<'e, 'a>(_: Ctx<'e>, _: &CryptoReq<'a>) -> CryptoRet<'e> {
    answer(crypto_status::LIMIT)
}
extern "C" fn rng<'e, 'a>(_: Ctx<'e>, _: &CryptoReq<'a>) -> CryptoRet<'e> {
    answer(crypto_status::RNG)
}
extern "C" fn bad<'e, 'a>(_: Ctx<'e>, _: &CryptoReq<'a>) -> CryptoRet<'e> {
    answer(crypto_status::BAD)
}
extern "C" fn ok<'e, 'a>(_: Ctx<'e>, _: &CryptoReq<'a>) -> CryptoRet<'e> {
    answer(crypto_status::OK)
}

/// The status the fixture's DRY_RUN `open` answers over this host.
fn checked(crypto: for<'e, 'a> extern "C" fn(Ctx<'e>, &CryptoReq<'a>) -> CryptoRet<'e>) -> Status {
    let mut out = OutLease::new(vec![0; 4096], 1 << 20).expect("a free ACTIVE slot");
    let OpenAnswer::Done(status, None) =
        fx::admitted().open::<marker::Secret>(host(crypto), Vec::new(), OPEN_DRY_RUN, &mut out)
    else {
        panic!("DRY_RUN builds no instance");
    };
    status
}

#[test]
fn a_host_crypto_err_in_check_is_failed_never_refused() {
    assert_eq!(checked(invalid), Status::FAILED, "INVALID");
    assert_eq!(checked(unavailable), Status::FAILED, "UNAVAILABLE");
    assert_eq!(checked(limit), Status::FAILED, "LIMIT");
    assert_eq!(checked(rng), Status::FAILED, "RNG");
}

#[test]
fn a_signature_that_does_not_verify_is_not_a_crypto_err() {
    // BAD is `Ok(false)` from `Host::verify`, so the fixture's `?` has nothing to propagate.
    assert_eq!(checked(bad), Status::OK);
    assert_eq!(checked(ok), Status::OK);
}

#[test]
fn outside_check_the_crypto_map_is_unchanged() {
    fn refused_with(e: CryptoErr) -> Fail {
        Fail::from(e)
    }
    assert_eq!(
        (
            refused_with(CryptoErr::Invalid).status(),
            refused_with(CryptoErr::Invalid).code()
        ),
        (Status::REFUSED, refused::R_INVALID)
    );
    assert_eq!(
        (
            refused_with(CryptoErr::Unavailable).status(),
            refused_with(CryptoErr::Unavailable).code()
        ),
        (Status::REFUSED, refused::R_UNSUPPORTED)
    );
    assert_eq!(
        (
            refused_with(CryptoErr::Rng).status(),
            refused_with(CryptoErr::Rng).code()
        ),
        (Status::FAILED, failed::F_UNAVAILABLE)
    );
}
