// SPDX-License-Identifier: Apache-2.0
//! The config-only CHECK has no synchronous host services either. Remember attempts so a
//! parser cannot ignore a denied host result and publish an apparently successful CHECK.
use busbar_ffi::{CryptoReq, CryptoRet, Ctx, DeploymentId, Host, HostFns, RawOut, Status, Str};
use std::cell::Cell;

thread_local! { static ATTEMPTED: Cell<bool> = const { Cell::new(false) }; }
fn attempted() {
    ATTEMPTED.set(true);
}
extern "C" fn clock(_: Ctx<'_>) -> u64 {
    attempted();
    0
}
extern "C" fn random(ctx: Ctx<'_>, _: usize) -> CryptoRet<'_> {
    attempted();
    CryptoRet::empty(ctx, busbar_plugin_abi::host::crypto_status::LIMIT)
}
extern "C" fn crypto<'e>(ctx: Ctx<'e>, _: &CryptoReq<'_>) -> CryptoRet<'e> {
    attempted();
    CryptoRet::empty(ctx, busbar_plugin_abi::host::crypto_status::LIMIT)
}
extern "C" fn log(_: Ctx<'_>, _: u32, _: u32, _: Str<'_>) {
    attempted();
}
extern "C" fn level(_: Ctx<'_>) -> u32 {
    attempted();
    0
}
extern "C" fn grow(_: Ctx<'_>, _: &mut RawOut, _: usize) -> bool {
    attempted();
    false
}
/// The one host read a CHECK may make (IF round 28/29 §5 `deployment`, §11.2 `BootPlan`): a plugin binds to the
/// install in `check`, and core re-runs the 2a/2b checks once the id is published. A pure read of process state,
/// not a service: it is not an attempt.
extern "C" fn deployment(_: Ctx<'_>) -> DeploymentId {
    busbar_plugin_abi::host_side::host_vt::vt::deployment()
}
extern "C" fn migrate(_: Ctx<'_>, _: u64) -> Status {
    attempted();
    Status::REFUSED
}
static CHECK_HOST: Host = Host::new(
    0,
    HostFns {
        now: Some(clock),
        mono: Some(clock),
        random: Some(random),
        crypto: Some(crypto),
        log: Some(log),
        log_level: Some(level),
        grow: Some(grow),
        deployment: Some(deployment),
        migrate_admit: Some(migrate),
    },
);

pub(super) fn run<T>(body: impl FnOnce(&'static Host) -> T) -> (T, bool) {
    ATTEMPTED.set(false);
    let result = body(&CHECK_HOST);
    (result, ATTEMPTED.replace(false))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ignored_synchronous_host_results_still_refuse_config_only_check() {
        let (_, attempted) = run(|host| {
            host.scoped(|ctx| {
                host.fns().now.expect("denial entry")(ctx);
            })
        });
        assert!(attempted);
        assert!(
            !run(|_| ()).1,
            "a fresh pure parser does not inherit another check's attempt"
        );
    }

    #[test]
    fn a_deployment_read_is_not_an_attempt_but_every_other_service_still_is() {
        let (_, attempted) = run(|host| {
            host.scoped(|ctx| {
                host.fns().deployment.expect("deployment entry")(ctx);
            })
        });
        assert!(!attempted, "check binds to the install with deployment_id");
        let (_, attempted) = run(|host| {
            host.scoped(|ctx| {
                host.fns().deployment.expect("deployment entry")(ctx);
                host.fns().log_level.expect("denial entry")(ctx);
            })
        });
        assert!(
            attempted,
            "a deployment read does not lift the denial of another host service"
        );
    }
}
