// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::mechanism::call::{Blob, OutHead, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, GenIn, RefreshIn, ValidateIn};
use busbar_contract::abi::secret::{slot, ResolveIn, ResolveOut, ERROR_KIND_NOT_FOUND};

use super::door_both_ways::{
    self as both, close, input, line, open, output, release, same, Loaded,
};
use crate::actual_env_secret as secret_fixture;
use crate::dispatch::kinds::export::Export;
use crate::dispatch::kinds::secret::Secret;
use crate::dispatch::{load_linked, Frame, LinkedRow, Plugin};

#[path = "../../tests/fixtures/secret_door_plugin.rs"]
pub(crate) mod secret_door_plugin;

const MATERIAL: &str = "s3cr3t-both-ways";

const HIT: &str = "BUSBAR_LOADER_SECRET_BOTH_WAYS_HIT";
const MISS: &str = "BUSBAR_LOADER_SECRET_BOTH_WAYS_MISS";

const CROSSINGS: u64 = 10;

fn json(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

fn crossings(p: &Plugin<Secret>) -> u64 {
    p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst)
}

fn validate(p: &Plugin<Secret>, settings: &[u8]) -> String {
    let mut v: Frame<ValidateIn, OutHead> = Frame::new(input(), output());
    v.input.settings = json(settings);
    line("validate", &p.call(life::VALIDATE, &mut v))
}

fn refresh(p: &Plugin<Secret>, generation: u64) -> String {
    let mut r: Frame<RefreshIn, OutHead> = Frame::new(input(), output());
    r.input.generation = generation;
    r.input.settings = json(b"{}");
    line("refresh", &p.call(life::REFRESH, &mut r))
}

fn retire(p: &Plugin<Secret>, generation: u64) -> String {
    let mut r: Frame<GenIn, OutHead> = Frame::new(input(), output());
    r.input.generation = generation;
    line("retire", &p.call(life::RETIRE, &mut r))
}

fn resolve(p: &Plugin<Secret>, settings: &[u8]) -> String {
    let mut buf = vec![0_u8; busbar_contract::abi::secret::FIRST_SECRET_CAP];
    let mut r: Frame<ResolveIn, ResolveOut> = Frame::new(input(), output());
    r.input.settings = json(settings);
    r.input.secret_buf = buf.as_mut_ptr();
    r.input.secret_cap = buf.len();
    let c = p.call(slot::RESOLVE, &mut r);
    let material = if c.outcome == Outcome::Ready && !r.out.secret.ptr.is_null() {
        assert_eq!(r.out.secret.ptr, buf.as_ptr(), "in the host's buffer");
        String::from_utf8_lossy(&buf[..r.out.secret.len]).into_owned()
    } else {
        String::new()
    };
    buf.fill(0);
    format!(
        "{} error_kind={} material={material:?}",
        line("resolve", &c),
        r.out.error_kind
    )
}

fn script(p: &Plugin<Secret>) -> Vec<String> {
    let hit = format!(r#"{{"key": "{HIT}"}}"#);
    let miss = format!(r#"{{"key": "{MISS}"}}"#);
    let mut t = vec![validate(p, b"{}"), line("open", &open(p, b"{}"))];
    t.push(resolve(p, hit.as_bytes()));
    t.push(line("release", &release(p, 1)));
    t.push(resolve(p, miss.as_bytes()));
    t.push(refresh(p, 2));
    t.push(resolve(p, hit.as_bytes()));
    t.push(line("release", &release(p, 1)));
    t.push(retire(p, 1));
    t.push(line("close", &close(p)));
    t.push(resolve(p, hit.as_bytes()));
    t
}

fn linked() -> Loaded<Secret> {
    both::linked::<Secret>(secret_fixture::door)
}

fn dropped() -> Loaded<Secret> {
    let path = secret_fixture::cdylib();
    both::dropped_from::<Secret>(secret_fixture::door, &path)
}

#[test]
fn a_linked_and_a_dropped_in_secret_plugin_resolve_identically() {
    std::env::set_var(HIT, MATERIAL);
    std::env::remove_var(MISS);
    let (linked, dropped) = (linked(), dropped());
    let (a, b) = (script(&linked.plugin), script(&dropped.plugin));
    same(&a, &b);

    assert_eq!(crossings(&linked.plugin), CROSSINGS, "linked crossings");
    assert_eq!(
        crossings(&dropped.plugin),
        CROSSINGS,
        "dropped-in crossings"
    );

    assert!(a[1].contains("Ready"), "{}", a[1]);
    assert!(
        a[2].contains("Ready") && a[2].contains(MATERIAL) && a[2].contains("lease=0"),
        "a hit is READY with its material in the host's buffer, under no lease: {}",
        a[2]
    );
    assert!(a[3].contains("Refused"), "no lease to release: {}", a[3]);
    assert!(
        a[4].contains("Failed") && a[4].contains(&format!("error_kind={ERROR_KIND_NOT_FOUND}")),
        "a miss is FAILED, NOT_FOUND: {}",
        a[4]
    );
    assert!(
        a[5].contains("Ready"),
        "refresh to the next generation: {}",
        a[5]
    );
    assert!(a[6].contains(MATERIAL), "a hit after the refresh: {}", a[6]);
    assert!(a[7].contains("Refused"), "no lease to release: {}", a[7]);
    assert!(
        a[8].contains("Ready") && a[9].contains("Ready"),
        "retire, close"
    );
    assert!(a[10].contains("Fault"), "a resolve after close: {}", a[10]);
}

#[test]
fn a_secret_plugin_that_breaks_resolve_is_refused_through_both_doors() {
    let broken = secret_door_plugin::broken::door;
    let run = |p: &Plugin<Secret>| {
        let opened = line("open", &open(p, b"{}"));
        let resolved = resolve(p, b"{}");
        vec![opened, resolved]
    };
    let linked = run(&both::linked::<Secret>(broken).plugin);
    assert!(linked[0].contains("Ready"), "{}", linked[0]);
    assert!(linked[1].contains("Fault"), "{}", linked[1]);
    let dropped = both::dropped::<Secret>(broken, "secret_broken_door");
    same(&linked, &run(&dropped.plugin));
}

#[test]
fn the_secret_door_is_not_another_kinds_door() {
    let dispatcher = std::sync::Arc::new(crate::dispatch::Dispatcher::new(
        crate::dispatch::DispatchConfig::default(),
    ));
    let row = LinkedRow::of(secret_fixture::door).expect("the linked row states");
    let err = load_linked::<Export>(&row, both::bind(&dispatcher))
        .expect_err("a secret door is not an export door");
    let said = format!("{err:?}");
    assert!(said.contains("Secret") || said.contains("Kind"), "{said}");
}
