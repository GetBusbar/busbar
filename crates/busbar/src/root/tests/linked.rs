// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE PLANE, BOTH DOORS, ONE ROW** — #2 rule (1) on the plane axis, at the composition root.
//!
//! `busbar-plugin-example-plane` is a `["cdylib", "rlib"]` crate, so this binary holds the SAME plane
//! two ways at once: LINKED (its `PLANE_DECL`, through the rlib, in [`Linked::hot_planes`]) and
//! DROPPED IN (its cdylib, packaged into a signed tarball in a temp `plugins/` directory and found by
//! [`dropped_planes`], the scan boot runs over the configured `plugins.dir`). Each arm is folded by
//! [`plane_rows`] — the rows [`register_planes`] installs — and then by the kernel's own boot fold
//! (`merged_boot_plane_decls`: ordering, same-key skip, claim guard). The arms must agree byte for
//! byte on every row: the contract declaration, every hook, the claims and admission a row answers,
//! and the order.
//!
//! This is the loader's `plane_conformance_tests` (which compares the two DECLS) carried one layer
//! up, to the thing a deployment actually gets from a plane: its registry row.
//!
//! ## Red-before-green, PERMANENTLY
//!
//! [`the_boot_that_does_not_hand_the_dropped_in_planes_over_diverges`] is the RED arm and it stays:
//! it replays the boot before this change — `register_planes(&LINKED)`, the dropped-in plane never
//! handed to the axis — and shows the two builds disagreeing. If the two doors ever stop meeting in
//! one function, the equality tests below go red for the same reason that arm is unequal.

use super::*;
use crate::root::boot::dropped_planes;
use crate::root::loader::sign::{DiagnosticDecl, SigningKey, TrustPolicy};
use crate::root::loader::PluginRegistry;
use crate::root::test_plugins;
use busbar_kernel::plane::registry::{merged_boot_plane_decls, BuildCtx};
use busbar_plugin_example_plane::PLANE_DECL as LINKED_DECL;

/// The linked example plane, as the build table carries it.
pub(super) static LINKED_HOT: [&hot::PlaneDecl; 1] = [&LINKED_DECL];

/// A table with the given plane rows and HOT-lane planes and nothing on any other axis.
pub(super) fn linked(
    planes: &'static [PlaneDecl],
    hot_planes: &'static [&'static hot::PlaneDecl],
) -> Linked {
    Linked {
        planes,
        hot_planes,
        plane_doors: &[],
        secrets: &[],
        plane_door_slots: &[],
        plane_door_declares: &[],
        protocols: &[],
        path_ingress: &[],
        body_ingress: &[],
        protocol_seams: &[],
        diagnostics: &[],
        ws_arrivals: &[],
        on_host: &[],
        compose: &[],
        stdio_serve: &[],
        cli_help: &[],
        export_doors: &[],
        stores: &[],
        hook_doors: &[],
        auths: &[],
        gauntlet_one_shot: &[],
        gauntlet_session: &[],
        transports: &[],
        claims: &[],
        node: &[],
    }
}

/// A Rust-hook plane row keyed `key` (declaring section `key`), leaked for the table.
fn native(key: &'static str) -> &'static [PlaneDecl] {
    let declaration = PlaneDeclaration {
        key,
        fallback: false,
        config_section: key,
        scope_kinds: &[],
        subject_noun: key,
        admin_noun: key,
        audit_kind: key,
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &[],
        billable_classes: &[],
        fee_units: &[],
        metric_families: &[],
        record_kinds: &[],
        required_config_sections: &[],
        trust_keys: &[],
        served_op_classes: &[],
        caller_credential_refusal: None,
    };
    let hooks = PlaneHooks {
        wire_format_names: || &[busbar_kernel::plane::WIRE_HTTP_JSON],
        ..HOT_PLANE_HOOKS
    };
    Box::leak(Box::new([PlaneDecl::assemble(declaration, hooks)]))
}

/// EVERYTHING a registry row answers, as one line: the contract declaration, the wire formats, what
/// its claims / admission / build hooks answer, and which optional hooks it carries.
fn render(row: &PlaneDecl) -> String {
    let ctx = BuildCtx {
        endpoint_slot: None,
        agent_defs: &(),
        tool_defs: &(),
        public_url: None,
        prior: None,
    };
    let optional = [
        row.routes.is_some(),
        row.admin_routes.is_some(),
        row.openapi.is_some(),
        row.hydrate.is_some(),
        row.start.is_some(),
        row.config_validate.is_some(),
        row.named_def_list.is_some(),
        row.named_def_get.is_some(),
        row.registry_contains.is_some(),
        row.reresolve_gates.is_some(),
        row.openapi_schemas.is_some(),
        row.on_swap.is_some(),
        row.parse_section.is_some(),
        row.parse_endpoint.is_some(),
        row.lower_endpoint.is_some(),
        row.build_runtime.is_some(),
        row.viewer.is_some(),
        row.retain_verify_gates.is_some(),
        row.default_section.is_some(),
        row.resolve_provider.is_some(),
    ];
    format!(
        "{:?} wire={:?} claims={:?} admission={:?} build={} hooks={optional:?}",
        row.declaration,
        (row.wire_format_names)(),
        (row.claims)(&()),
        (row.admission)(&()),
        (row.build)(&ctx).is_some(),
    )
}

/// The installed rows after the kernel's boot fold, rendered in fold order.
fn folded(rows: Vec<&'static PlaneDecl>) -> Vec<String> {
    merged_boot_plane_decls(&rows, &[])
        .into_iter()
        .map(render)
        .collect()
}

/// The example plane's cdylib in this target dir (uplifted or under `deps`, newest wins). Under CI a
/// missing artifact is a failure, never a skip: this is the plane axis's both-doors proof.
fn cdylib() -> Option<std::path::PathBuf> {
    let found = test_plugins::cdylib_path("busbar_plugin_example_plane");
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "the example plane cdylib is not built under CI; the both-doors proof must not skip"
    );
    found
}

/// A fresh `plugins/` directory holding the example plane's cdylib as a SIGNED first-party tarball,
/// and the default trust posture that admits it (the release key held, no opt-ins).
fn plugins_dir(tag: &str, lib: &[u8]) -> (std::path::PathBuf, TrustPolicy) {
    let dir = test_plugins::scratch(&format!("root-dropped-plane-{tag}"));
    let release = test_plugins::key(7);
    let manifest = test_plugins::manifest("plane", "example-plane", "busbar");
    let tarball = test_plugins::signed(&release, manifest, lib);
    std::fs::write(dir.join("example-plane.tar.gz"), tarball).unwrap();
    (dir, test_plugins::release_policy(&release))
}

/// The example plane dropped into a fresh `plugins/` directory and found by the boot scan.
pub(super) fn dropped(tag: &str) -> Option<Vec<DynPlane>> {
    let lib = std::fs::read(cdylib()?).expect("read the example plane cdylib");
    let (dir, policy) = plugins_dir(tag, &lib);
    let planes = dropped_planes(&dir, &policy).expect("the signed plane loads");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(planes.len(), 1, "the scan finds the one dropped-in plane");
    Some(planes)
}

/// THE EXIT TEST. Linked or dropped in, the example plane installs the same row — same declaration,
/// same hooks, same claims — in the same slot, behind a Rust-hook plane that was linked ahead of it.
#[test]
fn a_linked_and_a_dropped_in_plane_install_byte_identical_rows() {
    let Some(dropped) = dropped("equal") else {
        eprintln!("skip: example plane cdylib not built");
        return;
    };
    let ahead = native("neutral");
    let linked_arm = folded(plane_rows(&linked(ahead, &LINKED_HOT), Vec::new()).unwrap());
    let dropped_arm = folded(plane_rows(&linked(ahead, &[]), dropped).unwrap());
    assert_eq!(
        linked_arm, dropped_arm,
        "the two doors installed different rows"
    );

    // Not vacuous: the plane's row is there, after the linked row, and says what the plane declares.
    let plane = crate::root::loader::link_plane(&LINKED_DECL, "reference").unwrap();
    assert_eq!(linked_arm.len(), 2, "{linked_arm:#?}");
    assert!(
        linked_arm[0].contains("key: \"neutral\""),
        "{linked_arm:#?}"
    );
    for fact in [
        format!("key: {:?}", plane.name()),
        format!("config_section: {:?}", plane.section_key()),
    ] {
        assert!(
            linked_arm[1].contains(&fact),
            "{fact} not in {}",
            linked_arm[1]
        );
    }

    // THE FULL DECLARATION: the installed row states exactly what the plane's decl states, every
    // field — mapped here independently of the adapter (see `stated`), so an adapter that dropped or
    // defaulted any one field installs a row that differs.
    let stated = stated(&LINKED_DECL);
    assert!(
        linked_arm[1].contains(&format!("{stated:?}")),
        "the installed row is not the plane's own declaration:\n  stated: {stated:?}\n  row:    {}",
        linked_arm[1]
    );
    let dropped_row = folded(plane_rows(&linked(&[], &[]), dropped_again()).unwrap());
    assert!(
        dropped_row[0].contains(&format!("{stated:?}")),
        "the dropped-in row is not the plane's own declaration:\n  stated: {stated:?}\n  row:    {}",
        dropped_row[0]
    );
}

/// The example plane dropped in once more, for a second fold in the same test.
fn dropped_again() -> Vec<DynPlane> {
    dropped("equal-again").expect("the cdylib was found for the first fold")
}

/// The `PlaneDeclaration` a decl STATES — every field, mapped here from what the loader's admission
/// read off the decl (`link_plane`; the loader's own `plane_conformance_tests` hold that read
/// to the raw `#[repr(C)]` static, field for field) — with no adapter in between. The yardstick the
/// installed row is held to: an adapter that dropped or defaulted any one field disagrees with it.
fn stated(d: &'static hot::PlaneDecl) -> PlaneDeclaration {
    let plane: &'static DynPlane = Box::leak(Box::new(
        crate::root::loader::link_plane(d, "yardstick").expect("the decl is admitted"),
    ));
    let h: &'static crate::root::loader::HotDeclaration = plane.declaration();
    let strs = |v: &'static [String]| -> &'static [&'static str] {
        v.iter().map(|x| x.as_str()).collect::<Vec<_>>().leak()
    };
    PlaneDeclaration {
        key: plane.name(),
        fallback: h.fallback,
        config_section: plane.section_key(),
        scope_kinds: strs(&h.scope_kinds),
        subject_noun: h.subject_noun.as_str(),
        admin_noun: h.admin_noun.as_str(),
        audit_kind: h.audit_kind.as_str(),
        card_signing_domain: h.signing_domain.as_deref(),
        card_kid_prefix: h.signing_kid_prefix.as_deref(),
        owned_config_sections: strs(&h.owned_sections),
        billable_classes: h
            .billable_classes
            .iter()
            .map(
                |(class, family)| busbar_kernel::plane::registry::BillableClass {
                    class: class.as_str(),
                    family: family.as_str(),
                },
            )
            .collect::<Vec<_>>()
            .leak(),
        fee_units: strs(&h.fee_units),
        metric_families: h
            .metric_families
            .iter()
            .map(|f| busbar_contract::plane::MetricFamily {
                name: f.name.as_str(),
                kind: f.kind.as_str(),
                label_keys: strs(&f.label_keys),
            })
            .collect::<Vec<_>>()
            .leak(),
        record_kinds: strs(&h.record_kinds),
        required_config_sections: strs(&h.required_sections),
        trust_keys: &[],
        served_op_classes: h
            .served_op_classes
            .iter()
            .map(|(op, name)| busbar_contract::plane::ServedOpClass {
                op: busbar_contract::ids::OpClassId::new(op.as_str()),
                name: name.as_str(),
            })
            .collect::<Vec<_>>()
            .leak(),
        caller_credential_refusal: None,
    }
}

/// THE OTHER VALUE OF EACH FLAG: a plane that declares itself the fallback and signs nothing installs
/// exactly that — the example states the opposite of both, so together the two cover every field in
/// each of its states.
#[test]
fn a_fallback_plane_that_signs_nothing_installs_exactly_that() {
    let variant: &'static hot::PlaneDecl = Box::leak(Box::new(hot::PlaneDecl {
        fallback: 1,
        signing_domain: busbar_contract::abi::hot::DeclStr::NONE,
        signing_kid_prefix: busbar_contract::abi::hot::DeclStr::NONE,
        ..LINKED_DECL
    }));
    let table: &'static [&'static hot::PlaneDecl] = Box::leak(Box::new([variant]));
    let rows = plane_rows(&linked(&[], table), Vec::new()).unwrap();
    assert_eq!(rows.len(), 1);
    let expected = stated(variant);
    assert!(expected.fallback && expected.card_signing_domain.is_none());
    assert_eq!(rows[0].declaration, expected);
}

/// THE SAME REFUSAL, BOTH DOORS: a plane whose key a linked plane already holds is skipped by the
/// boot fold, whichever door it came in by — the linked holder keeps the slot either way.
#[test]
fn a_plane_whose_key_is_taken_is_skipped_the_same_way_by_either_door() {
    let Some(dropped) = dropped("taken") else {
        eprintln!("skip: example plane cdylib not built");
        return;
    };
    let key = crate::root::loader::link_plane(&LINKED_DECL, "reference")
        .unwrap()
        .name()
        .to_string();
    let holder = native(Box::leak(key.into_boxed_str()));
    let linked_arm = folded(plane_rows(&linked(holder, &LINKED_HOT), Vec::new()).unwrap());
    let dropped_arm = folded(plane_rows(&linked(holder, &[]), dropped).unwrap());
    assert_eq!(linked_arm, dropped_arm);
    assert_eq!(
        linked_arm,
        folded(holder.iter().collect()),
        "the holder keeps the slot"
    );
}

/// THE SAME ADMISSION, BOTH DOORS: a plane declaration that names no plane is refused before it is
/// installed, and the refusal is the one function's — the linked door gives it too.
#[test]
fn a_plane_that_names_nothing_is_refused_at_the_linked_door_too() {
    let nameless: &'static hot::PlaneDecl = Box::leak(Box::new(hot::PlaneDecl {
        name_len: 0,
        ..LINKED_DECL
    }));
    let table: &'static [&'static hot::PlaneDecl] = Box::leak(Box::new([nameless]));
    let refusal = plane_rows(&linked(&[], table), Vec::new())
        .map(|_| ())
        .unwrap_err();
    assert!(refusal.contains("declares no name"), "{refusal}");
}

/// THE TRUST GATE HOLDS ON THIS DOOR: the same plane, unsigned, under the default posture is skipped
/// by the scan and never loaded — no plane reaches the axis.
#[test]
fn an_untrusted_dropped_in_plane_reaches_no_row() {
    let Some(path) = cdylib() else {
        eprintln!("skip: example plane cdylib not built");
        return;
    };
    let lib = std::fs::read(path).unwrap();
    let (dir, mut policy) = plugins_dir("untrusted", &lib);
    policy.first_party_key = Some(test_plugins::key(9).verifying_key());
    let planes = dropped_planes(&dir, &policy).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(planes.is_empty(), "an untrusted plane was loaded");
}

/// **THE RED ARM — the boot before the dropped-in door met the axis, kept as the witness.** K1's
/// `register_planes(&LINKED)` installed the linked tables only; a plane dropped into `plugins/` was
/// loadable and never handed over. Replayed here, the two builds install different planes.
#[test]
fn the_boot_that_does_not_hand_the_dropped_in_planes_over_diverges() {
    let Some(dropped) = dropped("red") else {
        eprintln!("skip: example plane cdylib not built");
        return;
    };
    let linked_arm = folded(plane_rows(&linked(&[], &LINKED_HOT), Vec::new()).unwrap());
    drop(dropped);
    let bypassed_arm = folded(plane_rows(&linked(&[], &[]), Vec::new()).unwrap());
    assert_ne!(
        linked_arm, bypassed_arm,
        "a boot that drops the dropped-in planes must install a different axis"
    );
}

// ── ONE PLANE, BOTH DOORS, ONE SERVE (item 63 / TRACKER H6 part 1) ──────────────────────────────
//
// The rows above prove a dropped-in plane INSTALLS like its linked twin. These prove it SERVES like
// it: each arm boots its own process (the plane axis, the host's journal and the metering book are
// process state, exactly as they are for a deployment), installs the example plane through one door,
// parses a config carrying its `example:` section, builds the app through the kernel's own
// `build_app_from_config` and serves one request through the kernel's own router. What each arm
// served — the response, the audit rows the plane journalled through the host, and the metering rows
// the host ledgered for it — is written out and compared here.

/// The arm a child process of this test binary runs ([`serve_arm`]); unset in the parent.
const SERVE_ARM: &str = "BUSBAR_ROOT_SERVE_ARM";
/// Where the child writes what its arm served.
const SERVE_OUT: &str = "BUSBAR_ROOT_SERVE_OUT";

/// The deployment every arm serves: a public URL (the plane's audience is derived from it) and the
/// plane's own section, which the plane quotes back in its reply.
const SERVE_CONFIG: &str =
    "store: {module: memory}\npublic_url: https://gw.example.com\nexample:\n  greeting: hi\n  \
                            depth: 2\nproviders: {}\nmodels: {}\npools: {}\n";

/// The journal scope the example plane appends its audit rows to (the plane's own constant).
const AUDIT_SCOPE: u32 = 0x0045_5850;

/// The `#[repr(C)]` journal read query, laid out as the plane ABI publishes it (`JournalQuery`: size,
/// version, pad, scope, pad, from_seq, limit — the layout golden pins it). The composition root
/// links no ABI crate of its own, so it states the published layout, as any reader of the ABI may.
#[repr(C)]
struct JournalQuery {
    size: u32,
    version: u16,
    _reserved: u16,
    scope: u32,
    _reserved2: u32,
    from_seq: u64,
    limit: u64,
}

/// The example plane's audit rows, read back through the host's own `journal_read` slot — verified
/// chain, then `seq · prev_hash · hash · content` per row — as hex.
fn audit_rows(app: &busbar_kernel::state::App) -> String {
    let scope = busbar_kernel::plane_host::DispatchScope::new();
    busbar_kernel::plane_host::with_borrowed_host(app, &scope, |host, vt| {
        let query = JournalQuery {
            size: core::mem::size_of::<JournalQuery>() as u32,
            version: 0,
            _reserved: 0,
            scope: AUDIT_SCOPE,
            _reserved2: 0,
            from_seq: 0,
            limit: 0,
        };
        let mut buf = vec![0u8; 1 << 16];
        let mut written = 0usize;
        let read = vt.journal_read.expect("the host journals");
        let status = read(
            host,
            std::ptr::from_ref(&query).cast(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut written,
        );
        assert_eq!(status, StatusClass::Ok, "the host reads its journal back");
        buf.truncate(written);
        buf.iter().map(|b| format!("{b:02x}")).collect()
    })
}

/// The metering rows the host ledgered this arm, flushed and read back for today's bucket.
fn metering_rows(app: &busbar_kernel::state::App) -> Vec<String> {
    let gov = app
        .governance
        .as_ref()
        .expect("governance is always available");
    gov.flush_metering();
    let now = busbar_kernel::store::now_ms() / 1_000;
    let mut rows: Vec<String> = gov
        .metering_for(busbar_kernel::governance::metering_bucket(now))
        .expect("the metering rows read")
        .iter()
        .map(|row| format!("{row:?}"))
        .collect();
    rows.sort();
    rows
}

/// THE DROPPED-IN ROWS WITH THE DRIVE BYPASSED — the RED arm: the plane is installed through the
/// dropped-in door exactly as the serving arms are, but its row carries the pre-K7 inert hooks (no
/// claims, no admission, no build, no routes), so nothing drives it over the ABI.
fn bypassed(rows: Vec<&'static PlaneDecl>) -> Vec<&'static PlaneDecl> {
    const INERT: PlaneHooks = PlaneHooks {
        claims: |_| Vec::new(),
        admission: |_| None,
        build: |_| None,
        routes: None,
        ..HOT_PLANE_HOOKS
    };
    rows.into_iter()
        .map(|row| &*Box::leak(Box::new(PlaneDecl::assemble(row.declaration, INERT))))
        .collect()
}

/// ONE ARM, run only in a child process [`a_linked_and_a_dropped_in_plane_serve_one_request_identically`]
/// starts; a no-op anywhere else.
#[tokio::test]
async fn serve_arm() {
    let (Ok(arm), Ok(out)) = (std::env::var(SERVE_ARM), std::env::var(SERVE_OUT)) else {
        return;
    };
    // The host's entropy, armed first thing in this fresh process (first install wins): a fixed
    // draw, so a plane id synthesized from it is the same through either door — and is not the
    // entropy port's failure path.
    busbar_contract::codec::install_entropy_source(host_entropy);
    let dropped_in = || {
        let lib = std::fs::read(cdylib().expect("the parent found the cdylib")).unwrap();
        let (dir, policy) = plugins_dir(&format!("serve-{arm}"), &lib);
        let planes = dropped_planes(&dir, &policy).expect("the signed plane loads");
        let _ = std::fs::remove_dir_all(&dir);
        planes
    };
    let rows = match arm.as_str() {
        "linked" => plane_rows(&linked(&[], &LINKED_HOT), Vec::new()),
        // The same linked plane, declaring a live answer (the response-stream carrier) and that its
        // dispatch blocks (minor 32) — which a live answer requires: served on a blocking thread
        // rather than inline — the other door mode, which must answer identically.
        "blocking" => {
            let blocking: &'static hot::PlaneDecl = Box::leak(Box::new(hot::PlaneDecl {
                provided_carriers: LINKED_DECL.provided_carriers
                    | busbar_contract::abi::hot::IngressCarrier::ResponseStream.bit(),
                dispatch_flags: busbar_contract::abi::hot::decl::DISPATCH_BLOCKS,
                ..LINKED_DECL
            }));
            let table: &'static [&'static hot::PlaneDecl] = Box::leak(Box::new([blocking]));
            plane_rows(&linked(&[], table), Vec::new())
        }
        "dropped" => plane_rows(&linked(&[], &[]), dropped_in()),
        "bypass" => plane_rows(&linked(&[], &[]), dropped_in()).map(bypassed),
        other => panic!("unknown arm {other}"),
    }
    .expect("the rows fold");
    let mut seeded = vec![busbar_kernel::test_support::neutral_fallback_plane()];
    seeded.extend(rows);
    let _registry = busbar_kernel::plane::registry::TestRegistryIsolation::seeded(&seeded);

    let deploy = busbar_kernel::config::deploy_from_yaml_str(SERVE_CONFIG).expect("parses");
    let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
    let app = std::sync::Arc::new(
        busbar_kernel::test_support::build_once(cfg, None).expect("the app builds"),
    );
    let router = busbar_kernel::build_router(app.clone());

    use tower::ServiceExt;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/example")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from("{\"ping\":1}"))
        .unwrap();
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = response.status().as_u16();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body reads");
    let (audit, metering) = (audit_rows(&app), metering_rows(&app));

    // THE CARRIER (DEC-SERVE G2): the plane reads the head and answers its provider's status,
    // headers and body — first a buffered answer, then one over the reply buffer, which streams.
    let provider = answered(
        &router,
        axum::http::Request::builder()
            .method("POST")
            .uri("/example?trace=on&n=2")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .header("x-example-status", "429")
            .body(axum::body::Body::from("{\"ping\":2}"))
            .unwrap(),
    )
    .await;
    let over = crate::root::loader::MAX_PLANE_REPLY_LEN + 1;
    let streamed = answered(
        &router,
        axum::http::Request::builder()
            .method("POST")
            .uri("/example")
            .header("x-example-status", "206")
            .header("x-example-size", over.to_string())
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await;
    // THE CALLER'S CREDENTIAL (CRED-STRIP, #65/#40(b)): the plane echoes every header it was
    // handed — once with the credential on the bearer carrier, once on a native-SDK key carrier, and
    // once on BOTH (the bearer is the one the gate takes; the key header is a credential all the
    // same). The credential is an unsigned JWT whose `aud` claim is this plane's audience (the public
    // URL joined to `/example`), which the open chain admits.
    const CALLER_JWT: &str = "eyJhbGciOiJub25lIn0.\
        eyJhdWQiOiJodHRwczovL2d3LmV4YW1wbGUuY29tL2V4YW1wbGUiLCJzdWIiOiJjYWxsZXIifQ.c2ln";
    let bearer = format!("Bearer {CALLER_JWT}");
    let mut echoed = Vec::new();
    let (on_bearer, on_key) = (
        ("authorization", bearer.as_str()),
        ("x-api-key", CALLER_JWT),
    );
    for carriers in [&[on_bearer][..], &[on_key], &[on_bearer, on_key]] {
        let mut request = axum::extract::Request::<()>::builder()
            .method("POST")
            .uri("/example")
            .header("x-example-status", "200")
            .header("x-example-echo", "1");
        for (carrier, value) in carriers {
            request = request.header(*carrier, *value);
        }
        let request = request.body(axum::body::Body::empty()).unwrap();
        echoed.push(answered(&router, request).await["body"].clone());
    }
    let first_byte = first_byte_lead(&router).await;
    let served = serde_json::json!({
        "echoed": echoed,
        "status": status,
        "body": String::from_utf8_lossy(&body),
        "audit": audit,
        "metering": metering,
        "provider": provider,
        "streamed": streamed,
        "first_byte_lead_ms": first_byte,
    });
    std::fs::write(out, served.to_string()).expect("the arm writes what it served");
}

/// How long a PAUSE in the plane's stream lasts: its first byte goes out, then it sleeps this long,
/// then it writes the rest and returns.
const STREAM_PAUSE_MS: u64 = 300;

/// WHEN THE FIRST STREAMED BYTE REACHED THE CALLER, against when the body ended — the end is when
/// the plane's dispatch returned, since the stream closes then. Measured by timestamps on the
/// caller's side, in milliseconds: the first data frame's arrival and the end of the body are each
/// stamped as the caller polls them, and the lead is their difference (`None` when the answer is
/// not the plane's 64-byte body). A live stream leads by about the plane's pause; a body held until
/// the dispatch returns leads by ~0.
async fn first_byte_lead(router: &axum::Router) -> Option<u128> {
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/example")
        .header("x-example-status", "200")
        .header("x-example-size", "64")
        .header("x-example-pause-ms", STREAM_PAUSE_MS.to_string())
        .body(axum::body::Body::empty())
        .unwrap();
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    let mut body = response.into_body();
    let mut first = None;
    let mut bytes = 0usize;
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame.expect("the body reads").into_data() {
            bytes += data.len();
            first.get_or_insert_with(std::time::Instant::now);
        }
    }
    let end = std::time::Instant::now();
    // A door that did not serve the plane (the bypass arm) answers something else: no lead.
    let first = first.filter(|_| bytes == 64)?;
    Some(end.duration_since(first).as_millis())
}

/// The fixed host entropy [`serve_arm`] installs.
fn host_entropy(out: &mut [u8]) -> bool {
    out.fill(0x5a);
    true
}

/// What `router` answered `request`: the status, every header in order, whether the body's length
/// was known before it was read (`None` = it streamed), and the body — a long one as its length and
/// whether it is the example plane's `a..z` pattern.
async fn answered(
    router: &axum::Router,
    request: axum::http::Request<axum::body::Body>,
) -> serde_json::Value {
    use http_body::Body as _;
    use tower::ServiceExt;
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = response.status().as_u16();
    let headers: Vec<String> = response
        .headers()
        .iter()
        .map(|(n, v)| format!("{n}: {}", String::from_utf8_lossy(v.as_bytes())))
        .collect();
    let known_len = response.body().size_hint().exact();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body reads");
    let text = if body.len() > 4096 {
        let pattern = body
            .iter()
            .enumerate()
            .all(|(i, b)| *b == b'a' + (i % 26) as u8);
        serde_json::json!({ "len": body.len(), "pattern": pattern })
    } else {
        serde_json::json!(String::from_utf8_lossy(&body))
    };
    serde_json::json!({
        "status": status,
        "headers": headers,
        "known_len": known_len,
        "body": text,
    })
}

/// Run [`serve_arm`] for `arm` in a fresh process of this test binary; what it served.
fn serve_in_a_fresh_process(arm: &str) -> serde_json::Value {
    let out = std::env::temp_dir().join(format!(
        "busbar-root-serve-{arm}-{}.json",
        std::process::id()
    ));
    let run = std::process::Command::new(std::env::current_exe().expect("the test binary"))
        .args(["--exact", "root::linked::tests::serve_arm"])
        .args(["--test-threads", "1", "--nocapture"])
        .env(SERVE_ARM, arm)
        .env(SERVE_OUT, &out)
        .output()
        .expect("the test binary runs");
    let text =
        String::from_utf8_lossy(&run.stdout).into_owned() + &String::from_utf8_lossy(&run.stderr);
    assert!(run.status.success(), "the {arm} arm failed:\n{text}");
    assert!(
        text.contains("1 passed"),
        "the {arm} arm ran nothing:\n{text}"
    );
    let served = std::fs::read_to_string(&out).expect("the arm wrote what it served");
    let _ = std::fs::remove_file(&out);
    serde_json::from_str(&served).expect("the arm wrote JSON")
}

/// THE EXIT TEST (item 63 / TRACKER H6 part 1). The SAME plane crate, LINKED (its rlib's
/// `PLANE_DECL`) and DROPPED IN (its cdylib, signed into `plugins/`), serves the same request through
/// the kernel's own config parse, app build and router: byte-identical response, audit rows and
/// metering rows. Not vacuous: the response is the plane's own (`200`, its JSON, quoting the
/// `example:` section — which therefore crossed `build` over the ABI), the plane journalled one audit
/// row through the host, and the host ledgered its metering.
///
/// And the RED arm, kept: the same dropped-in plane with its drive bypassed (the pre-K7 inert hooks)
/// serves nothing — the request falls to the protocol fallback — and diverges on all three.
#[test]
fn a_linked_and_a_dropped_in_plane_serve_one_request_identically() {
    if std::env::var_os(SERVE_ARM).is_some() || cdylib().is_none() {
        eprintln!("skip: a child arm, or the example plane cdylib is not built");
        return;
    }
    let mut linked = serve_in_a_fresh_process("linked");
    let mut dropped = serve_in_a_fresh_process("dropped");
    let mut blocking = serve_in_a_fresh_process("blocking");
    // THE FIRST STREAMED BYTE, TIMED. A live-answering plane (the response-stream carrier, which
    // requires DISPATCH_BLOCKS) sends its first byte to the caller BEFORE its dispatch returns:
    // the byte leads the end of the body by about the plane's pause. Inline (no bit, no live
    // carrier) the host holds the body until the dispatch returns, so the byte leads by ~0 — the
    // contrast that makes the blocking arm's lead a measurement, not a construction.
    let lead = |arm: &mut serde_json::Value| {
        arm.as_object_mut()
            .and_then(|o| o.remove("first_byte_lead_ms"))
            .and_then(|v| v.as_u64())
            .expect("the arm timed its first byte")
    };
    let (inline_lead, dropped_lead, live_lead) =
        (lead(&mut linked), lead(&mut dropped), lead(&mut blocking));
    eprintln!(
        "first byte ahead of the dispatch's return: live {live_lead} ms, inline linked \
         {inline_lead} ms / dropped {dropped_lead} ms (plane pause {STREAM_PAUSE_MS} ms)"
    );
    assert!(
        live_lead >= STREAM_PAUSE_MS / 2,
        "with DISPATCH_BLOCKS the first byte reached the caller only {live_lead} ms before the \
         dispatch returned (pause {STREAM_PAUSE_MS} ms)"
    );
    assert!(
        inline_lead < STREAM_PAUSE_MS / 2 && dropped_lead < STREAM_PAUSE_MS / 2,
        "inline, the body is held until the dispatch returns: leads {inline_lead}/{dropped_lead} ms"
    );
    assert_eq!(
        linked, dropped,
        "the two doors served the same request differently"
    );
    // Inline on the worker (the example plane does not block) or on a blocking thread (the same
    // plane declaring DISPATCH_BLOCKS, minor 32): one answer, byte for byte.
    assert_eq!(
        linked, blocking,
        "the inline and the blocking dispatch served the same request differently"
    );

    assert_eq!(linked["status"], 200, "{linked:#}");
    assert_eq!(
        linked["body"], r#"{"plane":"example","bytes":10,"section":{"greeting":"hi","depth":2}}"#,
        "the reply is the plane's own and quotes the section it was built with: {linked:#}"
    );
    assert_ne!(
        linked["audit"], "",
        "the plane journalled its audit row: {linked:#}"
    );
    assert!(
        linked["audit"]
            .as_str()
            .is_some_and(|hex| hex.starts_with("01000000")),
        "exactly one audit row: {linked:#}"
    );
    assert_eq!(
        linked["metering"].as_array().map(Vec::len),
        Some(1),
        "the host ledgered the plane's metering: {linked:#}"
    );

    // THE CARRIER (DEC-SERVE G2), both doors alike (the equality above): the plane read the method,
    // path, query and headers, and its provider's status, headers and body passed through untouched
    // — no JSON content type stamped over its own, no 200 over its 429. The id it synthesized drew
    // the HOST's entropy (0x5a…), not the port's failure path, through the dropped-in door too.
    assert_eq!(
        linked["provider"],
        serde_json::json!({
            "status": 429,
            "headers": [
                "content-type: text/plain; charset=utf-8",
                "x-example-id: 5a5a5a5a5a5a5a5a",
                "content-length: 37",
            ],
            "known_len": 37,
            "body": "POST /example?trace=on&n=2\n{\"ping\":2}",
        }),
        "{linked:#}"
    );
    // A body one byte over the reply buffer went out through the response-stream emit kind: its
    // length was unknown when the head was served, and every byte arrived, in order.
    assert_eq!(
        linked["streamed"],
        serde_json::json!({
            "status": 206,
            "headers": [
                "content-type: text/plain; charset=utf-8",
                "x-example-id: 5a5a5a5a5a5a5a5a",
            ],
            "known_len": null,
            "body": { "len": crate::root::loader::MAX_PLANE_REPLY_LEN + 1, "pattern": true },
        }),
        "{linked:#}"
    );

    // THE CALLER'S CREDENTIAL NEVER REACHES THE PLANE, through either door (the equality above):
    // every credential carrier the gate reads is gone from the head the plane read — the one that
    // carried the token and the one it did not need — and nothing else is.
    assert_eq!(
        linked["echoed"],
        serde_json::json!([
            "x-example-status: 200\nx-example-echo: 1\n",
            "x-example-status: 200\nx-example-echo: 1\n",
            "x-example-status: 200\nx-example-echo: 1\n",
        ]),
        "a plane saw a credential carrier the auth gate reads: {linked:#}"
    );

    let bypassed = serve_in_a_fresh_process("bypass");
    for leg in [
        "status", "body", "audit", "metering", "provider", "streamed",
    ] {
        assert_ne!(
            bypassed[leg], dropped[leg],
            "with its drive bypassed the dropped-in plane must not serve the same {leg}"
        );
    }
}

/// THE KERNEL SERVES NO EXPORT MODULE OF ITS OWN (K9e-2: its last built-in became a linked sink),
/// so the refusal of a row "spelling a built-in module" has nothing left to guard and is gone. What
/// replaces it: every module is a row of the axis, and each LINKED export row answers its own
/// module ahead of any row a plugins directory drops in under the same alias — a dropped-in row
/// never takes a module from the sink this build links. RED: without the linked rows, the
/// dropped-in one answers.
#[test]
fn every_linked_export_row_answers_its_module_ahead_of_a_dropped_in_spelling() {
    let release = test_plugins::key(7);
    let doors = crate::LINKED.export_doors.iter().map(|d| (d.name, d.alias));
    for (name, alias) in doors {
        let scan = || export_row_registry(alias, "k9e-dropped", alias, "busbar", &release, vec![]);
        let rows = linked_exports(crate::LINKED.export_doors).expect("the linked export rows");
        let both = scan().link(rows).expect("the linked door admits them");
        let answering = |r: &PluginRegistry| r.resolve(alias).map(|p| p.manifest.name.clone());
        assert_eq!(answering(&both).as_deref(), Some(name), "{alias}");
        // RED ARM: the dropped-in row alone answers.
        assert_eq!(
            answering(&scan()).as_deref(),
            Some("k9e-dropped"),
            "{alias}"
        );
    }
}

/// THE HOST'S METRIC CATALOG CANNOT DRIFT (K9a S1). Every `busbar_*` series constant the host's
/// metric modules define is in [`HOST_SERIES`], so a first-party plugin's claim on one is refused;
/// and a derived histogram series is the host's too. RED: drop an entry from the list and the
/// scan names it.
#[test]
fn the_host_series_catalog_holds_every_series_the_host_defines() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let sources = [
        "busbar-kernel/src/metrics/mod.rs",
        "busbar-kernel/src/telemetry.rs",
        "busbar-kernel/src/proxy/proxy_vocab.rs",
    ];
    let mut defined = Vec::new();
    for file in sources {
        let text = std::fs::read_to_string(root.join(file)).expect("read a metric module");
        // A `const NAME: &str =` followed (on its line or the next) by a `"busbar_…"` literal.
        let mut pending = false;
        for line in text.lines() {
            let decl = line.contains("const ") && line.contains(": &str =");
            if decl || pending {
                if let Some(start) = line.find("\"busbar_") {
                    let rest = &line[start + 1..];
                    defined.push(rest[..rest.find('"').expect("closed")].to_string());
                    pending = false;
                    continue;
                }
                pending = decl && line.trim_end().ends_with('=');
            }
        }
    }
    assert!(
        defined.len() >= HOST_SERIES.len(),
        "the scan found {defined:?}"
    );
    let missing: Vec<&String> = defined.iter().filter(|n| !host_series(n)).collect();
    assert!(
        missing.is_empty(),
        "host series missing from HOST_SERIES: {missing:?}"
    );
    assert!(host_series("busbar_request_duration_seconds_count"));
    assert!(!host_series("busbar_example_deliveries_total"));
}

/// A fresh `plugins/` directory holding one `kind: export` row signed by `signer` under `publisher`,
/// declaring `decls`, scanned under a posture holding the release key `[7; 32]` and allowlisting
/// any other signer as its publisher. Manifest-only: nothing here is loaded.
fn declaring_registry(
    tag: &str,
    publisher: &str,
    signer: &SigningKey,
    decls: Vec<DiagnosticDecl>,
) -> PluginRegistry {
    let name = format!("s3-{tag}");
    export_row_registry(tag, &name, &name, publisher, signer, decls)
}

/// [`declaring_registry`]'s row under the `name` and `alias` given.
fn export_row_registry(
    tag: &str,
    name: &str,
    alias: &str,
    publisher: &str,
    signer: &SigningKey,
    decls: Vec<DiagnosticDecl>,
) -> PluginRegistry {
    let dir = test_plugins::scratch(&format!("root-s3-{tag}"));
    let mut manifest = test_plugins::manifest("export", name, publisher);
    manifest.alias = alias.into();
    manifest.declares.diagnostics = decls;
    let lib = b"a manifest-only row";
    std::fs::write(
        dir.join("s3.tar.gz"),
        test_plugins::signed(signer, manifest, lib),
    )
    .unwrap();
    let mut policy = test_plugins::release_policy(&test_plugins::key(7));
    policy.publishers = [(publisher.to_string(), signer.verifying_key())]
        .into_iter()
        .filter(|_| publisher != "busbar")
        .collect();
    let registry = test_plugins::boot_with(&dir, &policy);
    let _ = std::fs::remove_dir_all(&dir);
    registry
}

fn decl(code: u16, severity: &str) -> DiagnosticDecl {
    DiagnosticDecl {
        code,
        slug: format!("s3-code-{code}"),
        title: "A declared plugin code".into(),
        severity: severity.into(),
        summary: "The plugin raised it.".into(),
        action: "Read the plugin's docs.".into(),
        since: "1.6.0".into(),
    }
}

/// **K9a S3 — PLUGIN DIAGNOSTICS join the catalogue.** A first-party plugin's declared code becomes
/// a catalogue entry one for one (its class from its thousands digit, its severity from its token),
/// so the host's fold resolves a diagnostic the plugin raises under it exactly as a built-in one.
/// RED ARMS: the same declaration from a third party is refused; a code the catalogue already holds
/// is refused (never shadowed); a class or severity that is not the host's is refused. (The loader's
/// both-ways test proves either door states the same declaration as first-party.)
#[test]
fn a_first_party_plugins_declared_codes_join_the_catalogue_and_nothing_else_does() {
    use busbar_contract::diagnostic::{Class, Severity};
    use busbar_kernel::diagnostics::{by_code, REGISTRY};
    let release = test_plugins::key(7);
    assert!(by_code(6990).is_none(), "the witness code must be free");
    let registry = declaring_registry("ok", "busbar", &release, vec![decl(6990, "actionable")]);
    let declared = declared_diagnostics(&registry, &[]).expect("a first-party declaration joins");
    assert_eq!(declared.len(), 1);
    let d = declared[0];
    assert_eq!(
        (d.code, d.class, d.severity, d.slug, d.retired),
        (
            6990,
            Class::Plugins,
            Severity::Actionable,
            "s3-code-6990",
            false
        )
    );
    assert_eq!(d.banner().to_string(), "BUSBAR-6990");

    let acme = test_plugins::key(8);
    let third = declaring_registry("third", "acme", &acme, vec![decl(6990, "actionable")]);
    let refused = declared_diagnostics(&third, &[]).expect_err("a third party is refused");
    assert!(refused.contains("not first-party"), "{refused}");

    let taken = REGISTRY[0].code;
    for (tag, bad) in [
        ("taken", decl(taken, "actionable")),
        ("class", decl(990, "actionable")),
        ("severity", decl(6991, "loud")),
    ] {
        let registry = declaring_registry(tag, "busbar", &release, vec![bad]);
        let refused = declared_diagnostics(&registry, &[]).expect_err(tag);
        assert!(refused.starts_with("plugin 's3-"), "{tag}: {refused}");
    }
}

/// K5d (DECISIONS #2 rule (1), #40) — THE LINKED STORE AND THE RANKING HOOKS ARE ROWS OF THE ROOT'S
/// LINKED TABLES. The kernel names neither; `main` hands the `stores`/`hooks` tables to the kernel's
/// cold-kind axis (`root::linked::register_stores` -> `preflight::install_linked_rows`), which
/// registers them through `PluginRegistry::link` like any dropped-in row: the linked store is an
/// ephemeral in-process store that opens (a config names it; no row is a default, Q-STORE = (B));
/// the hook table is the linked ranking DOOR, whose Statement claims each built-in strategy word
/// (the root's hook axis binds it).
///
/// RED by deleting the `store-memory` / `hooks-ranking` rows of `[package.metadata.busbar.linked]`:
/// the tables carry no store (and no ranking row) to hand the kernel.
#[test]
fn the_linked_store_and_ranking_hooks_are_rows_of_the_linked_tables() {
    let stores: Vec<_> = crate::LINKED.stores.iter().map(|s| s.1).collect();
    assert_eq!(stores, [true], "one linked store: ephemeral");
    assert!(
        !(crate::LINKED.stores[0].2)().is_null(),
        "the linked store states its door"
    );
    let strategies = [
        busbar_kernel::config::STRATEGY_CHEAPEST,
        busbar_kernel::config::STRATEGY_FASTEST,
        busbar_kernel::config::STRATEGY_LEAST_BUSY,
        busbar_kernel::config::STRATEGY_USAGE,
    ];
    // Each linked hook door's claimed hook words (its Statement's `MARK_WORD_HOOK` marks).
    let words: Vec<Vec<String>> = crate::LINKED
        .hook_doors
        .iter()
        .map(|door| {
            let stated =
                crate::root::loader::dispatch::rendering_of(*door).expect("the door states");
            busbar_contract::abi::mechanism::rendering::read(&stated)
                .expect("the rendering reads")
                .mark_words
                .into_iter()
                .filter(|(class, _)| {
                    *class == busbar_contract::abi::mechanism::door::MARK_WORD_HOOK
                })
                .map(|(_, word)| word)
                .collect()
        })
        .collect();
    let want: Vec<Vec<String>> = if cfg!(linked_axis_hooks) {
        vec![strategies.iter().map(|s| s.to_string()).collect()]
    } else {
        Vec::new()
    };
    assert_eq!(words, want, "the ranking door claims every strategy word");
}

/// WIRE-SECRET (THE DESIGN, "Plugins"; TODO step 28) — THE SECRET AXIS IS THE ROOT'S, OVER THE ONE
/// DISPATCHER. `env` and `file` are the linked secret plugins the root's axis answers for, by the
/// module alias their Statements declare; a reference resolves through the secret kind table on
/// `root::dispatch`'s dispatcher, on one shared instance, and the refusal text is the plugin's own
/// (1.5.5's). A module no plugin answers is refused.
///
/// RED by dropping a door from the linked table: `file` stops being linked.
#[test]
fn the_secret_axis_resolves_the_linked_sources_over_the_one_dispatcher() {
    use busbar_contract::secret::SecretAxis;
    let axis = super::link_secrets(crate::LINKED.secrets).expect("the linked secret doors state");
    assert!(axis.linked("env") && axis.linked("file") && !axis.answers("vault"));
    let env = axis.shared("env").expect("env opens");
    assert!(
        std::sync::Arc::ptr_eq(&env, &axis.shared("env").expect("env opens")),
        "one shared instance per linked plugin"
    );
    let var = "BUSBAR_WIRE_SECRET_ROOT_AXIS";
    std::env::set_var(var, "hunter2");
    let got = env
        .resolve(format!(r#"{{"key":"{var}"}}"#).as_bytes())
        .expect("a set variable resolves");
    assert_eq!(got.expose_secret().as_slice(), b"hunter2");
    std::env::remove_var(var);
    let refused = env
        .resolve(br#"{"key":"BUSBAR_WIRE_SECRET_ROOT_UNSET"}"#)
        .unwrap_err();
    assert_eq!(
        refused.text,
        "secret env:BUSBAR_WIRE_SECRET_ROOT_UNSET cannot resolve: environment variable \
         'BUSBAR_WIRE_SECRET_ROOT_UNSET' is unset"
    );
    assert!(axis.shared("vault").is_err());
}

/// SEAM-L(s), THE PER-AXIS FOLD: a door row and a legacy row sharing a plane key — the door owns the
/// plane axis for it (the kernel's boot fold keeps the door's row), and the legacy row yields that
/// axis alone: a legacy row of another key is untouched, and nothing on any other axis is read here
/// (the legacy crate's other tables are its own). RED: the linked row came first and won the key,
/// so a plane flipped onto its door only when its legacy row left whole.
#[test]
fn a_door_owns_the_plane_axis_for_its_key_and_a_legacy_row_keeps_the_rest() {
    let legacy = &native("seam-l-shared")[0];
    let other = &native("seam-l-other")[0];
    let door = &native("seam-l-shared")[0];
    let rows = doors_own_their_plane_keys(vec![legacy, other, door], &[door]);
    assert_eq!(rows.len(), 2, "the legacy row yields the shared key");
    assert!(
        std::ptr::eq(rows[0], other),
        "a legacy row of another key stays"
    );
    assert!(std::ptr::eq(rows[1], door), "the door serves the plane");
    let folded = merged_boot_plane_decls(&rows, &[]);
    let shared = folded
        .iter()
        .find(|d| d.key == "seam-l-shared")
        .expect("the shared key is registered");
    assert!(
        std::ptr::eq(*shared, door),
        "the boot fold keeps the door's row"
    );
}

/// SEAM-L(s), THE ENGINE RIDES THE KEY: a door taking the key of the legacy row that is the fallback
/// plane takes over that row's engine (the fallback flag, the runtime it builds and the view the
/// core's own readers walk) and keeps every other word of its own. RED: the fold dropped the legacy
/// row whole, so with a linked llm door the node had no fallback runtime and `/metrics` lost its lane
/// gauges (`metrics_scrape_boot_window` under `--features llm-on-driver`).
#[test]
fn a_door_taking_the_fallback_planes_key_keeps_its_engine() {
    let base = &native("seam-l-engine")[0];
    let legacy: &'static PlaneDecl = Box::leak(Box::new(PlaneDecl {
        declaration: PlaneDeclaration {
            fallback: true,
            ..base.declaration
        },
        build_runtime: Some(|_, _| Arc::new(()) as Arc<dyn std::any::Any + Send + Sync>),
        viewer: Some(|_| &busbar_kernel::plane_host::EMPTY_VIEW),
        ..*base
    }));
    let door: &'static PlaneDecl = Box::leak(Box::new(PlaneDecl {
        declaration: PlaneDeclaration {
            config_section: "seam-l-door-section",
            ..base.declaration
        },
        ..*base
    }));
    let rows = doors_own_their_plane_keys(vec![legacy, door], &[door]);
    assert_eq!(rows.len(), 1, "one row serves the key");
    let row = rows[0];
    assert!(!std::ptr::eq(row, legacy), "the door serves the plane");
    assert_eq!(
        row.config_section, "seam-l-door-section",
        "the door's own words stay"
    );
    assert!(
        row.fallback,
        "the fallback plane is still the fallback plane"
    );
    assert!(
        row.build_runtime.is_some() && row.viewer.is_some(),
        "the engine's runtime and view ride the key"
    );
    let folded = merged_boot_plane_decls(&rows, &[]);
    let kept = folded
        .iter()
        .find(|d| d.key == "seam-l-engine")
        .expect("the key is registered");
    assert!(
        kept.fallback && kept.viewer.is_some(),
        "the boot fold keeps it"
    );
    // A legacy row with no engine leaves the door's row untouched (the shared-key case above).
    let plain = &native("seam-l-plain")[0];
    let plain_door = &native("seam-l-plain")[0];
    let rows = doors_own_their_plane_keys(vec![plain, plain_door], &[plain_door]);
    assert!(std::ptr::eq(rows[0], plain_door), "nothing to carry");
}

/// SEAM-L(s): a key two door rows both register on the same axis is a boot refusal naming both.
#[test]
fn a_key_two_doors_register_refuses_the_boot_naming_both() {
    assert!(refuse_a_key_two_doors_register(&[
        ("door-a".to_string(), "k1"),
        ("door-b".to_string(), "k2"),
    ])
    .is_ok());
    let refusal = refuse_a_key_two_doors_register(&[
        ("door-a".to_string(), "k1"),
        ("door-b".to_string(), "k1"),
    ])
    .expect_err("one axis, one owner");
    assert!(
        refusal.contains("door-a") && refusal.contains("door-b") && refusal.contains("k1"),
        "{refusal}"
    );
}

/// ONE DISPATCHER PER PROCESS: a door row's probe binds on the process's one dispatcher, so a door
/// in the build spawns no second set of `busbar-dispatch` threads (the boot test reads the count).
/// RED: the probe had a dispatcher of its own, built with the default shape.
#[test]
fn a_door_rows_probe_binds_on_the_processs_one_dispatcher() {
    assert!(Arc::ptr_eq(
        &door_probe_dispatcher(),
        &crate::root::dispatch::dispatcher()
    ));
}
