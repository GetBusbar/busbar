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
use busbar_kernel::plane::registry::{merged_boot_plane_decls, BuildCtx};
use busbar_plugin_example_plane::PLANE_DECL as LINKED_DECL;
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};

/// The linked example plane, as the build table carries it.
static LINKED_HOT: [&HotPlaneDecl; 1] = [&LINKED_DECL];

/// A table with the given plane rows and HOT-lane planes and nothing on any other axis.
fn linked(planes: &'static [PlaneDecl], hot_planes: &'static [&'static HotPlaneDecl]) -> Linked {
    Linked {
        planes,
        hot_planes,
        protocols: &[],
        path_ingress: &[],
        body_ingress: &[],
        protocol_seams: &[],
        diagnostics: &[],
        ws_arrivals: &[],
        on_host: &[],
        compose: &[],
        stdio_serve: &[],
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
    let found = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile = exe.parent()?.parent()?;
        let name = busbar_plugin_loader::plugin_library_filename("busbar_plugin_example_plane");
        [profile.join(&name), profile.join("deps").join(&name)]
            .into_iter()
            .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
            .max()
            .map(|(_, p)| p)
    })();
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "the example plane cdylib is not built under CI; the both-doors proof must not skip"
    );
    found
}

/// A fresh `plugins/` directory holding the example plane's cdylib as a SIGNED first-party tarball,
/// and the default trust posture that admits it (the release key held, no opt-ins).
fn plugins_dir(tag: &str, lib: &[u8]) -> (std::path::PathBuf, TrustPolicy) {
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-dropped-plane-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let release = SigningKey::from_bytes(&[7u8; 32]);
    let manifest = Manifest {
        name: "busbar-plugin-example-plane".into(),
        alias: "example-plane".into(),
        kind: "plane".into(),
        version: "1.6.0".into(),
        publisher: "busbar".into(),
        abi_version: 1,
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
    };
    let signed = sign(&release, manifest, lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "libplane.so", lib).unwrap();
    std::fs::write(dir.join("example-plane.tar.gz"), tarball).unwrap();
    let policy = TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        binary_version: "1.6.0".into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    };
    (dir, policy)
}

/// The example plane dropped into a fresh `plugins/` directory and found by the boot scan.
fn dropped(tag: &str) -> Option<Vec<DynPlane>> {
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
    let plane = busbar_plugin_loader::link_plane(&LINKED_DECL, "reference").unwrap();
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
/// read off the decl (`link_plane`; `busbar-plugin-loader`'s `plane_conformance_tests` hold that read
/// to the raw `#[repr(C)]` static, field for field) — with no adapter in between. The yardstick the
/// installed row is held to: an adapter that dropped or defaulted any one field disagrees with it.
fn stated(d: &'static HotPlaneDecl) -> PlaneDeclaration {
    let plane: &'static DynPlane = Box::leak(Box::new(
        busbar_plugin_loader::link_plane(d, "yardstick").expect("the decl is admitted"),
    ));
    let h: &'static busbar_plugin_loader::HotDeclaration = plane.declaration();
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
    }
}

/// THE OTHER VALUE OF EACH FLAG: a plane that declares itself the fallback and signs nothing installs
/// exactly that — the example states the opposite of both, so together the two cover every field in
/// each of its states.
#[test]
fn a_fallback_plane_that_signs_nothing_installs_exactly_that() {
    let variant: &'static HotPlaneDecl = Box::leak(Box::new(HotPlaneDecl {
        fallback: 1,
        signing_domain: busbar_plugin_loader::HotDeclStr::NONE,
        signing_kid_prefix: busbar_plugin_loader::HotDeclStr::NONE,
        ..LINKED_DECL
    }));
    let table: &'static [&'static HotPlaneDecl] = Box::leak(Box::new([variant]));
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
    let key = busbar_plugin_loader::link_plane(&LINKED_DECL, "reference")
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
    let nameless: &'static HotPlaneDecl = Box::leak(Box::new(HotPlaneDecl {
        name_len: 0,
        ..LINKED_DECL
    }));
    let table: &'static [&'static HotPlaneDecl] = Box::leak(Box::new([nameless]));
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
    policy.first_party_key = Some(SigningKey::from_bytes(&[9u8; 32]).verifying_key());
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
const SERVE_CONFIG: &str = "public_url: https://gw.example.com\nexample:\n  greeting: hi\n  \
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
    let dropped_in = || {
        let lib = std::fs::read(cdylib().expect("the parent found the cdylib")).unwrap();
        let (dir, policy) = plugins_dir(&format!("serve-{arm}"), &lib);
        let planes = dropped_planes(&dir, &policy).expect("the signed plane loads");
        let _ = std::fs::remove_dir_all(&dir);
        planes
    };
    let rows = match arm.as_str() {
        "linked" => plane_rows(&linked(&[], &LINKED_HOT), Vec::new()),
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
    let response = router.oneshot(request).await.expect("the router answers");
    let status = response.status().as_u16();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body reads");
    let served = serde_json::json!({
        "status": status,
        "body": String::from_utf8_lossy(&body),
        "audit": audit_rows(&app),
        "metering": metering_rows(&app),
    });
    std::fs::write(out, served.to_string()).expect("the arm writes what it served");
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
    let linked = serve_in_a_fresh_process("linked");
    let dropped = serve_in_a_fresh_process("dropped");
    assert_eq!(
        linked, dropped,
        "the two doors served the same request differently"
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

    let bypassed = serve_in_a_fresh_process("bypass");
    for leg in ["status", "body", "audit", "metering"] {
        assert_ne!(
            bypassed[leg], dropped[leg],
            "with its drive bypassed the dropped-in plane must not serve the same {leg}"
        );
    }
}

/// A `kind: export` row whose name or alias spells a built-in export module is refused before the
/// export axis is installed: every `export:` instance naming it would reach the built-in, so the
/// plugin would sit on the axis unreachable, silently. A row spelling neither is admitted.
#[test]
fn an_export_row_spelling_a_built_in_module_is_refused() {
    let registry_of = |tag: &str, name: &str, alias: &str| {
        let dir = std::env::temp_dir().join(format!(
            "busbar-root-export-shadow-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let lib = b"not a library";
        let release = SigningKey::from_bytes(&[7u8; 32]);
        let manifest = Manifest {
            name: name.into(),
            alias: alias.into(),
            kind: "export".into(),
            version: "1.6.0".into(),
            publisher: "busbar".into(),
            abi_version: busbar_plugin_loader::supported_abi("export")[1],
            sha256: String::new(),
            signature: String::new(),
            description: String::new(),
            homepage: String::new(),
            license: String::new(),
            needs: Default::default(),
            settings_schema: None,
            schema_derived: false,
            host: None,
            declares: Default::default(),
        };
        let signed = sign(&release, manifest, lib);
        let tarball = busbar_plugin_loader::tarball::package(&signed, "libexport.so", lib).unwrap();
        std::fs::write(dir.join("export.tar.gz"), tarball).unwrap();
        let policy = TrustPolicy {
            first_party_key: Some(release.verifying_key()),
            binary_version: "1.6.0".into(),
            first_party_floors: Default::default(),
            first_party_high_water: Default::default(),
            publishers: Default::default(),
            allow_unsigned: false,
            allow_third_party: false,
            min_versions: Default::default(),
        };
        let registry = busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the scan");
        let _ = std::fs::remove_dir_all(&dir);
        registry
    };
    for (tag, name, alias) in [
        ("name", "prometheus", "k9-prom"),
        ("alias", "k9-file", "request-log-file"),
    ] {
        assert_eq!(
            shadowed_export(&registry_of(tag, name, alias)),
            Err(format!(
                "export plugin '{name}' spells a built-in export module"
            )),
        );
    }
    assert_eq!(
        shadowed_export(&registry_of("clear", "k9-tail", "k9-tail")),
        Ok(())
    );
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
        "busbar-substrate-values/src/handlers.rs",
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
    decls: Vec<busbar_plugin_loader::sign::DiagnosticDecl>,
) -> busbar_plugin_loader::PluginRegistry {
    let dir = std::env::temp_dir().join(format!("busbar-root-s3-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let release = SigningKey::from_bytes(&[7u8; 32]);
    let mut manifest = Manifest {
        name: format!("s3-{tag}"),
        alias: format!("s3-{tag}"),
        kind: "export".into(),
        version: "1.6.0".into(),
        publisher: publisher.into(),
        abi_version: 3,
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
    };
    manifest.declares.diagnostics = decls;
    let lib = b"a manifest-only row";
    let signed = sign(signer, manifest, lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "lib.so", lib).unwrap();
    std::fs::write(dir.join("s3.tar.gz"), tarball).unwrap();
    let policy = TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        binary_version: "1.6.0".into(),
        publishers: [(publisher.to_string(), signer.verifying_key())]
            .into_iter()
            .filter(|_| publisher != "busbar")
            .collect(),
        ..Default::default()
    };
    let registry = busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the scan");
    let _ = std::fs::remove_dir_all(&dir);
    registry
}

fn decl(code: u16, severity: &str) -> busbar_plugin_loader::sign::DiagnosticDecl {
    busbar_plugin_loader::sign::DiagnosticDecl {
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
    use busbar_substrate_values::diagnostics::{by_code, Class, Severity};
    let release = SigningKey::from_bytes(&[7u8; 32]);
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

    let acme = SigningKey::from_bytes(&[8u8; 32]);
    let third = declaring_registry("third", "acme", &acme, vec![decl(6990, "actionable")]);
    let refused = declared_diagnostics(&third, &[]).expect_err("a third party is refused");
    assert!(refused.contains("not first-party"), "{refused}");

    let taken = busbar_substrate_values::diagnostics::REGISTRY[0].code;
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

/// **K9a S5 — THE HOST'S EGRESS CARRIER applies the host's URL policy before any hop.** A target the
/// built-in webhook guard refuses — plaintext, loopback, cloud metadata — is refused with the
/// guard's own words and nothing is dialled, so a plugin sink can reach no further than the host's
/// own telemetry egress may. RED: carry the request without the policy check and the loopback
/// target is dialled (a `request` failure, not a `refused` one).
#[cfg(linked_egress)]
#[test]
fn the_egress_carrier_refuses_what_the_host_policy_refuses() {
    use busbar_plugin_loader::{EgressCarrier as _, HostResult, HttpRequest};
    for url in [
        "http://collector.example/v1",
        "https://127.0.0.1:9/v1",
        "https://169.254.169.254/latest",
    ] {
        let request = HttpRequest {
            method: "POST".into(),
            url: url.into(),
            headers: Vec::new(),
            body: "{}".into(),
            timeout_ms: 500,
        };
        match HostEgressCarrier.carry(&request) {
            HostResult::Failed { step, error, .. } => {
                assert_eq!(step, "refused", "{url}: {error}");
                let guard = busbar_kernel::observability::validate_webhook_url(Some(url.into()));
                assert_eq!(Err(error), guard, "{url}");
            }
            other => panic!("{url} was carried: {other:?}"),
        }
        // K9c: the policy asked WITHOUT carrying — the same guard, the same words.
        let guard = busbar_kernel::observability::validate_webhook_url(Some(url.into()));
        assert_eq!(HostEgressCarrier.admit(url), guard.map(|_| ()), "{url}");
    }
    assert_eq!(
        HostEgressCarrier.admit("https://collector.example/v1"),
        Ok(())
    );
}
