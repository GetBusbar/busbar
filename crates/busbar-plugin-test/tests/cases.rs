// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The IF §14 conformance cases (ABI-MIN3-INTERFACE §14; WBS rule 10, W1-T1): one module per live case, each in
//! its own `tests/<case>.rs`, compiled into this one test binary so the cases cost one link step in CI. A case
//! file belongs to the task its ignore reasons name; that task fills and un-ignores its arms. Deleted or replaced
//! cases have no file: C-TLS-UNVERIFIED, C-CANCEL-NOHOP, C-COLD-NONBLOCK, C-TLS-REFUSED (now C-TRANSPORT) and
//! C-CARRIER-FOLD (now C-RETIRE); C-FIPS runs only in the private FIPS build, C-CONTENT-NOTEXT arrives with its
//! 1.6.x producer, and C-FIPS-GATE is an arm of C-UNAVAILABLE. X1's CI-job cases are busbar-ci-checks tests, not
//! arms here: C-DEV-EDGES (plugin_rules, rule 1b), C-NO-HOST-LINK (host_link), C-ALIAS's manifest job (fleet,
//! c-alias), C-NO-LICENCE (a) (core_src, no-licence) and C-TRANSPORT test 11 (core_src, c-transport; plugin_rules,
//! the fleet loopback lint).
//! Rule 15: no `unsafe` in any case file.
#![forbid(unsafe_code)]

/// Custom conformance registries share process-owned sinks, watchdog and instance IDs.
/// Like the suite harness, these cases run one test per process under nextest.
fn process_resources() -> &'static busbar_plugin_loader::process::ProcessResources {
    static PROCESS: std::sync::OnceLock<busbar_plugin_loader::process::ProcessResources> =
        std::sync::OnceLock::new();
    PROCESS.get_or_init(|| {
        busbar_plugin_loader::process::ProcessResources::new().expect("test process resources")
    })
}

#[path = "bridge_fixture.rs"]
mod bridge_fixture;
#[path = "c_a2a_card_redirect.rs"]
mod c_a2a_card_redirect;
#[path = "c_a2a_push_url.rs"]
mod c_a2a_push_url;
#[path = "c_absent_store.rs"]
mod c_absent_store;
#[path = "c_admit_header.rs"]
mod c_admit_header;
#[path = "c_admit_unload.rs"]
mod c_admit_unload;
#[path = "c_affinity.rs"]
mod c_affinity;
#[path = "c_alias.rs"]
mod c_alias;
#[path = "c_alloc.rs"]
mod c_alloc;
#[path = "c_alloc_load.rs"]
mod c_alloc_load;
#[path = "c_allow_dest.rs"]
mod c_allow_dest;
#[path = "c_alpn.rs"]
mod c_alpn;
#[path = "c_append.rs"]
mod c_append;
#[path = "c_attempt.rs"]
mod c_attempt;
#[path = "c_audit.rs"]
mod c_audit;
#[path = "c_authority.rs"]
mod c_authority;
#[path = "c_auto_traits.rs"]
mod c_auto_traits;
#[path = "c_blind.rs"]
mod c_blind;
#[path = "c_boot_order.rs"]
mod c_boot_order;
#[path = "c_cancel.rs"]
mod c_cancel;
#[path = "c_cancel_bill.rs"]
mod c_cancel_bill;
#[path = "c_cancel_inflight.rs"]
mod c_cancel_inflight;
#[path = "c_cancel_migrate.rs"]
mod c_cancel_migrate;
#[path = "c_cancel_open.rs"]
mod c_cancel_open;
#[path = "c_channel.rs"]
mod c_channel;
#[path = "c_close_log.rs"]
mod c_close_log;
#[path = "c_close_parked.rs"]
mod c_close_parked;
#[path = "c_commit.rs"]
mod c_commit;
#[path = "c_conn_scope.rs"]
mod c_conn_scope;
#[path = "c_connect.rs"]
mod c_connect;
#[path = "c_cost_terms.rs"]
mod c_cost_terms;
#[path = "c_cred_cache.rs"]
mod c_cred_cache;
#[path = "c_crypto_await.rs"]
mod c_crypto_await;
#[path = "c_crypto_selftest.rs"]
mod c_crypto_selftest;
#[path = "c_deployment_id.rs"]
mod c_deployment_id;
#[path = "c_dialect_auth.rs"]
mod c_dialect_auth;
#[path = "c_dtls_fp.rs"]
mod c_dtls_fp;
#[path = "c_egress_class.rs"]
mod c_egress_class;
#[path = "c_egress_ownport.rs"]
mod c_egress_ownport;
#[path = "c_entitle.rs"]
mod c_entitle;
#[path = "c_entry_guard.rs"]
mod c_entry_guard;
#[path = "c_error_records.rs"]
mod c_error_records;
#[path = "c_errors.rs"]
mod c_errors;
#[path = "c_export_delivery.rs"]
mod c_export_delivery;
#[path = "c_export_streams.rs"]
mod c_export_streams;
#[path = "c_fail_facts.rs"]
mod c_fail_facts;
#[path = "c_fail_reset.rs"]
mod c_fail_reset;
#[path = "c_gen_wrap.rs"]
mod c_gen_wrap;
#[path = "c_grpc_deadline.rs"]
mod c_grpc_deadline;
#[path = "c_header.rs"]
mod c_header;
#[path = "c_hook_projection.rs"]
mod c_hook_projection;
#[path = "c_ice.rs"]
mod c_ice;
#[path = "c_issued_shape.rs"]
mod c_issued_shape;
#[path = "c_key_carriers.rs"]
mod c_key_carriers;
#[path = "c_keys_stale.rs"]
mod c_keys_stale;
#[path = "c_leak.rs"]
mod c_leak;
#[path = "c_lift.rs"]
mod c_lift;
#[path = "c_limits.rs"]
mod c_limits;
#[path = "c_line_carrier.rs"]
mod c_line_carrier;
#[path = "c_login_kind.rs"]
mod c_login_kind;
#[path = "c_login_outage.rs"]
mod c_login_outage;
#[path = "c_login_pkce.rs"]
mod c_login_pkce;
#[path = "c_mcp_argguard.rs"]
mod c_mcp_argguard;
#[path = "c_mcp_ask.rs"]
mod c_mcp_ask;
#[path = "c_mcp_channel.rs"]
mod c_mcp_channel;
#[path = "c_mcp_connect.rs"]
mod c_mcp_connect;
#[path = "c_mcp_tasks.rs"]
mod c_mcp_tasks;
#[path = "c_metric.rs"]
mod c_metric;
#[path = "c_migrate.rs"]
mod c_migrate;
#[path = "c_migrate_admit.rs"]
mod c_migrate_admit;
#[path = "c_mint.rs"]
mod c_mint;
#[path = "c_msg_flags.rs"]
mod c_msg_flags;
#[path = "c_need_decode.rs"]
mod c_need_decode;
#[path = "c_need_kind.rs"]
mod c_need_kind;
#[path = "c_needfut_late.rs"]
mod c_needfut_late;
#[path = "c_needfut_shared.rs"]
mod c_needfut_shared;
#[path = "c_nested.rs"]
mod c_nested;
#[path = "c_no_licence.rs"]
mod c_no_licence;
#[path = "c_null_empty.rs"]
mod c_null_empty;
#[path = "c_observe.rs"]
mod c_observe;
#[path = "c_opener_refuse.rs"]
mod c_opener_refuse;
#[path = "c_out_rewrite.rs"]
mod c_out_rewrite;
#[path = "c_outbound_settings.rs"]
mod c_outbound_settings;
#[path = "c_outbound_style.rs"]
mod c_outbound_style;
#[path = "c_panic.rs"]
mod c_panic;
#[path = "c_panic_cancel.rs"]
mod c_panic_cancel;
#[path = "c_panic_host.rs"]
mod c_panic_host;
#[path = "c_path_claim.rs"]
mod c_path_claim;
#[path = "c_plane_admin.rs"]
mod c_plane_admin;
#[path = "c_plane_chain.rs"]
mod c_plane_chain;
#[path = "c_plane_deferred_forward.rs"]
mod c_plane_deferred_forward;
#[path = "c_plane_describe_r10.rs"]
mod c_plane_describe_r10;
#[path = "c_plane_trailers.rs"]
mod c_plane_trailers;
#[path = "c_pool_key.rs"]
mod c_pool_key;
#[path = "c_pool_state.rs"]
mod c_pool_state;
#[path = "c_pool_warm.rs"]
mod c_pool_warm;
#[path = "c_provider_keys.rs"]
mod c_provider_keys;
#[path = "c_provision.rs"]
mod c_provision;
#[path = "c_public_url.rs"]
mod c_public_url;
#[path = "c_random.rs"]
mod c_random;
#[path = "c_ref_path.rs"]
mod c_ref_path;
#[path = "c_refusal_map.rs"]
mod c_refusal_map;
#[path = "c_replay.rs"]
mod c_replay;
#[path = "c_retire.rs"]
mod c_retire;
#[path = "c_rmw.rs"]
mod c_rmw;
#[path = "c_route_cred_header.rs"]
mod c_route_cred_header;
#[path = "c_scheme.rs"]
mod c_scheme;
#[path = "c_scrub.rs"]
mod c_scrub;
#[path = "c_scrub_cut.rs"]
mod c_scrub_cut;
#[path = "c_scrub_hit.rs"]
mod c_scrub_hit;
#[path = "c_scrub_one.rs"]
mod c_scrub_one;
#[path = "c_scrub_race.rs"]
mod c_scrub_race;
#[path = "c_scrub_retire.rs"]
mod c_scrub_retire;
#[path = "c_secret_cycle.rs"]
mod c_secret_cycle;
#[path = "c_secret_foreign.rs"]
mod c_secret_foreign;
#[path = "c_secret_ref.rs"]
mod c_secret_ref;
#[path = "c_session_drop.rs"]
mod c_session_drop;
#[path = "c_session_order.rs"]
mod c_session_order;
#[path = "c_sign.rs"]
mod c_sign;
#[path = "c_slot_align.rs"]
mod c_slot_align;
#[path = "c_slot_reuse.rs"]
mod c_slot_reuse;
#[path = "c_slot_stale.rs"]
mod c_slot_stale;
#[path = "c_span_records.rs"]
mod c_span_records;
#[path = "c_stale.rs"]
mod c_stale;
#[path = "c_stale_panic.rs"]
mod c_stale_panic;
#[path = "c_stash_reopen.rs"]
mod c_stash_reopen;
#[path = "c_stdio_respawn.rs"]
mod c_stdio_respawn;
#[path = "c_store_bags.rs"]
mod c_store_bags;
#[path = "c_store_commit.rs"]
mod c_store_commit;
#[path = "c_store_info.rs"]
mod c_store_info;
#[path = "c_store_lane.rs"]
mod c_store_lane;
#[path = "c_strategy_word.rs"]
mod c_strategy_word;
#[path = "c_style_vocab.rs"]
mod c_style_vocab;
#[path = "c_sugar.rs"]
mod c_sugar;
#[path = "c_suite_export.rs"]
mod c_suite_export;
#[path = "c_suite_secret.rs"]
mod c_suite_secret;
#[path = "c_suite_transport.rs"]
mod c_suite_transport;
#[path = "c_ticket_either.rs"]
mod c_ticket_either;
#[path = "c_tls_key.rs"]
mod c_tls_key;
#[path = "c_token_pad.rs"]
mod c_token_pad;
#[path = "c_token_space.rs"]
mod c_token_space;
#[path = "c_transport.rs"]
mod c_transport;
#[path = "c_transport_backpressure.rs"]
mod c_transport_backpressure;
#[path = "c_transport_close.rs"]
mod c_transport_close;
#[path = "c_transport_defaults.rs"]
mod c_transport_defaults;
#[path = "c_transport_refuse.rs"]
mod c_transport_refuse;
#[path = "c_trust_verify.rs"]
mod c_trust_verify;
#[path = "c_unavailable.rs"]
mod c_unavailable;
#[path = "c_unix_dest.rs"]
mod c_unix_dest;
#[path = "c_unknown_tag.rs"]
mod c_unknown_tag;
#[path = "c_upgrade.rs"]
mod c_upgrade;
#[path = "c_upstream_auth.rs"]
mod c_upstream_auth;
#[path = "c_usage.rs"]
mod c_usage;
#[path = "c_verdict_cache.rs"]
mod c_verdict_cache;
#[path = "c_watch_ceiling.rs"]
mod c_watch_ceiling;
#[path = "c_watch_churn.rs"]
mod c_watch_churn;
#[path = "c_webrtc_dial.rs"]
mod c_webrtc_dial;
#[path = "c_webrtc_ice_restart.rs"]
mod c_webrtc_ice_restart;
#[path = "c_work_recovery.rs"]
mod c_work_recovery;
#[path = "c_zeroize.rs"]
mod c_zeroize;
#[path = "c_zeroize_fresh.rs"]
mod c_zeroize_fresh;
#[path = "c_zeroize_grow.rs"]
mod c_zeroize_grow;
#[path = "c_zeroize_sync.rs"]
mod c_zeroize_sync;
#[path = "fu3-check-crypto-failed.rs"]
mod fu3_check_crypto_failed;
#[path = "fixtures/min3_endpoints.rs"]
mod min3_endpoints;
#[path = "fixtures/min3_export.rs"]
mod min3_export;
#[path = "fixtures/min3_export_fail.rs"]
mod min3_export_fail;
#[path = "fixtures/min3_export_metrics.rs"]
mod min3_export_metrics;
#[path = "fixtures/min3_second.rs"]
mod min3_second;
#[path = "fixtures/min3_secret.rs"]
mod min3_secret;
#[path = "fixtures/min3_store.rs"]
mod min3_store;
#[path = "fixtures/min3_transport.rs"]
mod min3_transport;

/// Every `tests/*.rs` is wired: a module of this binary or a `[[test]]` target of the manifest
/// (`autotests = false`, so an unwired file would never run).
#[test]
fn every_tests_file_is_wired() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests");
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("Cargo.toml");
    let cases = include_str!("cases.rs");
    for entry in std::fs::read_dir(dir).expect("tests/") {
        let name = entry
            .expect("entry")
            .file_name()
            .into_string()
            .expect("UTF-8 name");
        if !name.ends_with(".rs") || name == "cases.rs" {
            continue;
        }
        let module = format!("#[path = \"{name}\"]");
        let target = format!("path = \"tests/{name}\"");
        assert!(
            cases.contains(&module) || manifest.contains(&target),
            "tests/{name} is wired nowhere: add it to cases.rs or a [[test]] target"
        );
    }
}
