// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ICE (ABI-MIN3-INTERFACE §14): Two rendezvous on one media port routed by ufrag; bad MESSAGE-INTEGRITY never a
//! path; PATH_DENIED, unbound SEND_TO, PATH_REBIND.
//!
//! The core arms run in busbar-core-connector over a scripted transport (the media session and the shared
//! media-port carrier are crate-private there, and that crate is not a dependency of this one), so the arm
//! moved to the owner's crate (WBS rule 10):
//!
//! - TEST-VALUE `rendezvous_checks_route_by_ufrag`, one test per clause:
//!   two rendezvous on one port routed by ufrag:
//!   `busbar_core_connector::dtls::carrier::tests::two_rendezvous_on_one_media_port_are_routed_by_ufrag`;
//!   a bad MESSAGE-INTEGRITY never a path:
//!   `busbar_core_connector::dtls::session::tests::a_check_with_a_bad_message_integrity_never_becomes_a_path`;
//!   a CONN_DIAL candidate at a metadata address PATH_DENIED, no packet:
//!   `busbar_core_connector::dtls::session::tests::a_dial_candidate_at_a_metadata_address_is_denied_and_nothing_is_sent`;
//!   a secured SEND_TO an unbound path dropped:
//!   `busbar_core_connector::dtls::session::tests::a_secured_send_to_an_unbound_path_is_dropped_and_counted`;
//!   PATH_REBIND moves the binding, PATH_BOUND:
//!   `busbar_core_connector::dtls::session::tests::a_path_rebind_moves_the_binding_and_yields_path_bound`.
