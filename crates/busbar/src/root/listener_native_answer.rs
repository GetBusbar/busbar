// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Every refusal the native listener answers, written in one place. Core decides the row
//! (`busbar_kernel::auth::admission_table`), core writes the body before a caller is verified,
//! and a plane renders the same record in its dialect after. Nothing here closes a connection:
//! each function returns a response.

use std::sync::Arc;

use axum::response::Response;
use busbar_kernel::auth::admission_table::{BodyBy, Refusal};
use busbar_kernel::auth::core_answer;
use busbar_kernel::inbound::native::RequestBinding;
use busbar_kernel::inbound::request_snapshot::ChargedRequestSnapshot;
use busbar_kernel::plane_driver::port::PortSeat;
use busbar_kernel::plane_driver::port_session::ToClient;

use super::{data, InputError};

/// Whether a credential carrier of the route is on the request's head. It changes what core
/// records for an unverified request, never a byte of the answer.
pub(super) fn presented(binding: &RequestBinding, carriers: &[Box<str>]) -> bool {
    binding.head().fields.iter().any(|(name, _)| {
        carriers
            .iter()
            .any(|carrier| carrier.eq_ignore_ascii_case(name))
    })
}

/// Core's own answer to `refusal`: core's one shape. `text`: the words of a row that has none of
/// its own. `challenge`: the route's declared challenge (used only by a row that sends one).
pub(super) fn core(
    binding: &RequestBinding,
    refusal: Refusal,
    verified: bool,
    text: &str,
    challenge: Option<&str>,
) -> Result<Response, InputError> {
    let row = refusal.row(verified);
    tracing::debug!(
        row = row.row,
        status = row.status,
        code = row.code,
        "native request refused"
    );
    data::refusal_response(
        core_answer::answer(refusal, &row, text, challenge).into_items(),
        &binding.request().storage(),
    )
}

/// The one answer to a request that is not verified: on a route its chain denied, and on no
/// route. The same status and bytes whatever the route, so a caller that has not authenticated
/// learns nothing about which routes exist; only the `WWW-Authenticate` text is the route's own,
/// where its protocol's specification requires one.
pub(super) fn unverified(
    binding: &RequestBinding,
    carriers: &[Box<str>],
    challenge: Option<&str>,
) -> Result<Response, InputError> {
    core(
        binding,
        Refusal::Unverified {
            presented: presented(binding, carriers),
        },
        false,
        "",
        challenge,
    )
}

/// What a refusal after verification is rendered with: the route's plane, on the head it was
/// lent, with the route's credential carriers withheld.
pub(super) struct Renderer<'a> {
    pub(super) seat: &'a PortSeat,
    pub(super) route: u32,
    pub(super) head: &'a Arc<ChargedRequestSnapshot>,
    pub(super) withheld: &'a Arc<[Box<str>]>,
    pub(super) request_id: u64,
}

/// The answer to `refusal` on a route. Before verification core writes it and no plugin code
/// runs. After, the plane renders core's record in its dialect where the table says the plane
/// writes the body; core's shape is used when the plane cannot, and core adds the headers the
/// row fixes (`Retry-After`, `Allow`) whoever wrote the body.
pub(super) fn route(
    binding: &RequestBinding,
    refusal: Refusal,
    verified: bool,
    text: &str,
    challenge: Option<&str>,
    renderer: Option<Renderer<'_>>,
) -> Result<Response, InputError> {
    let row = refusal.row(verified);
    let (BodyBy::Plane, Some(renderer)) = (row.by, renderer) else {
        return core(binding, refusal, verified, text, challenge);
    };
    let record = core_answer::client_refusal(&row, text);
    let mut items = crate::root::port_mount::upgrade_refusal_items(
        renderer.seat,
        renderer.route,
        renderer.head,
        renderer.withheld,
        renderer.request_id,
        record,
    );
    // The headers the row fixes are core's, whatever dialect the body is in.
    if let Some(ToClient::Head { fields, .. }) = items.first_mut() {
        if let Some(seconds) = row.retry_after_s {
            if !fields
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case(b"retry-after"))
            {
                fields.push((b"retry-after".to_vec(), seconds.to_string().into_bytes()));
            }
        }
        if let Some(methods) = row.allow {
            fields.push((b"allow".to_vec(), core_answer::allow_value(methods)));
        }
    }
    tracing::debug!(
        row = row.row,
        status = row.status,
        code = row.code,
        "native request refused after verification"
    );
    data::refusal_response(items, &binding.request().storage())
}
