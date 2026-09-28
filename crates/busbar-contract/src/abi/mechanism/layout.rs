// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MECHANISM'S LAYOUT, PINNED AT COMPILE TIME: the size, alignment and every field offset of
//! every `#[repr(C)]` type under `abi/mechanism/`, every kind table and every kind's own shapes,
//! as `const` assertions, so a drift fails the build of every target rather than one test run. The numbers are the 64-bit
//! layout (every target busbar ships); a 32-bit build fails here, by design. `tests/golden/abi-layout.golden` records the same numbers.

use std::mem::{align_of, offset_of, size_of};

use super::call::{AbiStr, Blob, Diag, Envelope, InHead, MetricEntry, OutHead, RawOutcome};
use super::door::{Door, KindTailHead, MetricFamily, Statement};
use super::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, OpsHead, RefreshIn, ReleaseIn, TickIn,
    TickOut, ValidateIn,
};
use super::ticket::{CompletionHandle, HostCtx, HostTables, Ticket};

/// `pin!(T, size, align, field = offset, …)`: a compile-time layout assertion.
macro_rules! pin {
    ($t:ty, $size:expr, $align:expr $(, $f:ident = $off:expr)* $(,)?) => {
        const _: () = {
            assert!(size_of::<$t>() == $size);
            assert!(align_of::<$t>() == $align);
            $(assert!(offset_of!($t, $f) == $off);)*
        };
    };
}

pin!(RawOutcome, 1, 1);
pin!(AbiStr, 16, 8, ptr = 0, len = 8);
pin!(Blob, 24, 8, ptr = 0, len = 8, fmt = 16, flags = 20);
pin!(
    InHead,
    88,
    8,
    size = 0,
    op = 4,
    flags = 8,
    deadline_class = 12,
    _reserved = 13,
    host = 16,
    ticket = 24,
    deadline_ns = 32,
    trace_id = 40,
    parent_span_id = 56,
    extensions = 64
);
pin!(
    MetricEntry,
    32,
    8,
    family_idx = 0,
    kind = 4,
    _reserved = 5,
    value = 8,
    label_vals = 16,
    label_vals_len = 24
);
pin!(
    Diag,
    24,
    8,
    id_idx = 0,
    severity = 4,
    _reserved = 5,
    text = 8
);
pin!(
    Envelope,
    32,
    8,
    metrics = 0,
    metrics_len = 8,
    diags = 16,
    diags_len = 24
);
pin!(
    OutHead,
    96,
    8,
    size = 0,
    outcome = 4,
    _reserved = 5,
    wake_at_ns = 8,
    lease = 16,
    error = 24,
    envelope = 40,
    extensions = 72
);
pin!(
    Door,
    40,
    8,
    magic = 0,
    mechanism_version = 8,
    size = 12,
    kind = 16,
    kind_abi = 20,
    statement = 24,
    ops = 32
);
pin!(
    MetricFamily,
    72,
    8,
    name = 0,
    help = 16,
    unit = 32,
    label_keys = 48,
    label_keys_len = 56,
    kind = 64,
    _reserved = 65
);
pin!(
    Statement,
    152,
    8,
    size = 0,
    kind = 4,
    kind_abi = 8,
    max_inflight = 12,
    name = 16,
    version = 32,
    families = 48,
    families_len = 56,
    diag_ids = 64,
    diag_ids_len = 72,
    kind_tail = 80,
    extensions = 88,
    secret_refs = 112,
    secret_refs_len = 120,
    settings_schema = 128
);
pin!(KindTailHead, 8, 4, size = 0, _reserved = 4);
pin!(Ticket, 8, 4, slot = 0, generation = 4);
pin!(CompletionHandle, 16, 4, ticket = 0, seq = 8, _reserved = 12);
pin!(HostCtx, 8, 8, ptr = 0);
pin!(
    HostTables,
    32,
    8,
    size = 0,
    _reserved = 4,
    ctx = 8,
    wake = 16,
    conns = 24
);
pin!(
    OpsHead,
    80,
    8,
    size = 0,
    slots = 4,
    validate = 8,
    open = 16,
    refresh = 24,
    retire = 32,
    tick = 40,
    drive = 48,
    cancel = 56,
    release = 64,
    close = 72
);
pin!(ValidateIn, 112, 8, head = 0, settings = 88);
pin!(
    OpenIn,
    144,
    8,
    head = 0,
    host = 88,
    settings = 96,
    secrets = 120,
    secrets_len = 128,
    generation = 136
);
pin!(OpenOut, 104, 8, head = 0, instance = 96);
pin!(GenIn, 96, 8, head = 0, generation = 88);
pin!(
    RefreshIn,
    136,
    8,
    head = 0,
    generation = 88,
    settings = 96,
    secrets = 120,
    secrets_len = 128
);
pin!(TickIn, 96, 8, head = 0, now_ns = 88);
pin!(TickOut, 104, 8, head = 0, next_tick_ns = 96);
pin!(DriveIn, 96, 8, head = 0, driver = 88);
pin!(CancelIn, 96, 8, head = 0, ticket = 88);
pin!(
    CancelOut,
    104,
    8,
    head = 0,
    disposition = 96,
    _reserved = 100
);
pin!(ReleaseIn, 96, 8, head = 0, lease = 88);
pin!(crate::abi::store::Ops, 80, 8, head = 0);
pin!(crate::abi::secret::Ops, 88, 8, head = 0, resolve = 80,);
pin!(
    crate::abi::secret::ResolveIn,
    112,
    8,
    head = 0,
    settings = 88,
);
pin!(
    crate::abi::secret::ResolveOut,
    128,
    8,
    head = 0,
    secret = 96,
    error_kind = 120,
    _reserved = 124,
);
// THE AUTH KIND (v3, design B.3): its table, its Statement tail and every op's `in`/`out`.
mod auth {
    use super::{align_of, offset_of, size_of};
    use crate::abi::auth::*;

    pin!(
        Ops,
        128,
        8,
        head = 0,
        verify = 80,
        begin_login = 88,
        complete_login = 96,
        open_outbound = 104,
        outbound_ready = 112,
        fields = 120
    );
    pin!(StyleDecl, 24, 8, name = 0, flags = 16, _reserved = 20);
    pin!(
        AuthTail,
        72,
        8,
        head = 0,
        caps = 8,
        facts = 12,
        login_kind = 16,
        _reserved = 20,
        styles = 24,
        styles_len = 32,
        aliases = 40,
        aliases_len = 48,
        carriers = 56,
        carriers_len = 64
    );
    pin!(Span, 8, 4, off = 0, len = 4);
    pin!(NamedValue, 40, 8, name = 0, value = 16);
    pin!(
        RequestFacts,
        112,
        8,
        method = 0,
        authority = 16,
        canonical_path = 32,
        query = 48,
        timestamp = 64,
        body_hash = 72,
        body_hash_present = 104,
        _reserved = 108
    );
    pin!(
        IdentityBuf,
        32,
        8,
        buf = 0,
        buf_cap = 8,
        groups = 16,
        groups_cap = 24,
        _reserved = 28
    );
    pin!(
        IdentityOut,
        80,
        8,
        subject = 0,
        key_id = 8,
        key_name = 16,
        user = 24,
        provider = 32,
        name = 40,
        claims = 48,
        claims_fmt = 56,
        flags = 60,
        ttl_secs = 64,
        groups_len = 72,
        _reserved = 76
    );
    pin!(
        VerifyIn,
        272,
        8,
        head = 0,
        credential = 88,
        carrier = 112,
        carrier_len = 120,
        request = 128,
        out_buf = 240
    );
    pin!(
        IdentifyOut,
        192,
        8,
        head = 0,
        verdict = 96,
        needed_groups = 100,
        needed_bytes = 104,
        identity = 112
    );
    pin!(
        BeginLoginIn,
        168,
        8,
        head = 0,
        redirect_uri = 88,
        state = 104,
        nonce = 120,
        code_challenge = 136,
        scopes = 152,
        scopes_len = 160
    );
    pin!(
        LoginField,
        40,
        8,
        name = 0,
        label = 16,
        kind = 32,
        required = 36
    );
    pin!(
        BeginLoginOut,
        136,
        8,
        head = 0,
        shape = 96,
        _reserved = 100,
        authorize_url = 104,
        form = 120,
        form_len = 128
    );
    pin!(
        CompleteLoginIn,
        216,
        8,
        head = 0,
        code = 88,
        state = 112,
        redirect_uri = 128,
        code_verifier = 144,
        submitted = 168,
        submitted_len = 176,
        out_buf = 184
    );
    pin!(
        OpenOutboundIn,
        152,
        8,
        head = 0,
        style = 88,
        credential = 104,
        settings = 128
    );
    pin!(OpenOutboundOut, 104, 8, head = 0, handle = 96);
    pin!(OutboundReadyIn, 96, 8, head = 0, handle = 88);
    pin!(
        OutboundReadyOut,
        104,
        8,
        head = 0,
        ready = 96,
        _reserved = 100
    );
    pin!(
        FieldSpan,
        24,
        4,
        name = 0,
        value = 8,
        flags = 16,
        _reserved = 20
    );
    pin!(
        FieldsIn,
        288,
        8,
        head = 0,
        handle = 88,
        mode = 96,
        _reserved = 100,
        request = 104,
        caller_credential = 216,
        field_buf = 240,
        field_buf_cap = 248,
        fields = 256,
        fields_cap = 264,
        _reserved2 = 268,
        headers = 272,
        headers_len = 280
    );
    pin!(
        FieldsOut,
        112,
        8,
        head = 0,
        fields_len = 96,
        needed_fields = 100,
        needed_bytes = 104
    );
}
// ── HOOK (M3-SHAPES, abi-v2-perkind.md B.4) ─────────────────────────────────────────────────────
pin!(
    crate::abi::hook::Ops,
    136,
    8,
    head = 0,
    decide = 80,
    transform = 88,
    notify = 96,
    configure = 104,
    status = 112,
    describe = 120,
    serve = 128,
);
pin!(crate::abi::hook::SignalValue, 16, 8);
pin!(
    crate::abi::hook::SignalEntry,
    24,
    8,
    id = 0,
    tag = 4,
    value = 8
);
pin!(
    crate::abi::hook::RequestView,
    80,
    8,
    request_id = 0,
    pool = 8,
    ingress_dialect = 24,
    message_count = 40,
    total_chars = 48,
    max_tokens = 56,
    flags = 60,
    signals = 64,
    signals_len = 72,
);
pin!(
    crate::abi::hook::CandidateStatic,
    104,
    8,
    idx = 0,
    _reserved = 4,
    model = 8,
    provider = 24,
    weight = 40,
    _reserved3 = 44,
    context_max = 48,
    tier = 56,
    cost_per_mtok = 72,
    tags = 80,
    tags_len = 88,
    present = 96,
    _reserved2 = 100,
);
pin!(
    crate::abi::hook::CandidateDynamic,
    56,
    8,
    latency_ms = 0,
    available_concurrency = 8,
    budget_remaining = 16,
    rate_headroom = 24,
    signals = 32,
    signals_len = 40,
    present = 48,
    _reserved = 52,
);
pin!(
    crate::abi::hook::PromptView,
    48,
    8,
    system = 0,
    message_count = 16,
    body = 24,
);
pin!(
    crate::abi::hook::UserView,
    48,
    8,
    key_id = 0,
    key_name = 16,
    user = 32
);
pin!(
    crate::abi::hook::BudgetBucketState,
    96,
    8,
    bucket_id = 0,
    budget_group = 16,
    pool = 32,
    spend_micros_at_current_rate = 48,
    remaining_micros = 56,
    window_start = 64,
    budget_period = 72,
    present = 88,
    _reserved = 92,
);
pin!(
    crate::abi::hook::DecideIn,
    384,
    8,
    head = 0,
    request = 88,
    candidates = 168,
    candidate_dynamics = 176,
    candidates_len = 184,
    prompt = 192,
    user = 240,
    budget_remaining = 288,
    budget = 296,
    budget_len = 304,
    present = 312,
    _reserved = 316,
    order_buf = 320,
    order_cap = 328,
    reject_message_buf = 336,
    reject_message_cap = 344,
    restrict_tags_buf = 352,
    restrict_tags_cap = 360,
    rewrite_buf = 368,
    rewrite_cap = 376,
);
pin!(
    crate::abi::hook::DecideOut,
    152,
    8,
    head = 0,
    verbs = 96,
    reject_status = 100,
    _reserved = 102,
    reject_message_written = 104,
    reject_message_needed = 112,
    restrict_tags_written = 120,
    restrict_tags_needed = 128,
    order_written = 136,
    order_needed = 144,
);
pin!(
    crate::abi::hook::TransformOut,
    136,
    8,
    head = 0,
    verbs = 96,
    reject_status = 100,
    _reserved = 102,
    reject_message_written = 104,
    reject_message_needed = 112,
    rewrite_written = 120,
    rewrite_needed = 128,
);
pin!(
    crate::abi::hook::StageView,
    144,
    8,
    request_id = 0,
    pool = 8,
    ingress_dialect = 24,
    message_count = 40,
    total_chars = 48,
    remaining_candidates = 56,
    model = 64,
    previous_failure = 80,
    outcome = 96,
    max_tokens = 112,
    flags = 116,
    at = 120,
    attempt_number = 124,
    status = 128,
    _reserved = 130,
    stage_present = 132,
    _reserved2 = 136,
);
pin!(crate::abi::hook::NotifyIn, 232, 8, head = 0, stage = 88);
pin!(
    crate::abi::hook::ConfigureIn,
    120,
    8,
    head = 0,
    version = 88,
    settings = 96,
);
pin!(
    crate::abi::hook::ConfigureOut,
    104,
    8,
    head = 0,
    acked_version = 96
);
pin!(crate::abi::hook::StatusOut, 120, 8, head = 0, status = 96);
pin!(
    crate::abi::hook::DescribeOut,
    120,
    8,
    head = 0,
    describe = 96
);
pin!(
    crate::abi::hook::ServeIn,
    176,
    8,
    head = 0,
    method = 88,
    path = 104,
    query = 120,
    headers = 136,
    headers_len = 144,
    body = 152,
);
pin!(
    crate::abi::hook::ServeOut,
    144,
    8,
    head = 0,
    status_code = 96,
    _reserved = 98,
    headers_out = 104,
    headers_out_len = 112,
    body = 120,
);
pin!(
    crate::abi::hook::Tail,
    56,
    8,
    head = 0,
    kind_class = 8,
    prompt_access = 12,
    user_access = 16,
    infallible = 20,
    _reserved = 21,
    requested_signals = 24,
    requested_signals_len = 32,
    routes = 40,
    routes_len = 48,
);

// ── EXPORT (M3-SHAPES, abi-v2-perkind.md B.5) ───────────────────────────────────────────────────
pin!(
    crate::abi::export::Ops,
    120,
    8,
    head = 0,
    deliver = 80,
    scrape = 88,
    status = 96,
    check = 104,
    serve = 112,
);
pin!(
    crate::abi::export::DeliverIn,
    136,
    8,
    head = 0,
    op_id = 88,
    stream = 104,
    _reserved = 105,
    batch = 112,
);
pin!(
    crate::abi::export::ScrapeSample,
    24,
    8,
    label_vals = 0,
    label_vals_len = 8,
    value = 16
);
pin!(
    crate::abi::export::ScrapeFamily,
    88,
    8,
    name = 0,
    help = 16,
    unit = 32,
    label_keys = 48,
    label_keys_len = 56,
    kind = 64,
    _reserved = 65,
    samples = 72,
    samples_len = 80,
);
pin!(
    crate::abi::export::ScrapeIn,
    120,
    8,
    head = 0,
    families = 88,
    families_len = 96,
    buf = 104,
    cap = 112,
);
pin!(
    crate::abi::export::ScrapeOut,
    112,
    8,
    head = 0,
    written = 96,
    needed = 104
);
pin!(crate::abi::export::StatusOut, 120, 8, head = 0, status = 96);
pin!(
    crate::abi::export::CheckIn,
    96,
    8,
    head = 0,
    phase = 88,
    _reserved = 92
);
pin!(
    crate::abi::export::CheckOut,
    120,
    8,
    head = 0,
    findings = 96
);
pin!(
    crate::abi::export::ServeIn,
    176,
    8,
    head = 0,
    method = 88,
    path = 104,
    query = 120,
    headers = 136,
    headers_len = 144,
    body = 152,
);
pin!(
    crate::abi::export::ServeOut,
    144,
    8,
    head = 0,
    status_code = 96,
    _reserved = 98,
    headers_out = 104,
    headers_out_len = 112,
    body = 120,
);
pin!(
    crate::abi::export::Tail,
    24,
    8,
    head = 0,
    streams = 8,
    streams_len = 16
);

pin!(crate::abi::plane::Ops, 80, 8, head = 0);
pin!(crate::abi::transport::Ops, 80, 8, head = 0);
