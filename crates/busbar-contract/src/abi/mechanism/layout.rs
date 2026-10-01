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
    40,
    8,
    size = 0,
    _reserved = 4,
    ctx = 8,
    wake = 16,
    conns = 24,
    services = 32
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
pin!(crate::abi::store::Ops, 456, 8, head = 0);
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
    136,
    8,
    head = 0,
    version = 88,
    settings = 96,
    name = 120,
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
    crate::abi::hook::Route,
    40,
    8,
    path = 0,
    method = 16,
    auth = 32,
    _reserved = 36
);
pin!(
    crate::abi::hook::Tail,
    72,
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
    declared_words = 56,
    declared_words_len = 64,
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
pin!(crate::abi::export::ScrapeLabel, 32, 8, key = 0, value = 16);
pin!(
    crate::abi::export::ScrapeSample,
    48,
    8,
    name = 0,
    labels = 16,
    labels_len = 24,
    value = 32
);
pin!(
    crate::abi::export::ScrapeFamily,
    72,
    8,
    name = 0,
    help = 16,
    unit = 32,
    kind = 48,
    _reserved = 49,
    samples = 56,
    samples_len = 64,
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
    crate::abi::export::CheckInstance,
    40,
    8,
    name = 0,
    settings = 16
);
pin!(
    crate::abi::export::CheckIn,
    112,
    8,
    head = 0,
    phase = 88,
    _reserved = 92,
    instances = 96,
    instances_len = 104,
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
    crate::abi::export::Route,
    40,
    8,
    path = 0,
    method = 16,
    auth = 32,
    _reserved = 36
);
pin!(
    crate::abi::export::Tail,
    40,
    8,
    head = 0,
    streams = 8,
    streams_len = 16,
    routes = 24,
    routes_len = 32,
);

// ── THE TRANSPORT KIND (abi/transport/) ──────────────────────────────────────────────────────
mod transport_kind {
    use crate::abi::transport::*;
    use std::mem::{align_of, offset_of, size_of};

    pin!(
        Ops,
        224,
        8,
        head = 0,
        listen = 80,
        accept = 88,
        dial = 96,
        read = 104,
        write = 112,
        flush = 120,
        shut = 128,
        arrival = 136,
        locate = 144,
        begin = 152,
        ingest = 160,
        emit = 168,
        encode = 176,
        refuse = 184,
        finish = 192,
        detach = 200,
        adopt = 208,
        timer = 216
    );
    pin!(
        Claim,
        88,
        8,
        key = 0,
        selector_forms = 16,
        egress_selector_forms = 32,
        facts = 48,
        facts_len = 56,
        status_namespace = 64,
        session = 80,
        session_bound = 81,
        unit0_trigger = 82,
        status_at = 83,
        _reserved = 84
    );
    pin!(StatusRow, 16, 4, claim = 0, lo = 4, hi = 8, class = 12);
    pin!(
        SettingDecl,
        40,
        8,
        path = 0,
        kind = 16,
        _reserved = 20,
        default = 24
    );
    pin!(
        TransportTail,
        168,
        8,
        head = 0,
        role = 8,
        framing = 12,
        facts = 16,
        handshake_max_steps = 20,
        composes_over = 24,
        composes_over_len = 32,
        claims = 40,
        claims_len = 48,
        upgrades_to = 56,
        upgrades_to_len = 64,
        handoff_from = 72,
        handoff_to = 88,
        handoff_binding_fact = 104,
        handshake_frame_kind = 120,
        status_rows = 136,
        status_rows_len = 144,
        settings = 152,
        settings_len = 160
    );
    pin!(Field, 32, 8, name = 0, value = 16);
    pin!(
        Destination,
        72,
        8,
        kind = 0,
        _reserved = 4,
        authority = 8,
        program = 24,
        args = 40,
        args_len = 48,
        env = 56,
        env_len = 64
    );
    pin!(
        ConnFacts,
        104,
        8,
        size = 0,
        _reserved = 4,
        offered_name = 8,
        agreed_protocol = 24,
        peer_subject = 40,
        peer_issuer = 56,
        peer_fingerprint = 72,
        claim = 88
    );
    pin!(
        FramePiece,
        40,
        8,
        stream = 0,
        offset = 8,
        len = 16,
        status_code = 24,
        status_class = 28,
        flags = 29,
        _reserved = 30,
        retry_after_secs = 32
    );
    pin!(
        FramerSink,
        64,
        8,
        wire = 0,
        wire_cap = 8,
        frame = 16,
        frame_cap = 24,
        pieces = 32,
        pieces_cap = 40,
        now_monotonic_ns = 48,
        now_unix_ns = 56
    );
    pin!(
        FramerYield,
        32,
        8,
        wire_len = 0,
        frame_len = 8,
        pieces_len = 16,
        flags = 20,
        next_deadline_ns = 24
    );
    pin!(
        ListenIn,
        120,
        8,
        head = 0,
        bind = 88,
        addr_buf = 104,
        addr_cap = 112
    );
    pin!(
        ListenOut,
        112,
        8,
        head = 0,
        listener = 96,
        addr_written = 104
    );
    pin!(
        AcceptIn,
        112,
        8,
        head = 0,
        listener = 88,
        peer_buf = 96,
        peer_cap = 104
    );
    pin!(AcceptOut, 112, 8, head = 0, conn = 96, peer_written = 104);
    pin!(DialIn, 96, 8, head = 0, dest = 88);
    pin!(ConnOut, 104, 8, head = 0, conn = 96);
    pin!(ReadIn, 112, 8, head = 0, conn = 88, buf = 96, cap = 104);
    pin!(WriteIn, 112, 8, head = 0, conn = 88, bytes = 96, len = 104);
    pin!(IoOut, 104, 8, head = 0, len = 96);
    pin!(ConnIn, 96, 8, head = 0, conn = 88);
    pin!(
        ShutIn,
        104,
        8,
        head = 0,
        conn = 88,
        reason = 96,
        _reserved = 100
    );
    pin!(
        ArrivalIn,
        112,
        8,
        head = 0,
        conn = 88,
        peer_buf = 96,
        peer_cap = 104
    );
    pin!(
        ArrivalOut,
        120,
        8,
        head = 0,
        peer_written = 96,
        peer_needed = 104,
        local_port = 112,
        _reserved = 116
    );
    pin!(
        LocateIn,
        152,
        8,
        head = 0,
        target = 88,
        authority_buf = 104,
        authority_cap = 112,
        name_buf = 120,
        name_cap = 128,
        alpn_buf = 136,
        alpn_cap = 144
    );
    pin!(
        LocateOut,
        152,
        8,
        head = 0,
        authority_written = 96,
        authority_needed = 104,
        name_written = 112,
        name_needed = 120,
        secure = 128,
        has_name = 132,
        alpn_written = 136,
        alpn_needed = 144
    );
    pin!(FramerOut, 136, 8, head = 0, yielded = 96, framing = 128);
    pin!(
        BeginIn,
        184,
        8,
        head = 0,
        side = 88,
        _reserved = 92,
        target = 96,
        facts = 112,
        sink = 120
    );
    pin!(
        IngestIn,
        184,
        8,
        head = 0,
        framing = 88,
        bytes = 96,
        len = 104,
        end = 112,
        _reserved = 116,
        sink = 120
    );
    pin!(
        EmitIn,
        200,
        8,
        head = 0,
        framing = 88,
        stream = 96,
        bytes = 104,
        len = 112,
        end_of_frame = 120,
        _reserved = 124,
        sink = 128,
        deadline_ns = 192
    );
    pin!(
        EncodeIn,
        184,
        8,
        head = 0,
        fields = 88,
        fields_len = 96,
        body = 104,
        body_len = 112,
        sink = 120
    );
    pin!(
        RefuseIn,
        192,
        8,
        head = 0,
        framing = 88,
        stream = 96,
        has_stream = 104,
        _reserved = 108,
        bytes = 112,
        len = 120,
        sink = 128
    );
    pin!(
        FinishIn,
        168,
        8,
        head = 0,
        framing = 88,
        reason = 96,
        _reserved = 100,
        sink = 104
    );
    pin!(FramingIn, 160, 8, head = 0, framing = 88, sink = 96);
    pin!(
        AdoptIn,
        184,
        8,
        head = 0,
        side = 88,
        _reserved = 92,
        facts = 96,
        leftover = 104,
        leftover_len = 112,
        sink = 120
    );
}

// ── THE HOST CONNECTOR (abi/host/conn/connector.rs) ──────────────────────────────────────────────
mod host_connector {
    use crate::abi::host::conn::connector::*;
    use std::mem::{align_of, offset_of, size_of};

    pin!(
        Need,
        96,
        8,
        direction = 0,
        egress_class = 4,
        transport = 8,
        auth = 24,
        target_from = 40,
        trust_from = 56,
        details = 72
    );
    pin!(
        EstablishIn,
        48,
        8,
        head = 0,
        need = 24,
        _reserved = 28,
        target = 32
    );
    pin!(StreamIn, 32, 8, head = 0, stream = 24);
    pin!(IoIn, 48, 8, head = 0, stream = 24, buf = 32, len = 40);
    pin!(
        UpgradeIn,
        64,
        8,
        head = 0,
        stream = 24,
        offered_name = 32,
        trust = 48
    );
    pin!(FactsIn, 40, 8, head = 0, stream = 24, facts = 32);
    pin!(
        StreamFacts,
        56,
        8,
        size = 0,
        secure = 4,
        endpoint = 8,
        agreed_protocol = 24,
        peer_cert_hash = 40
    );
    pin!(CheckoutIn, 32, 4, head = 0, need = 24, _reserved = 28);
    pin!(
        CheckinIn,
        40,
        8,
        head = 0,
        stream = 24,
        disposition = 32,
        _reserved = 36
    );
    pin!(RandomIn, 40, 8, head = 0, buf = 24, len = 32);
    pin!(
        ProcessIdentity,
        48,
        8,
        size = 0,
        _reserved = 4,
        pid = 8,
        os_user = 16,
        program = 32
    );
    pin!(IdentityIn, 32, 8, head = 0, identity = 24);
    pin!(
        ConnectorSlots,
        104,
        8,
        size = 0,
        slots = 4,
        establish = 8,
        reject_endpoint = 16,
        side_stream = 24,
        read = 32,
        write = 40,
        upgrade_secure = 48,
        facts = 56,
        checkout = 64,
        checkin = 72,
        close = 80,
        random = 88,
        identity = 96
    );
}

// ── THE HOST SERVICES (abi/host/service.rs) ─────────────────────────────────────────────────────
#[rustfmt::skip]
mod host_service {
    use crate::abi::host::service::*;
    use std::mem::{align_of, offset_of, size_of};

    pin!(ServiceHead, 24, 4, size = 0, op = 4, handle = 8);
    pin!(ServiceOut, 64, 8, size = 0, outcome = 4, _reserved = 5, value = 8, len = 16,
        items = 24, needed_bytes = 32, needed_items = 40, error = 48);
    pin!(ItemSpan, 16, 4, key_off = 0, key_len = 4, value_off = 8, value_len = 12);
    pin!(ServiceBufs, 32, 8, buf = 0, cap = 8, spans = 16, spans_cap = 24);
    pin!(ClockReading, 24, 8, size = 0, _reserved = 4, wall_ns = 8, mono_ns = 16);
    pin!(ClockNowIn, 32, 8, head = 0, reading = 24);
    pin!(RecordsGetIn, 88, 8, head = 0, kind = 24, key = 40, into = 56);
    pin!(RecordsListIn, 112, 8, head = 0, kind = 24, prefix = 40, after = 56, limit = 72,
        _reserved = 76, into = 80);
    pin!(RecordsClaimIn, 64, 8, head = 0, kind = 24, key = 40, ttl_ms = 56);
    pin!(DestJudgeIn, 48, 8, head = 0, dest = 24, egress_class = 40, flags = 44);
    pin!(SignIn, 80, 8, head = 0, data = 24, into = 48);
    pin!(UnitNestIn, 112, 8, head = 0, verb = 24, target = 40, body = 56, into = 80);
    pin!(WorkOpenIn, 64, 8, head = 0, kind = 24, record = 40);
    pin!(WorkFindIn, 72, 8, head = 0, reference = 24, into = 40);
    pin!(WorkSettleIn, 56, 8, head = 0, handle = 24, record = 32);
    pin!(WorkResumeIn, 64, 8, head = 0, handle = 24, into = 32);
    pin!(TrustSightIn, 56, 8, head = 0, counterparty = 24, catalogue_hash = 40);
    pin!(TrustDueIn, 56, 8, head = 0, into = 24);
    pin!(VerifyLookupIn, 72, 8, head = 0, key = 24, into = 40);
    pin!(VerifyStoreIn, 72, 8, head = 0, key = 24, entry = 40, ttl_ms = 64);
    pin!(EntitlementCheckIn, 40, 8, head = 0, target = 24);
    pin!(ContentScanIn, 80, 8, head = 0, content = 24, into = 48);
    pin!(HookCallIn, 72, 8, head = 0, stage = 24, _reserved = 28, view = 32, into = 40);
    pin!(RandomFillIn, 64, 8, head = 0, len = 24, into = 32);
    pin!(HostSlots, 160, 8, size = 0, slots = 4, clock_now = 8, records_get = 16,
        records_list = 24, records_claim = 32, dest_judge = 40, sign = 48, unit_nest = 56,
        work_open = 64, work_find = 72, work_settle = 80, work_resume = 88, trust_sight = 96,
        trust_due = 104, verify_lookup = 112, verify_store = 120, entitlement_check = 128,
        content_scan = 136, hook_call = 144, random_fill = 152);
}

// ── THE PLANE KIND (abi/plane/) ─────────────────────────────────────────────────────────────
#[rustfmt::skip]
mod plane_kind {
    use std::mem::{align_of, offset_of, size_of};

    use crate::abi::plane::*;

    pin!(Ops, 136, 8, head = 0, arrive = 80, on_piece = 88, refusal = 96, serve = 104,
        hydrate = 112, start = 120, project = 128);
    pin!(Section, 24, 8, name = 0, flags = 16, _reserved = 20);
    pin!(DialectAuth, 24, 8, dialect = 0, _reserved = 4, style = 8);
    pin!(OpClass, 32, 8, op = 0, name = 16);
    pin!(BillableClass, 32, 8, class = 0, family = 16);
    pin!(RouteCost, 16, 8, class = 0, _reserved = 4, weight = 8);
    pin!(RecordChain, 16, 4, kind = 0, framing = 4, flags = 8, _reserved = 12);
    pin!(PinMechanism, 24, 8, token = 0, flags = 16, _reserved = 20);
    pin!(TrustKey, 56, 8, key = 0, role = 16, flags = 20, default = 24, mechanisms = 40,
        mechanisms_len = 48);
    pin!(PlaneTail, 360, 8, head = 0, flags = 8, ingress = 12, dispatch_shape = 16,
        _reserved = 20, scope = 24, label = 40, subject_noun = 56, admin_noun = 72,
        audit_kind = 88, signing_domain = 104, signing_kid_prefix = 120, cli_help = 136,
        sections = 152, sections_len = 160, dialects = 168, dialects_len = 176,
        dialect_auth = 184, dialect_auth_len = 192, scope_kinds = 200, scope_kinds_len = 208,
        op_classes = 216, op_classes_len = 224, billable_classes = 232,
        billable_classes_len = 240, route_cost = 248, route_cost_len = 256, fee_units = 264,
        fee_units_len = 272, record_kinds = 280, record_kinds_len = 288, needs = 296,
        needs_len = 304, egress_targets = 312, egress_targets_len = 320, record_chains = 328,
        record_chains_len = 336, trust_keys = 344, trust_keys_len = 352);
    pin!(Claim, 56, 8, verb = 0, target = 16, carrier = 32, flags = 48, _reserved = 52);
    pin!(AdminRoute, 40, 8, verb = 0, target = 16, flags = 32, _reserved = 36);
    pin!(PlaneSnapshot, 104, 8, size = 0, _reserved = 4, generation = 8, claims = 16,
        claims_len = 24, admin_routes = 32, admin_routes_len = 40, openapi = 48,
        audience = 72, resource_metadata = 88);
    pin!(PlaneOpenIn, 160, 8, open = 0, public_url = 144);
    pin!(PlaneOpenOut, 112, 8, open = 0, snapshot = 104);
    pin!(PlaneRefreshOut, 104, 8, head = 0, snapshot = 96);
    pin!(Field, 32, 8, name = 0, value = 16);
    pin!(Span, 8, 4, offset = 0, len = 4);
    pin!(OutField, 16, 4, name = 0, value = 8);
    pin!(UnitCount, 16, 8, class = 0, source = 4, amount = 8);
    pin!(RecordWrite, 24, 4, kind = 0, op = 4, key = 8, value = 16);
    pin!(ArriveIn, 176, 8, head = 0, unit = 88, claim = 96, _reserved = 100, target = 104,
        fields = 120, fields_len = 128, body = 136, units_buf = 160, units_cap = 168);
    pin!(ArriveOut, 120, 8, head = 0, op_class = 96, principal_need = 100, dialect = 104,
        units_written = 108, units_needed = 112, _reserved = 116);
    pin!(OnPieceIn, 248, 8, head = 0, unit = 88, from = 96, flags = 100, stream = 104,
        bytes = 112, status_code = 136, status_class = 140, reply_buf = 144, reply_cap = 152,
        units_buf = 160, units_cap = 168, records_buf = 176, records_cap = 184,
        fields_buf = 192, fields_cap = 200, arena_buf = 208, arena_cap = 216, member = 224,
        attempt_no = 240, _reserved = 244);
    pin!(OnPieceOut, 176, 8, head = 0, emitted = 96, more = 104, flags = 108,
        reply_status = 112, fields_written = 116, fields_needed = 120, units_written = 124,
        units_needed = 128, records_written = 132, records_needed = 136, verdict = 140,
        arena_written = 144, arena_needed = 152, verb = 160, target = 168);
    pin!(RefusalIn, 168, 8, head = 0, cause = 88, status = 92, dialect = 96, _reserved = 100,
        text = 104, reply_buf = 120, reply_cap = 128, fields_buf = 136, fields_cap = 144,
        arena_buf = 152, arena_cap = 160);
    pin!(RefusalOut, 144, 8, head = 0, reply_written = 96, reply_needed = 104,
        arena_written = 112, arena_needed = 120, marker = 128, fields_written = 132,
        fields_needed = 136, _reserved = 140);
    pin!(ServeIn, 200, 8, head = 0, route = 88, _reserved = 92, target = 96, fields = 112,
        fields_len = 120, body = 128, reply_buf = 152, reply_cap = 160, fields_buf = 168,
        fields_cap = 176, arena_buf = 184, arena_cap = 192);
    pin!(ServeOut, 144, 8, head = 0, reply_written = 96, reply_needed = 104,
        arena_written = 112, arena_needed = 120, status = 128, fields_written = 132,
        fields_needed = 136, _reserved = 140);
    pin!(PlaneDriveIn, 112, 8, drive = 0, sessions_buf = 96, sessions_cap = 104);
    pin!(PlaneDriveOut, 104, 8, head = 0, sessions_written = 96, sessions_needed = 100);
    pin!(ProjectIn, 184, 8, head = 0, claim = 88, _reserved = 92, target = 96, fields = 112,
        fields_len = 120, body = 128, signals_buf = 152, signals_cap = 160, arena_buf = 168,
        arena_cap = 176);
    pin!(ProjectOut, 208, 8, head = 0, view = 96, body = 176, signals_needed = 184,
        _reserved = 188, arena_written = 192, arena_needed = 200);
}
