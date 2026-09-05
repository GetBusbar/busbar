//! The plane is a value, and asking it twice gives the same answer.
//!
//! A plane that remembers something between calls is a plane whose answer depends on what happened
//! earlier, and the loop has no way to see that. So three properties are asserted here rather than
//! promised: the type can be shared across threads, it holds nothing that can be mutated through a
//! shared reference, and every method returns the same thing when called twice on the same inputs.

mod harness;

use busbar_contract::bounded::Labels;
use busbar_contract::ids::{AdminVerbId, LaneId};
use busbar_contract::plane::{Ingress, Plane};
use busbar_contract::unit::{Refusal, RefusalReason, Step, UnitEnd};
use busbar_contract::wire::FrameCursor;
use busbar_plane_llm::{LlmPlane, Upstream};
use std::path::{Path, PathBuf};

/// The plane can be registered once and called from every worker.
#[test]
fn the_plane_is_shareable() {
    fn require<T: Send + Sync + 'static>() {}
    require::<LlmPlane>();
}

/// The plane can be copied, which a type holding a cell or a lock cannot be.
///
/// This is the compile-time half of the interior-mutability check: every one of the standard
/// shared-mutation containers is either not `Copy` or not `Sync`, so a plane that grew one would
/// stop satisfying this bound and the build would fail here rather than in production.
#[test]
fn the_plane_is_a_plain_value() {
    fn require<T: Copy + Sync + Send + Eq>() {}
    require::<LlmPlane>();
    require::<Upstream>();
}

/// The source holds no shared-mutation container and no mutable static.
///
/// The compile-time check above catches a field; this catches one hidden inside a static or behind
/// a type alias, which is the way the property is usually lost.
#[test]
fn the_source_holds_nothing_mutable() {
    let banned = [
        "Cell<",
        "RefCell<",
        "Mutex<",
        "RwLock<",
        "AtomicUsize",
        "AtomicU64",
        "AtomicU32",
        "AtomicBool",
        "OnceLock",
        "OnceCell",
        "LazyLock",
        "static mut",
        "UnsafeCell",
        "thread_local",
    ];
    let mut offenders = Vec::new();
    walk(&src_dir(), &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            for name in banned {
                if line.contains(name) {
                    offenders.push(format!("{}:{}: {name}", path.display(), n + 1));
                }
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "the plane's own source can mutate state through a shared reference: {offenders:?}"
    );
}

/// One configured upstream, enough to exercise every method.
const UPSTREAMS: &[Upstream] = &[Upstream {
    lane: LaneId::new("lane-openai"),
    host: "openai.invalid",
    dialect: "openai",
    model: "gpt-4o-mini",
}];

/// A request in the dialect the upstream speaks.
const BODY: &str =
    r#"{"model":"gpt-4o-mini","max_tokens":32,"messages":[{"role":"user","content":"Hello"}]}"#;

/// An answer in the same dialect.
const ANSWER: &str = r#"{"id":"chatcmpl-1","object":"chat.completion","created":1752000000,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":4,"total_tokens":16,"prompt_tokens_details":{"cached_tokens":5}}}"#;

/// Every method called twice gives the same answer.
///
/// The two calls are made on two separately constructed planes over two separate arenas, so a value
/// that survived from the first call would have to survive the plane as well — which is the whole
/// property being asserted.
#[test]
fn every_method_answers_the_same_way_twice() {
    let first = run_once();
    let second = run_once();
    assert_eq!(
        first, second,
        "a plane method's answer changed between two identical calls"
    );
}

/// Everything one pass through the plane produces, as comparable values.
#[derive(Debug, PartialEq, Eq)]
struct Pass {
    op: String,
    ingress_facts: Vec<(String, String)>,
    egress_body: Vec<u8>,
    egress_auth: String,
    response_facts: Vec<(String, String)>,
    encoded_response: Vec<u8>,
    refusal: Vec<u8>,
    ending: Option<Vec<u8>>,
    credential: String,
    destination: String,
    scope: Vec<String>,
    admit: String,
    legs: usize,
    usage: Vec<String>,
    audit: String,
    plane_facts: Vec<(String, String)>,
    content_facts: Vec<(String, String)>,
}

/// Drive the plane once, end to end, and collect everything it said.
#[allow(clippy::too_many_lines)]
fn run_once() -> Pass {
    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for("openai"), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);

    let frames = vec![harness::frame(BODY.as_bytes())];
    let mut cursor = FrameCursor::new(&frames);
    let draft = match plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("decodes")
    {
        Ingress::OneShot(draft) => draft,
        other => panic!("expected one complete unit, got {other:?}"),
    };

    let unit = harness::unit(draft.op, draft.body_ir);
    let dest = harness::destination("openai.invalid", LaneId::new("lane-openai"));
    let egress = plane
        .encode_egress(&unit, &dest, None, &ctx)
        .expect("encodes");

    let answer = vec![harness::frame(ANSWER.as_bytes())];
    let mut answers = FrameCursor::new(&answer);
    let progress = plane
        .decode_response(&mut answers, &dest, None, &ctx)
        .expect("reads the answer");
    let response = match progress {
        busbar_contract::plane::Progress::Terminal { r, .. } => r,
        other => panic!("a whole answer body must be terminal, got {other:?}"),
    };

    let encoded = plane
        .encode_response(&response, None, &ctx)
        .expect("writes the answer");
    let refusal = plane
        .encode_refusal(
            &Refusal {
                step: Step::Admit,
                reason: RefusalReason::OverBudget,
                retry_after_secs: None,
                stream: None,
                correlates: None,
            },
            Some(&draft),
            None,
            &ctx,
        )
        .expect("writes a refusal");
    let ending = plane
        .encode_end(
            &unit,
            &UnitEnd::Failed {
                step: Step::Route,
                reason: busbar_contract::unit::FailureReason::Transport,
            },
            None,
            &ctx,
        )
        .expect("writes an ending");

    Pass {
        op: draft.op.to_string(),
        ingress_facts: pairs(&draft.facts),
        egress_body: egress.body.as_slice().to_vec(),
        egress_auth: egress.auth.to_string(),
        response_facts: pairs(&response.facts),
        encoded_response: encoded.as_slice().to_vec(),
        refusal: refusal.as_slice().to_vec(),
        ending: ending.map(|e| e.as_slice().to_vec()),
        credential: format!("{:?}", plane.authenticate(&unit, &ctx)),
        destination: format!("{:?}", plane.verify(&unit, &ctx)),
        scope: plane
            .approve(&unit, &ctx)
            .resources
            .as_slice()
            .iter()
            .map(|r| format!("{}:{}", r.kind, r.name))
            .collect(),
        admit: format!("{:?}", plane.admit(&unit, &ctx)),
        legs: plane.route(&unit, &ctx).legs.len(),
        usage: plane
            .meter(&unit, &response, &ctx)
            .lines
            .as_slice()
            .iter()
            .map(|l| format!("{}={:?}", l.class, l.quantity))
            .collect(),
        audit: format!("{:?}", plane.audit(&unit, &UnitEnd::Completed, &ctx)),
        plane_facts: pairs(
            &plane
                .plane_facts(AdminVerbId::new("dialects"), &ctx)
                .expect("the dialects verb is declared")
                .facts,
        ),
        content_facts: pairs(&plane.content_facts(&unit, &response, &ctx).facts),
    }
}

/// A fact map as comparable pairs, in insertion order.
fn pairs(facts: &busbar_contract::bounded::Facts<'_>) -> Vec<(String, String)> {
    facts
        .iter()
        .map(|(k, v)| (k.to_string(), format!("{v:?}")))
        .collect()
}

/// A verb this plane does not declare is refused, not answered with an empty map.
#[test]
fn an_undeclared_verb_is_refused() {
    let plane = LlmPlane::EMPTY;
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new("/v1/messages", &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    assert!(plane
        .plane_facts(AdminVerbId::new("not-a-verb"), &ctx)
        .is_err());
}

/// The crate's own source directory.
fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Walk every source file under a directory.
fn walk(dir: &Path, f: &mut impl FnMut(&Path, &str)) {
    let entries = std::fs::read_dir(dir).expect("the source directory is readable");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, f);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).expect("a source file is readable");
            f(&path, &text);
        }
    }
}
