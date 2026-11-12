"""Core pipeline tiers and conformance stage classification; raw verdicts never change."""

import hashlib
import json
from pathlib import Path

from check import Violation

MODULES = [
    "test_build_closure",
    "test_cargo_capture",
    "test_release_producer",
    "test_release_verifier",
    "test_oci_provenance",
    "test_release_monitor",
    "test_audit_verifier_packaging",
    "test_security_gate",
    "test_artifacts",
    "test_scanner_retrieval",
    "test_development_stage",
]
MISSING = "release-stage subject absent: ModernCI builder key or exact-source attestation delivery not supplied"

# The one definition of core's protected-ref pipelines: (source, branch) -> tier.
# DEV: pushes and owner API pipelines on dev (dev merge requests are classified
# separately). QA: protected qa pushes and the owner's dev schedules (only the
# "qa-nightly" schedule runs QA jobs; the YAML selects it). MAIN signs and
# releases only what QA certified; it runs no conformance of its own.
PROTECTED_PIPELINES = {
    ("push", "dev"): "dev",
    ("api", "dev"): "dev",
    ("push", "qa"): "qa",
    ("schedule", "dev"): "qa",
}
# Protected pipelines that may write a trusted cache: every protected tier
# pipeline except owner API runs (which only re-qualify published dev).
CACHE_PRODUCER_PIPELINES = frozenset(
    pair for pair in PROTECTED_PIPELINES if pair[0] != "api"
)
# Suites whose inputs exist only after main signs the certified binary: the
# Sigstore bundle and the builder's SLSA provenance. DEV and QA defer them.
SIGNED_RELEASE_SUITES = ("slsa-verifier", "sigstore")
# Conformance stages that judge unsigned artifacts: every suite except the
# signed-release ones must pass; those must be exactly the unattempted not-run.
UNSIGNED_STAGES = ("dev", "qa")


def protected_tier(env):
    """'dev' or 'qa' for a protected core tier pipeline, else None (fail closed)."""
    pair = (env.get("CI_PIPELINE_SOURCE"), env.get("CI_COMMIT_BRANCH"))
    if env.get("CI_COMMIT_REF_PROTECTED") != "true":
        return None
    return PROTECTED_PIPELINES.get(pair)


def cache_producer(env):
    """The protected tier of a pipeline that may publish a trusted cache, else None."""
    pair = (env.get("CI_PIPELINE_SOURCE"), env.get("CI_COMMIT_BRANCH"))
    return protected_tier(env) if pair in CACHE_PRODUCER_PIPELINES else None


def stage_context(env):
    """Use controller CI context, never candidate conformance output.

    dev: dev merge requests, dev pushes and owner API pipelines on dev (unchanged).
    qa: protected qa pushes and the owner's dev schedule (qa-nightly). Every suite
    is required except the signed-release ones, which main runs after signing.
    release: anything else; every suite and the Sigstore evidence are required.
    """
    source = env.get("CI_PIPELINE_SOURCE")
    branch = env.get("CI_COMMIT_BRANCH")
    target = env.get("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")
    same_project = bool(env.get("CI_PROJECT_ID")) and env.get(
        "CI_MERGE_REQUEST_SOURCE_PROJECT_ID"
    ) == env.get("CI_PROJECT_ID")
    development = (source in ("push", "api") and branch == "dev") or (
        source == "merge_request_event" and target == "dev" and same_project
    )
    qa = not development and protected_tier(env) == "qa"
    return {
        "stage": "dev" if development else ("qa" if qa else "release"),
        "pipeline_source": source,
        "commit_branch": branch,
        "commit_ref_protected": env.get("CI_COMMIT_REF_PROTECTED") == "true",
        "merge_request_target": target,
        "same_project_merge_request": (
            same_project if source == "merge_request_event" else False
        ),
    }


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise Violation("missing or nonregular release-stage evidence")
    return json.loads(path.read_text())


def engineering(q, report_path):
    report = load(report_path)
    if not (
        report.get("schema") == "busbar.release-engineering/1"
        and report.get("status") == "pass"
        and report.get("source") == q.receipt["source"]
        and report.get("policy_revision") == q.receipt["policy_revision"]
        and report.get("modules") == MODULES
        and type(report.get("tests")) is int
        and report["tests"] >= 60
        and all(
            type(report.get(key)) is int and report[key] == 0
            for key in ("failures", "errors", "skipped")
        )
        and report.get("production_signing") is False
        and report.get("release_attestation_verified") is False
    ):
        raise Violation("required release engineering tests did not pass")
    if getattr(q, "execution", None):
        runtime = report.get("runtime", {})
        if (
            runtime.get("mode") != "protected-offline"
            or runtime.get("manifest_sha256")
            != q.receipt["conformance_inputs"]["mounted_manifest_sha256"]
        ):
            raise Violation("release engineering used unqualified instruments")
    expected = {
        str(path.relative_to(q.trusted)): sha(path)
        for directory in (q.trusted / "scripts/release", q.trusted / "scripts/security")
        for path in directory.glob("*.py")
    }
    for name in (
        "scripts/release-build.sh",
        "scripts/pgo-build.sh",
        "Dockerfile",
        "release/release-targets.json",
        "scripts/architecture/native_release_stage.py",
        "scripts/architecture/native.py",
        "testing/conformance/sigstore.py",
        "testing/conformance/slsa-verifier.sh",
    ):
        expected[name] = sha(q.trusted / name)
    if report.get("inputs") != expected:
        raise Violation("release engineering source inventory differs")
    for name, expected_hash in expected.items():
        if sha(q.root / name) != expected_hash:
            raise Violation(
                "release engineering candidate differs from approved policy: " + name
            )
    return report


def run_engineering(q, collect):
    output = (
        q.work if getattr(q, "execution", None) else q.evidence
    ) / "release-engineering"
    output.mkdir()
    report = output / "result.json"
    try:
        q.run(
            "release-engineering",
            [
                "python3",
                "-I",
                str(q.trusted / "scripts/release/development_checks.py"),
                "--source",
                q.receipt["source"],
                "--policy",
                q.receipt["policy_revision"],
                "--output",
                str(report),
            ],
            timeout=1800,
        )
    finally:
        if getattr(q, "execution", None) and report.exists():
            destination = q.evidence / "release-engineering"
            destination.mkdir()
            collect(q, report, destination / "result.json", limit=1024 * 1024)
    report = q.evidence / "release-engineering/result.json"
    engineering(q, report)
    q.receipt["release_engineering"] = {
        "path": "release-engineering/result.json",
        "sha256": sha(report),
        "required_for_stage": "dev",
    }
    return report


def classify(q, report_path):
    """Only unattempted signed-release readiness may be nonblocking before main.

    dev and qa judge unsigned artifacts with the same strict rule: every suite
    passes and is armed, except slsa-verifier, which must be exactly the
    unattempted not-run (its builder attestation exists only after signing).
    """
    context = q.receipt.get("conformance_stage", {})
    stage = context.get("stage")
    if stage not in UNSIGNED_STAGES:
        raise Violation("release-stage evidence cannot use unsigned-stage classification")
    report = engineering(q, report_path)
    source = q.evidence / "conformance"
    invocation = load(source / "invocation.json")
    if not (
        invocation.get("repo") == "GetBusbar/busbar"
        and invocation.get("commit") == q.receipt["source"]
        and invocation.get("core_pin") == q.receipt["source"]
        and invocation.get("exit_code") == 1
    ):
        raise Violation(
            "development classification requires complete exact-source failed invocation"
        )
    for name in (
        "testing/conformance/suites.tsv",
        "testing/conformance/slsa-verifier.sh",
    ):
        if sha(q.root / name) != sha(q.trusted / name):
            raise Violation("core release-stage controls differ from approved policy")
    required_inputs = {
        "testing/conformance/run.sh",
        "testing/conformance/tools.sh",
        "testing/conformance/suites.tsv",
    }
    if not required_inputs <= invocation.get("inputs", {}).keys():
        raise Violation("conformance invocation input set is incomplete")
    suites = {}
    for line in (q.root / "testing/conformance/suites.tsv").read_text().splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            name, command = line.split("\t", 1)
            if name in suites:
                raise Violation("duplicate core suite")
            suites[name] = command
    if "slsa-verifier" not in suites or set(invocation["verdicts"]) != {
        name + ".json" for name in suites
    }:
        raise Violation("core conformance verdict set is incomplete")
    for name, command in suites.items():
        path = source / "verdicts" / (name + ".json")
        result = load(path)
        if (
            sha(path) != invocation["verdicts"][path.name]
            or result.get("repo") != "GetBusbar/busbar"
            or result.get("commit") != q.receipt["source"]
            or result.get("core_pin") != q.receipt["source"]
        ):
            raise Violation("core conformance subject or digest differs")
        if name == "slsa-verifier":
            if not (
                result.get("status") == "not-run"
                and result.get("armed") is False
                and result.get("reason") == MISSING
            ):
                raise Violation("attempted or malformed provenance cannot be deferred")
        elif result.get("status") != "pass" or result.get("armed") is not True:
            raise Violation(
                "required development conformance suite did not pass: " + name
            )
    coverage = load(q.trusted / "conformance/ci-coverage.json")
    rows = coverage.get("suites", coverage.get("coverage", {}))
    # The generated coverage contract still names slsa-verifier "qa" (its
    # generator assigns every non-Sigstore suite to QA); its builder
    # attestation only exists once main signs, so dev and QA defer it.
    if (
        rows.get("slsa-verifier", {}).get("stage") != "qa"
        or rows.get("sigstore", {}).get("stage") != "main"
    ):
        raise Violation("release-stage classification differs from approved coverage")
    for name, expected in invocation.get("inputs", {}).items():
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or sha(q.root / path) != expected:
            raise Violation("conformance invocation inputs differ")
    return {
        "schema": "busbar.development-conformance/1" if stage == "dev" else "busbar.qa-conformance/1",
        "status": "pass",
        "stage": stage,
        "stage_context": context,
        "source": q.receipt["source"],
        "policy_revision": q.receipt["policy_revision"],
        "coverage_sha256": sha(q.trusted / "conformance/ci-coverage.json"),
        "invocation_sha256": sha(source / "invocation.json"),
        "engineering": {
            "path": "release-engineering/result.json",
            "sha256": sha(report_path),
            "tests": report["tests"],
        },
        "required_suites": sorted(set(suites) - {"slsa-verifier"}),
        "release_readiness": {
            "slsa-verifier": {"stage": "main", "status": "not-run", "armed": False}
        },
        "raw_invocation_exit_code": 1,
        "release_attestation_verified": False,
    }
