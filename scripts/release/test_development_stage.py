"""Stage routing keeps missing release subjects distinct from required dev tests."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/architecture"))
import native_release_stage as stages


class StageClassification(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.q = SimpleNamespace(
            root=self.root,
            trusted=self.root,
            evidence=self.root / "evidence",
            receipt={"source": "a" * 40, "policy_revision": "b" * 40},
        )
        self.q.receipt["conformance_stage"] = stages.stage_context(
            {"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_BRANCH": "dev"}
        )
        for name in (
            "scripts/release",
            "scripts/security",
            "scripts/architecture",
            "release",
            "conformance",
            "testing/conformance",
            "evidence/conformance/verdicts",
        ):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        for name in (
            "scripts/release-build.sh",
            "scripts/pgo-build.sh",
            "Dockerfile",
            "release/release-targets.json",
            "scripts/architecture/native_release_stage.py",
            "scripts/architecture/native.py",
            "testing/conformance/sigstore.py",
            "testing/conformance/slsa-verifier.sh",
            "testing/conformance/run.sh",
            "testing/conformance/tools.sh",
            "testing/conformance/slsa-verifier.sh",
        ):
            (self.root / name).write_text("fixture")
        (self.root / "testing/conformance/suites.tsv").write_text(
            "tls\tbash tls.sh\nslsa-verifier\tbash testing/conformance/slsa-verifier.sh\n"
        )
        (self.root / "conformance/ci-coverage.json").write_text(
            json.dumps(
                {
                    "suites": {
                        "sigstore": {"stage": "main"},
                        "slsa-verifier": {"stage": "qa"},
                    }
                }
            )
        )
        verdicts = {}
        for name in ("tls", "slsa-verifier"):
            value = {
                "suite": name,
                "repo": "GetBusbar/busbar",
                "commit": "a" * 40,
                "core_pin": "a" * 40,
                "status": "pass" if name == "tls" else "not-run",
                "armed": name == "tls",
            }
            if name == "slsa-verifier":
                value["reason"] = stages.MISSING
            path = self.q.evidence / "conformance/verdicts" / f"{name}.json"
            path.write_text(json.dumps(value))
            verdicts[path.name] = stages.sha(path)
        inputs = {
            name: stages.sha(self.root / name)
            for name in (
                "testing/conformance/run.sh",
                "testing/conformance/tools.sh",
                "testing/conformance/suites.tsv",
            )
        }
        self.invocation = self.q.evidence / "conformance/invocation.json"
        self.invocation.write_text(
            json.dumps(
                {
                    "repo": "GetBusbar/busbar",
                    "commit": "a" * 40,
                    "core_pin": "a" * 40,
                    "exit_code": 1,
                    "verdicts": verdicts,
                    "inputs": inputs,
                }
            )
        )
        (self.q.evidence / "release-engineering").mkdir()
        self.report = self.q.evidence / "release-engineering/result.json"
        self.report.write_text(
            json.dumps(
                {
                    "schema": "busbar.release-engineering/1",
                    "status": "pass",
                    **self.q.receipt,
                    "modules": stages.MODULES,
                    "tests": 60,
                    "failures": 0,
                    "errors": 0,
                    "skipped": 0,
                    "production_signing": False,
                    "release_attestation_verified": False,
                    "inputs": {
                        name: stages.sha(self.root / name)
                        for name in (
                            "scripts/release-build.sh",
                            "scripts/pgo-build.sh",
                            "Dockerfile",
                            "release/release-targets.json",
                            "scripts/architecture/native_release_stage.py",
                            "scripts/architecture/native.py",
                            "testing/conformance/sigstore.py",
                            "testing/conformance/slsa-verifier.sh",
                        )
                    },
                }
            )
        )

    def test_exact_missing_qa_subject_is_classified_without_rewriting_raw_evidence(
        self,
    ):
        before = self.invocation.read_bytes()
        result = stages.classify(self.q, self.report)
        self.assertEqual(result["required_suites"], ["tls"])
        self.assertFalse(result["release_attestation_verified"])
        self.assertEqual(
            result["release_readiness"]["slsa-verifier"]["status"], "not-run"
        )
        self.assertEqual(self.invocation.read_bytes(), before)

    def test_real_failed_or_invalid_provenance_and_other_suite_failures_stay_fatal(
        self,
    ):
        for name, changes in [
            ("slsa-verifier", {"status": "fail", "armed": True}),
            ("slsa-verifier", {"reason": "wrong signature"}),
            ("tls", {"status": "not-run", "armed": False}),
        ]:
            path = self.q.evidence / "conformance/verdicts" / f"{name}.json"
            original = path.read_bytes()
            value = json.loads(original)
            value.update(changes)
            path.write_text(json.dumps(value))
            invocation = json.loads(self.invocation.read_text())
            invocation["verdicts"][path.name] = stages.sha(path)
            self.invocation.write_text(json.dumps(invocation))
            with self.assertRaises(stages.Violation):
                stages.classify(self.q, self.report)
            path.write_bytes(original)
            invocation["verdicts"][path.name] = stages.sha(path)
            self.invocation.write_text(json.dumps(invocation))

    def test_missing_engineering_incomplete_roster_and_stale_source_refuse(self):
        original = self.report.read_bytes()
        for changes in (
            {"tests": 0},
            {"skipped": 1},
            {"source": "c" * 40},
            {"status": "fail"},
            {"inputs": {}},
        ):
            value = json.loads(original)
            value.update(changes)
            self.report.write_text(json.dumps(value))
            with self.assertRaises(stages.Violation):
                stages.classify(self.q, self.report)
        self.report.write_bytes(original)
        invocation = json.loads(self.invocation.read_text())
        invocation["verdicts"].pop("tls.json")
        self.invocation.write_text(json.dumps(invocation))
        with self.assertRaises(stages.Violation):
            stages.classify(self.q, self.report)


class QaStage(unittest.TestCase):
    """QA certifies unsigned bytes: strict suites, signing evidence deferred to main."""

    def test_protected_qa_push_and_dev_schedule_are_the_qa_stage(self):
        qa = {"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_BRANCH": "qa", "CI_COMMIT_REF_PROTECTED": "true"}
        nightly = {"CI_PIPELINE_SOURCE": "schedule", "CI_COMMIT_BRANCH": "dev", "CI_COMMIT_REF_PROTECTED": "true"}
        self.assertEqual(stages.stage_context(qa)["stage"], "qa")
        self.assertEqual(stages.stage_context(nightly)["stage"], "qa")
        for env in (dict(qa, CI_COMMIT_REF_PROTECTED="false"), dict(nightly, CI_COMMIT_REF_PROTECTED="false"),
                    dict(qa, CI_COMMIT_BRANCH="main")):
            self.assertEqual(stages.stage_context(env)["stage"], "release")
        # dev semantics are unchanged, protected or not.
        for protected in ("true", "false"):
            self.assertEqual(stages.stage_context({"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_BRANCH": "dev",
                                                   "CI_COMMIT_REF_PROTECTED": protected})["stage"], "dev")
        self.assertEqual(stages.UNSIGNED_STAGES, ("dev", "qa"))

    def test_one_definition_of_protected_tier_pipelines(self):
        self.assertEqual(stages.protected_tier({"CI_PIPELINE_SOURCE": "api", "CI_COMMIT_BRANCH": "dev",
                                                "CI_COMMIT_REF_PROTECTED": "true"}), "dev")
        self.assertIsNone(stages.cache_producer({"CI_PIPELINE_SOURCE": "api", "CI_COMMIT_BRANCH": "dev",
                                                 "CI_COMMIT_REF_PROTECTED": "true"}))
        self.assertIsNone(stages.protected_tier({"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_BRANCH": "dev"}))
        import native
        self.assertEqual(native.PROTECTED_REF_PIPELINES, frozenset(stages.PROTECTED_PIPELINES))

    def test_debug_assertion_subject_runs_in_qa_only_and_never_stages_the_release_binary(self):
        import native
        import native_certified

        for env, allowed in (({"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_BRANCH": "qa",
                               "CI_COMMIT_REF_PROTECTED": "true"}, True),
                              ({"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_BRANCH": "dev"}, False)):
            with self.subTest(env=env), tempfile.TemporaryDirectory() as temporary:
                q = native.Qualification.__new__(native.Qualification)
                q.root = q.evidence = Path(temporary)
                q.env, q.receipt, q.debug_subject = {}, {"steps": []}, True
                q.sdk, q.save = (lambda: q.root), (lambda: None)
                q.conformance = lambda name: q.receipt["steps"].append({"name": name})
                q.run = lambda name, argv: q.receipt["steps"].append({"name": name, "argv": argv})
                with patch.dict(os.environ, env, clear=True), patch.object(
                        stages, "run_engineering", return_value=q.evidence / "report"), patch.object(
                        native_certified, "stage", side_effect=AssertionError("staged release binary")):
                    if allowed:
                        q.core_conformance()
                        self.assertEqual(q.receipt["conformance_subject"]["kind"], "debug-assertions")
                        self.assertNotIn("BUSBAR_CONFORMANCE_SUBJECT", q.env)
                        self.assertIsNone(q.receipt["conformance_results"]["subject_sha256"])
                    else:
                        with self.assertRaisesRegex(stages.Violation, "QA tier only"):
                            q.core_conformance()

    def test_release_stage_classification_is_refused(self):
        q = SimpleNamespace(receipt={"conformance_stage": {"stage": "release"}})
        with self.assertRaisesRegex(stages.Violation, "release-stage"):
            stages.classify(q, Path("unused"))


class TrustedStage(unittest.TestCase):
    def test_only_dev_branch_or_same_project_dev_mr_qualifies(self):
        for pipeline in ("push", "api"):
            for branch in ("qa", "main", "", "dev"):
                self.assertEqual(
                    stages.stage_context(
                        {"CI_PIPELINE_SOURCE": pipeline, "CI_COMMIT_BRANCH": branch}
                    )["stage"],
                    "dev" if branch == "dev" else "release",
                )
        base = {
            "CI_PIPELINE_SOURCE": "merge_request_event",
            "CI_PROJECT_ID": "3",
            "CI_MERGE_REQUEST_SOURCE_PROJECT_ID": "3",
            "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "dev",
        }
        self.assertEqual(stages.stage_context(base)["stage"], "dev")
        protected = {"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_BRANCH": "dev"}
        self.assertIs(stages.stage_context(protected)["commit_ref_protected"], False)
        self.assertIs(stages.stage_context({**protected, "CI_COMMIT_REF_PROTECTED": "true"})["commit_ref_protected"], True)
        self.assertIs(stages.stage_context({**protected, "CI_COMMIT_REF_PROTECTED": "TRUE"})["commit_ref_protected"], False)
        for changes in (
            {"CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main"},
            {"CI_MERGE_REQUEST_SOURCE_PROJECT_ID": "4"},
            {"CI_PROJECT_ID": ""},
            {"CI_PIPELINE_SOURCE": "schedule"},
        ):
            self.assertEqual(
                stages.stage_context({**base, **changes})["stage"], "release"
            )

    def test_controller_requires_missing_release_inputs_on_qa_and_main(self):
        import native

        import native_certified

        protected_qa = {"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_REF_PROTECTED": "true"}
        for branch, raw_failure, env in (
            ("dev", True, {"CI_PIPELINE_SOURCE": "api"}),
            ("qa", True, {"CI_PIPELINE_SOURCE": "api"}),
            ("main", True, {"CI_PIPELINE_SOURCE": "api"}),
            ("dev", False, {"CI_PIPELINE_SOURCE": "api"}),
            ("qa-push", True, protected_qa),
        ):
            unsigned = branch in ("dev", "qa-push")
            with self.subTest(
                branch=branch
            ), tempfile.TemporaryDirectory() as temporary:
                q = native.Qualification.__new__(native.Qualification)
                q.root = q.evidence = Path(temporary)
                q.env = {}
                q.receipt = {"steps": []}
                q.sdk = lambda: q.root

                def conformance(name):
                    q.receipt["steps"].append(
                        {"name": name, "status": "fail", "exit_code": 1}
                    )
                    raise stages.Violation(
                        "core-native-conformance failed; no automatic retry"
                        if raw_failure
                        else "indirect conformance diagnostic evidence"
                    )

                def run(name, argv):
                    q.receipt["steps"].append(
                        {
                            "name": name,
                            "argv": argv,
                            "exit_code": int("--require" in argv),
                        }
                    )
                    if "--require" in argv:
                        raise stages.Violation("release missing")

                q.conformance, q.run = conformance, run
                staged = {"sha256": "c" * 64}
                with patch.dict(
                    os.environ,
                    dict(env, CI_COMMIT_BRANCH=branch.removesuffix("-push")),
                    clear=True,
                ), patch.object(
                    native_certified, "stage", return_value=(None, staged)
                ), patch.object(
                    native_certified, "verify_unchanged"
                ), patch.object(
                    stages, "run_engineering", return_value=q.evidence / "report"
                ), patch.object(
                    stages, "classify", return_value={"status": "pass"}
                ) as classify:
                    if unsigned and raw_failure:
                        q.core_conformance()
                        classify.assert_called_once()
                    else:
                        with self.assertRaises(stages.Violation):
                            q.core_conformance()
                        classify.assert_not_called()
                self.assertEqual(q.receipt["steps"][0]["exit_code"], 1)
                self.assertEqual(
                    "--require" in q.receipt["steps"][-1]["argv"], not unsigned
                )
                if unsigned and raw_failure:
                    key = "development_conformance" if branch == "dev" else "qa_conformance"
                    self.assertEqual(q.receipt[key], {"status": "pass"})
                    self.assertEqual(q.receipt["conformance_subject"]["sha256"], "c" * 64)


class SigstoreStage(unittest.TestCase):
    def execute(self, require=False, values=None):
        with tempfile.TemporaryDirectory() as temporary:
            env = {
                k: v
                for k, v in os.environ.items()
                if not k.startswith("BUSBAR_SIGSTORE_")
            }
            env.update(CONFORMANCE_OUT=temporary, **(values or {}))
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(ROOT / "testing/conformance/sigstore.py"),
                    *(["--require"] if require else []),
                ],
                env=env,
                capture_output=True,
            )
            return result.returncode, json.loads(
                (Path(temporary) / "verdict.json").read_text()
            )

    def test_development_missing_stays_notrun_and_main_missing_fails(self):
        code, verdict = self.execute()
        self.assertEqual(code, 0)
        self.assertEqual(verdict["status"], "not-run")
        self.assertFalse(verdict["armed"])
        code, verdict = self.execute(True)
        self.assertEqual(code, 1)
        self.assertEqual(verdict["status"], "not-run")

    def test_partial_supplied_inputs_are_fatal_even_in_development(self):
        code, verdict = self.execute(
            values={"BUSBAR_SIGSTORE_ARTIFACT": "/not-an-artifact"}
        )
        self.assertEqual(code, 1)
        self.assertEqual(verdict["status"], "fail")

    def test_fully_supplied_malformed_receipt_fails_before_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / "receipt.json"
            receipt.write_text("not JSON")
            code, verdict = self.execute(
                values={
                    "BUSBAR_SIGSTORE_ARTIFACT": str(root / "artifact"),
                    "BUSBAR_SIGSTORE_BUNDLE": str(root / "bundle"),
                    "BUSBAR_SIGSTORE_RECEIPT": str(receipt),
                    "BUSBAR_SIGSTORE_CERTIFICATE_IDENTITY": "https://github.com/fixture",
                    "BUSBAR_SIGSTORE_OIDC_ISSUER": "https://github.com",
                }
            )
            self.assertEqual(code, 1)
            self.assertEqual(verdict["status"], "fail")

    def test_unsigned_qa_preflight_is_notrun_without_a_network_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {
                k: v
                for k, v in os.environ.items()
                if k not in ("BUSBAR_DEV_PROVENANCE_DIR", "BUSBAR_BUILDER_PUB")
            }
            env.update(CONFORMANCE_OUT=temporary)
            result = subprocess.run(
                ["bash", str(ROOT / "testing/conformance/slsa-verifier.sh")],
                env=env,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            verdict = json.loads((Path(temporary) / "verdict.json").read_text())
            self.assertEqual(verdict["status"], "not-run")
            self.assertEqual(verdict["reason"], stages.MISSING)


if __name__ == "__main__":
    unittest.main()
