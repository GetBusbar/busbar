"""Protected producer fixtures. No production signature or registry write."""

import base64
from pathlib import Path
import unittest
from unittest import mock

import native_provenance as p
import release_producer as producer
import release_verifier as verifier
import test_native_provenance as fixtures
from test_oci_provenance import oci_fixture
from test_build_closure import closure_fixture


class ProducerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = f = fixtures.ProvenanceTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.root = f.root
        self.closure = closure_fixture(
            self.root, f.artifact, f.plan["target"], f.plan["source_commit"]
        )
        f.plan["artifact_sha256"] = p.digest(f.artifact)
        f.receipt["artifact_sha256"] = f.plan["artifact_sha256"]
        f.statement.write_bytes(p.canonical(p.statement(f.plan, f.receipt, f.artifact)))
        qa = f.inventory()
        qa_data = p.load(qa)
        bundle = self.root / "native.bundle.json"
        bundle.write_bytes(p.canonical(self.bundle(f.statement)))
        qa_data["artifacts"][0]["bundle"] = str(bundle)
        qa.write_bytes(p.canonical(qa_data))
        closure = self.root / "build-closure.json"
        closure.write_bytes(p.canonical(self.closure))
        self.plan = self.root / "publication.json"
        observation = self.root / "independent-observation.json"
        observation.write_bytes(
            p.canonical(
                {
                    "schema": "busbar.native-execution-observation/1",
                    "policy_sha256": "c" * 64,
                    **{
                        key: f.plan[key]
                        for key in (
                            "builder_id",
                            "source_commit",
                            "invocation_id",
                            "artifact_sha256",
                        )
                    },
                    "controls": {key: True for key in producer.ISOLATION_CONTROLS},
                    "candidate_uid": 1000,
                    "exit_code": 0,
                    "runtime_sha256": "d" * 64,
                    "toolchain_image_sha256": "e" * 64,
                    "finished_on": f.plan["finished_on"],
                }
            )
        )
        self.plan.write_bytes(
            p.canonical(
                {
                    "schema": producer.SCHEMA,
                    "release": "1.6.0",
                    "qa_manifest": {"path": str(qa), "sha256": p.digest(qa)},
                    "subjects": {
                        f.artifact.name: {
                            "build_closure": {
                                "path": str(closure),
                                "sha256": p.digest(closure),
                            },
                            "build_capture": {
                                "compiler_output": str(self.root / "busbar"),
                                **{
                                    key: {
                                        "path": str(self.root / filename),
                                        "sha256": p.digest(self.root / filename),
                                    }
                                    for key, filename in (
                                        ("cargo_metadata", "cargo-metadata.json"),
                                        ("cargo_lock", "Cargo.lock"),
                                        ("cargo_messages", "cargo-messages.jsonl"),
                                        ("binary", "busbar"),
                                    )
                                },
                            },
                            "component_name": "busbar",
                        }
                    },
                    "oci": [],
                    "isolation_policy_sha256": "c" * 64,
                    "isolation_observations": {
                        f.artifact.name: {
                            "path": str(observation),
                            "sha256": p.digest(observation),
                        }
                    },
                }
            )
        )
        self.output = self.root / "public"
        self.trust = self.root / "trust.json"
        self.trust.write_bytes(
            p.canonical({**f.trust(), "builder_id": f.plan["builder_id"]})
        )

    def bundle(self, statement):
        # Control-flow fixture: crypto invocation is mocked; no valid log assertion.
        return {
            "dsseEnvelope": {
                "payloadType": "application/vnd.in-toto+json",
                "payload": base64.b64encode(statement.read_bytes()).decode(),
                "signatures": [],
            },
            "verificationMaterial": {
                "tlogEntries": [
                    {"inclusionProof": {"checkpoint": {"envelope": "fixture"}}}
                ]
            },
        }

    def prepare(self):
        with mock.patch.object(producer.stage, "stage") as verify:
            draft = producer.prepare(self.plan, p.digest(self.plan), self.output)
            self.assertEqual(verify.call_args.args[:2], ("verify", "qa"))
        path = self.root / "draft.json"
        path.write_bytes(p.canonical(draft))
        return path

    def supply_bundles(self, draft):
        for request in p.load(draft)["signing_requests"]:
            (self.output / request["bundle"]).write_bytes(
                p.canonical(self.bundle(self.output / request["statement"]))
            )

    def finalize(self, draft):
        return producer.finalize(
            draft, p.digest(draft), self.output, self.trust, p.digest(self.trust)
        )

    def test_prepare_is_data_only_and_finalization_requires_real_bundles(self):
        draft = self.prepare()
        self.assertFalse((self.output / verifier.INVENTORY).exists())
        self.assertEqual(len(p.load(draft)["signing_requests"]), 1)
        with self.assertRaises(ValueError):
            self.finalize(draft)
        self.supply_bundles(draft)
        with mock.patch.object(p, "command"):
            result = self.finalize(draft)
        self.assertFalse(result["publication_ready"])
        self.assertFalse((self.output / verifier.BUNDLE).exists())
        (self.output / verifier.BUNDLE).write_bytes(
            p.canonical(self.bundle(self.output / verifier.STATEMENT))
        )
        with mock.patch.object(p, "command"):
            verdict = verifier.verify(
                self.output,
                result["inventory_sha256"],
                self.trust,
                p.digest(self.trust),
            )
        self.assertEqual(verdict["artifacts"], 1)

    def test_failed_qa_or_wrong_plan_pin_never_produces_output(self):
        with self.assertRaises(ValueError):
            producer.prepare(self.plan, "0" * 64, self.output)
        with mock.patch.object(
            producer.stage, "stage", side_effect=ValueError("unqualified QA")
        ):
            with self.assertRaises(ValueError):
                producer.prepare(self.plan, p.digest(self.plan), self.output)
        self.assertFalse(self.output.exists())

    def test_incomplete_independently_required_artifact_set_refuses(self):
        data = p.load(self.plan)
        data["subjects"]["missing.tar.gz"] = data["subjects"][
            self.fixture.artifact.name
        ]
        self.plan.write_bytes(p.canonical(data))
        with self.assertRaises(ValueError):
            producer.prepare(self.plan, p.digest(self.plan), self.output)

    def test_unisolated_forged_or_different_build_observation_refuses_before_qa(self):
        plan = p.load(self.plan)
        binding = plan["isolation_observations"][self.fixture.artifact.name]
        path = Path(binding["path"])
        original = p.load(path)
        for change in (
            {"source_commit": "f" * 40},
            {"candidate_uid": 0},
            {"policy_sha256": "f" * 64},
            {"controls": {}},
            {"controls": {**original["controls"], "receipts_unmounted": False}},
        ):
            path.write_bytes(p.canonical({**original, **change}))
            binding["sha256"] = p.digest(path)
            self.plan.write_bytes(p.canonical(plan))
            with mock.patch.object(
                producer.stage, "stage"
            ) as verify, self.assertRaises(ValueError):
                producer.prepare(self.plan, p.digest(self.plan), self.output)
            verify.assert_not_called()

    def test_protected_collection_can_relocate_binary_without_rewriting_cargo_stream(
        self,
    ):
        plan = p.load(self.plan)
        capture = plan["subjects"][self.fixture.artifact.name]["build_capture"]
        original = Path(capture["binary"]["path"])
        collected = self.root / "controller-collected-binary"
        original.rename(collected)
        capture["binary"]["path"] = str(collected)
        self.plan.write_bytes(p.canonical(plan))
        draft = self.prepare()
        self.assertEqual(p.load(draft)["inventory"]["schema"], verifier.SCHEMA_V3)

    def test_fabricated_component_inventory_and_missing_build_capture_refuse(self):
        plan = p.load(self.plan)
        subject = plan["subjects"][self.fixture.artifact.name]
        closure = Path(subject["build_closure"]["path"])
        data = p.load(closure)
        data["components"][0]["version"] = "invented"
        closure.write_bytes(p.canonical(data))
        subject["build_closure"]["sha256"] = p.digest(closure)
        self.plan.write_bytes(p.canonical(plan))
        with mock.patch.object(producer.stage, "stage"), self.assertRaisesRegex(
            ValueError, "protected build capture"
        ):
            producer.prepare(self.plan, p.digest(self.plan), self.output)
        subject.pop("build_capture")
        self.plan.write_bytes(p.canonical(plan))
        with mock.patch.object(producer.stage, "stage"), self.assertRaises(ValueError):
            producer.prepare(self.plan, p.digest(self.plan), self.output)
        self.assertFalse(self.output.exists())

    def test_symlink_or_device_input_and_overwrite_refuse(self):
        link = self.root / "link"
        link.symlink_to(self.fixture.artifact)
        with self.assertRaises(ValueError):
            producer.transfer(link, self.root / "copy", p.digest(self.fixture.artifact))
        with self.assertRaises(FileExistsError):
            producer.transfer(
                self.fixture.artifact,
                self.fixture.artifact,
                p.digest(self.fixture.artifact),
            )
        with self.assertRaises(ValueError):
            producer.transfer("/dev/null", self.root / "device-copy", "0" * 64)

    def test_mutation_extra_files_and_false_log_verification_refuse(self):
        draft = self.prepare()
        self.supply_bundles(draft)
        with mock.patch.object(p, "command", side_effect=ValueError("untrusted log")):
            with self.assertRaises(ValueError):
                self.finalize(draft)
        extra = self.output / "private-receipt.json"
        extra.write_text("private")
        with mock.patch.object(p, "command"), self.assertRaises(ValueError):
            self.finalize(draft)
        extra.unlink()
        sbom = self.output / p.load(draft)["inventory"]["artifacts"][0]["sbom"]["name"]
        sbom.write_text("changed")
        with mock.patch.object(p, "command"), self.assertRaises(ValueError):
            self.finalize(draft)
        self.assertFalse((self.output / verifier.INVENTORY).exists())

    def test_oci_prepare_finalize_and_independent_consumer_round_trip(self):
        f = self.fixture
        publication = p.load(self.plan)
        qa_path = Path(publication["qa_manifest"]["path"])
        qa = p.load(qa_path)
        entry = qa["artifacts"][0]
        f.plan["target"] = "x86_64-unknown-linux-gnu"
        f.receipt.update(target=f.plan["target"], host_target=f.plan["target"])
        Path(entry["plan"]).write_bytes(p.canonical(f.plan))
        Path(entry["receipt"]).write_bytes(p.canonical(f.receipt))
        entry["plan_sha256"] = p.digest(entry["plan"])
        f.statement.write_bytes(p.canonical(p.statement(f.plan, f.receipt, f.artifact)))
        Path(entry["bundle"]).write_bytes(p.canonical(self.bundle(f.statement)))
        qa_path.write_bytes(p.canonical(qa))
        publication["qa_manifest"]["sha256"] = p.digest(qa_path)
        archive = self.root / "input-oci.tar"
        closure_path = Path(
            publication["subjects"][f.artifact.name]["build_closure"]["path"]
        )
        closure = p.load(closure_path)
        closure["target"] = f.plan["target"]
        closure_path.write_bytes(p.canonical(closure))
        publication["subjects"][f.artifact.name]["build_closure"]["sha256"] = p.digest(
            closure_path
        )
        ref = oci_fixture(archive, binary=b"native executable")
        publication["oci"] = [
            {
                "reference": ref,
                "archive": {"path": str(archive), "sha256": p.digest(archive)},
                "platforms": {
                    "linux/amd64": {
                        "artifact": f.artifact.name,
                        "member": "busbar",
                        "path": "/busbar",
                    }
                },
            }
        ]
        self.plan.write_bytes(p.canonical(publication))
        draft = self.prepare()
        self.supply_bundles(draft)
        requests = p.load(draft)["signing_requests"]
        self.assertEqual(requests[1]["registry_reference"], ref)
        statement = self.output / requests[1]["statement"]
        envelope = p.canonical(
            {
                "payloadType": "application/vnd.in-toto+json",
                "payload": base64.b64encode(statement.read_bytes()).decode(),
            }
        )
        with mock.patch.object(p, "command", return_value=envelope):
            result = self.finalize(draft)
        (self.output / verifier.BUNDLE).write_bytes(
            p.canonical(self.bundle(self.output / verifier.STATEMENT))
        )
        with mock.patch.object(p, "command", return_value=envelope):
            verdict = verifier.verify(
                self.output,
                result["inventory_sha256"],
                self.trust,
                p.digest(self.trust),
            )
        self.assertEqual(verdict["oci_indexes"], 1)
        self.assertTrue(verdict["registry_verified"])


if __name__ == "__main__":
    unittest.main()
