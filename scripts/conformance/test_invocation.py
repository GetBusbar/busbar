"""Focused invocation binding and refusal fixtures."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from invocation import Refused, validated_verdicts


def invocation_record(verdicts):
    first = verdicts[0]
    payloads = {f"{v['suite']}.json": json.dumps(v).encode() for v in verdicts}
    receipt = {"schema": "busbar.conformance.invocation/1", "invocation_id": "1" * 32,
               "repo": first["repo"], "commit": first["commit"], "core_pin": first["core_pin"],
               "started_at": first["generated_at"], "finished_at": first["generated_at"],
               "exit_code": int(any(v["status"] != "pass" for v in verdicts)),
               "inputs": {"testing/conformance/" + name: "a" * 64 for name in ("run.sh", "tools.sh", "suites.tsv")},
               "verdicts": {name: hashlib.sha256(data).hexdigest() for name, data in payloads.items()}}
    return receipt


def archive(verdicts, mutate=None):
    receipt = invocation_record(verdicts)
    if mutate:
        mutate(receipt)
    payloads = {f"{v['suite']}.json": json.dumps(v).encode() for v in verdicts}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        files = {"verdicts/" + name: data for name, data in payloads.items()}
        files["invocation.json"] = json.dumps(receipt).encode()
        for name, data in files.items():
            member = tarfile.TarInfo("target/conformance/" + name)
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
    return buf.getvalue()


class Invocation(unittest.TestCase):
    def setUp(self):
        self.verdict = {"suite": "sample", "status": "pass", "armed": True, "repo": "test/repo",
                        "commit": "a" * 40, "core_pin": "b" * 40, "generated_at": "2026-01-01T00:00:00Z"}

    def validate(self, data, state="green"):
        return validated_verdicts(data, repo="test/repo", head="a" * 40, state=state)

    def test_successful_job_and_complete_generation_are_both_required(self):
        data = archive([self.verdict])
        self.assertEqual(self.validate(data), {"sample": self.verdict})
        for state in (None, "red", "running", "cancelled"):
            with self.subTest(state=state), self.assertRaises(Refused):
                self.validate(data, state)

    def test_receipt_mismatches_never_supply_a_pass(self):
        cases = {
            "exit": lambda r: r.update(exit_code=2),
            "boolean-exit": lambda r: r.update(exit_code=False),
            "head": lambda r: r.update(commit="c" * 40),
            "input": lambda r: r.update(inputs={}),
            "identity": lambda r: r.update(invocation_id=""),
            "output": lambda r: r["verdicts"].update({"sample.json": "0" * 64}),
            "stale": lambda r: r.update(started_at="2026-01-02T00:00:00Z", finished_at="2026-01-02T00:00:00Z"),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name), self.assertRaises(Refused):
                self.validate(archive([self.verdict], mutate))


if __name__ == "__main__":
    unittest.main()
