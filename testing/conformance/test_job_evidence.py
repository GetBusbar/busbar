"""The verdict stamp must identify the native job that actually ran its judge."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/conformance'))
from sync import stamp_problem

JUDGE = (ROOT / 'testing/conformance/run.sh').read_text().split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
HEAD = 'a' * 40
CORE = 'b' * 40
REPO = 'GetBusbar/busbar'
URL = 'https://github.com/GetBusbar/busbar/-/jobs/2371'


class NativeJobEvidence(unittest.TestCase):
    def judge(self, **overrides):
        env = dict(CONF_REPO=REPO, CONF_HEAD=HEAD, BUSBAR_PIN=CORE,
                   CONF_MCI_URL='https://eu-central.modernci.dev',
                   CI_SERVER_HOST='github.com', CI_JOB_ID='2371',
                   CI_PIPELINE_ID='1420', CI_JOB_URL=URL)
        env.update(overrides)
        with tempfile.TemporaryDirectory() as directory:
            raw, output = Path(directory) / 'raw.json', Path(directory) / 'verdict.json'
            raw.write_text(json.dumps(dict(suite='tls', status='pass', armed=True)))
            result = subprocess.run([sys.executable, '-I', '-', str(raw), 'tls', '0', str(output)],
                                    input=JUDGE, text=True, capture_output=True, env=env)
            return result, json.loads(output.read_text()) if output.exists() else None

    def test_native_job_is_bound_and_accepted_by_manifest_reader(self):
        result, verdict = self.judge()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(verdict['run_id'], f'gitlab:{REPO}@{HEAD}:pipeline:1420:job:2371')
        self.assertEqual(verdict['evidence'], URL)
        self.assertIsNone(stamp_problem(verdict, REPO, HEAD, CORE))

    def test_missing_or_inconsistent_job_metadata_cannot_be_modernci_evidence(self):
        for change in ({'CI_JOB_ID': ''}, {'CI_PIPELINE_ID': ''}, {'CI_JOB_URL': ''},
                       {'CI_JOB_URL': URL + '?token=private'}, {'CI_JOB_ID': '99'},
                       {'CI_SERVER_HOST': 'other.invalid'}):
            with self.subTest(change=change):
                result, verdict = self.judge(**change)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(verdict)

    def test_manifest_refuses_another_job_source_or_server(self):
        _, verdict = self.judge()
        for change in ({'evidence': URL.replace('2371', '2372')},
                       {'evidence': URL.replace('github.com', 'other.invalid')},
                       {'run_id': verdict['run_id'].replace(HEAD, 'c' * 40)},
                       {'run_id': verdict['run_id'].replace('pipeline:1420', 'pipeline:0')}):
            with self.subTest(change=change):
                self.assertIsNotNone(stamp_problem({**verdict, **change}, REPO, HEAD, CORE))

    def test_modernci_execution_retains_its_own_evidence(self):
        result, verdict = self.judge(CI_SERVER_HOST='')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(verdict['run_id'], f'modernci:{REPO}@{HEAD}:conformance')
        self.assertIsNone(stamp_problem(verdict, REPO, HEAD, CORE))


if __name__ == '__main__':
    unittest.main()
