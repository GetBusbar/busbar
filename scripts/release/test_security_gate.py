"""Focused publication scanner integration, without building the release fixtures."""
from pathlib import Path
from contextlib import redirect_stdout
import io
import json
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import publish_gate as pg
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'security'))
import artifacts


class SecurityGate(unittest.TestCase):
    def test_artifact_receipt_is_required_before_rule_passes(self):
        inp = SimpleNamespace(root=Path('/trusted'), cand=Path('/candidate'))
        for error in (ValueError('private-match'), OSError('private-path')):
            verdict = pg.Verdict()
            with patch.object(pg, 'release_targets', return_value=[{'kind':'image','target':'image-linux-amd64'}]), \
                 patch.object(artifacts, 'scan_candidate', side_effect=error), \
                 self.assertRaises(pg.CannotRun) as caught:
                pg.gs_security(inp, verdict)
            self.assertNotIn('private', str(caught.exception))
            self.assertFalse(verdict.checked.get('G-S'))
        evidence = {'status': 'pass', 'subjects': {'sboms/fixture.cdx.json': 'a' * 64}}
        verdict = pg.Verdict()
        with patch.object(pg, 'release_targets', return_value=[{'kind':'image','target':'image-linux-amd64'}]), \
             patch.object(artifacts, 'scan_candidate', return_value=evidence) as scanner:
            self.assertEqual(pg.gs_security(inp, verdict), evidence)
            scanner.assert_called_once_with(inp.root, inp.cand, ['linux/amd64'])
        self.assertTrue(verdict.checked.get('G-S'))

    def test_plugin_signer_cannot_run_before_matching_sbom_scans(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'release').mkdir()
            (root / 'release/plugin-pins.tsv').write_text('busbar-store-fixture\tv1.6.0\t' + 'a' * 40 + '\n')
            plugins = root / 'plugins'
            plugins.mkdir()
            for target, _, _ in pg.PLUGIN_TARGETS:
                (plugins / ('busbar-store-fixture-1.6.0-' + target + '.tar.gz')).write_bytes(b'fixture')
            inp = SimpleNamespace(root=root, net=Mock(), trust={'k1': 'fixture-public-key'})
            inp.net.release_published.return_value = False
            common = dict(inp=inp, out=root / 'out', repo='busbar-store-fixture', tag='v1.6.0',
                          plugins=plugins, k1_cmd='must-not-run', k2_key='must-not-run')
            with patch.object(pg, 'g14_trust'), patch.object(pg, 'registry_plugins', return_value=['busbar-store-fixture']), \
                 patch.object(pg, 'pack_out', return_value=(0, 'name=busbar-store-fixture version=1.6.0 publisher=busbar signed=false')), \
                 patch.object(pg, 'seal_release', side_effect=RuntimeError('signer reached')) as seal:
                with patch.object(artifacts, 'scan_plugin_candidate', side_effect=ValueError('missing SBOM')), \
                     self.assertRaises(pg.CannotRun):
                    pg.cmd_plugin_release(**common)
                seal.assert_not_called()
                with patch.object(artifacts, 'scan_plugin_candidate', return_value={'status': 'pass'}), \
                     self.assertRaisesRegex(RuntimeError, 'signer reached'):
                    pg.cmd_plugin_release(**common)
                seal.assert_called_once()

    def test_plugin_publication_carries_and_rechecks_signed_sbom_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'release').mkdir()
            (root / 'release/plugin-pins.tsv').write_text('busbar-store-fixture\tv1.6.0\t' + 'a' * 40 + '\n')
            plugins, out, back = root / 'plugins', root / 'out', root / 'download'
            plugins.mkdir()
            back.mkdir()
            subjects = {}
            for target, _, _ in pg.PLUGIN_TARGETS:
                name = 'busbar-store-fixture-1.6.0-' + target + '.tar.gz'
                (plugins / name).write_bytes(b'unsigned fixture')
                sbom = target + '.cdx.json'
                (plugins / sbom).write_text('{"fixture":true}')
                subjects[name] = dict(artifact_sha256=pg.sha256_file(plugins / name), sbom=sbom,
                                      sbom_sha256=pg.sha256_file(plugins / sbom))
            inp = SimpleNamespace(root=root, net=Mock(), trust={'k1': 'fixture-public-key'})
            inp.net.release_published.return_value = False
            inp.net.release_exists.return_value = True
            def seal(_inp, _vd, rows, destination, _key):
                signed = destination / 'signed'
                signed.mkdir()
                for archive, *_ in rows:
                    (signed / archive.name).write_bytes(archive.read_bytes() + b'sealed fixture')
            def sign(_inp, _key, files):
                for path in files:
                    Path(str(path) + '.sig').write_bytes(b'fixture signature')
            uploads = []
            def run(argv, **kwargs):
                if argv[1:3] == ['release', 'upload']:
                    uploads.extend(Path(p) for p in argv[7:])
                if argv[1:3] == ['release', 'download']:
                    for path in uploads:
                        shutil.copyfile(path, back / path.name)
                return subprocess.CompletedProcess(argv, 0)
            with patch.object(pg, 'g14_trust'), patch.object(pg, 'registry_plugins', return_value=['busbar-store-fixture']), \
                 patch.object(pg, 'pack_out', return_value=(0, 'name=busbar-store-fixture version=1.6.0 publisher=busbar signed=false')), \
                 patch.object(artifacts, 'scan_plugin_candidate', return_value={'status':'pass', 'subjects':subjects}), \
                 patch.object(pg, 'seal_release', side_effect=seal), patch.object(pg, 'k2_sign_and_check', side_effect=sign), \
                 patch.object(pg, 'tool', return_value='gh'), patch.object(pg, 'run', side_effect=run), \
                 patch.object(pg.tempfile, 'mkdtemp', return_value=str(back)), redirect_stdout(io.StringIO()):
                self.assertEqual(pg.cmd_plugin_release(inp, out, 'busbar-store-fixture', 'v1.6.0',
                                                       plugins, 'fixture-key', 'fixture-key'), 0)
            evidence = json.loads((back / 'plugin-security.json').read_text())
            self.assertEqual(set(evidence['signed_artifacts']), set(subjects))
            sums = pg.read_sums(back / 'SHA256SUMS')
            for name in ['plugin-security.json', *[row['sbom'] for row in subjects.values()]]:
                self.assertEqual(sums[name], pg.sha256_file(back / name))
