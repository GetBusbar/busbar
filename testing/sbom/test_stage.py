"""Small offline fixtures for manifest-adjacent output on a read-only checkout."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('sbom_stage', HERE / 'stage.py')
staging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(staging)
spec = importlib.util.spec_from_file_location('sbom_crosscheck', HERE / 'crosscheck.py')
crosscheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(crosscheck)


def fixture(root):
    files = {
        'Cargo.toml': '[workspace]\nmembers=["crates/dependency"]\n[workspace.package]\nversion="1.0.0"\nedition="2021"\n',
        'crates/dependency/Cargo.toml': '[package]\nname="sbom-fixture-dependency"\nversion.workspace=true\nedition.workspace=true\n',
        'crates/dependency/src/lib.rs': 'pub fn fixture() {}\n',
        'crates/busbar/src/main.rs': 'fn main() {}\n',
        'dist/default/Cargo.toml': '[package]\nname="busbar-default"\nversion="1.0.0"\nedition="2021"\n[[bin]]\nname="busbar"\npath="../../crates/busbar/src/main.rs"\n[dependencies]\nsbom-fixture-dependency={path="../../crates/dependency"}\n[workspace]\nmembers=["."]\n',
    }
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)
    subprocess.run(['cargo', 'generate-lockfile', '--offline', '--manifest-path', str(root / 'dist/default/Cargo.toml')],
                   cwd=root, check=True, capture_output=True, timeout=30)


def metadata(root):
    return json.loads(subprocess.check_output(['cargo', 'metadata', '--offline', '--locked',
        '--format-version', '1', '--manifest-path', str(root / 'dist/default/Cargo.toml')], cwd=root, timeout=30))


class WritableView(unittest.TestCase):
    def test_readonly_inputs_keep_the_original_locked_closure(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root, view = Path(directory) / 'source', Path(directory) / 'view'
            fixture(root)
            original = metadata(root)
            lock = root / 'dist/default/Cargo.lock'
            before = lock.read_bytes()
            lock.chmod(0o444)
            (root / 'dist/default/Cargo.toml').chmod(0o444)
            manifest = staging.stage(root, view)
            self.assertEqual(manifest.read_bytes(), (root / 'dist/default/Cargo.toml').read_bytes())
            self.assertEqual((manifest.parent / 'Cargo.lock').read_bytes(), before)
            self.assertTrue((manifest.parent / 'Cargo.lock').stat().st_mode & stat.S_IWUSR)
            self.assertEqual(crosscheck.closure(metadata(view)), crosscheck.closure(original))
            (manifest.parent / 'busbar_bin.cdx.json').write_text('{}')
            self.assertFalse((root / 'dist/default/busbar_bin.cdx.json').exists())
            self.assertEqual(lock.read_bytes(), before)

    def test_preexisting_sbom_and_build_output_cannot_be_reused(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root, view = Path(directory) / 'source', Path(directory) / 'view'
            fixture(root)
            (root / 'dist/default/busbar_bin.cdx.json').write_text('stale')
            (root / 'target').mkdir()
            (root / 'dist/default/target').mkdir()
            staging.stage(root, view)
            self.assertFalse((view / 'dist/default/busbar_bin.cdx.json').exists())
            self.assertFalse((view / 'target').exists())
            self.assertFalse((view / 'dist/default/target').exists())

    def test_existing_private_view_is_not_reused(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root, view = Path(directory) / 'source', Path(directory) / 'view'
            fixture(root)
            staging.stage(root, view)
            with self.assertRaises(FileExistsError):
                staging.stage(root, view)


if __name__ == '__main__':
    unittest.main()
